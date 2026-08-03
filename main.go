package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// ArtifactState represents the lifecycle state of an artifact in the registry.
// Only artifacts in "trusted" state are available for runtime consumption.
type ArtifactState string

const (
	StateAcquired    ArtifactState = "acquired"    // downloaded/received but not yet scanned
	StateQuarantined ArtifactState = "quarantined" // being scanned by quarantine pipeline
	StateTrusted     ArtifactState = "trusted"     // all checks passed, available for runtime
	StateRevoked     ArtifactState = "revoked"     // revoked, blocked from runtime use
	StateDeleted     ArtifactState = "deleted"     // soft-deleted, metadata retained for audit
)

// validStates is the set of all recognized artifact states.
var validStates = map[ArtifactState]bool{
	StateAcquired:    true,
	StateQuarantined: true,
	StateTrusted:     true,
	StateRevoked:     true,
	StateDeleted:     true,
}

// Artifact represents a model or related file in the registry.
type Artifact struct {
	Name     string `json:"name" yaml:"name"`
	Format   string `json:"format" yaml:"format"`
	Filename string `json:"filename" yaml:"filename"`
	// ObjectPath is the immutable, content-addressed path used by runtime
	// consumers after promotion. Filename remains the quarantine input name.
	ObjectPath      string            `json:"object_path,omitempty" yaml:"object_path,omitempty"`
	SHA256          string            `json:"sha256" yaml:"sha256"`
	SizeBytes       int64             `json:"size_bytes" yaml:"size_bytes"`
	Source          string            `json:"source,omitempty" yaml:"source,omitempty"`
	PromotedAt      string            `json:"promoted_at" yaml:"promoted_at"`
	State           ArtifactState     `json:"state" yaml:"state"`
	ScanResults     map[string]string `json:"scan_results,omitempty" yaml:"scan_results,omitempty"`
	ScannerVersions map[string]string `json:"scanner_versions,omitempty" yaml:"scanner_versions,omitempty"`
	PolicyVersion   string            `json:"policy_version,omitempty" yaml:"policy_version,omitempty"`
	SourceRevision  string            `json:"source_revision,omitempty" yaml:"source_revision,omitempty"`
	// gguf-guard integrity data (GGUF files only)
	GGUFGuardFingerprint map[string]any `json:"gguf_guard_fingerprint,omitempty" yaml:"gguf_guard_fingerprint,omitempty"`
	GGUFGuardManifest    string         `json:"gguf_guard_manifest,omitempty" yaml:"gguf_guard_manifest,omitempty"`
}

// Manifest is the runtime registry manifest (stored as JSON).
type Manifest struct {
	Version int                  `json:"version"`
	Models  []Artifact           `json:"models"`
	Events  []RegistryAuditEvent `json:"events,omitempty"`
}

type RegistryAuditEvent struct {
	Sequence  int64         `json:"sequence"`
	Timestamp string        `json:"timestamp"`
	Action    string        `json:"action"`
	Name      string        `json:"name"`
	FromState ArtifactState `json:"from_state,omitempty"`
	ToState   ArtifactState `json:"to_state,omitempty"`
	SHA256    string        `json:"sha256,omitempty"`
	// Artifact is a complete post-transition snapshot. Replaying every snapshot
	// must reconstruct Manifest.Models exactly; a hash-valid chain with altered
	// metadata or skipped transitions is rejected.
	Artifact Artifact `json:"artifact"`
	PrevHash string   `json:"prev_hash"`
	Hash     string   `json:"hash"`
}

// ModelsLock is the baked-in models.lock.yaml (immutable OS boot fallback).
type ModelsLock struct {
	Version int        `yaml:"version"`
	Models  []Artifact `yaml:"models"`
}

// PromoteRequest is sent by the promotion pipeline to admit an artifact.
type PromoteRequest struct {
	Name                 string            `json:"name"`
	Filename             string            `json:"filename"`
	SHA256               string            `json:"sha256"`
	SizeBytes            int64             `json:"size_bytes"`
	Source               string            `json:"source,omitempty"`
	ScanResults          map[string]string `json:"scan_results,omitempty"`
	ScannerVersions      map[string]string `json:"scanner_versions,omitempty"`
	PolicyVersion        string            `json:"policy_version,omitempty"`
	SourceRevision       string            `json:"source_revision,omitempty"`
	GGUFGuardFingerprint map[string]any    `json:"gguf_guard_fingerprint,omitempty"`
	GGUFGuardManifest    string            `json:"gguf_guard_manifest,omitempty"`
}

var (
	manifest     Manifest
	manifestMu   sync.RWMutex
	registryDir  string
	manifestPath string
	allowedFmts  = map[string]bool{"gguf": true, "safetensors": true}
	serviceToken string
	// P0: fail-closed auth — mutations are blocked when no token is configured
	// unless INSECURE_DEV_MODE=true is explicitly set.
	insecureDevMode bool
)

const (
	maxRequestBodySize = 1 << 20
	maxManifestBytes   = 16 << 20
	maxTokenBytes      = 4096
	maxIntegrityBytes  = 1 << 20
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var hashVerifySlots = make(chan struct{}, 4)

// loadServiceToken reads the service-to-service auth token from disk.
func loadServiceToken() error {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = "/run/secure-ai/service-token"
	}
	// #nosec G703 -- administrator-selected credential path; bounded regular-file and identity checks follow.
	if info, err := os.Lstat(tokenPath); err == nil && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("service token must not be accessible by group or other users")
	}
	data, err := readRegularBounded(tokenPath, maxTokenBytes)
	if err != nil {
		if insecureDevMode {
			log.Printf("WARNING: service token not loaded (%v) — INSECURE_DEV_MODE enabled, non-health APIs allowed without auth", err)
			return nil
		} else {
			return fmt.Errorf("service authentication unavailable: %w", err)
		}
	}
	serviceToken = strings.TrimSpace(string(data))
	if serviceToken == "" {
		if insecureDevMode {
			log.Printf("WARNING: service token file is empty — INSECURE_DEV_MODE enabled, non-health APIs allowed without auth")
			return nil
		} else {
			return fmt.Errorf("service token file is empty")
		}
	}
	if len(serviceToken) < 32 || strings.ContainsAny(serviceToken, " \t\r\n") {
		return fmt.Errorf("service token must be at least 32 bytes without whitespace")
	}
	log.Printf("service token loaded from %s", tokenPath)
	return nil
}

func readRegularBounded(path string, limit int64) ([]byte, error) {
	// #nosec G703 -- callers supply administrator-configured paths; this helper rejects links and identity changes.
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symbolic links are not allowed")
	}
	// #nosec G304,G703 -- validated administrator path, followed by opened-file and post-open identity checks.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// #nosec G703 -- paired with pre/opened identity checks above.
	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, fmt.Errorf("file changed while opening or is a symbolic link")
	}
	if !opened.Mode().IsRegular() || opened.Size() > limit {
		return nil, fmt.Errorf("file must be regular and no larger than %d bytes", limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	return data, nil
}

// requireServiceToken wraps every non-health handler with Bearer authentication.
func requireServiceToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if serviceToken == "" {
			if insecureDevMode {
				next(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "service authentication unavailable",
			})
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(serviceToken)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		next(w, r)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func loadManifest() error {
	// Try runtime manifest first (writable storage)
	data, err := readRegularBounded(manifestPath, maxManifestBytes)
	if err == nil {
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&manifest); err != nil {
			return err
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return fmt.Errorf("manifest must contain exactly one JSON value")
		}
		// Runtime manifests are writable state and must never gain trust through a
		// compatibility default. Missing states fail validation below.
		if err := validateManifest(manifest); err != nil {
			return err
		}
		if len(manifest.Models) != 0 && len(manifest.Events) == 0 {
			if os.Getenv("ALLOW_LEGACY_MANIFEST_MIGRATION") != "true" {
				return fmt.Errorf("runtime manifest has models but no replayable audit history")
			}
			for i := range manifest.Models {
				artifact := &manifest.Models[i]
				if artifact.State != StateTrusted || artifact.ObjectPath != "" {
					continue
				}
				objectRel, migrateErr := storeContentAddressedObject(
					artifact.Filename, artifact.SHA256, artifact.Format, artifact.SizeBytes,
				)
				if migrateErr != nil {
					return fmt.Errorf("migrate legacy artifact %q: %w", artifact.Name, migrateErr)
				}
				artifact.ObjectPath = objectRel
			}
			ensureRegistryEventBaseline()
			if err := saveManifest(); err != nil {
				return fmt.Errorf("persist migrated manifest: %w", err)
			}
			log.Printf("WARNING: migrated legacy runtime manifest; unset ALLOW_LEGACY_MANIFEST_MIGRATION before restart")
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("read runtime manifest: %w", err)
	}

	// Fall back to baked-in models.lock.yaml
	lockPath := os.Getenv("REGISTRY_LOCK_PATH")
	if lockPath == "" {
		lockPath = "/etc/secure-ai/policy/models.lock.yaml"
	}
	data, err = readRegularBounded(lockPath, maxManifestBytes)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read fallback manifest: %w", err)
		}
		manifest = Manifest{Version: 1, Models: []Artifact{}}
		return nil
	}
	var lock ModelsLock
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&lock); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("models lock must contain exactly one YAML document")
	}
	manifest = Manifest{Version: lock.Version, Models: lock.Models}
	// Backfill State for lock file entries
	for i := range manifest.Models {
		if manifest.Models[i].State == "" {
			manifest.Models[i].State = StateTrusted
		}
	}
	return validateManifest(manifest)
}

func saveManifest() error {
	if err := validateManifest(manifest); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > maxManifestBytes {
		return fmt.Errorf("manifest exceeds %d-byte limit", maxManifestBytes)
	}
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(manifestPath), ".manifest-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, manifestPath); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(manifestPath))
	if err == nil {
		err = dir.Sync()
		_ = dir.Close()
	}
	return err
}

func validateManifest(candidate Manifest) error {
	if candidate.Version != 1 {
		return fmt.Errorf("unsupported manifest version %d", candidate.Version)
	}
	if len(candidate.Models) > 100_000 || len(candidate.Events) > 100_000 {
		return fmt.Errorf("manifest exceeds entry limits")
	}
	names := make(map[string]struct{}, len(candidate.Models))
	activeFiles := make(map[string]string, len(candidate.Models))
	for _, artifact := range candidate.Models {
		if err := validateArtifactMetadata(artifact); err != nil {
			return err
		}
		if _, exists := names[artifact.Name]; exists {
			return fmt.Errorf("duplicate artifact name %q", artifact.Name)
		}
		names[artifact.Name] = struct{}{}
		if artifact.State != StateDeleted {
			if previous, exists := activeFiles[artifact.Filename]; exists {
				return fmt.Errorf("artifacts %q and %q share an active filename", previous, artifact.Name)
			}
			activeFiles[artifact.Filename] = artifact.Name
		}
	}
	if len(candidate.Events) == 0 {
		// Baked-in models.lock.yaml is an immutable boot fallback and has no event
		// history. Writable runtime manifests with models are rejected in
		// loadManifest and every mutation establishes a replay baseline.
		return nil
	}
	previous := "genesis"
	for i, event := range candidate.Events {
		if event.Sequence != int64(i+1) || event.PrevHash != previous || event.Hash != hashRegistryEvent(event) {
			return fmt.Errorf("audit chain break at event %d", i+1)
		}
		if err := validateRegistryEvent(event); err != nil {
			return fmt.Errorf("invalid audit event %d: %w", i+1, err)
		}
		previous = event.Hash
	}
	replayed, err := replayRegistryEvents(candidate.Events)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(replayed, candidate.Models) {
		return fmt.Errorf("manifest models do not exactly match full audit replay")
	}
	return nil
}

func validateArtifactMetadata(artifact Artifact) error {
	if artifact.Name == "" || len(artifact.Name) > 256 || strings.TrimSpace(artifact.Name) != artifact.Name ||
		strings.ContainsAny(artifact.Name, "\x00\r\n") {
		return fmt.Errorf("invalid artifact name")
	}
	if _, err := registryRel(artifact.Filename); err != nil {
		return fmt.Errorf("artifact %q has invalid filename", artifact.Name)
	}
	if !sha256Pattern.MatchString(artifact.SHA256) {
		return fmt.Errorf("artifact %q has invalid SHA-256", artifact.Name)
	}
	if !allowedFmts[artifact.Format] || formatFromFilename(artifact.Filename) != artifact.Format ||
		artifact.SizeBytes < 0 || len(artifact.Source) > 4096 || !validStates[artifact.State] ||
		len(artifact.PolicyVersion) > 256 || len(artifact.SourceRevision) > 256 ||
		!validateEvidenceMap(artifact.ScanResults) || !validateEvidenceMap(artifact.ScannerVersions) ||
		!validateStructuredMetadata(artifact.GGUFGuardFingerprint) {
		return fmt.Errorf("artifact %q has invalid metadata", artifact.Name)
	}
	if artifact.PromotedAt != "" {
		if _, err := time.Parse(time.RFC3339, artifact.PromotedAt); err != nil {
			return fmt.Errorf("artifact %q has invalid timestamp", artifact.Name)
		}
	}
	if artifact.GGUFGuardManifest != "" {
		if _, err := registryRel(artifact.GGUFGuardManifest); err != nil {
			return fmt.Errorf("artifact %q has invalid GGUF manifest path", artifact.Name)
		}
	}
	if artifact.ObjectPath != "" {
		expected, err := contentAddressedObjectRel(artifact.SHA256, artifact.Format)
		if err != nil || artifact.ObjectPath != expected {
			return fmt.Errorf("artifact %q has invalid content-addressed object path", artifact.Name)
		}
	}
	return nil
}

func validateStructuredMetadata(value any) bool {
	nodes := 0
	var walk func(reflect.Value, int) bool
	walk = func(current reflect.Value, depth int) bool {
		if depth > 32 {
			return false
		}
		nodes++
		if nodes > 10_000 {
			return false
		}
		if !current.IsValid() {
			return true
		}
		if current.Kind() == reflect.Interface {
			if current.IsNil() {
				return true
			}
			return walk(current.Elem(), depth+1)
		}
		switch current.Kind() {
		case reflect.Map:
			if current.Len() > 4096 || current.Type().Key().Kind() != reflect.String {
				return false
			}
			iter := current.MapRange()
			for iter.Next() {
				if iter.Key().Len() == 0 || iter.Key().Len() > 256 || !walk(iter.Value(), depth+1) {
					return false
				}
			}
			return true
		case reflect.Slice, reflect.Array:
			if current.Len() > 4096 {
				return false
			}
			for i := 0; i < current.Len(); i++ {
				if !walk(current.Index(i), depth+1) {
					return false
				}
			}
			return true
		case reflect.String:
			return current.Len() <= 4096 && !strings.ContainsAny(current.String(), "\x00\r\n")
		case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
			return true
		default:
			return false
		}
	}
	return walk(reflect.ValueOf(value), 0)
}

func validateRegistryEvent(event RegistryAuditEvent) error {
	if !validArtifactName(event.Name) || !sha256Pattern.MatchString(event.SHA256) {
		return fmt.Errorf("invalid name or digest")
	}
	if _, err := time.Parse(time.RFC3339Nano, event.Timestamp); err != nil {
		return fmt.Errorf("invalid timestamp")
	}
	if event.FromState != "" && !validStates[event.FromState] {
		return fmt.Errorf("invalid source state")
	}
	if !validStates[event.ToState] {
		return fmt.Errorf("invalid destination state")
	}
	if err := validateArtifactMetadata(event.Artifact); err != nil {
		return fmt.Errorf("invalid artifact snapshot: %w", err)
	}
	if event.Artifact.Name != event.Name || event.Artifact.SHA256 != event.SHA256 ||
		event.Artifact.State != event.ToState {
		return fmt.Errorf("event fields do not match artifact snapshot")
	}
	switch event.Action {
	case "bootstrap":
		if event.FromState != "" {
			return fmt.Errorf("invalid bootstrap transition")
		}
	case "acquire":
		if event.FromState != "" || event.ToState != StateAcquired {
			return fmt.Errorf("invalid acquire transition")
		}
	case "quarantine":
		if event.FromState != StateAcquired || event.ToState != StateQuarantined {
			return fmt.Errorf("invalid quarantine transition")
		}
	case "promote":
		if event.ToState != StateTrusted || event.Artifact.ObjectPath == "" {
			return fmt.Errorf("invalid promote transition")
		}
	case "revoke":
		if event.FromState == "" || event.FromState == StateDeleted || event.ToState != StateRevoked {
			return fmt.Errorf("invalid revoke transition")
		}
	case "delete":
		if event.FromState == "" || event.FromState == StateDeleted || event.ToState != StateDeleted {
			return fmt.Errorf("invalid delete transition")
		}
	default:
		return fmt.Errorf("unknown action")
	}
	return nil
}

func replayRegistryEvents(events []RegistryAuditEvent) ([]Artifact, error) {
	replayed := make(map[string]Artifact, len(events))
	order := make([]string, 0, len(events))
	seenLifecycleEvent := false
	for i, event := range events {
		current, exists := replayed[event.Name]
		switch event.Action {
		case "bootstrap":
			if seenLifecycleEvent {
				return nil, fmt.Errorf("audit replay event %d has a bootstrap after lifecycle history began", i+1)
			}
			if exists {
				return nil, fmt.Errorf("audit replay event %d recreates artifact %q", i+1, event.Name)
			}
			order = append(order, event.Name)
		case "acquire":
			seenLifecycleEvent = true
			if exists {
				return nil, fmt.Errorf("audit replay event %d recreates artifact %q", i+1, event.Name)
			}
			order = append(order, event.Name)
		case "promote":
			seenLifecycleEvent = true
			if event.FromState == "" {
				if exists {
					return nil, fmt.Errorf("audit replay event %d has empty source for existing artifact %q", i+1, event.Name)
				}
				order = append(order, event.Name)
			} else if !exists || current.State != event.FromState {
				return nil, fmt.Errorf("audit replay event %d has impossible transition for %q", i+1, event.Name)
			}
		default:
			seenLifecycleEvent = true
			if !exists || current.State != event.FromState || current.SHA256 != event.SHA256 {
				return nil, fmt.Errorf("audit replay event %d has impossible transition for %q", i+1, event.Name)
			}
			prior := current
			prior.State = event.ToState
			if !reflect.DeepEqual(prior, event.Artifact) {
				return nil, fmt.Errorf("audit replay event %d altered metadata outside promotion for %q", i+1, event.Name)
			}
		}
		replayed[event.Name] = event.Artifact
	}
	models := make([]Artifact, 0, len(order))
	for _, name := range order {
		models = append(models, replayed[name])
	}
	return models, nil
}

func hashRegistryEvent(event RegistryAuditEvent) string {
	event.Hash = ""
	data, _ := json.Marshal(event)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func ensureRegistryEventBaseline() {
	if len(manifest.Events) != 0 {
		return
	}
	for _, artifact := range manifest.Models {
		appendRegistryEvent("bootstrap", artifact, "")
	}
}

func appendRegistryEvent(action string, artifact Artifact, from ArtifactState) {
	previous := "genesis"
	if len(manifest.Events) > 0 {
		previous = manifest.Events[len(manifest.Events)-1].Hash
	}
	event := RegistryAuditEvent{
		Sequence: int64(len(manifest.Events) + 1), Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Action: action, Name: artifact.Name, FromState: from, ToState: artifact.State,
		SHA256: artifact.SHA256, Artifact: artifact, PrevHash: previous,
	}
	event.Hash = hashRegistryEvent(event)
	manifest.Events = append(manifest.Events, event)
}

func cloneManifest(candidate Manifest) (Manifest, error) {
	data, err := json.Marshal(candidate)
	if err != nil {
		return Manifest{}, err
	}
	var cloned Manifest
	if err := json.Unmarshal(data, &cloned); err != nil {
		return Manifest{}, err
	}
	return cloned, nil
}

func decodeRegistryRequest(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("request must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func validArtifactName(name string) bool {
	return name != "" && len(name) <= 256 && strings.TrimSpace(name) == name &&
		!strings.ContainsAny(name, "\x00\r\n")
}

func validateEvidenceMap(values map[string]string) bool {
	if len(values) > 64 {
		return false
	}
	for key, value := range values {
		if key == "" || len(key) > 256 || len(value) > 1024 || strings.ContainsAny(key+value, "\x00\r\n") {
			return false
		}
	}
	return true
}

func formatFromFilename(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".gguf":
		return "gguf"
	case ".safetensors":
		return "safetensors"
	default:
		return ext
	}
}

func registryRel(filename string) (string, error) {
	if filename == "" {
		return "", fmt.Errorf("empty filename")
	}
	if len(filename) > 4096 {
		return "", fmt.Errorf("filename exceeds 4096 bytes")
	}
	if strings.ContainsRune(filename, 0) {
		return "", fmt.Errorf("filename contains null byte")
	}

	if strings.Contains(filename, "\\") {
		return "", fmt.Errorf("filename contains path separator")
	}
	clean := filepath.Clean(filename)
	if clean == "." || !filepath.IsLocal(clean) {
		return "", fmt.Errorf("filename escapes registry directory")
	}
	return clean, nil
}

func registryPath(filename string) (string, error) {
	rel, err := registryRel(filename)
	if err != nil {
		return "", err
	}
	return filepath.Join(registryDir, rel), nil
}

func contentAddressedObjectRel(digest, format string) (string, error) {
	if !sha256Pattern.MatchString(digest) || !allowedFmts[format] {
		return "", fmt.Errorf("invalid content-addressed object identity")
	}
	return filepath.Join("objects", "sha256", digest[:2], digest+"."+format), nil
}

func artifactStorageRel(artifact Artifact) string {
	if artifact.ObjectPath != "" {
		return artifact.ObjectPath
	}
	return artifact.Filename
}

// storeContentAddressedObject takes an immutable snapshot of a verified
// quarantine input. The destination is created with link(2)-style no-replace
// semantics: an existing digest object is verified and is never overwritten.
func storeContentAddressedObject(sourceRel, digest, format string, expectedSize int64) (string, error) {
	sourceRel, err := registryRel(sourceRel)
	if err != nil {
		return "", err
	}
	objectRel, err := contentAddressedObjectRel(digest, format)
	if err != nil {
		return "", err
	}
	root, err := openRegistryRoot()
	if err != nil {
		return "", err
	}
	defer root.Close()

	objectDir := filepath.Dir(objectRel)
	if err := root.MkdirAll(objectDir, 0o700); err != nil {
		return "", err
	}
	for _, dir := range []string{"objects", filepath.Join("objects", "sha256"), objectDir} {
		info, statErr := root.Lstat(dir)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o022 != 0 {
			return "", fmt.Errorf("content-addressed storage directory is unsafe")
		}
	}

	if _, statErr := root.Lstat(objectRel); statErr == nil {
		actual, verifyErr := verifyFileHash(root, objectRel, digest)
		if verifyErr != nil || actual != digest {
			return "", fmt.Errorf("existing content-addressed object failed verification")
		}
		info, infoErr := root.Stat(objectRel)
		if infoErr != nil || info.Mode().Perm()&0o222 != 0 ||
			(expectedSize != 0 && info.Size() != expectedSize) {
			return "", fmt.Errorf("existing content-addressed object has unsafe mode or unexpected size")
		}
		return objectRel, nil
	} else if !os.IsNotExist(statErr) {
		return "", statErr
	}

	source, err := root.Open(sourceRel)
	if err != nil {
		return "", err
	}
	defer source.Close()
	before, err := source.Stat()
	if err != nil || !before.Mode().IsRegular() || fileLinkCount(before) > 1 {
		return "", fmt.Errorf("source artifact must be a non-hard-linked regular file")
	}
	if expectedSize != 0 && before.Size() != expectedSize {
		return "", fmt.Errorf("source artifact size changed")
	}

	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	tempRel := filepath.Join(objectDir, "."+hex.EncodeToString(random[:])+".tmp")
	temp, err := root.OpenFile(tempRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return "", err
	}
	tempPresent := true
	defer func() {
		_ = temp.Close()
		if tempPresent {
			_ = root.Remove(tempRel)
		}
	}()

	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(temp, h), io.LimitReader(source, before.Size()+1))
	if err != nil || written != before.Size() {
		return "", fmt.Errorf("copy content-addressed object: source changed or read failed")
	}
	var extra [1]byte
	if n, readErr := source.Read(extra[:]); (readErr != nil && readErr != io.EOF) || n != 0 {
		return "", fmt.Errorf("source artifact changed while copying")
	}
	after, err := source.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) || fileLinkCount(after) > 1 {
		return "", fmt.Errorf("source artifact changed while copying")
	}
	if actual := hex.EncodeToString(h.Sum(nil)); actual != digest {
		return "", fmt.Errorf("source digest mismatch while storing object")
	}
	if err := temp.Sync(); err != nil {
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}
	if err := root.Link(tempRel, objectRel); err != nil {
		if _, statErr := root.Lstat(objectRel); statErr == nil {
			if _, verifyErr := verifyFileHash(root, objectRel, digest); verifyErr == nil {
				return objectRel, nil
			}
		}
		return "", fmt.Errorf("publish content-addressed object: %w", err)
	}
	if err := root.Remove(tempRel); err != nil {
		return "", err
	}
	tempPresent = false
	if dir, openErr := root.Open(objectDir); openErr == nil {
		if syncErr := dir.Sync(); syncErr != nil {
			_ = dir.Close()
			return "", syncErr
		}
		_ = dir.Close()
	}
	if _, err := verifyFileHash(root, objectRel, digest); err != nil {
		return "", err
	}
	return objectRel, nil
}

func openRegistryRoot() (*os.Root, error) {
	return os.OpenRoot(registryDir)
}

// verifyFileHash computes sha256 of a file and compares to expected.
func verifyFileHash(root *os.Root, rel, expected string) (string, error) {
	f, err := root.Open(rel)
	if err != nil {
		return "", err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return "", fmt.Errorf("artifact must be a regular file")
	}
	if links := fileLinkCount(before); links > 1 {
		return "", fmt.Errorf("hard-linked artifacts are not allowed")
	}

	h := sha256.New()
	if _, err := io.CopyN(h, f, before.Size()); err != nil {
		return "", err
	}
	var extra [1]byte
	if n, readErr := f.Read(extra[:]); (readErr != nil && readErr != io.EOF) || n != 0 {
		return "", fmt.Errorf("artifact changed while hashing")
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) || fileLinkCount(after) > 1 {
		return "", fmt.Errorf("artifact changed while hashing")
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if expected != "" && actual != expected {
		return actual, fmt.Errorf("hash mismatch: expected %s, got %s", expected, actual)
	}
	return actual, nil
}

func fileLinkCount(info os.FileInfo) uint64 {
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return 0
	}
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0
	}
	field := value.FieldByName("Nlink")
	if !field.IsValid() {
		return 0
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return field.Uint()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if value := field.Int(); value > 0 {
			// #nosec G115 -- every positive int64 value is representable as uint64.
			return uint64(value)
		}
	}
	return 0
}

func verifyRegistryFile(filename, expected string) (string, error) {
	select {
	case hashVerifySlots <- struct{}{}:
		defer func() { <-hashVerifySlots }()
	default:
		return "", fmt.Errorf("verification capacity exhausted")
	}
	rel, err := registryRel(filename)
	if err != nil {
		return "", err
	}
	root, err := openRegistryRoot()
	if err != nil {
		return "", err
	}
	defer root.Close()
	if _, err := registryFileInfo(root, rel); err != nil {
		return "", err
	}
	return verifyFileHash(root, rel, expected)
}

func verifyArtifactFile(artifact Artifact) (string, error) {
	storageRel := artifactStorageRel(artifact)
	if artifact.ObjectPath != "" {
		root, err := openRegistryRoot()
		if err != nil {
			return "", err
		}
		info, err := registryFileInfo(root, storageRel)
		_ = root.Close()
		if err != nil || info.Mode().Perm()&0o222 != 0 {
			return "", fmt.Errorf("content-addressed object must be read-only and regular")
		}
	}
	return verifyRegistryFile(storageRel, artifact.SHA256)
}

func registryFileInfo(root *os.Root, rel string) (os.FileInfo, error) {
	lexical := filepath.Join(registryDir, rel)
	if info, err := os.Lstat(lexical); err != nil {
		return nil, err
	} else if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symbolic-link artifacts are not allowed")
	}
	info, err := root.Stat(rel)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || fileLinkCount(info) > 1 {
		return nil, fmt.Errorf("artifact must be a non-hard-linked regular file")
	}
	return info, nil
}

func handleListModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	manifestMu.RLock()
	defer manifestMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(manifest.Models)
}

func handleGetModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if !validArtifactName(name) {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	m, ok := registryArtifactByName(name)
	if !ok {
		http.Error(w, "model not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m)
}

func registryArtifactByName(name string) (Artifact, bool) {
	manifestMu.RLock()
	defer manifestMu.RUnlock()
	for _, artifact := range manifest.Models {
		if artifact.Name == name {
			return artifact, true
		}
	}
	return Artifact{}, false
}

// handleModelPath returns the filesystem path for a model.
// P0 fix: only serves artifacts in "trusted" state — revoked artifacts are blocked.
func handleModelPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if !validArtifactName(name) {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	m, ok := registryArtifactByName(name)
	if !ok {
		http.Error(w, "model not found", http.StatusNotFound)
		return
	}
	if m.State != StateTrusted {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("artifact %q is in %q state — only trusted artifacts can be loaded", name, m.State),
		})
		return
	}
	if m.ObjectPath == "" {
		http.Error(w, "trusted artifact has not been migrated to content-addressed storage", http.StatusConflict)
		return
	}
	path, err := registryPath(m.ObjectPath)
	if err != nil {
		http.Error(w, "invalid registry filename", http.StatusInternalServerError)
		return
	}
	if _, err := verifyArtifactFile(m); err != nil {
		http.Error(w, "content-addressed object failed digest verification", http.StatusConflict)
		return
	}
	current, stillTrusted := registryArtifactByName(name)
	if !stillTrusted || current.State != StateTrusted || current.SHA256 != m.SHA256 ||
		current.ObjectPath != m.ObjectPath {
		http.Error(w, "artifact trust changed during resolution", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"path": path, "sha256": m.SHA256, "size_bytes": m.SizeBytes,
		"storage_contract": "content-addressed-v1",
	})
}

func handlePromote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PromoteRequest
	if err := decodeRegistryRequest(w, r, &req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !validArtifactName(req.Name) || req.Filename == "" || !sha256Pattern.MatchString(req.SHA256) {
		http.Error(w, "name, filename, and sha256 are required", http.StatusBadRequest)
		return
	}
	if req.SizeBytes < 0 || len(req.Source) > 4096 || len(req.PolicyVersion) > 256 ||
		len(req.SourceRevision) > 256 || !validateEvidenceMap(req.ScanResults) ||
		!validateEvidenceMap(req.ScannerVersions) || !validateStructuredMetadata(req.GGUFGuardFingerprint) {
		http.Error(w, "invalid promotion metadata", http.StatusBadRequest)
		return
	}
	if req.GGUFGuardManifest != "" {
		if _, err := registryRel(req.GGUFGuardManifest); err != nil {
			http.Error(w, "invalid gguf-guard manifest path", http.StatusBadRequest)
			return
		}
	}
	if !insecureDevMode {
		if req.PolicyVersion == "" || len(req.ScanResults) == 0 || len(req.ScanResults) != len(req.ScannerVersions) {
			http.Error(w, "promotion requires policy version and scanner evidence", http.StatusUnprocessableEntity)
			return
		}
		for scanner, result := range req.ScanResults {
			if result != "pass" || req.ScannerVersions[scanner] == "" {
				http.Error(w, "promotion scanner evidence did not pass validation", http.StatusUnprocessableEntity)
				return
			}
		}
	}

	if _, err := registryRel(req.Filename); err != nil {
		http.Error(w, fmt.Sprintf("invalid filename: %v", err), http.StatusBadRequest)
		return
	}

	// Validate format
	format := formatFromFilename(req.Filename)
	if !allowedFmts[format] {
		http.Error(w, fmt.Sprintf("format %q not allowed; permitted: gguf, safetensors", format), http.StatusForbidden)
		return
	}
	if !insecureDevMode {
		eligible := false
		filenameConflict := false
		manifestMu.RLock()
		for _, existing := range manifest.Models {
			if existing.Name != req.Name && existing.Filename == req.Filename && existing.State != StateDeleted {
				filenameConflict = true
			}
			if existing.Name == req.Name && existing.State == StateQuarantined &&
				existing.Filename == req.Filename && existing.SHA256 == req.SHA256 &&
				(existing.SizeBytes == 0 || req.SizeBytes == 0 || existing.SizeBytes == req.SizeBytes) {
				eligible = true
			}
		}
		manifestMu.RUnlock()
		if filenameConflict {
			http.Error(w, "artifact filename is already registered", http.StatusConflict)
			return
		}
		if !eligible {
			http.Error(w, "production promotion requires a matching quarantined artifact", http.StatusConflict)
			return
		}
	}

	// Verify the file exists in the registry directory and hash matches
	actualHash, err := verifyRegistryFile(req.Filename, req.SHA256)
	if err != nil {
		http.Error(w, fmt.Sprintf("hash verification failed: %v", err), http.StatusConflict)
		return
	}
	// Get file size
	root, err := openRegistryRoot()
	if err != nil {
		http.Error(w, "registry unavailable", http.StatusServiceUnavailable)
		return
	}
	rel, _ := registryRel(req.Filename)
	info, err := registryFileInfo(root, rel)
	_ = root.Close()
	if err != nil {
		http.Error(w, "cannot stat model file", http.StatusInternalServerError)
		return
	}
	if req.SizeBytes != 0 && req.SizeBytes != info.Size() {
		http.Error(w, "declared size does not match artifact", http.StatusConflict)
		return
	}
	objectRel, err := storeContentAddressedObject(req.Filename, actualHash, format, info.Size())
	if err != nil {
		http.Error(w, fmt.Sprintf("content-addressed storage failed: %v", err), http.StatusConflict)
		return
	}

	artifact := Artifact{
		Name:                 req.Name,
		Format:               format,
		Filename:             req.Filename,
		ObjectPath:           objectRel,
		SHA256:               actualHash,
		SizeBytes:            info.Size(),
		Source:               req.Source,
		PromotedAt:           time.Now().UTC().Format(time.RFC3339),
		State:                StateTrusted,
		ScanResults:          req.ScanResults,
		ScannerVersions:      req.ScannerVersions,
		PolicyVersion:        req.PolicyVersion,
		SourceRevision:       req.SourceRevision,
		GGUFGuardFingerprint: req.GGUFGuardFingerprint,
		GGUFGuardManifest:    req.GGUFGuardManifest,
	}

	manifestMu.Lock()
	defer manifestMu.Unlock()
	before, err := cloneManifest(manifest)
	if err != nil {
		http.Error(w, "failed to prepare manifest update", http.StatusInternalServerError)
		return
	}
	ensureRegistryEventBaseline()
	committed := false
	defer func() {
		if !committed {
			manifest = before
		}
	}()

	// Replace existing entry with same name, or append
	replaced := false
	foundExisting := false
	fromState := ArtifactState("")
	for i, m := range manifest.Models {
		if m.Name != req.Name && m.Filename == req.Filename && m.State != StateDeleted {
			http.Error(w, "artifact filename is already registered", http.StatusConflict)
			return
		}
		if m.Name == req.Name {
			foundExisting = true
			// Block promotion of deleted artifacts
			if m.State == StateDeleted {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("cannot promote artifact %q: currently in deleted state", req.Name),
				})
				return
			}
			if !insecureDevMode && (m.State != StateQuarantined || m.Filename != req.Filename ||
				m.SHA256 != req.SHA256 || (m.SizeBytes != 0 && m.SizeBytes != info.Size())) {
				http.Error(w, "production promotion requires a matching quarantined artifact", http.StatusConflict)
				return
			}
			fromState = m.State
			manifest.Models[i] = artifact
			replaced = true
			break
		}
	}
	if !insecureDevMode && !foundExisting {
		http.Error(w, "production promotion requires a previously acquired and quarantined artifact", http.StatusConflict)
		return
	}
	if !replaced {
		manifest.Models = append(manifest.Models, artifact)
	}
	appendRegistryEvent("promote", artifact, fromState)

	if err := saveManifest(); err != nil {
		manifest = before
		http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
		return
	}
	committed = true

	log.Printf("PROMOTED: %s (%s) sha256=%s state=%s", artifact.Name, artifact.Filename, artifact.SHA256, artifact.State)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(artifact)
}

// handleDelete performs a soft delete — sets state to "deleted" and removes the
// file from disk, but retains metadata in the manifest for audit purposes.
func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if !validArtifactName(name) {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.Lock()
	defer manifestMu.Unlock()
	before, err := cloneManifest(manifest)
	if err != nil {
		http.Error(w, "failed to prepare manifest update", http.StatusInternalServerError)
		return
	}
	ensureRegistryEventBaseline()
	committed := false
	defer func() {
		if !committed {
			manifest = before
		}
	}()

	for i, m := range manifest.Models {
		if m.Name == name {
			if m.State == StateDeleted {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{
					"status": "already_deleted",
					"name":   name,
				})
				return
			}
			manifest.Models[i].State = StateDeleted
			appendRegistryEvent("delete", manifest.Models[i], m.State)
			if err := saveManifest(); err != nil {
				manifest = before
				http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
				return
			}
			committed = true
			// Persist the deny state before removing bytes. A removal failure is safe:
			// deleted artifacts are never returned to runtime consumers. Digest
			// objects can be shared, so retain one while another live record refers to it.
			storageRel := artifactStorageRel(m)
			storageReferenced := false
			if m.ObjectPath != "" {
				for j, other := range manifest.Models {
					if j != i && other.State != StateDeleted && other.ObjectPath == m.ObjectPath {
						storageReferenced = true
						break
					}
				}
			}
			if rel, relErr := registryRel(storageRel); relErr == nil && !storageReferenced {
				if root, rootErr := openRegistryRoot(); rootErr == nil {
					removeErr := root.Remove(rel)
					_ = root.Close()
					if removeErr != nil && !os.IsNotExist(removeErr) {
						log.Printf("warning: could not remove deleted artifact %q: %v", m.Name, removeErr)
					}
				}
			}
			log.Printf("DELETED (soft): %s (%s) sha256=%s", m.Name, m.Filename, m.SHA256)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "name": name})
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

// handleRevoke marks an artifact as revoked without deleting it from disk.
// Revoked artifacts remain in the manifest for audit purposes but cannot be loaded.
func handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if !validArtifactName(name) {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.Lock()
	defer manifestMu.Unlock()
	before, err := cloneManifest(manifest)
	if err != nil {
		http.Error(w, "failed to prepare manifest update", http.StatusInternalServerError)
		return
	}
	ensureRegistryEventBaseline()
	committed := false
	defer func() {
		if !committed {
			manifest = before
		}
	}()

	for i, m := range manifest.Models {
		if m.Name == name {
			if m.State == StateRevoked {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{
					"status": "already_revoked",
					"name":   name,
				})
				return
			}
			if m.State == StateDeleted {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("cannot revoke artifact %q: already in deleted state", name),
				})
				return
			}
			manifest.Models[i].State = StateRevoked
			appendRegistryEvent("revoke", manifest.Models[i], m.State)
			if err := saveManifest(); err != nil {
				manifest = before
				http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
				return
			}
			committed = true
			log.Printf("REVOKED: %s (%s) sha256=%s", m.Name, m.Filename, m.SHA256)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status": "revoked",
				"name":   name,
			})
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

// AcquireRequest is sent when an artifact is first received/downloaded.
type AcquireRequest struct {
	Name      string `json:"name"`
	Filename  string `json:"filename"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Source    string `json:"source,omitempty"`
}

// handleAcquire registers a newly downloaded artifact in "acquired" state.
func handleAcquire(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AcquireRequest
	if err := decodeRegistryRequest(w, r, &req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !validArtifactName(req.Name) || req.Filename == "" || !sha256Pattern.MatchString(req.SHA256) ||
		req.SizeBytes < 0 || len(req.Source) > 4096 {
		http.Error(w, "valid name, filename, sha256, and size are required", http.StatusBadRequest)
		return
	}
	if _, err := registryPath(req.Filename); err != nil {
		http.Error(w, fmt.Sprintf("invalid filename: %v", err), http.StatusBadRequest)
		return
	}

	format := formatFromFilename(req.Filename)
	if !allowedFmts[format] {
		http.Error(w, fmt.Sprintf("format %q not allowed; permitted: gguf, safetensors", format), http.StatusForbidden)
		return
	}

	artifact := Artifact{
		Name:       req.Name,
		Format:     format,
		Filename:   req.Filename,
		SHA256:     req.SHA256,
		SizeBytes:  req.SizeBytes,
		Source:     req.Source,
		PromotedAt: time.Now().UTC().Format(time.RFC3339),
		State:      StateAcquired,
	}

	manifestMu.Lock()
	defer manifestMu.Unlock()
	before, err := cloneManifest(manifest)
	if err != nil {
		http.Error(w, "failed to prepare manifest update", http.StatusInternalServerError)
		return
	}
	ensureRegistryEventBaseline()
	committed := false
	defer func() {
		if !committed {
			manifest = before
		}
	}()
	for _, existing := range manifest.Models {
		if existing.Name == req.Name || (existing.Filename == req.Filename && existing.State != StateDeleted) {
			http.Error(w, "artifact name or filename is already registered", http.StatusConflict)
			return
		}
	}
	manifest.Models = append(manifest.Models, artifact)
	appendRegistryEvent("acquire", artifact, "")

	if err := saveManifest(); err != nil {
		manifest = before
		http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
		return
	}
	committed = true

	log.Printf("ACQUIRED: %s (%s) state=%s", artifact.Name, artifact.Filename, artifact.State)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(artifact)
}

// handleQuarantine transitions an artifact from "acquired" to "quarantined" state.
func handleQuarantine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if !validArtifactName(name) {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.Lock()
	defer manifestMu.Unlock()
	before, err := cloneManifest(manifest)
	if err != nil {
		http.Error(w, "failed to prepare manifest update", http.StatusInternalServerError)
		return
	}
	ensureRegistryEventBaseline()
	committed := false
	defer func() {
		if !committed {
			manifest = before
		}
	}()

	for i, m := range manifest.Models {
		if m.Name == name {
			if m.State == StateQuarantined {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{
					"status": "already_quarantined",
					"name":   name,
				})
				return
			}
			if m.State != StateAcquired {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("cannot quarantine artifact %q: must be in acquired state, currently %s", name, m.State),
				})
				return
			}
			manifest.Models[i].State = StateQuarantined
			appendRegistryEvent("quarantine", manifest.Models[i], m.State)
			if err := saveManifest(); err != nil {
				manifest = before
				http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
				return
			}
			committed = true
			log.Printf("QUARANTINED: %s (%s) sha256=%s", m.Name, m.Filename, m.SHA256)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status": "quarantined",
				"name":   name,
			})
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

func handleVerifyAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	manifestMu.RLock()
	models := make([]Artifact, len(manifest.Models))
	copy(models, manifest.Models)
	manifestMu.RUnlock()

	results := make([]map[string]string, 0, len(models))
	allOk := true

	for _, m := range models {
		if m.State == StateDeleted {
			results = append(results, map[string]string{
				"name":   m.Name,
				"state":  string(StateDeleted),
				"status": "skipped",
				"reason": "deleted artifact bytes are intentionally absent",
			})
			continue
		}
		storageRel := artifactStorageRel(m)
		if _, err := registryRel(storageRel); err != nil {
			allOk = false
			results = append(results, map[string]string{
				"name":   m.Name,
				"status": "failed",
				"error":  "invalid registry filename",
			})
			continue
		}
		actual, err := verifyArtifactFile(m)
		if err != nil {
			allOk = false
			results = append(results, map[string]string{
				"name":     m.Name,
				"status":   "failed",
				"expected": m.SHA256,
				"actual":   actual,
				"error":    err.Error(),
			})
		} else {
			results = append(results, map[string]string{
				"name":   m.Name,
				"status": "verified",
				"sha256": actual,
			})
		}
	}

	status := "ok"
	if !allOk {
		status = "failed"
	}

	w.Header().Set("Content-Type", "application/json")
	if !allOk {
		w.WriteHeader(http.StatusConflict)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  status,
		"models":  results,
		"checked": len(results),
	})
}

func handleIntegrityStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resultPath := os.Getenv("INTEGRITY_RESULT_PATH")
	if resultPath == "" {
		resultPath = "/var/lib/secure-ai/logs/integrity-last.json"
	}

	data, err := readRegularBounded(resultPath, maxIntegrityBytes)
	if err != nil {
		if !os.IsNotExist(err) {
			http.Error(w, "integrity result unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "unknown",
			"detail": "no integrity check has run yet",
		})
		return
	}
	var result any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(&result); err != nil {
		http.Error(w, "integrity result unavailable", http.StatusServiceUnavailable)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		http.Error(w, "integrity result unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func handleVerifyModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if !validArtifactName(name) {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	m, ok := registryArtifactByName(name)
	if !ok {
		http.Error(w, "model not found", http.StatusNotFound)
		return
	}
	storageRel := artifactStorageRel(m)
	if _, err := registryRel(storageRel); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"status":      "failed",
			"name":        name,
			"error":       "invalid registry filename",
			"safe_to_use": "false",
		})
		return
	}
	actual, err := verifyArtifactFile(m)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"status":      "failed",
			"name":        name,
			"expected":    m.SHA256,
			"actual":      actual,
			"error":       err.Error(),
			"safe_to_use": "false",
		})
		return
	}
	safeToUse := "true"
	if m.State != StateTrusted {
		safeToUse = "false"
	} else if current, ok := registryArtifactByName(name); !ok || current.State != StateTrusted ||
		current.SHA256 != m.SHA256 || current.ObjectPath != m.ObjectPath {
		safeToUse = "false"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":      "verified",
		"name":        name,
		"sha256":      actual,
		"state":       string(m.State),
		"safe_to_use": safeToUse,
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	manifestMu.RLock()
	count := len(manifest.Models)
	stateCounts := map[string]int{}
	for _, model := range manifest.Models {
		stateCounts[string(model.State)]++
	}
	manifestMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"model_count":   count,
		"trusted_count": stateCounts[string(StateTrusted)],
		"state_counts":  stateCounts,
	})
}

func handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	manifestMu.RLock()
	events := append([]RegistryAuditEvent(nil), manifest.Events...)
	manifestMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

// ggufGuardBin is fixed so request data cannot select an executable. The
// container build injects ggufGuardSHA256 with -X after compiling the pinned
// gguf-guard source archive.
var ggufGuardBin = "/usr/local/bin/gguf-guard"
var ggufGuardSHA256 string

var errGGUFGuardUnavailable = errors.New("gguf-guard executable unavailable")

var ggufVerifySlots = make(chan struct{}, 2)

func handleVerifyGGUFManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if !validArtifactName(name) {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}
	if err := validateGGUFGuardBinary(); err != nil {
		http.Error(w, "gguf-guard verification service unavailable", http.StatusServiceUnavailable)
		return
	}

	m, ok := registryArtifactByName(name)
	if !ok {
		http.Error(w, "model not found", http.StatusNotFound)
		return
	}
	if m.GGUFGuardManifest == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "skipped",
			"name":   name,
			"reason": "no gguf-guard manifest available",
		})
		return
	}

	storageRel := artifactStorageRel(m)
	modelPath, err := registryPath(storageRel)
	if err != nil {
		http.Error(w, "invalid registry filename", http.StatusConflict)
		return
	}
	manifestFile, err := registryPath(m.GGUFGuardManifest)
	if err != nil {
		http.Error(w, "invalid gguf-guard manifest path", http.StatusConflict)
		return
	}
	if _, err := verifyArtifactFile(m); err != nil {
		http.Error(w, "model integrity verification failed", http.StatusConflict)
		return
	}
	if _, err := verifyRegistryFile(m.GGUFGuardManifest, ""); err != nil {
		http.Error(w, "gguf-guard manifest integrity check failed", http.StatusConflict)
		return
	}

	out, err := runGGUFGuardVerify(modelPath, manifestFile)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "failed",
			"name":   name,
			"error":  out,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "verified",
		"name":   name,
		"detail": out,
	})
}

func validateGGUFGuardBinary() error {
	before, err := os.Lstat(ggufGuardBin)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		before.Mode().Perm()&0o111 == 0 || fileLinkCount(before) > 1 {
		return errGGUFGuardUnavailable
	}
	f, err := os.Open(ggufGuardBin)
	if err != nil {
		return errGGUFGuardUnavailable
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return errGGUFGuardUnavailable
	}
	if ggufGuardSHA256 != "" {
		if !sha256Pattern.MatchString(ggufGuardSHA256) {
			return errGGUFGuardUnavailable
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil || hex.EncodeToString(h.Sum(nil)) != ggufGuardSHA256 {
			return errGGUFGuardUnavailable
		}
	}
	after, err := os.Lstat(ggufGuardBin)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) {
		return errGGUFGuardUnavailable
	}
	return nil
}

// runGGUFGuardVerify runs gguf-guard verify-manifest and returns output and error.
func runGGUFGuardVerify(modelPath, manifestFile string) (string, error) {
	if err := validateGGUFGuardBinary(); err != nil {
		return "gguf-guard verification service unavailable", err
	}
	select {
	case ggufVerifySlots <- struct{}{}:
		defer func() { <-ggufVerifySlots }()
	default:
		return "verification capacity exhausted", fmt.Errorf("verification capacity exhausted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// #nosec G204 -- executable is fixed at build time, digest-validated above, and no shell is involved.
	out, err := exec.CommandContext(ctx, ggufGuardBin, "verify-manifest", modelPath, manifestFile).CombinedOutput()
	result := strings.TrimSpace(string(out))
	if len(result) > 4096 {
		result = result[:4096] + "...[truncated]"
	}
	if ctx.Err() != nil {
		return "verification timed out", ctx.Err()
	}
	if err != nil {
		return result, err
	}
	return result, nil
}

func newRegistryMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/stats", requireServiceToken(handleStats))
	mux.HandleFunc("/v1/models", requireServiceToken(handleListModels))
	mux.HandleFunc("/v1/model", requireServiceToken(handleGetModel))
	mux.HandleFunc("/v1/model/path", requireServiceToken(handleModelPath))
	mux.HandleFunc("/v1/model/verify", requireServiceToken(handleVerifyModel))
	mux.HandleFunc("/v1/models/verify-all", requireServiceToken(handleVerifyAll))
	mux.HandleFunc("/v1/integrity/status", requireServiceToken(handleIntegrityStatus))
	mux.HandleFunc("/v1/model/verify-manifest", requireServiceToken(handleVerifyGGUFManifest))
	mux.HandleFunc("/v1/model/acquire", requireServiceToken(handleAcquire))
	mux.HandleFunc("/v1/model/quarantine", requireServiceToken(handleQuarantine))
	mux.HandleFunc("/v1/model/promote", requireServiceToken(handlePromote))
	mux.HandleFunc("/v1/model/delete", requireServiceToken(handleDelete))
	mux.HandleFunc("/v1/model/revoke", requireServiceToken(handleRevoke))
	mux.HandleFunc("/v1/audit", requireServiceToken(handleAuditEvents))
	return mux
}

func validateRegistryBind(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	loopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		loopback = true
	}
	if !loopback && os.Getenv("ALLOW_REMOTE_BIND") != "true" {
		return fmt.Errorf("non-loopback bind requires ALLOW_REMOTE_BIND=true and an authenticated TLS reverse proxy")
	}
	if !loopback && insecureDevMode {
		return fmt.Errorf("INSECURE_DEV_MODE is restricted to loopback listeners")
	}
	return nil
}

func ensureRegistryDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("REGISTRY_DIR must be absolute")
	}
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("REGISTRY_DIR must be a non-symlink directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("REGISTRY_DIR must not be writable by group or other users")
	}
	return nil
}

func main() {
	if exitCode, handled := runRegistryCheckpointCommand(os.Args[1:]); handled {
		os.Exit(exitCode)
	}
	// P0: require explicit opt-in for insecure dev mode
	insecureDevMode = os.Getenv("INSECURE_DEV_MODE") == "true"
	if insecureDevMode {
		log.Println("WARNING: INSECURE_DEV_MODE=true — auth will not be enforced for non-health APIs. DO NOT use in production.")
	}

	registryDir = os.Getenv("REGISTRY_DIR")
	if registryDir == "" {
		registryDir = "/registry"
	}
	if err := ensureRegistryDirectory(registryDir); err != nil {
		log.Fatalf("invalid registry directory: %v", err)
	}
	manifestPath = filepath.Join(registryDir, "manifest.json")
	if err := validateGGUFGuardBinary(); err != nil {
		log.Fatalf("required gguf-guard executable validation failed: %v", err)
	}

	if err := loadManifest(); err != nil {
		log.Fatalf("could not load trusted manifest: %v", err)
	}
	log.Printf("loaded %d model(s) from manifest", len(manifest.Models))

	if err := loadServiceToken(); err != nil {
		log.Fatal(err)
	}

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8470"
	}
	if err := validateRegistryBind(bind); err != nil {
		log.Fatalf("invalid bind address: %v", err)
	}

	log.Printf("ai-model-registry listening on %s (auth_required=%v)", bind, !insecureDevMode || serviceToken != "")
	server := &http.Server{
		Addr:              bind,
		Handler:           securityHeaders(newRegistryMux()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down ai-model-registry...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
	log.Println("ai-model-registry stopped")
}
