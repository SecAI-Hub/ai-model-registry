package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
	Name            string            `json:"name" yaml:"name"`
	Format          string            `json:"format" yaml:"format"`
	Filename        string            `json:"filename" yaml:"filename"`
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
	Version int        `json:"version"`
	Models  []Artifact `json:"models"`
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

// loadServiceToken reads the service-to-service auth token from disk.
func loadServiceToken() {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = "/run/secure-ai/service-token"
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		if insecureDevMode {
			log.Printf("WARNING: service token not loaded (%v) — INSECURE_DEV_MODE enabled, mutations allowed without auth", err)
		} else {
			log.Printf("WARNING: service token not loaded (%v) — mutating operations will be rejected (set INSECURE_DEV_MODE=true to override)", err)
		}
		return
	}
	serviceToken = strings.TrimSpace(string(data))
	if serviceToken == "" {
		if insecureDevMode {
			log.Printf("WARNING: service token file is empty — INSECURE_DEV_MODE enabled, mutations allowed without auth")
		} else {
			log.Printf("WARNING: service token file is empty — mutating operations will be rejected")
		}
		return
	}
	log.Printf("service token loaded from %s", tokenPath)
}

// requireServiceToken wraps a handler to enforce Bearer token auth on mutating endpoints.
// P0 fix: if no token is configured, mutations are REJECTED unless INSECURE_DEV_MODE=true.
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
				"error": "no service token configured — mutating operations disabled (set INSECURE_DEV_MODE=true for development)",
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

func loadManifest() error {
	// Try runtime manifest first (writable storage)
	data, err := os.ReadFile(manifestPath)
	if err == nil {
		if err := json.Unmarshal(data, &manifest); err != nil {
			return err
		}
		// Backfill State for manifests created before State field existed
		for i := range manifest.Models {
			if manifest.Models[i].State == "" {
				manifest.Models[i].State = StateTrusted
			}
		}
		return nil
	}

	// Fall back to baked-in models.lock.yaml
	lockPath := os.Getenv("REGISTRY_LOCK_PATH")
	if lockPath == "" {
		lockPath = "/etc/secure-ai/policy/models.lock.yaml"
	}
	data, err = os.ReadFile(lockPath)
	if err != nil {
		manifest = Manifest{Version: 1, Models: []Artifact{}}
		return nil
	}
	var lock ModelsLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return err
	}
	manifest = Manifest{Version: lock.Version, Models: lock.Models}
	// Backfill State for lock file entries
	for i := range manifest.Models {
		if manifest.Models[i].State == "" {
			manifest.Models[i].State = StateTrusted
		}
	}
	return nil
}

func saveManifest() error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(manifestPath, data, 0644)
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

// verifyFileHash computes sha256 of a file and compares to expected.
func verifyFileHash(path, expected string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if expected != "" && actual != expected {
		return actual, fmt.Errorf("hash mismatch: expected %s, got %s", expected, actual)
	}
	return actual, nil
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
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.RLock()
	defer manifestMu.RUnlock()
	for _, m := range manifest.Models {
		if m.Name == name {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(m)
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

// handleModelPath returns the filesystem path for a model.
// P0 fix: only serves artifacts in "trusted" state — revoked artifacts are blocked.
func handleModelPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.RLock()
	defer manifestMu.RUnlock()
	for _, m := range manifest.Models {
		if m.Name == name {
			if m.State != StateTrusted {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("artifact %q is in %q state — only trusted artifacts can be loaded", name, m.State),
				})
				return
			}
			path := filepath.Join(registryDir, m.Filename)
			if _, err := os.Stat(path); err != nil {
				http.Error(w, "model file not found on disk", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"path": path})
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

func handlePromote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PromoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Filename == "" || req.SHA256 == "" {
		http.Error(w, "name, filename, and sha256 are required", http.StatusBadRequest)
		return
	}

	// Validate format
	format := formatFromFilename(req.Filename)
	if !allowedFmts[format] {
		http.Error(w, fmt.Sprintf("format %q not allowed; permitted: gguf, safetensors", format), http.StatusForbidden)
		return
	}

	// Verify the file exists in the registry directory and hash matches
	filePath := filepath.Join(registryDir, req.Filename)
	actualHash, err := verifyFileHash(filePath, req.SHA256)
	if err != nil {
		http.Error(w, fmt.Sprintf("hash verification failed: %v", err), http.StatusConflict)
		return
	}

	// Get file size
	info, err := os.Stat(filePath)
	if err != nil {
		http.Error(w, "cannot stat model file", http.StatusInternalServerError)
		return
	}

	artifact := Artifact{
		Name:                 req.Name,
		Format:               format,
		Filename:             req.Filename,
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

	// Replace existing entry with same name, or append
	replaced := false
	for i, m := range manifest.Models {
		if m.Name == req.Name {
			// Block promotion of deleted artifacts
			if m.State == StateDeleted {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("cannot promote artifact %q: currently in deleted state", req.Name),
				})
				return
			}
			manifest.Models[i] = artifact
			replaced = true
			break
		}
	}
	if !replaced {
		manifest.Models = append(manifest.Models, artifact)
	}

	if err := saveManifest(); err != nil {
		http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
		return
	}

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
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.Lock()
	defer manifestMu.Unlock()

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
			// Remove the model file from disk but keep metadata
			filePath := filepath.Join(registryDir, m.Filename)
			if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
				log.Printf("warning: could not remove %s: %v", filePath, err)
			}
			if err := saveManifest(); err != nil {
				http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
				return
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
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.Lock()
	defer manifestMu.Unlock()

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
			if err := saveManifest(); err != nil {
				http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
				return
			}
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Filename == "" {
		http.Error(w, "name and filename are required", http.StatusBadRequest)
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

	// Replace existing entry with same name, or append
	replaced := false
	for i, m := range manifest.Models {
		if m.Name == req.Name {
			manifest.Models[i] = artifact
			replaced = true
			break
		}
	}
	if !replaced {
		manifest.Models = append(manifest.Models, artifact)
	}

	if err := saveManifest(); err != nil {
		http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
		return
	}

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
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.Lock()
	defer manifestMu.Unlock()

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
			if err := saveManifest(); err != nil {
				http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
				return
			}
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
		filePath := filepath.Join(registryDir, m.Filename)
		actual, err := verifyFileHash(filePath, m.SHA256)
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

	data, err := os.ReadFile(resultPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "unknown",
			"detail": "no integrity check has run yet",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleVerifyModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.RLock()
	defer manifestMu.RUnlock()

	for _, m := range manifest.Models {
		if m.Name == name {
			filePath := filepath.Join(registryDir, m.Filename)
			actual, err := verifyFileHash(filePath, m.SHA256)
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
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status":      "verified",
				"name":        name,
				"sha256":      actual,
				"state":       string(m.State),
				"safe_to_use": safeToUse,
			})
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	manifestMu.RLock()
	count := len(manifest.Models)
	stateCounts := map[string]int{}
	for _, m := range manifest.Models {
		stateCounts[string(m.State)]++
	}
	manifestMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"model_count":   count,
		"trusted_count": stateCounts["trusted"],
		"state_counts":  stateCounts,
		"registry_dir":  registryDir,
		"auth_required": !insecureDevMode || serviceToken != "",
	})
}

// ggufGuardBin is the path to the gguf-guard binary for manifest verification.
var ggufGuardBin = "/usr/local/bin/gguf-guard"

func handleVerifyGGUFManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing ?name= parameter", http.StatusBadRequest)
		return
	}

	manifestMu.RLock()
	defer manifestMu.RUnlock()

	for _, m := range manifest.Models {
		if m.Name == name {
			if m.GGUFGuardManifest == "" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{
					"status": "skipped",
					"name":   name,
					"reason": "no gguf-guard manifest available",
				})
				return
			}

			modelPath := filepath.Join(registryDir, m.Filename)
			manifestFile := m.GGUFGuardManifest

			out, err := runGGUFGuardVerify(ggufGuardBin, modelPath, manifestFile)
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
			return
		}
	}
	http.Error(w, "model not found", http.StatusNotFound)
}

// runGGUFGuardVerify runs gguf-guard verify-manifest and returns output and error.
func runGGUFGuardVerify(bin, modelPath, manifestFile string) (string, error) {
	out, err := exec.Command(bin, "verify-manifest", modelPath, manifestFile).CombinedOutput()
	result := strings.TrimSpace(string(out))
	if err != nil {
		return result, err
	}
	return result, nil
}

func main() {
	// P0: require explicit opt-in for insecure dev mode
	insecureDevMode = os.Getenv("INSECURE_DEV_MODE") == "true"
	if insecureDevMode {
		log.Println("WARNING: INSECURE_DEV_MODE=true — auth will not be enforced for mutations. DO NOT use in production.")
	}

	registryDir = os.Getenv("REGISTRY_DIR")
	if registryDir == "" {
		registryDir = "/registry"
	}
	manifestPath = filepath.Join(registryDir, "manifest.json")

	if err := loadManifest(); err != nil {
		log.Printf("warning: could not load manifest: %v", err)
		manifest = Manifest{Version: 1, Models: []Artifact{}}
	}
	log.Printf("loaded %d model(s) from manifest", len(manifest.Models))

	loadServiceToken()

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "127.0.0.1:8470"
	}

	mux := http.NewServeMux()
	// Read-only endpoints — no auth required
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/models", handleListModels)
	mux.HandleFunc("/v1/model", handleGetModel)
	mux.HandleFunc("/v1/model/path", handleModelPath)
	mux.HandleFunc("/v1/model/verify", handleVerifyModel)
	mux.HandleFunc("/v1/models/verify-all", handleVerifyAll)
	mux.HandleFunc("/v1/integrity/status", handleIntegrityStatus)
	mux.HandleFunc("/v1/model/verify-manifest", handleVerifyGGUFManifest)
	// Mutating endpoints — require service token (fail-closed)
	mux.HandleFunc("/v1/model/acquire", requireServiceToken(handleAcquire))
	mux.HandleFunc("/v1/model/quarantine", requireServiceToken(handleQuarantine))
	mux.HandleFunc("/v1/model/promote", requireServiceToken(handlePromote))
	mux.HandleFunc("/v1/model/delete", requireServiceToken(handleDelete))
	mux.HandleFunc("/v1/model/revoke", requireServiceToken(handleRevoke))

	log.Printf("ai-model-registry listening on %s (auth_required=%v)", bind, !insecureDevMode || serviceToken != "")
	if err := http.ListenAndServe(bind, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
