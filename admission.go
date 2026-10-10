package main

// Helper admission is deliberately distinct from the main appliance's staged
// promotion API. All durable records remain in Manifest and its Artifact events.
import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	admissionMode           = "helper-v2-required"
	admissionVersion        = 2
	admissionBodyLimit      = 64 << 10
	admissionRecordLimit    = 64 << 10
	admissionEvidenceLimit  = 1 << 20
	admissionEvidenceCount  = 32
	admissionPreparedLimit  = 32
	admissionOutboxOverhead = int64(8 << 20) // policy copies, bounded scan output, atomic journal overlap
	admissionLifetime       = 1800 * time.Second
	admissionWorkLimit      = 20 * time.Second
	admissionMaxArtifact    = int64(64 << 30)
	admissionMaxRetained    = int64(1 << 50)
)

var admissionNames = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var admissionRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)
var admissionBoot = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var admissionPolicyNames = []string{"policy.yaml", "models.lock.yaml", "sources.allowlist.yaml"}

// Configuration is administrator controlled, never accepted in an API request.
// No omitted budget/path can silently select a permissive default.
type AdmissionConfig struct {
	Version            int    `json:"version"`
	PolicyDir          string `json:"policy_dir"`
	PolicyBundleSHA256 string `json:"policy_bundle_sha256"`
	OutboxDir          string `json:"outbox_dir"`
	PipelineSHA256     string `json:"pipeline_sha256"`
	ProducerUID        int    `json:"producer_uid"`
	OutboxGID          int    `json:"outbox_gid"`
	MaxArtifactBytes   int64  `json:"max_artifact_bytes"`
	RetainedByteLimit  int64  `json:"retained_byte_limit"`
	MinFreeBytes       int64  `json:"min_free_bytes"`
}

type AdmissionPolicyBundle struct {
	Version    int               `json:"version"`
	SHA256     string            `json:"sha256"`
	Components map[string]string `json:"components"`
}

type admissionPolicy struct {
	Bundle          AdmissionPolicyBundle
	Raw             map[string][]byte
	Pins            map[string]string
	SourcePrefixes  []string
	RequireBehavior bool
	AllowLocal      bool
	AllowedFormats  map[string]bool
}

type AdmissionScanContext struct {
	PipelineSHA256  string `json:"pipeline_sha256"`
	RequireBehavior bool   `json:"require_behavior"`
}

func admissionContextDigest(bundle string, context AdmissionScanContext) string {
	return admissionDigest("HelperAdmissionContext-v2", bundle, context.PipelineSHA256, strconv.FormatBool(context.RequireBehavior))
}

type AdmissionPrepareRequest struct {
	ProtocolVersion     int                   `json:"protocol_version"`
	AdmissionID         string                `json:"admission_id"`
	Name                string                `json:"name"`
	Filename            string                `json:"filename"`
	ArtifactKind        string                `json:"artifact_kind"`
	Format              string                `json:"format"`
	SHA256              string                `json:"sha256"`
	SizeBytes           int64                 `json:"size_bytes"`
	Source              string                `json:"source"`
	SourceRevision      string                `json:"source_revision"`
	PolicyBundle        AdmissionPolicyBundle `json:"policy_bundle"`
	ContextSHA256       string                `json:"context_sha256"`
	EvidenceBudgetBytes int64                 `json:"evidence_budget_bytes"`
}

type AdmissionEvidence struct {
	Role      string `json:"role"`
	Filename  string `json:"filename"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type AdmissionCommitRequest struct {
	ProtocolVersion      int                 `json:"protocol_version"`
	AdmissionID          string              `json:"admission_id"`
	PrepareReceiptSHA256 string              `json:"prepare_receipt_sha256"`
	Evidence             []AdmissionEvidence `json:"evidence"`
}

// Receipt encoding is length-prefixed UTF-8 fields, not language-dependent JSON.
// Its event sequence is safe to bind; including the enclosing event hash would
// introduce a circular hash. Historical receipts never imply current trust.
type AdmissionReceipt struct {
	Version               int    `json:"version"`
	Phase                 string `json:"phase"`
	AdmissionID           string `json:"admission_id"`
	RequestSHA256         string `json:"request_sha256"`
	BindingSHA256         string `json:"binding_sha256"`
	BootID                string `json:"boot_id"`
	ExpiresBootNS         int64  `json:"expires_boot_ns,string"`
	ReservedRegistryBytes int64  `json:"reserved_registry_bytes"`
	ReservedOutboxBytes   int64  `json:"reserved_outbox_bytes"`
	EventSequence         int64  `json:"event_sequence"`
	CreatedAt             string `json:"created_at"`
	SHA256                string `json:"sha256"`
}

type AdmissionScannerOutcome struct {
	SchemaVersion  int     `json:"schema_version"`
	Passed         bool    `json:"passed"`
	Verdict        string  `json:"verdict"`
	Available      *bool   `json:"available"`
	Scanner        string  `json:"scanner"`
	ScannerVersion *string `json:"scanner_version"`
	Reason         string  `json:"reason"`
	ScannedCount   int64   `json:"scanned_count"`
}

type AdmissionGate struct {
	Verdict   string `json:"verdict"`
	Reason    string `json:"reason"`
	Count     int64  `json:"count"`
	Assurance string `json:"assurance"`
}

type AdmissionReport struct {
	Version        int                                `json:"version"`
	AdmissionID    string                             `json:"admission_id"`
	Filename       string                             `json:"filename"`
	SHA256         string                             `json:"sha256"`
	SizeBytes      int64                              `json:"size_bytes"`
	Source         string                             `json:"source"`
	SourceRevision string                             `json:"source_revision"`
	PolicyBundle   AdmissionPolicyBundle              `json:"policy_bundle"`
	PipelineSHA256 string                             `json:"pipeline_sha256"`
	Gates          map[string]AdmissionGate           `json:"gates"`
	Scanners       map[string]AdmissionScannerOutcome `json:"scanners"`
}

type AdmissionRecord struct {
	Version        int                     `json:"version"`
	Context        AdmissionScanContext    `json:"context"`
	Prepare        AdmissionPrepareRequest `json:"prepare"`
	PrepareReceipt AdmissionReceipt        `json:"prepare_receipt"`
	Commit         *AdmissionCommitRequest `json:"commit,omitempty"`
	CommitReceipt  *AdmissionReceipt       `json:"commit_receipt,omitempty"`
	Report         *AdmissionReport        `json:"report,omitempty"`
}

var configuredAdmission *AdmissionConfig

func admissionEnabled() bool { return os.Getenv("REGISTRY_ADMISSION_MODE") == admissionMode }

func admissionDigest(domain string, values ...string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(domain + "\x00"))
	for _, value := range values {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len([]byte(value))))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func admissionRequestDigest(phase string, raw []byte) string {
	return admissionDigest("HelperAdmissionRequest-v2", phase, string(raw))
}

func admissionReceiptDigest(r AdmissionReceipt) string {
	return admissionDigest("HelperAdmissionReceipt-v2", strconv.Itoa(r.Version), r.Phase,
		r.AdmissionID, r.RequestSHA256, r.BindingSHA256, r.BootID,
		strconv.FormatInt(r.ExpiresBootNS, 10), strconv.FormatInt(r.ReservedRegistryBytes, 10),
		strconv.FormatInt(r.ReservedOutboxBytes, 10), strconv.FormatInt(r.EventSequence, 10), r.CreatedAt)
}

func admissionBinding(req AdmissionPrepareRequest) string {
	return admissionDigest("HelperAdmissionBinding-v2", req.AdmissionID, req.Name, req.Filename,
		req.ArtifactKind, req.Format, req.SHA256, strconv.FormatInt(req.SizeBytes, 10),
		req.Source, req.SourceRevision, req.PolicyBundle.SHA256,
		req.ContextSHA256,
		strconv.FormatInt(req.EvidenceBudgetBytes, 10))
}

// encoding/json normally accepts duplicate object keys. V2 never permits this,
// including in nested policy/evidence values, before decoding typed fields.
func decodeAdmissionJSON(raw []byte, limit int, target any) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return errors.New("admission JSON size invalid")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var value func(int) error
	value = func(depth int) error {
		nodes++
		if depth > 32 || nodes > 10000 {
			return errors.New("admission JSON complexity exceeded")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				token, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok || keys[key] {
					return errors.New("duplicate admission JSON key")
				}
				keys[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid JSON object")
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid JSON array")
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("admission JSON has trailing value")
	}
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	if err := typed.Decode(target); err != nil {
		return err
	}
	var tree any
	shape := json.NewDecoder(bytes.NewReader(raw))
	shape.UseNumber()
	if err := shape.Decode(&tree); err != nil {
		return err
	}
	return requireAdmissionFields(tree, reflect.TypeOf(target).Elem())
}

func requireAdmissionFields(value any, kind reflect.Type) error {
	if kind.Kind() == reflect.Pointer {
		if value == nil {
			return nil
		}
		return requireAdmissionFields(value, kind.Elem())
	}
	if value == nil {
		return errors.New("required admission value cannot be null")
	}
	switch kind.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return errors.New("admission object required")
		}
		for i := 0; i < kind.NumField(); i++ {
			field := kind.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")
			if tag[0] == "-" {
				continue
			}
			item, exists := object[tag[0]]
			if !exists {
				optional := false
				for _, option := range tag[1:] {
					optional = optional || option == "omitempty"
				}
				if optional {
					continue
				}
				return fmt.Errorf("required admission field %s missing", tag[0])
			}
			if err := requireAdmissionFields(item, field.Type); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return errors.New("admission map required")
		}
		for _, item := range object {
			if err := requireAdmissionFields(item, kind.Elem()); err != nil {
				return err
			}
		}
	case reflect.Slice:
		items, ok := value.([]any)
		if !ok {
			return errors.New("admission array required")
		}
		for _, item := range items {
			if err := requireAdmissionFields(item, kind.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func readAdmissionBody(w http.ResponseWriter, r *http.Request, target any) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, admissionBodyLimit)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if err := decodeAdmissionJSON(raw, admissionBodyLimit, target); err != nil {
		return nil, err
	}
	return raw, nil
}

func validateAdmissionBundle(bundle AdmissionPolicyBundle) error {
	if bundle.Version != 1 || !sha256Pattern.MatchString(bundle.SHA256) || len(bundle.Components) != len(admissionPolicyNames) {
		return errors.New("invalid admission policy bundle")
	}
	values := []string{}
	for _, name := range admissionPolicyNames {
		digest := bundle.Components[name]
		if !sha256Pattern.MatchString(digest) {
			return errors.New("policy component missing")
		}
		values = append(values, name, digest)
	}
	if admissionDigest("HelperAdmissionPolicy-v1", values...) != bundle.SHA256 {
		return errors.New("policy bundle digest mismatch")
	}
	return nil
}

func validateAdmissionSource(req AdmissionPrepareRequest) error {
	if req.Source == "" {
		if req.SourceRevision != "" {
			return errors.New("local input cannot claim a remote revision")
		}
		return nil
	}
	parsed, err := url.Parse(req.Source)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "huggingface.co" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" ||
		strings.ContainsAny(req.Source, "%\\\x00\r\n") || !admissionRevision.MatchString(req.SourceRevision) {
		return errors.New("only exact immutable HTTPS Hugging Face source profiles are admitted")
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(parts) != 5 || !admissionNames.MatchString(parts[0]) || !admissionNames.MatchString(parts[1]) ||
		parts[2] != "resolve" || parts[3] != req.SourceRevision || parts[4] != req.Filename {
		return errors.New("source path does not bind the exact artifact/revision")
	}
	return nil
}

func validateAdmissionPrepare(req AdmissionPrepareRequest) error {
	if req.ProtocolVersion != admissionVersion || !sha256Pattern.MatchString(req.AdmissionID) ||
		!validArtifactName(req.Name) || strings.ContainsRune(req.Name, utf8.RuneError) || !admissionNames.MatchString(req.Filename) || req.ArtifactKind != "file" ||
		!allowedFmts[req.Format] || formatFromFilename(req.Filename) != req.Format ||
		!sha256Pattern.MatchString(req.SHA256) || !sha256Pattern.MatchString(req.ContextSHA256) || req.SizeBytes <= 0 || req.SizeBytes > admissionMaxArtifact ||
		req.EvidenceBudgetBytes <= 0 || req.EvidenceBudgetBytes > admissionEvidenceLimit {
		return errors.New("invalid or unsupported admission identity/limits")
	}
	if err := validateAdmissionBundle(req.PolicyBundle); err != nil {
		return err
	}
	return validateAdmissionSource(req)
}

func validateAdmissionCommit(req AdmissionCommitRequest) error {
	if req.ProtocolVersion != admissionVersion || !sha256Pattern.MatchString(req.AdmissionID) ||
		!sha256Pattern.MatchString(req.PrepareReceiptSHA256) || len(req.Evidence) < 1 || len(req.Evidence) > admissionEvidenceCount {
		return errors.New("invalid commit identity/inventory")
	}
	names, roles := map[string]bool{}, map[string]bool{}
	var total int64
	for _, e := range req.Evidence {
		if (e.Role != "pipeline-report" && e.Role != "gguf-integrity") || roles[e.Role] || names[e.Filename] ||
			e.Filename == "intent.json" || e.Filename == "ready" ||
			!admissionNames.MatchString(e.Filename) || !sha256Pattern.MatchString(e.SHA256) || e.SizeBytes <= 0 || e.SizeBytes > admissionEvidenceLimit {
			return errors.New("invalid/duplicate evidence descriptor")
		}
		names[e.Filename], roles[e.Role] = true, true
		total += e.SizeBytes
	}
	if !roles["pipeline-report"] || total > admissionEvidenceLimit {
		return errors.New("evidence budget exceeded or report missing")
	}
	return nil
}

func validateAdmissionReceipt(r AdmissionReceipt, phase string, req AdmissionPrepareRequest) error {
	if r.Version != admissionVersion || r.Phase != phase || r.AdmissionID != req.AdmissionID ||
		!sha256Pattern.MatchString(r.RequestSHA256) || r.BindingSHA256 != admissionBinding(req) ||
		!admissionBoot.MatchString(r.BootID) || r.ExpiresBootNS <= 0 || r.EventSequence <= 0 || r.EventSequence > maxManifestEntries ||
		r.ReservedRegistryBytes != req.SizeBytes+req.EvidenceBudgetBytes || r.ReservedOutboxBytes != r.ReservedRegistryBytes+admissionOutboxOverhead ||
		r.SHA256 != admissionReceiptDigest(r) {
		return errors.New("invalid admission receipt")
	}
	_, err := time.Parse(time.RFC3339Nano, r.CreatedAt)
	return err
}

func validateAdmissionMetadata(artifact Artifact) error {
	record := artifact.Admission
	if record == nil {
		return nil
	}
	raw, err := json.Marshal(artifact)
	if err != nil || len(raw) > admissionRecordLimit || record.Version != admissionVersion {
		return errors.New("invalid admission record")
	}
	req := record.Prepare
	if err := validateAdmissionPrepare(req); err != nil {
		return err
	}
	if !sha256Pattern.MatchString(record.Context.PipelineSHA256) || req.ContextSHA256 != admissionContextDigest(req.PolicyBundle.SHA256, record.Context) {
		return errors.New("admission scan context binding mismatch")
	}
	if artifact.Name != req.Name || artifact.Filename != req.Filename || artifact.Format != req.Format ||
		artifact.SHA256 != req.SHA256 || artifact.SizeBytes != req.SizeBytes || artifact.Source != req.Source ||
		artifact.SourceRevision != req.SourceRevision || artifact.PolicyVersion != req.PolicyBundle.SHA256 {
		return errors.New("admission does not bind artifact identity/policy")
	}
	if err := validateAdmissionReceipt(record.PrepareReceipt, "prepared", req); err != nil {
		return err
	}
	if record.Commit == nil || record.CommitReceipt == nil || record.Report == nil {
		if record.Commit != nil || record.CommitReceipt != nil || record.Report != nil || artifact.State == StateTrusted || artifact.ObjectPath != "" {
			return errors.New("incomplete committed admission")
		}
		return nil
	}
	if err := validateAdmissionCommit(*record.Commit); err != nil {
		return err
	}
	if artifact.State == StateAcquired || artifact.State == StateQuarantined || artifact.ObjectPath == "" ||
		record.CommitReceipt.BootID != record.PrepareReceipt.BootID || record.CommitReceipt.ExpiresBootNS != record.PrepareReceipt.ExpiresBootNS ||
		record.CommitReceipt.EventSequence <= record.PrepareReceipt.EventSequence {
		return errors.New("commit receipt changed preparation lifetime or lifecycle")
	}
	if record.Commit.AdmissionID != req.AdmissionID || record.Commit.PrepareReceiptSHA256 != record.PrepareReceipt.SHA256 {
		return errors.New("commit binding mismatch")
	}
	if err := validateAdmissionReceipt(*record.CommitReceipt, "committed", req); err != nil {
		return err
	}
	return validateAdmissionReport(*record.Report, req, record.Context)
}

func trustedAdmissionFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || !checkpointTrustedOwner(info) || fileLinkCount(info) != 1 || info.Size() > limit {
		return nil, errors.New("admission configuration owner/mode invalid")
	}
	// Fixed administrator-selected control input; nonblocking/no-follow protects
	// against a replacement with a special file between inspection and open.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("control file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("control file read/size failure")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	named, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || !os.SameFile(after, named) ||
		after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) ||
		after.Mode() != opened.Mode() || fileLinkCount(after) != 1 || !checkpointTrustedOwner(after) {
		return nil, errors.New("control file changed while reading")
	}
	return data, nil
}

func checkedAdmissionDirectory(path string) error {
	clean, err := filepath.Abs(path)
	if err != nil || path == "" || clean != path {
		return errors.New("admission path must be clean and absolute")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("admission directory cannot contain symlinks")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("unsafe admission directory")
	}
	return nil
}

func admissionOwnedBy(info os.FileInfo, uid, gid int) bool {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(metadata.Uid) == int64(uid) && int64(metadata.Gid) == int64(gid)
}

func loadAdmissionPolicy(config AdmissionConfig) (admissionPolicy, error) {
	policy := admissionPolicy{Raw: map[string][]byte{}, Pins: map[string]string{}, RequireBehavior: true, AllowedFormats: map[string]bool{"gguf": true, "safetensors": true}}
	policy.Bundle = AdmissionPolicyBundle{Version: 1, Components: map[string]string{}}
	if err := checkedAdmissionDirectory(config.PolicyDir); err != nil {
		return policy, err
	}
	values := []string{}
	for _, name := range admissionPolicyNames {
		raw, err := trustedAdmissionFile(filepath.Join(config.PolicyDir, name), maxRequestBodySize)
		if err != nil {
			return policy, fmt.Errorf("policy %s unavailable: %w", name, err)
		}
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		policy.Raw[name] = raw
		policy.Bundle.Components[name] = digest
		values = append(values, name, digest)
	}
	policy.Bundle.SHA256 = admissionDigest("HelperAdmissionPolicy-v1", values...)
	if policy.Bundle.SHA256 != config.PolicyBundleSHA256 {
		return policy, errors.New("installed policy bytes do not match configured bundle")
	}
	var configPolicy struct {
		Models map[string]any `yaml:"models"`
	}
	if err := yaml.Unmarshal(policy.Raw["policy.yaml"], &configPolicy); err != nil {
		return policy, err
	}
	if value, present := configPolicy.Models["require_behavior_tests"]; present {
		checked, ok := value.(bool)
		if !ok {
			return policy, errors.New("behavior policy must be boolean")
		}
		policy.RequireBehavior = checked
	}
	if value, present := configPolicy.Models["allow_local_imports"]; present {
		checked, ok := value.(bool)
		if !ok {
			return policy, errors.New("local-import policy must be boolean")
		}
		policy.AllowLocal = checked
	}
	if value, present := configPolicy.Models["allowed_formats"]; present {
		formats, ok := value.([]any)
		if !ok || len(formats) == 0 {
			return policy, errors.New("format policy must be a nonempty array")
		}
		policy.AllowedFormats = map[string]bool{}
		for _, value := range formats {
			name, ok := value.(string)
			if !ok {
				return policy, errors.New("invalid policy format")
			}
			policy.AllowedFormats[name] = true
		}
	}
	var pins struct {
		Models []struct {
			Filename string `yaml:"filename"`
			SHA256   string `yaml:"sha256"`
		} `yaml:"models"`
	}
	if err := yaml.Unmarshal(policy.Raw["models.lock.yaml"], &pins); err != nil {
		return policy, err
	}
	for _, pin := range pins.Models {
		if !admissionNames.MatchString(pin.Filename) || !sha256Pattern.MatchString(pin.SHA256) || policy.Pins[pin.Filename] != "" {
			return policy, errors.New("invalid/duplicate policy pin")
		}
		policy.Pins[pin.Filename] = pin.SHA256
	}
	var sources struct {
		Models []struct {
			URLPrefix string `yaml:"url_prefix"`
		} `yaml:"models"`
	}
	if err := yaml.Unmarshal(policy.Raw["sources.allowlist.yaml"], &sources); err != nil {
		return policy, err
	}
	for _, source := range sources.Models {
		if source.URLPrefix == "" {
			return policy, errors.New("empty policy source prefix")
		}
		policy.SourcePrefixes = append(policy.SourcePrefixes, source.URLPrefix)
	}
	return policy, nil
}

func initializeAdmission() error {
	configuredAdmission = nil
	mode := os.Getenv("REGISTRY_ADMISSION_MODE")
	if mode == "" {
		return nil
	}
	if mode != admissionMode || insecureDevMode {
		return errors.New("unsupported/insecure helper admission mode")
	}
	raw, err := trustedAdmissionFile(os.Getenv("ADMISSION_CONFIG_PATH"), admissionBodyLimit)
	if err != nil {
		return fmt.Errorf("admission configuration unavailable: %w", err)
	}
	var config AdmissionConfig
	if err := decodeAdmissionJSON(raw, admissionBodyLimit, &config); err != nil {
		return err
	}
	if config.Version != 1 || !sha256Pattern.MatchString(config.PipelineSHA256) || !sha256Pattern.MatchString(config.PolicyBundleSHA256) || config.ProducerUID < 0 || config.ProducerUID > 2147483647 || config.OutboxGID < 0 || config.OutboxGID > 2147483647 ||
		config.MaxArtifactBytes <= 0 || config.MaxArtifactBytes > admissionMaxArtifact ||
		config.RetainedByteLimit <= 0 || config.RetainedByteLimit > admissionMaxRetained ||
		config.MinFreeBytes <= 0 || config.MinFreeBytes >= config.RetainedByteLimit {
		return errors.New("invalid/missing admission limits or identity")
	}
	if err := checkedAdmissionDirectory(config.OutboxDir); err != nil {
		return err
	}
	outbox, err := os.Lstat(config.OutboxDir)
	if err != nil || outbox.Mode().Perm()&0o007 != 0 || !admissionOwnedBy(outbox, config.ProducerUID, config.OutboxGID) {
		return errors.New("private outbox ownership/mode does not match configured producer/group")
	}
	if _, err := loadAdmissionPolicy(config); err != nil {
		return err
	}
	if config.OutboxDir == registryDir || strings.HasPrefix(config.OutboxDir, registryDir+string(os.PathSeparator)) || strings.HasPrefix(registryDir, config.OutboxDir+string(os.PathSeparator)) {
		return errors.New("outbox and registry store must not overlap")
	}
	configuredAdmission = &config
	return nil
}

func rejectLegacyAdmission(w http.ResponseWriter, r *http.Request) bool {
	if !admissionEnabled() {
		return false
	}
	http.Error(w, "helper admission v2 required; legacy admission is disabled", http.StatusConflict)
	return true
}

func handleAdmissionCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	manifestMu.RLock()
	ready := !manifestPersistenceFailed
	manifestMu.RUnlock()
	if !admissionOperational() || !ready {
		http.Error(w, "helper admission v2 unavailable", http.StatusServiceUnavailable)
		return
	}
	policy, err := loadAdmissionPolicy(*configuredAdmission)
	if err != nil {
		http.Error(w, "trusted admission policy unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"service": "ai-model-registry", "protocol_version": admissionVersion, "mode": admissionMode,
		"artifact_kinds": []string{"file"}, "formats": []string{"gguf", "safetensors"}, "scanner_evidence_version": 2,
		"policy_bundle": policy.Bundle, "pipeline_sha256": configuredAdmission.PipelineSHA256,
		"scan_context":   AdmissionScanContext{PipelineSHA256: configuredAdmission.PipelineSHA256, RequireBehavior: policy.RequireBehavior},
		"context_sha256": admissionContextDigest(policy.Bundle.SHA256, AdmissionScanContext{PipelineSHA256: configuredAdmission.PipelineSHA256, RequireBehavior: policy.RequireBehavior}),
		"receipt_lookup": "/v1/model?name={name}", "persistence_ready": true,
		"limits": map[string]any{"max_body_bytes": admissionBodyLimit, "max_evidence_files": admissionEvidenceCount,
			"max_evidence_total_bytes": admissionEvidenceLimit, "max_artifact_record_bytes": admissionRecordLimit,
			"max_prepared": admissionPreparedLimit, "max_concurrent_commits": 2,
			"prepare_lifetime_seconds": int(admissionLifetime / time.Second), "commit_work_seconds": int(admissionWorkLimit / time.Second),
			"max_artifact_bytes": configuredAdmission.MaxArtifactBytes, "retained_byte_limit": configuredAdmission.RetainedByteLimit,
			"min_free_bytes": configuredAdmission.MinFreeBytes, "outbox_overhead_bytes": admissionOutboxOverhead, "manifest_scratch_bytes": maxManifestBytes},
	})
}

func admissionPlain(value string, maximum int, nonempty bool) bool {
	return (!nonempty || strings.TrimSpace(value) != "") && len(value) <= maximum &&
		!strings.ContainsAny(value, "\x00\r\n") && utf8.ValidString(value)
}

func validateAdmissionReport(report AdmissionReport, req AdmissionPrepareRequest, context AdmissionScanContext) error {
	if report.Version != 2 || report.AdmissionID != req.AdmissionID || report.Filename != req.Filename ||
		report.SHA256 != req.SHA256 || report.SizeBytes != req.SizeBytes || report.Source != req.Source ||
		report.SourceRevision != req.SourceRevision || !reflect.DeepEqual(report.PolicyBundle, req.PolicyBundle) ||
		report.PipelineSHA256 != context.PipelineSHA256 || req.ContextSHA256 != admissionContextDigest(req.PolicyBundle.SHA256, context) || len(report.Scanners) != 4 || len(report.Gates) != 8 {
		return errors.New("pipeline report identity/context/gates mismatch")
	}
	for key, scanner := range map[string]string{"modelscan": "modelscan", "fickling": "fickling", "modelaudit": "modelaudit", "gguf_guard": "gguf-guard"} {
		outcome, present := report.Scanners[key]
		if !present || outcome.SchemaVersion != 2 || outcome.Scanner != scanner ||
			!admissionPlain(outcome.Reason, 1024, true) || outcome.ScannedCount < 0 {
			return errors.New("invalid scanner outcome")
		}
		nonapplicable := key == "modelscan" || key == "fickling" || (key == "gguf_guard" && req.Format == "safetensors")
		if nonapplicable {
			if outcome.Verdict != "not_applicable" || outcome.Passed || outcome.Available != nil || outcome.ScannerVersion != nil || outcome.ScannedCount != 0 {
				return errors.New("nonapplicable scanner must never be a pass")
			}
		} else if outcome.Verdict != "pass" || !outcome.Passed || outcome.Available == nil || !*outcome.Available ||
			outcome.ScannerVersion == nil || !admissionPlain(*outcome.ScannerVersion, 1024, true) ||
			strings.TrimSpace(*outcome.ScannerVersion) == "unknown" || outcome.ScannedCount <= 0 {
			return errors.New("required scanner lacks actual versioned positive coverage")
		}
	}
	for _, key := range []string{"source_policy", "format_gate", "hash_pin", "provenance", "polyglot_check", "entropy", "weight_stats", "smoke_test"} {
		gate, present := report.Gates[key]
		if !present || !admissionPlain(gate.Reason, 1024, true) || gate.Count < 0 {
			return errors.New("invalid pipeline gate")
		}
		expected := "pass"
		if key == "smoke_test" {
			if req.Format == "safetensors" {
				expected = "not_applicable"
			} else if !context.RequireBehavior {
				expected = "not_required"
			}
		}
		if gate.Verdict != expected || (key == "weight_stats" && gate.Count <= 0) {
			return errors.New("required pipeline gate did not pass")
		}
		if key == "provenance" {
			expected := "recorded"
			if req.Source == "" {
				expected = "none"
			}
			if gate.Assurance != expected {
				return errors.New("source assurance is not the supported pinned-source profile")
			}
		} else if gate.Assurance != "" {
			return errors.New("unexpected gate assurance claim")
		}
		if expected != "pass" && gate.Count != 0 {
			return errors.New("nonexecuted gate cannot claim coverage")
		}
	}
	return nil
}
