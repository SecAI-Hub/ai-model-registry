package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const zeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

func TestRegistryMuxProtectsReadEndpoints(t *testing.T) {
	oldDev, oldToken := insecureDevMode, serviceToken
	insecureDevMode, serviceToken = false, ""
	t.Cleanup(func() {
		insecureDevMode, serviceToken = oldDev, oldToken
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	w := httptest.NewRecorder()
	newRegistryMux().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected protected read to fail closed, got %d", w.Code)
	}

	serviceToken = strings.Repeat("t", 32)
	req = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+serviceToken)
	w = httptest.NewRecorder()
	newRegistryMux().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected authenticated read, got %d", w.Code)
	}
}

func TestPromoteRejectsTrailingJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/model/promote", strings.NewReader(
		`{"name":"model","filename":"model.gguf","sha256":"`+zeroDigest+`","size_bytes":0} {}`))
	w := httptest.NewRecorder()
	handlePromote(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestProductionPromotionRequiresEvidence(t *testing.T) {
	oldDev := insecureDevMode
	insecureDevMode = false
	t.Cleanup(func() { insecureDevMode = oldDev })
	req := httptest.NewRequest(http.MethodPost, "/v1/model/promote", strings.NewReader(
		`{"name":"model","filename":"model.gguf","sha256":"`+zeroDigest+`","size_bytes":0}`))
	w := httptest.NewRecorder()
	handlePromote(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", w.Code, w.Body.String())
	}
}

func TestProductionPromotionRequiresMatchingQuarantinedArtifact(t *testing.T) {
	tmp := t.TempDir()
	oldDir, oldPath, oldDev := registryDir, manifestPath, insecureDevMode
	registryDir, manifestPath, insecureDevMode = tmp, filepath.Join(tmp, "manifest.json"), false
	t.Cleanup(func() {
		registryDir, manifestPath, insecureDevMode = oldDir, oldPath, oldDev
	})
	content := []byte("verified model")
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(tmp, "model.gguf"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name: "model", Format: "gguf", Filename: "model.gguf", SHA256: digest,
		SizeBytes: int64(len(content)), PromotedAt: time.Now().UTC().Format(time.RFC3339), State: StateAcquired,
	}}}
	manifestMu.Unlock()
	body := `{"name":"model","filename":"model.gguf","sha256":"` + digest +
		`","size_bytes":14,"scan_results":{"modelscan":"pass"},"scanner_versions":{"modelscan":"1.0"},"policy_version":"v1"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/model/promote", strings.NewReader(body))
	w := httptest.NewRecorder()
	handlePromote(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("acquired artifact bypassed quarantine: %d %s", w.Code, w.Body.String())
	}

	manifestMu.Lock()
	manifest.Models[0].State = StateQuarantined
	manifestMu.Unlock()
	req = httptest.NewRequest(http.MethodPost, "/v1/model/promote", strings.NewReader(body))
	w = httptest.NewRecorder()
	handlePromote(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("matching quarantined artifact was not promoted: %d %s", w.Code, w.Body.String())
	}
}

func TestValidateManifestRejectsMissingStateAndFilenameAliases(t *testing.T) {
	base := Artifact{
		Name: "one", Format: "gguf", Filename: "model.gguf", SHA256: zeroDigest,
		SizeBytes: 1, PromotedAt: time.Now().UTC().Format(time.RFC3339), State: StateTrusted,
	}
	missing := base
	missing.State = ""
	if err := validateManifest(Manifest{Version: 1, Models: []Artifact{missing}}); err == nil {
		t.Fatal("manifest with missing state was accepted")
	}
	alias := base
	alias.Name = "two"
	if err := validateManifest(Manifest{Version: 1, Models: []Artifact{base, alias}}); err == nil {
		t.Fatal("manifest with active filename aliases was accepted")
	}
}

func TestVerifyRegistryFileRejectsSymlinkAndHardlink(t *testing.T) {
	tmp := t.TempDir()
	oldDir := registryDir
	registryDir = tmp
	t.Cleanup(func() { registryDir = oldDir })
	content := []byte("artifact")
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	target := filepath.Join(tmp, "target.gguf")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(tmp, "link.gguf")); err == nil {
		if _, err := verifyRegistryFile("link.gguf", digest); err == nil {
			t.Fatal("expected symbolic link to be rejected")
		}
	}
	hardlink := filepath.Join(tmp, "hardlink.gguf")
	if err := os.Link(target, hardlink); err == nil {
		if _, err := verifyRegistryFile("target.gguf", digest); err == nil {
			t.Fatal("expected hard-linked artifact to be rejected")
		}
	}
}

func TestManifestAuditChainPersistsAtomically(t *testing.T) {
	tmp := t.TempDir()
	oldDir, oldPath := registryDir, manifestPath
	registryDir, manifestPath = tmp, filepath.Join(tmp, "manifest.json")
	t.Cleanup(func() {
		registryDir, manifestPath = oldDir, oldPath
	})
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	body := `{"name":"audit-model","filename":"audit-model.gguf","sha256":"` + zeroDigest + `","size_bytes":0}`
	req := httptest.NewRequest(http.MethodPost, "/v1/model/acquire", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleAcquire(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("acquire failed: %d %s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/model/quarantine?name=audit-model", nil)
	w = httptest.NewRecorder()
	handleQuarantine(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("quarantine failed: %d %s", w.Code, w.Body.String())
	}

	manifestMu.Lock()
	manifest = Manifest{}
	if err := loadManifest(); err != nil {
		manifestMu.Unlock()
		t.Fatal(err)
	}
	loaded := manifest
	manifestMu.Unlock()
	if len(loaded.Events) != 2 || loaded.Events[0].Action != "acquire" || loaded.Events[1].Action != "quarantine" {
		t.Fatalf("unexpected audit events: %#v", loaded.Events)
	}
	if err := validateManifest(loaded); err != nil {
		t.Fatalf("persisted audit chain is invalid: %v", err)
	}
}

func TestManifestMutationRollsBackWhenPersistenceFails(t *testing.T) {
	tmp := t.TempDir()
	oldDir, oldPath := registryDir, manifestPath
	registryDir, manifestPath = tmp, tmp
	t.Cleanup(func() {
		registryDir, manifestPath = oldDir, oldPath
	})
	artifactPath := filepath.Join(tmp, "model.gguf")
	if err := os.WriteFile(artifactPath, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name: "model", Filename: "model.gguf", SHA256: zeroDigest, State: StateTrusted,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/revoke?name=model", nil)
	w := httptest.NewRecorder()
	handleRevoke(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected persistence failure, got %d", w.Code)
	}
	manifestMu.RLock()
	state, events := manifest.Models[0].State, len(manifest.Events)
	manifestMu.RUnlock()
	if state != StateTrusted || events != 0 {
		t.Fatalf("in-memory mutation was not rolled back: state=%s events=%d", state, events)
	}
}

func TestManifestFullReplayRejectsMetadataTamperingAndSkippedTransitions(t *testing.T) {
	artifact := Artifact{
		Name: "replay", Format: "gguf", Filename: "replay.gguf", SHA256: zeroDigest,
		SizeBytes: 7, Source: "reviewed-source", PromotedAt: time.Now().UTC().Format(time.RFC3339),
		State: StateAcquired,
	}
	first := RegistryAuditEvent{
		Sequence: 1, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Action: "acquire",
		Name: artifact.Name, ToState: artifact.State, SHA256: artifact.SHA256,
		Artifact: artifact, PrevHash: "genesis",
	}
	first.Hash = hashRegistryEvent(first)
	quarantined := artifact
	quarantined.State = StateQuarantined
	second := RegistryAuditEvent{
		Sequence: 2, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Action: "quarantine",
		Name: artifact.Name, FromState: StateAcquired, ToState: StateQuarantined,
		SHA256: artifact.SHA256, Artifact: quarantined, PrevHash: first.Hash,
	}
	second.Hash = hashRegistryEvent(second)
	valid := Manifest{Version: 1, Models: []Artifact{quarantined}, Events: []RegistryAuditEvent{first, second}}
	if err := validateManifest(valid); err != nil {
		t.Fatalf("valid replay failed: %v", err)
	}

	tamperedEvent := valid
	tamperedEvent.Events = append([]RegistryAuditEvent(nil), valid.Events...)
	tamperedEvent.Events[1].Artifact.Source = "attacker-rewritten-source"
	tamperedEvent.Events[1].Hash = hashRegistryEvent(tamperedEvent.Events[1])
	tamperedEvent.Models = []Artifact{tamperedEvent.Events[1].Artifact}
	if err := validateManifest(tamperedEvent); err == nil {
		t.Fatal("state-only transition altered metadata without detection")
	}

	tamperedState := valid
	tamperedState.Models = append([]Artifact(nil), valid.Models...)
	tamperedState.Models[0].Source = "manifest-only-rewrite"
	if err := validateManifest(tamperedState); err == nil {
		t.Fatal("manifest state diverged from full replay without detection")
	}

	skipped := second
	skipped.FromState = StateTrusted
	skipped.Hash = hashRegistryEvent(skipped)
	if err := validateManifest(Manifest{Version: 1, Models: []Artifact{quarantined}, Events: []RegistryAuditEvent{first, skipped}}); err == nil {
		t.Fatal("impossible replay transition was accepted")
	}
	lateArtifact := artifact
	lateArtifact.Name, lateArtifact.Filename = "late", "late.gguf"
	lateBootstrap := RegistryAuditEvent{
		Sequence: 3, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Action: "bootstrap",
		Name: lateArtifact.Name, ToState: lateArtifact.State, SHA256: lateArtifact.SHA256,
		Artifact: lateArtifact, PrevHash: second.Hash,
	}
	lateBootstrap.Hash = hashRegistryEvent(lateBootstrap)
	if err := validateManifest(Manifest{
		Version: 1, Models: []Artifact{quarantined, lateArtifact},
		Events: []RegistryAuditEvent{first, second, lateBootstrap},
	}); err == nil {
		t.Fatal("late bootstrap bypassed lifecycle history")
	}
}

func TestRuntimeManifestWithModelsRequiresReplayableHistory(t *testing.T) {
	t.Setenv("ALLOW_LEGACY_MANIFEST_MIGRATION", "")
	tmp := t.TempDir()
	oldManifest, oldPath := manifest, manifestPath
	manifestPath = filepath.Join(tmp, "manifest.json")
	t.Cleanup(func() { manifest, manifestPath = oldManifest, oldPath })
	candidate := Manifest{Version: 1, Models: []Artifact{{
		Name: "legacy", Format: "gguf", Filename: "legacy.gguf", SHA256: zeroDigest,
		SizeBytes: 1, State: StateAcquired,
	}}}
	data, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadManifest(); err == nil || !strings.Contains(err.Error(), "no replayable audit history") {
		t.Fatalf("runtime manifest without history was accepted: %v", err)
	}
}

func TestExplicitLegacyMigrationCreatesObjectsAndReplayBaseline(t *testing.T) {
	t.Setenv("ALLOW_LEGACY_MANIFEST_MIGRATION", "true")
	tmp := t.TempDir()
	oldDir, oldPath, oldManifest := registryDir, manifestPath, manifest
	registryDir, manifestPath = tmp, filepath.Join(tmp, "manifest.json")
	t.Cleanup(func() { registryDir, manifestPath, manifest = oldDir, oldPath, oldManifest })
	content := []byte("reviewed legacy artifact")
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(tmp, "legacy.gguf"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := Manifest{Version: 1, Models: []Artifact{{
		Name: "legacy", Format: "gguf", Filename: "legacy.gguf", SHA256: digest,
		SizeBytes: int64(len(content)), State: StateTrusted,
	}}}
	data, _ := json.Marshal(candidate)
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadManifest(); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Events) != 1 || manifest.Events[0].Action != "bootstrap" ||
		manifest.Models[0].ObjectPath == "" {
		t.Fatalf("legacy migration was incomplete: %#v", manifest)
	}
	if _, err := verifyRegistryFile(manifest.Models[0].ObjectPath, digest); err != nil {
		t.Fatalf("migrated object failed verification: %v", err)
	}
}

func TestContentAddressedStorageNeverOverwritesAndPathReturnsDigestContract(t *testing.T) {
	tmp := t.TempDir()
	oldDir, oldManifest := registryDir, manifest
	registryDir = tmp
	t.Cleanup(func() { registryDir, manifest = oldDir, oldManifest })
	content := []byte("immutable model bytes")
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(tmp, "candidate.gguf"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	objectRel, err := storeContentAddressedObject("candidate.gguf", digest, "gguf", int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	expectedRel, _ := contentAddressedObjectRel(digest, "gguf")
	if objectRel != expectedRel {
		t.Fatalf("unexpected object path %q", objectRel)
	}
	if err := os.WriteFile(filepath.Join(tmp, "candidate.gguf"), []byte("replaced input"), 0o600); err != nil {
		t.Fatal(err)
	}
	if actual, err := verifyRegistryFile(objectRel, digest); err != nil || actual != digest {
		t.Fatalf("input replacement affected immutable object: %s %v", actual, err)
	}

	objectPath := filepath.Join(tmp, objectRel)
	if err := os.Chmod(objectPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectPath, []byte("tampered object"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := storeContentAddressedObject("candidate.gguf", digest, "gguf", int64(len(content))); err == nil {
		t.Fatal("existing digest path was overwritten or accepted after tampering")
	}

	if err := os.WriteFile(objectPath, content, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(objectPath, 0o400); err != nil {
		t.Fatal(err)
	}
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name: "runtime", Format: "gguf", Filename: "candidate.gguf", ObjectPath: objectRel,
		SHA256: digest, SizeBytes: int64(len(content)), State: StateTrusted,
	}}}
	req := httptest.NewRequest(http.MethodGet, "/v1/model/path?name=runtime", nil)
	w := httptest.NewRecorder()
	handleModelPath(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("digest contract endpoint failed: %d %s", w.Code, w.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["sha256"] != digest || response["storage_contract"] != "content-addressed-v1" || response["path"] != objectPath {
		t.Fatalf("incomplete digest consumer contract: %#v", response)
	}
}

func TestGGUFGuardBinaryValidationAndEndpointFailClosed(t *testing.T) {
	tmp := t.TempDir()
	oldBin, oldDigest := ggufGuardBin, ggufGuardSHA256
	ggufGuardBin = filepath.Join(tmp, "gguf-guard")
	t.Cleanup(func() { ggufGuardBin, ggufGuardSHA256 = oldBin, oldDigest })
	if err := os.WriteFile(ggufGuardBin, []byte("reviewed binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("reviewed binary"))
	ggufGuardSHA256 = hex.EncodeToString(sum[:])
	if err := validateGGUFGuardBinary(); err != nil {
		t.Fatalf("valid pinned guard rejected: %v", err)
	}
	ggufGuardSHA256 = zeroDigest
	if err := validateGGUFGuardBinary(); err == nil {
		t.Fatal("guard binary digest mismatch was accepted")
	}
	ggufGuardBin = filepath.Join(tmp, "missing")
	req := httptest.NewRequest(http.MethodPost, "/v1/model/verify-manifest?name=model", nil)
	w := httptest.NewRecorder()
	handleVerifyGGUFManifest(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing guard did not fail closed: %d %s", w.Code, w.Body.String())
	}
}

func TestDeleteRetainsContentObjectReferencedByAnotherArtifact(t *testing.T) {
	tmp := t.TempDir()
	oldDir, oldPath, oldManifest := registryDir, manifestPath, manifest
	registryDir, manifestPath = tmp, filepath.Join(tmp, "manifest.json")
	t.Cleanup(func() { registryDir, manifestPath, manifest = oldDir, oldPath, oldManifest })
	content := []byte("shared object")
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	objectRel, _ := contentAddressedObjectRel(digest, "gguf")
	if err := os.MkdirAll(filepath.Dir(filepath.Join(tmp, objectRel)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, objectRel), content, 0o400); err != nil {
		t.Fatal(err)
	}
	manifest = Manifest{Version: 1, Models: []Artifact{
		{Name: "first", Format: "gguf", Filename: "first.gguf", ObjectPath: objectRel, SHA256: digest, SizeBytes: int64(len(content)), State: StateTrusted},
		{Name: "second", Format: "gguf", Filename: "second.gguf", ObjectPath: objectRel, SHA256: digest, SizeBytes: int64(len(content)), State: StateTrusted},
	}}
	req := httptest.NewRequest(http.MethodDelete, "/v1/model/delete?name=first", nil)
	w := httptest.NewRecorder()
	handleDelete(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete failed: %d %s", w.Code, w.Body.String())
	}
	if _, err := verifyRegistryFile(objectRel, digest); err != nil {
		t.Fatalf("shared content object was removed: %v", err)
	}
}
