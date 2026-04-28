package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func init() {
	// Tests run in dev mode so mutation handlers can be called directly
	insecureDevMode = true
}

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body["status"])
	}
}

func TestListModelsEmpty(t *testing.T) {
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	w := httptest.NewRecorder()
	handleListModels(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var models []Artifact
	json.Unmarshal(w.Body.Bytes(), &models)
	if len(models) != 0 {
		t.Fatalf("expected empty list, got %d models", len(models))
	}
}

func TestPromoteInvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/model/promote", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handlePromote(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestPromoteMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/model/promote", nil)
	w := httptest.NewRecorder()
	handlePromote(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestRegistryPathRejectsEscapes(t *testing.T) {
	tmp := t.TempDir()
	oldRegistryDir := registryDir
	registryDir = tmp
	t.Cleanup(func() { registryDir = oldRegistryDir })

	badNames := []string{
		"../escape.gguf",
		filepath.Join("..", "escape.gguf"),
		filepath.Join(tmp, "..", "escape.gguf"),
		"bad\x00name.gguf",
	}
	for _, name := range badNames {
		if path, err := registryPath(name); err == nil {
			t.Fatalf("expected %q to be rejected, got %q", name, path)
		}
	}

	relative, err := registryPath(filepath.Join("nested", "model.gguf"))
	if err != nil {
		t.Fatalf("expected relative registry path to be accepted: %v", err)
	}
	if !strings.HasPrefix(relative, tmp) {
		t.Fatalf("expected %q to stay under %q", relative, tmp)
	}

	absolute := filepath.Join(tmp, "model.gguf")
	resolved, err := registryPath(absolute)
	if err != nil {
		t.Fatalf("expected absolute registry path to be accepted: %v", err)
	}
	if resolved != absolute {
		t.Fatalf("expected %q, got %q", absolute, resolved)
	}
}

func TestPromoteValidModel(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	// Create a fake model file
	fakeModel := filepath.Join(tmp, "test-model.gguf")
	os.WriteFile(fakeModel, []byte("fake model data"), 0644)

	body := `{
		"name": "test-model",
		"filename": "test-model.gguf",
		"sha256": "c4928585ac684a63148634c0655c561d94260f841aceb618ef21b6492e8a1da8",
		"size_bytes": 15,
		"scan_results": {}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/model/promote", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handlePromote(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Verify model is in manifest with trusted state
	manifestMu.RLock()
	count := len(manifest.Models)
	state := manifest.Models[0].State
	manifestMu.RUnlock()
	if count != 1 {
		t.Fatalf("expected 1 model in manifest, got %d", count)
	}
	if state != StateTrusted {
		t.Fatalf("expected state trusted, got %s", state)
	}
}

func TestDeleteSoftDelete(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	fakeModel := filepath.Join(tmp, "delete-me.gguf")
	os.WriteFile(fakeModel, []byte("data"), 0644)

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "delete-me",
		Filename: "delete-me.gguf",
		SHA256:   "abc123",
		State:    StateTrusted,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/v1/model/delete?name=delete-me", nil)
	w := httptest.NewRecorder()
	handleDelete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "deleted" {
		t.Fatalf("expected deleted, got %v", body["status"])
	}

	// Verify state changed to deleted but entry still in manifest
	manifestMu.RLock()
	count := len(manifest.Models)
	state := manifest.Models[0].State
	manifestMu.RUnlock()
	if count != 1 {
		t.Fatalf("expected 1 model in manifest (soft delete), got %d", count)
	}
	if state != StateDeleted {
		t.Fatalf("expected state deleted, got %s", state)
	}

	// Verify file removed from disk
	if _, err := os.Stat(fakeModel); !os.IsNotExist(err) {
		t.Fatalf("expected model file to be removed from disk")
	}
}

func TestDeleteAlreadyDeleted(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "already-gone",
		Filename: "already-gone.gguf",
		SHA256:   "abc123",
		State:    StateDeleted,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/v1/model/delete?name=already-gone", nil)
	w := httptest.NewRecorder()
	handleDelete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "already_deleted" {
		t.Fatalf("expected already_deleted, got %v", body["status"])
	}
}

func TestDeleteNonexistent(t *testing.T) {
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/v1/model/delete?name=nonexistent", nil)
	w := httptest.NewRecorder()
	handleDelete(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestVerifyAllEmpty(t *testing.T) {
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/models/verify-all", nil)
	w := httptest.NewRecorder()
	handleVerifyAll(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body["status"])
	}
}

func TestVerifyAllWithValidModel(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp

	fakeModel := filepath.Join(tmp, "test.gguf")
	os.WriteFile(fakeModel, []byte("fake model data"), 0644)

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "test",
		Filename: "test.gguf",
		SHA256:   "c4928585ac684a63148634c0655c561d94260f841aceb618ef21b6492e8a1da8",
		State:    StateTrusted,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/models/verify-all", nil)
	w := httptest.NewRecorder()
	handleVerifyAll(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("expected ok, got %v", body["status"])
	}
}

func TestVerifyAllDetectsTampered(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp

	fakeModel := filepath.Join(tmp, "tampered.gguf")
	os.WriteFile(fakeModel, []byte("tampered data"), 0644)

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "tampered",
		Filename: "tampered.gguf",
		SHA256:   "0000000000000000000000000000000000000000000000000000000000000000",
		State:    StateTrusted,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/models/verify-all", nil)
	w := httptest.NewRecorder()
	handleVerifyAll(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "failed" {
		t.Fatalf("expected failed, got %v", body["status"])
	}
}

func TestVerifyAllMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/models/verify-all", nil)
	w := httptest.NewRecorder()
	handleVerifyAll(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestVerifyModelWithSafeToUse(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp

	fakeModel := filepath.Join(tmp, "safe.gguf")
	os.WriteFile(fakeModel, []byte("fake model data"), 0644)

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "safe-model",
		Filename: "safe.gguf",
		SHA256:   "c4928585ac684a63148634c0655c561d94260f841aceb618ef21b6492e8a1da8",
		State:    StateTrusted,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/verify?name=safe-model", nil)
	w := httptest.NewRecorder()
	handleVerifyModel(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["safe_to_use"] != "true" {
		t.Fatalf("expected safe_to_use=true, got %v", body["safe_to_use"])
	}
}

func TestVerifyModelTamperedNotSafe(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp

	fakeModel := filepath.Join(tmp, "bad.gguf")
	os.WriteFile(fakeModel, []byte("tampered"), 0644)

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "bad-model",
		Filename: "bad.gguf",
		SHA256:   "0000000000000000000000000000000000000000000000000000000000000000",
		State:    StateTrusted,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/verify?name=bad-model", nil)
	w := httptest.NewRecorder()
	handleVerifyModel(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["safe_to_use"] != "false" {
		t.Fatalf("expected safe_to_use=false, got %v", body["safe_to_use"])
	}
}

func TestIntegrityStatusNoFile(t *testing.T) {
	os.Setenv("INTEGRITY_RESULT_PATH", "/tmp/nonexistent-integrity-result.json")
	defer os.Unsetenv("INTEGRITY_RESULT_PATH")

	req := httptest.NewRequest(http.MethodGet, "/v1/integrity/status", nil)
	w := httptest.NewRecorder()
	handleIntegrityStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "unknown" {
		t.Fatalf("expected unknown, got %v", body["status"])
	}
}

func TestIntegrityStatusWithFile(t *testing.T) {
	tmp := t.TempDir()
	resultFile := filepath.Join(tmp, "integrity-last.json")
	os.WriteFile(resultFile, []byte(`{"status":"ok","models_checked":2,"failures":0}`), 0644)
	os.Setenv("INTEGRITY_RESULT_PATH", resultFile)
	defer os.Unsetenv("INTEGRITY_RESULT_PATH")

	req := httptest.NewRequest(http.MethodGet, "/v1/integrity/status", nil)
	w := httptest.NewRecorder()
	handleIntegrityStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("expected ok, got %v", body["status"])
	}
	if body["models_checked"] != float64(2) {
		t.Fatalf("expected 2, got %v", body["models_checked"])
	}
}

// --- P0 tests: explicit artifact states ---

func TestRevokeModel(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "revoke-me",
		Filename: "revoke-me.gguf",
		SHA256:   "abc123",
		State:    StateTrusted,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/revoke?name=revoke-me", nil)
	w := httptest.NewRecorder()
	handleRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "revoked" {
		t.Fatalf("expected revoked, got %v", body["status"])
	}

	// Verify state changed in manifest
	manifestMu.RLock()
	state := manifest.Models[0].State
	manifestMu.RUnlock()
	if state != StateRevoked {
		t.Fatalf("expected state revoked, got %s", state)
	}
}

func TestRevokeAlreadyRevoked(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "already-revoked",
		Filename: "already-revoked.gguf",
		SHA256:   "abc123",
		State:    StateRevoked,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/revoke?name=already-revoked", nil)
	w := httptest.NewRecorder()
	handleRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "already_revoked" {
		t.Fatalf("expected already_revoked, got %v", body["status"])
	}
}

func TestRevokeNonexistent(t *testing.T) {
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/revoke?name=nope", nil)
	w := httptest.NewRecorder()
	handleRevoke(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestPathBlocksRevokedArtifact(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp

	fakeModel := filepath.Join(tmp, "revoked.gguf")
	os.WriteFile(fakeModel, []byte("data"), 0644)

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "revoked-model",
		Filename: "revoked.gguf",
		SHA256:   "abc",
		State:    StateRevoked,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/v1/model/path?name=revoked-model", nil)
	w := httptest.NewRecorder()
	handleModelPath(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for revoked artifact, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyRevokedModelNotSafe(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp

	fakeModel := filepath.Join(tmp, "revoked.gguf")
	os.WriteFile(fakeModel, []byte("fake model data"), 0644)

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "revoked-model",
		Filename: "revoked.gguf",
		SHA256:   "c4928585ac684a63148634c0655c561d94260f841aceb618ef21b6492e8a1da8",
		State:    StateRevoked,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/verify?name=revoked-model", nil)
	w := httptest.NewRecorder()
	handleVerifyModel(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["safe_to_use"] != "false" {
		t.Fatalf("revoked model should have safe_to_use=false, got %v", body["safe_to_use"])
	}
	if body["state"] != "revoked" {
		t.Fatalf("expected state=revoked, got %v", body["state"])
	}
}

// --- P0 tests: fail-closed auth ---

func TestFailClosedAuthBlocksMutations(t *testing.T) {
	origDev := insecureDevMode
	origToken := serviceToken
	defer func() {
		insecureDevMode = origDev
		serviceToken = origToken
	}()

	// Simulate production: no token, dev mode off
	serviceToken = ""
	insecureDevMode = false

	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/model/promote", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when no token and dev mode off, got %d", w.Code)
	}
}

func TestDevModeAllowsMutationsWithoutToken(t *testing.T) {
	origDev := insecureDevMode
	origToken := serviceToken
	defer func() {
		insecureDevMode = origDev
		serviceToken = origToken
	}()

	serviceToken = ""
	insecureDevMode = true

	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/model/promote", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 in dev mode, got %d", w.Code)
	}
}

// --- Expanded artifact state tests ---

func TestAcquireArtifact(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	body := `{
		"name": "new-model",
		"filename": "new-model.gguf",
		"sha256": "abc123",
		"size_bytes": 1024
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/model/acquire", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleAcquire(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	manifestMu.RLock()
	count := len(manifest.Models)
	state := manifest.Models[0].State
	manifestMu.RUnlock()
	if count != 1 {
		t.Fatalf("expected 1 model, got %d", count)
	}
	if state != StateAcquired {
		t.Fatalf("expected state acquired, got %s", state)
	}
}

func TestAcquireMissingFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/model/acquire", strings.NewReader(`{"name":""}`))
	w := httptest.NewRecorder()
	handleAcquire(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestAcquireDisallowedFormat(t *testing.T) {
	body := `{"name":"bad","filename":"bad.pkl","sha256":"abc","size_bytes":10}`
	req := httptest.NewRequest(http.MethodPost, "/v1/model/acquire", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleAcquire(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed format, got %d", w.Code)
	}
}

func TestQuarantineArtifact(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "scan-me",
		Filename: "scan-me.gguf",
		SHA256:   "abc123",
		State:    StateAcquired,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/quarantine?name=scan-me", nil)
	w := httptest.NewRecorder()
	handleQuarantine(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "quarantined" {
		t.Fatalf("expected quarantined, got %v", body["status"])
	}

	manifestMu.RLock()
	state := manifest.Models[0].State
	manifestMu.RUnlock()
	if state != StateQuarantined {
		t.Fatalf("expected state quarantined, got %s", state)
	}
}

func TestQuarantineAlreadyQuarantined(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "q-model",
		Filename: "q-model.gguf",
		SHA256:   "abc123",
		State:    StateQuarantined,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/quarantine?name=q-model", nil)
	w := httptest.NewRecorder()
	handleQuarantine(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "already_quarantined" {
		t.Fatalf("expected already_quarantined, got %v", body["status"])
	}
}

func TestQuarantineWrongState(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "trusted-model",
		Filename: "trusted-model.gguf",
		SHA256:   "abc123",
		State:    StateTrusted,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/quarantine?name=trusted-model", nil)
	w := httptest.NewRecorder()
	handleQuarantine(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestQuarantineNonexistent(t *testing.T) {
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/quarantine?name=nope", nil)
	w := httptest.NewRecorder()
	handleQuarantine(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestPathBlocksNonTrustedStates(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp

	for _, state := range []ArtifactState{StateAcquired, StateQuarantined, StateRevoked, StateDeleted} {
		fakeModel := filepath.Join(tmp, "model-"+string(state)+".gguf")
		os.WriteFile(fakeModel, []byte("data"), 0644)

		manifestMu.Lock()
		manifest = Manifest{Version: 1, Models: []Artifact{{
			Name:     "model-" + string(state),
			Filename: "model-" + string(state) + ".gguf",
			SHA256:   "abc",
			State:    state,
		}}}
		manifestMu.Unlock()

		req := httptest.NewRequest(http.MethodGet, "/v1/model/path?name=model-"+string(state), nil)
		w := httptest.NewRecorder()
		handleModelPath(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for %s state, got %d: %s", state, w.Code, w.Body.String())
		}
	}
}

func TestRevokeDeletedArtifactBlocked(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{{
		Name:     "deleted-model",
		Filename: "deleted-model.gguf",
		SHA256:   "abc123",
		State:    StateDeleted,
	}}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/model/revoke?name=deleted-model", nil)
	w := httptest.NewRecorder()
	handleRevoke(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFullLifecycleAcquireToDelete(t *testing.T) {
	tmp := t.TempDir()
	registryDir = tmp
	manifestPath = filepath.Join(tmp, "manifest.json")

	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	manifestMu.Unlock()

	// Step 1: Acquire
	acquireBody := `{"name":"lifecycle","filename":"lifecycle.gguf","sha256":"abc","size_bytes":100}`
	req := httptest.NewRequest(http.MethodPost, "/v1/model/acquire", strings.NewReader(acquireBody))
	w := httptest.NewRecorder()
	handleAcquire(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("acquire: expected 201, got %d", w.Code)
	}

	// Step 2: Quarantine
	req = httptest.NewRequest(http.MethodPost, "/v1/model/quarantine?name=lifecycle", nil)
	w = httptest.NewRecorder()
	handleQuarantine(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("quarantine: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Step 3: Promote (create file first since promote verifies hash)
	fakeModel := filepath.Join(tmp, "lifecycle.gguf")
	os.WriteFile(fakeModel, []byte("fake model data"), 0644)
	promoteBody := `{
		"name":"lifecycle",
		"filename":"lifecycle.gguf",
		"sha256":"c4928585ac684a63148634c0655c561d94260f841aceb618ef21b6492e8a1da8",
		"size_bytes":15,
		"scan_results":{}
	}`
	req = httptest.NewRequest(http.MethodPost, "/v1/model/promote", strings.NewReader(promoteBody))
	w = httptest.NewRecorder()
	handlePromote(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("promote: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Verify trusted state
	manifestMu.RLock()
	state := manifest.Models[0].State
	manifestMu.RUnlock()
	if state != StateTrusted {
		t.Fatalf("expected trusted after promote, got %s", state)
	}

	// Step 4: Revoke
	req = httptest.NewRequest(http.MethodPost, "/v1/model/revoke?name=lifecycle", nil)
	w = httptest.NewRecorder()
	handleRevoke(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Step 5: Delete (soft)
	req = httptest.NewRequest(http.MethodDelete, "/v1/model/delete?name=lifecycle", nil)
	w = httptest.NewRecorder()
	handleDelete(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify final state is deleted, metadata still present
	manifestMu.RLock()
	count := len(manifest.Models)
	finalState := manifest.Models[0].State
	manifestMu.RUnlock()
	if count != 1 {
		t.Fatalf("expected 1 model (soft delete preserves metadata), got %d", count)
	}
	if finalState != StateDeleted {
		t.Fatalf("expected state deleted, got %s", finalState)
	}
}

func TestHealthReportsStateCounts(t *testing.T) {
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{
		{Name: "a", State: StateAcquired},
		{Name: "b", State: StateQuarantined},
		{Name: "c", State: StateTrusted},
		{Name: "d", State: StateRevoked},
		{Name: "e", State: StateDeleted},
	}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["model_count"] != float64(5) {
		t.Fatalf("expected model_count=5, got %v", body["model_count"])
	}
	if body["trusted_count"] != float64(1) {
		t.Fatalf("expected trusted_count=1, got %v", body["trusted_count"])
	}
	stateCounts, ok := body["state_counts"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected state_counts map, got %T", body["state_counts"])
	}
	if stateCounts["acquired"] != float64(1) {
		t.Fatalf("expected acquired=1, got %v", stateCounts["acquired"])
	}
	if stateCounts["quarantined"] != float64(1) {
		t.Fatalf("expected quarantined=1, got %v", stateCounts["quarantined"])
	}
	if stateCounts["deleted"] != float64(1) {
		t.Fatalf("expected deleted=1, got %v", stateCounts["deleted"])
	}
}

func TestListShowsAllStates(t *testing.T) {
	manifestMu.Lock()
	manifest = Manifest{Version: 1, Models: []Artifact{
		{Name: "acq", State: StateAcquired},
		{Name: "quar", State: StateQuarantined},
		{Name: "trust", State: StateTrusted},
		{Name: "rev", State: StateRevoked},
		{Name: "del", State: StateDeleted},
	}}
	manifestMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	w := httptest.NewRecorder()
	handleListModels(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var models []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &models)
	if len(models) != 5 {
		t.Fatalf("expected 5 models, got %d", len(models))
	}

	states := map[string]bool{}
	for _, m := range models {
		s, _ := m["state"].(string)
		states[s] = true
	}
	for _, expected := range []string{"acquired", "quarantined", "trusted", "revoked", "deleted"} {
		if !states[expected] {
			t.Fatalf("expected state %q in list, not found", expected)
		}
	}
}
