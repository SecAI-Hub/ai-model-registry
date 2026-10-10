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
)

func scopedContractFixture(t *testing.T) (Artifact, string) {
	t.Helper()
	oldManifest, oldDir, oldFailed, oldScopes := manifest, registryDir, manifestPersistenceFailed, registryScopeTokens
	t.Cleanup(func() {
		manifest, registryDir, manifestPersistenceFailed, registryScopeTokens = oldManifest, oldDir, oldFailed, oldScopes
	})
	registryDir = t.TempDir()
	manifestPersistenceFailed = false
	registryScopeTokens = map[string]string{"read": strings.Repeat("a", 64), "verify": strings.Repeat("b", 64), "promote": strings.Repeat("c", 64), "admin": strings.Repeat("d", 64)}
	content := []byte("synthetic regular model")
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	rel, err := contentAddressedObjectRel(digest, "safetensors")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(registryDir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o400); err != nil {
		t.Fatal(err)
	}
	artifact := Artifact{Name: "Reviewed regular model", Filename: "registered.safetensors", Format: "safetensors", ObjectPath: rel, SHA256: digest, SizeBytes: int64(len(content)), State: StateTrusted}
	manifest = Manifest{Version: 1, Models: []Artifact{artifact}}
	return artifact, path
}

func TestScopedVerifiedPathHTTPContractAndTamper(t *testing.T) {
	artifact, path := scopedContractFixture(t)
	server := httptest.NewServer(newRegistryMux())
	defer server.Close()
	request := func(endpoint, role string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		if role != "" {
			req.Header.Set("Authorization", "Bearer "+registryScopeTokens[role])
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(response.Body).Decode(&body)
		return response.StatusCode, body
	}
	for _, role := range []string{"", "read", "promote"} {
		if code, _ := request("/v1/model/path?filename="+artifact.Filename, role); code != 403 {
			t.Fatalf("role %q got %d", role, code)
		}
	}
	for _, role := range []string{"verify", "admin"} {
		code, body := request("/v1/model/path?filename="+artifact.Filename, role)
		if code != 200 || body["schema_version"] != float64(1) || body["status"] != "verified" || body["safe_to_use"] != "true" || body["name"] != artifact.Name || body["filename"] != artifact.Filename || body["format"] != artifact.Format || body["sha256"] != artifact.SHA256 || body["path"] != path || body["size_bytes"] != float64(artifact.SizeBytes) || body["storage_contract"] != "content-addressed-v1" {
			t.Fatalf("incomplete contract: %d %#v", code, body)
		}
	}
	verify := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/model/verify?name=Reviewed+regular+model", nil)
	req.Header.Set("Authorization", "Bearer "+registryScopeTokens["verify"])
	newRegistryMux().ServeHTTP(verify, req)
	var verified map[string]any
	if err := json.Unmarshal(verify.Body.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if verify.Code != 200 || verified["schema_version"] != float64(1) || verified["sha256"] != artifact.SHA256 || verified["safe_to_use"] != "true" {
		t.Fatalf("verify metadata: %d %#v", verify.Code, verified)
	}
	if code, _ := request("/v1/models", "read"); code != 200 {
		t.Fatalf("read diagnostic list: %d", code)
	}
	manifestMu.Lock()
	manifest.Models[0].SizeBytes++
	manifestMu.Unlock()
	if code, _ := request("/v1/model/path?filename="+artifact.Filename, "verify"); code != 409 {
		t.Fatalf("incorrect enrolled size got %d", code)
	}
	manifestMu.Lock()
	manifest.Models[0].SizeBytes = artifact.SizeBytes
	manifestMu.Unlock()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered regular model"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if code, _ := request("/v1/model/path?filename="+artifact.Filename, "verify"); code != 409 {
		t.Fatalf("tampered model path got %d", code)
	}
}

func TestVerifiedPathSelectorsAndAmbiguousEnrollment(t *testing.T) {
	artifact, _ := scopedContractFixture(t)
	for _, selector := range []string{"", "name=", "filename=", "name=x&filename=" + artifact.Filename, "name=&filename=" + artifact.Filename, "filename=x&filename=x", "name=x&name=x", "filename=../x", "filename=%2Fx", "filename=child%2F..%2Fx", "filename=x%5Cy", "filename=x%00", "filename=bad%zz"} {
		response := httptest.NewRecorder()
		handleModelPath(response, httptest.NewRequest(http.MethodGet, "/v1/model/path?"+selector, nil))
		if response.Code != 400 {
			t.Fatalf("selector %q: %d %s", selector, response.Code, response.Body.String())
		}
	}
	manifest.Models = append(manifest.Models, artifact)
	for _, selector := range []string{"filename=" + artifact.Filename, "name=Reviewed+regular+model"} {
		response := httptest.NewRecorder()
		handleModelPath(response, httptest.NewRequest(http.MethodGet, "/v1/model/path?"+selector, nil))
		if response.Code != 404 {
			t.Fatalf("ambiguous selector got %d", response.Code)
		}
	}
}

func TestRegistryScopedCredentialLoadingFailClosed(t *testing.T) {
	oldScopes, oldService := registryScopeTokens, serviceToken
	t.Cleanup(func() { registryScopeTokens, serviceToken = oldScopes, oldService })
	for _, role := range []string{"read", "verify", "promote", "admin"} {
		t.Setenv("REGISTRY_"+strings.ToUpper(role)+"_TOKEN_PATH", "")
	}
	if selected, err := loadRegistryScopeTokens(); selected || err != nil {
		t.Fatalf("legacy mode changed: %v %v", selected, err)
	}
	dir := t.TempDir()
	paths := map[string]string{}
	for index, role := range []string{"read", "verify", "promote", "admin"} {
		path := filepath.Join(dir, role)
		if err := os.WriteFile(path, []byte(strings.Repeat(string(rune('a'+index)), 64)), 0o600); err != nil {
			t.Fatal(err)
		}
		paths[role] = path
		t.Setenv("REGISTRY_"+strings.ToUpper(role)+"_TOKEN_PATH", path)
		if index < 3 {
			if selected, err := loadRegistryScopeTokens(); !selected || err == nil {
				t.Fatal("partial scopes accepted")
			}
		}
	}
	if selected, err := loadRegistryScopeTokens(); !selected || err != nil {
		t.Fatalf("valid scopes failed: %v", err)
	}
	serviceToken = "legacy token must not survive scoped selection"
	if err := loadServiceToken(); err != nil || serviceToken != "" {
		t.Fatal("scoped load retained legacy authority")
	}
	if err := os.WriteFile(paths["read"], []byte(strings.Repeat("b", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRegistryScopeTokens(); err == nil {
		t.Fatal("duplicate scopes accepted")
	}
	if err := os.WriteFile(paths["read"], []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths["read"], 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRegistryScopeTokens(); err == nil {
		t.Fatal("unsafe scope permissions accepted")
	}
	if err := os.Remove(paths["read"]); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(paths["admin"], paths["read"]); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRegistryScopeTokens(); err == nil {
		t.Fatal("scope symlink accepted")
	}
}
