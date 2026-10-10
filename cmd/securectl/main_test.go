package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestModelQueryPathEncodesName(t *testing.T) {
	got := modelQueryPath("/v1/model", "Phi-3 Mini 3.8B (Q4_K_M)")
	want := "/v1/model?name=Phi-3+Mini+3.8B+%28Q4_K_M%29"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestAPIRequestRequiresAndAddsServiceToken(t *testing.T) {
	token := strings.Repeat("a", 32)
	tokenPath := t.TempDir() + "/token"
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SERVICE_TOKEN_PATH", tokenPath)
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()
	oldURL := registryURL
	registryURL = server.URL
	t.Cleanup(func() { registryURL = oldURL })
	_, code, err := apiGet("/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	if code != http.StatusOK || gotAuth != "Bearer "+token {
		t.Fatalf("code=%d auth=%q", code, gotAuth)
	}
}

func TestAPIRequestFailsClosedWithoutToken(t *testing.T) {
	t.Setenv("SERVICE_TOKEN_PATH", t.TempDir()+"/missing")
	oldURL := registryURL
	registryURL = "http://127.0.0.1:1"
	t.Cleanup(func() { registryURL = oldURL })
	if _, _, err := apiGet("/v1/models"); err == nil || !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("expected authentication error, got %v", err)
	}
}

func TestHealthDoesNotRequireOrSendToken(t *testing.T) {
	t.Setenv("SERVICE_TOKEN_PATH", t.TempDir()+"/missing")
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer server.Close()
	oldURL := registryURL
	registryURL = server.URL
	t.Cleanup(func() { registryURL = oldURL })
	if _, code, err := apiGet("/health"); err != nil || code != http.StatusOK {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if gotAuth != "" {
		t.Fatalf("health request leaked authorization header")
	}
}

func TestValidateRegistryURLRejectsPlaintextRemote(t *testing.T) {
	if err := validateRegistryURL("http://192.0.2.10:8470"); err == nil {
		t.Fatal("expected plaintext remote URL to be rejected")
	}
	if err := validateRegistryURL("https://registry.example.test"); err != nil {
		t.Fatalf("expected HTTPS URL to be accepted: %v", err)
	}
}

func TestAPIRequestRejectsOversizedResponse(t *testing.T) {
	tokenPath := t.TempDir() + "/token"
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("b", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SERVICE_TOKEN_PATH", tokenPath)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 1<<20+1))
	}))
	defer server.Close()
	oldURL := registryURL
	registryURL = server.URL
	t.Cleanup(func() { registryURL = oldURL })
	if _, _, err := apiGet("/v1/models"); err == nil {
		t.Fatal("expected oversized response to fail")
	}
}

func TestTypedVerificationMetadataRetainsLegacyCompatibility(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, schema := range []string{"", `"schema_version":1,`} {
		data := []byte(`{` + schema + `"status":"verified","sha256":"` + digest + `","state":"trusted","safe_to_use":"true"}`)
		result, err := decodeVerificationResponse(data, http.StatusOK)
		if err != nil || result.SHA256 != digest || result.SafeToUse != "true" {
			t.Fatalf("numeric/legacy contract: %#v %v", result, err)
		}
	}
	for _, data := range []string{`{"schema_version":"1"}`, `{"status":"verified"}`, `{"schema_version":2,"status":"verified","sha256":"` + digest + `","safe_to_use":"true"}`} {
		if _, err := decodeVerificationResponse([]byte(data), http.StatusOK); err == nil {
			t.Fatal("invalid verified result accepted")
		}
	}
}

func TestScopedAdministratorCredentialSelectedWithoutLegacyFallback(t *testing.T) {
	dir := t.TempDir()
	admin := dir + "/admin"
	if err := os.WriteFile(admin, []byte(strings.Repeat("d", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGISTRY_ADMIN_TOKEN_PATH", admin)
	t.Setenv("SERVICE_TOKEN_PATH", dir+"/missing-legacy")
	if token, err := readServiceToken(); err != nil || token != strings.Repeat("d", 64) {
		t.Fatalf("administrator not selected: %q %v", token, err)
	}
	legacy := dir + "/legacy"
	if err := os.WriteFile(legacy, []byte(strings.Repeat("e", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SERVICE_TOKEN_PATH", legacy)
	t.Setenv("REGISTRY_ADMIN_TOKEN_PATH", dir+"/missing-admin")
	if _, err := readServiceToken(); err == nil {
		t.Fatal("missing explicit administrator credential accepted")
	}
}

func TestTypedPathMetadataRetainsLocatorAndRejectsFailures(t *testing.T) {
	digest := strings.Repeat("a", 64)
	locator := `"path":"/registry/objects/model","sha256":"` + digest + `","size_bytes":22,"storage_contract":"content-addressed-v1"`
	for _, metadata := range []string{"", `"schema_version":1,"status":"verified","safe_to_use":"true","name":"demo","filename":"demo.safetensors","format":"safetensors",`} {
		result, err := decodePathResponse([]byte(`{`+metadata+locator+`}`), http.StatusOK)
		if err != nil || result.Path != "/registry/objects/model" || result.SizeBytes != 22 {
			t.Fatalf("locator compatibility: %#v %v", result, err)
		}
		if _, err := decodePathResponse([]byte(`{`+metadata+locator+`}`), http.StatusConflict); err == nil {
			t.Fatal("non200 locator accepted")
		}
	}
	for _, metadata := range []string{`"schema_version":"1",`, `"schema_version":1,"status":"unavailable","safe_to_use":"false",`, `"schema_version":2,`} {
		if _, err := decodePathResponse([]byte(`{`+metadata+locator+`}`), http.StatusOK); err == nil {
			t.Fatal("unsafe metadata accepted")
		}
	}
}
