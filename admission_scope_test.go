package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func admissionScopeFixture(t *testing.T) {
	t.Helper()
	previous := registryScopeTokens
	t.Cleanup(func() { registryScopeTokens = previous })
	registryScopeTokens = map[string]string{"read": strings.Repeat("a", 64), "verify": strings.Repeat("b", 64), "promote": strings.Repeat("c", 64), "admin": strings.Repeat("d", 64)}
}

func TestAdmissionScopedPromotionAuthority(t *testing.T) {
	for _, role := range []string{"promote", "admin"} {
		t.Run(role, func(t *testing.T) {
			fixture := setupAdmissionFixture(t)
			admissionScopeFixture(t)
			request := fixture.prepare("demo")
			for _, denied := range []string{"read", "verify"} {
				serviceToken = registryScopeTokens[denied]
				if response := admissionCall(t, http.MethodPost, "/v2/admission/prepare", request, request.AdmissionID); response.Code != 403 {
					t.Fatalf("%s prepare got %d", denied, response.Code)
				}
				if response := admissionCall(t, http.MethodPost, "/v2/admission/commit", nil, request.AdmissionID); response.Code != 403 {
					t.Fatalf("%s commit got %d", denied, response.Code)
				}
				capabilities := admissionCall(t, http.MethodGet, "/v2/admission/capabilities", nil, "")
				want := 200
				if denied == "verify" {
					want = 403
				}
				if capabilities.Code != want {
					t.Fatalf("%s capabilities got %d want%d", denied, capabilities.Code, want)
				}
			}
			serviceToken = registryScopeTokens[role]
			if response := admissionCall(t, http.MethodGet, "/v2/admission/capabilities", nil, ""); response.Code != 200 {
				t.Fatal(response.Body.String())
			}
			response := admissionCall(t, http.MethodPost, "/v2/admission/prepare", request, request.AdmissionID)
			if response.Code != 201 {
				t.Fatalf("%s prepare: %d %s", role, response.Code, response.Body.String())
			}
			prepared := decodeAdmissionArtifact(t, response)
			if response := admissionCall(t, http.MethodGet, "/v1/model?name=demo", nil, ""); response.Code != 200 {
				t.Fatalf("receipt lookup: %d", response.Code)
			}
			commit := fixture.stage(t, prepared)
			response = admissionCall(t, http.MethodPost, "/v2/admission/commit", commit, request.AdmissionID)
			if response.Code != 201 || decodeAdmissionArtifact(t, response).State != StateTrusted {
				t.Fatalf("%s commit: %d %s", role, response.Code, response.Body.String())
			}
			if response := admissionCall(t, http.MethodPost, "/v2/admission/commit", commit, request.AdmissionID); response.Code != 200 || len(manifest.Events) != 3 {
				t.Fatal("exact commit replay changed history")
			}
			if response := admissionCall(t, http.MethodPost, "/v1/model/promote", nil, ""); response.Code != 409 {
				t.Fatal("v1 promotion escaped required-v2 gate")
			}
			if role == "promote" {
				for _, endpoint := range []struct{ method, path string }{{"DELETE", "/v1/model/delete?name=demo"}, {"POST", "/v1/model/revoke?name=demo"}, {"GET", "/v1/audit"}, {"GET", "/v1/model/path?name=demo"}, {"GET", "/v1/models"}} {
					if response := admissionCall(t, endpoint.method, endpoint.path, nil, ""); response.Code != 403 {
						t.Fatalf("promotion authority widened at %s: %d", endpoint.path, response.Code)
					}
				}
			}
			serviceToken = registryScopeTokens["admin"]
			if response := admissionCall(t, http.MethodPost, "/v1/model/revoke?name=demo", nil, ""); response.Code != 200 {
				t.Fatal("administrator lost revoke authority")
			}
			if response := admissionCall(t, http.MethodPost, "/v2/admission/commit", commit, request.AdmissionID); response.Code != 200 || decodeAdmissionArtifact(t, response).State != StateRevoked {
				t.Fatal("replay revived revoked artifact")
			}
		})
	}
}

// Opt-in connected-source verification uses the existing admission fixture and
// actual Python client, without introducing a production module dependency.
func TestAdmissionClientScopedPromotion(t *testing.T) {
	clientRoot := os.Getenv("SECAI_ADMISSION_CLIENT_ROOT")
	if clientRoot == "" {
		t.Skip("set SECAI_ADMISSION_CLIENT_ROOT for connected client verification")
	}
	fixture := setupAdmissionFixture(t)
	admissionScopeFixture(t)
	server := httptest.NewServer(newRegistryMux())
	defer server.Close()
	request := fixture.prepare("demo")
	prepare, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	const script = `import json, sys
cfg = json.load(sys.stdin)
sys.path.insert(0, cfg["client_root"])
from quarantine.admission_client import AdmissionClient
client = AdmissionClient(cfg["origin"], cfg["token"])
client.preflight(cfg["bundle"], cfg["pipeline"], artifact_format="safetensors")
prepare = cfg["prepare"].encode()
if cfg["operation"] == "prepare":
    status, artifact = client.prepare(prepare)
else:
    assert client.lookup(prepare)["state"] == "quarantined"
    commit = cfg["commit"].encode()
    status, artifact = client.commit(prepare, commit)
    assert client.lookup(prepare, commit_raw=commit)["admission"]["commit_receipt"] == artifact["admission"]["commit_receipt"]
print(json.dumps({"status": status, "artifact": artifact}))
`
	run := func(operation string, commit []byte) Artifact {
		t.Helper()
		input, err := json.Marshal(map[string]any{"client_root": clientRoot, "origin": server.URL, "token": registryScopeTokens["promote"], "bundle": fixture.policy.Bundle, "pipeline": configuredAdmission.PipelineSHA256, "prepare": string(prepare), "commit": string(commit), "operation": operation})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "python3", "-I", "-B", "-c", script)
		command.Stdin = bytes.NewReader(input)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("actual client %s failed: %v %s", operation, err, output)
		}
		var result struct {
			Status   int      `json:"status"`
			Artifact Artifact `json:"artifact"`
		}
		if err := json.Unmarshal(output, &result); err != nil || result.Status != 201 {
			t.Fatalf("actual client result: %s %v", output, err)
		}
		return result.Artifact
	}
	prepared := run("prepare", nil)
	commit, err := json.Marshal(fixture.stage(t, prepared))
	if err != nil {
		t.Fatal(err)
	}
	accepted := run("commit", commit)
	if accepted.State != StateTrusted || accepted.Admission.CommitReceipt == nil || len(manifest.Events) != 3 {
		t.Fatal("actual client admission did not retain exact trusted receipt")
	}
}
