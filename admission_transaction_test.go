package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type admissionFixture struct {
	parent, outbox string
	data           []byte
	policy         admissionPolicy
}

func setupAdmissionFixture(t *testing.T) admissionFixture {
	t.Helper()
	oldManifest, oldDir, oldPath := manifest, registryDir, manifestPath
	oldConfig, oldLock, oldDev, oldToken := configuredAdmission, admissionStoreLock, insecureDevMode, serviceToken
	oldFailure, oldIO, oldLimits := manifestPersistenceFailed, manifestPersistence, manifestCapacityLimits
	oldNow, oldSpace := admissionNow, admissionSpace
	t.Cleanup(func() {
		if admissionStoreLock != nil && admissionStoreLock != oldLock {
			admissionStoreLock.Close()
		}
		manifest, registryDir, manifestPath = oldManifest, oldDir, oldPath
		configuredAdmission, admissionStoreLock, insecureDevMode, serviceToken = oldConfig, oldLock, oldDev, oldToken
		manifestPersistenceFailed, manifestPersistence, manifestCapacityLimits = oldFailure, oldIO, oldLimits
		admissionNow, admissionSpace = oldNow, oldSpace
	})
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	registryDir = filepath.Join(parent, "registry")
	outbox := filepath.Join(parent, "outbox")
	if err := initializeAdmissionTarget("registry", registryDir); err != nil {
		t.Fatal(err)
	}
	if err := initializeAdmissionTarget("outbox", outbox); err != nil {
		t.Fatal(err)
	}
	policyDir := filepath.Join(parent, "policy")
	if err := os.Mkdir(policyDir, 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte("synthetic unit-test bytes; not a scanner proof")
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	parts := map[string][]byte{
		"policy.yaml":            []byte("version: 1\nmodels:\n  allowed_formats: [gguf, safetensors]\n  allow_local_imports: true\n  require_behavior_tests: false\n"),
		"models.lock.yaml":       []byte("version: 1\nmodels:\n  - filename: demo.safetensors\n    sha256: " + hash + "\n  - filename: second.safetensors\n    sha256: " + hash + "\n"),
		"sources.allowlist.yaml": []byte("models:\n  - url_prefix: https://huggingface.co/example/\n"),
	}
	values := []string{}
	for _, name := range admissionPolicyNames {
		if err := os.WriteFile(filepath.Join(policyDir, name), parts[name], 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(parts[name])
		values = append(values, name, hex.EncodeToString(digest[:]))
	}
	config := AdmissionConfig{Version: 1, PolicyDir: policyDir, PolicyBundleSHA256: admissionDigest("HelperAdmissionPolicy-v1", values...), OutboxDir: outbox, PipelineSHA256: strings.Repeat("f", 64), ProducerUID: os.Geteuid(), OutboxGID: os.Getegid(), MaxArtifactBytes: 1 << 20, RetainedByteLimit: 512 << 20, MinFreeBytes: 1 << 20}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(parent, "config.json")
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGISTRY_ADMISSION_MODE", admissionMode)
	t.Setenv("ADMISSION_CONFIG_PATH", configPath)
	insecureDevMode = false
	serviceToken = strings.Repeat("t", 32)
	manifestPersistenceFailed = false
	manifestCapacityLimits = capacityLimits{maxManifestBytes, maxManifestEntries, maxManifestEntries}
	manifestPath = filepath.Join(registryDir, "manifest.json")
	if err := initializeAdmission(); err != nil {
		t.Fatal(err)
	}
	if err := lockAdmissionStore(); err != nil {
		t.Fatal(err)
	}
	if err := loadManifest(); err != nil {
		t.Fatal(err)
	}
	policy, err := loadAdmissionPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	admissionNow = func() (admissionTime, error) {
		return admissionTime{BootID: "12345678-1234-1234-1234-123456789abc", NS: 1000000}, nil
	}
	return admissionFixture{parent: parent, outbox: outbox, data: data, policy: policy}
}

func (f admissionFixture) prepare(name string) AdmissionPrepareRequest {
	req := admissionTestPrepare()
	req.Name = name
	req.Filename = name + ".safetensors"
	req.SHA256 = f.policy.Pins[req.Filename]
	req.SizeBytes = int64(len(f.data))
	req.PolicyBundle = f.policy.Bundle
	req.ContextSHA256 = admissionContextDigest(req.PolicyBundle.SHA256, AdmissionScanContext{PipelineSHA256: configuredAdmission.PipelineSHA256, RequireBehavior: f.policy.RequireBehavior})
	if name != "demo" {
		req.AdmissionID = strings.Repeat("2", 64)
	}
	return req
}

func admissionCall(t *testing.T, method, path string, value any, id string) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if value != nil {
		var err error
		raw, err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+serviceToken)
	req.Header.Set("Idempotency-Key", id)
	result := httptest.NewRecorder()
	newRegistryMux().ServeHTTP(result, req)
	return result
}

func decodeAdmissionArtifact(t *testing.T, result *httptest.ResponseRecorder) Artifact {
	t.Helper()
	var artifact Artifact
	if err := json.Unmarshal(result.Body.Bytes(), &artifact); err != nil {
		t.Fatalf("response%d %s: %v", result.Code, result.Body.String(), err)
	}
	return artifact
}

func (f admissionFixture) stage(t *testing.T, artifact Artifact) AdmissionCommitRequest {
	t.Helper()
	id := artifact.Admission.Prepare.AdmissionID
	for _, directory := range []string{id, filepath.Join(id, "input"), filepath.Join(id, "evidence")} {
		if err := os.Mkdir(filepath.Join(f.outbox, directory), 0750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.outbox, id, "input", artifact.Filename), f.data, 0440); err != nil {
		t.Fatal(err)
	}
	report := admissionTestReport(artifact.Admission.Prepare)
	report.PipelineSHA256 = artifact.Admission.Context.PipelineSHA256
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.outbox, id, "evidence", "pipeline.json"), raw, 0440); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return AdmissionCommitRequest{ProtocolVersion: 2, AdmissionID: id, PrepareReceiptSHA256: artifact.Admission.PrepareReceipt.SHA256, Evidence: []AdmissionEvidence{{Role: "pipeline-report", Filename: "pipeline.json", SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(raw))}}}
}

func TestAdmissionTransactionPrepareCommitReplayAndDeny(t *testing.T) {
	fixture := setupAdmissionFixture(t)
	request := fixture.prepare("demo")
	result := admissionCall(t, http.MethodPost, "/v2/admission/prepare", request, request.AdmissionID)
	if result.Code != http.StatusCreated {
		t.Fatalf("prepare%d: %s", result.Code, result.Body.String())
	}
	prepared := decodeAdmissionArtifact(t, result)
	if manifest.Version != 2 || len(manifest.Events) != 2 {
		t.Fatal("preparation not one durable two-event transaction")
	}
	replay := admissionCall(t, http.MethodPost, "/v2/admission/prepare", request, request.AdmissionID)
	if replay.Code != http.StatusOK || len(manifest.Events) != 2 {
		t.Fatal("prepare replay mutated history")
	}
	commit := fixture.stage(t, prepared)
	result = admissionCall(t, http.MethodPost, "/v2/admission/commit", commit, request.AdmissionID)
	if result.Code != http.StatusCreated {
		t.Fatalf("commit%d: %s", result.Code, result.Body.String())
	}
	accepted := decodeAdmissionArtifact(t, result)
	if accepted.State != StateTrusted || len(manifest.Events) != 3 {
		t.Fatal("commit did not create one trusted snapshot")
	}
	if err := loadManifest(); err != nil {
		t.Fatal(err)
	}
	replay = admissionCall(t, http.MethodPost, "/v2/admission/commit", commit, request.AdmissionID)
	if replay.Code != http.StatusOK || len(manifest.Events) != 3 || decodeAdmissionArtifact(t, replay).Admission.CommitReceipt.SHA256 != accepted.Admission.CommitReceipt.SHA256 {
		t.Fatal("restart replay changed receipt/history")
	}
	revoked := admissionCall(t, http.MethodPost, "/v1/model/revoke?name=demo", nil, "")
	if revoked.Code != 200 {
		t.Fatal(revoked.Body.String())
	}
	replay = admissionCall(t, http.MethodPost, "/v2/admission/commit", commit, request.AdmissionID)
	if replay.Code != 200 || decodeAdmissionArtifact(t, replay).State != StateRevoked || len(manifest.Events) != 4 {
		t.Fatal("replay revived revoked artifact")
	}
	denied := admissionCall(t, http.MethodGet, "/v1/model/path?name=demo", nil, "")
	if denied.Code != http.StatusForbidden {
		t.Fatal("revoked path became usable")
	}
}

func TestAdmissionPreparedDeleteNeverTouchesSharedFilename(t *testing.T) {
	fixture := setupAdmissionFixture(t)
	request := fixture.prepare("demo")
	sentinel := filepath.Join(registryDir, request.Filename)
	if err := os.WriteFile(sentinel, []byte("unrelated shared bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	result := admissionCall(t, http.MethodPost, "/v2/admission/prepare", request, request.AdmissionID)
	if result.Code != 201 {
		t.Fatal(result.Body.String())
	}
	result = admissionCall(t, http.MethodDelete, "/v1/model/delete?name=demo", nil, "")
	if result.Code != 200 {
		t.Fatal(result.Body.String())
	}
	raw, err := os.ReadFile(sentinel)
	if err != nil || string(raw) != "unrelated shared bytes" {
		t.Fatal("prepared delete modified shared input")
	}
	plan, err := plannedAdmissionReservations(manifest)
	if err != nil || plan.OutboxBytes == 0 || plan.RegistryBytes == 0 {
		t.Fatal("delete released retained debit")
	}
}

func TestAdmissionUnavailableLookupAndLegacyBypass(t *testing.T) {
	fixture := setupAdmissionFixture(t)
	request := fixture.prepare("demo")
	for _, path := range []string{"/v1/model/acquire", "/v1/model/quarantine?name=demo", "/v1/model/promote"} {
		result := admissionCall(t, http.MethodPost, path, request, request.AdmissionID)
		if result.Code != http.StatusConflict {
			t.Fatalf("legacy admission not blocked: %s %d", path, result.Code)
		}
	}
	manifestPersistenceFailed = true
	result := admissionCall(t, http.MethodGet, "/v1/model?name=demo", nil, "")
	if result.Code != http.StatusServiceUnavailable {
		t.Fatalf("unknown durability hidden as%d", result.Code)
	}
}

func TestAdmissionInitializerRefusesExistingTargets(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "new")
	if err := initializeAdmissionTarget("registry", target); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(target, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if initializeAdmissionTarget("registry", target) == nil {
		t.Fatal("initializer reset existing authority")
	}
	after, _ := os.ReadFile(filepath.Join(target, "manifest.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("initializer changed existing bytes")
	}
	empty := filepath.Join(parent, "empty")
	os.Mkdir(empty, 0700)
	if initializeAdmissionTarget("outbox", empty) == nil {
		t.Fatal("initializer adopted existing empty target")
	}
}

func TestAdmissionTransactionPersistenceFaults(t *testing.T) {
	for _, phase := range []string{"prepare", "commit"} {
		for _, fault := range []string{"write", "short-write", "file-sync", "rename", "directory-sync"} {
			t.Run(phase+"/"+fault, func(t *testing.T) {
				fixture := setupAdmissionFixture(t)
				request := fixture.prepare("demo")
				var payload any = request
				beforeEvents := 0
				if phase == "commit" {
					prepared := admissionCall(t, http.MethodPost, "/v2/admission/prepare", request, request.AdmissionID)
					if prepared.Code != 201 {
						t.Fatal(prepared.Body.String())
					}
					payload = fixture.stage(t, decodeAdmissionArtifact(t, prepared))
					beforeEvents = 2
				}
				original := manifestPersistence
				published := false
				manifestPersistence.rename = func(from, to string) error {
					if fault == "rename" {
						return syscall.EIO
					}
					err := original.rename(from, to)
					published = err == nil
					return err
				}
				switch fault {
				case "write":
					manifestPersistence.write = func(*os.File, []byte) (int, error) { return 0, syscall.ENOSPC }
				case "short-write":
					manifestPersistence.write = func(f *os.File, raw []byte) (int, error) { return f.Write(raw[:len(raw)/2]) }
				case "file-sync":
					manifestPersistence.syncFile = func(*os.File) error { return syscall.EIO }
				case "directory-sync":
					manifestPersistence.syncDirectory = func(path string) error {
						if published {
							return syscall.EIO
						}
						return original.syncDirectory(path)
					}
				}
				result := admissionCall(t, http.MethodPost, "/v2/admission/"+phase, payload, request.AdmissionID)
				if result.Code < 400 {
					t.Fatalf("fault returned success: %d", result.Code)
				}
				if fault == "directory-sync" {
					if !manifestPersistenceFailed {
						t.Fatal("uncertain publication did not latch unavailable")
					}
					if admissionCall(t, http.MethodGet, "/v1/model?name=demo", nil, "").Code != 503 {
						t.Fatal("unknown receipt visible as known")
					}
				} else if manifestPersistenceFailed || len(manifest.Events) != beforeEvents {
					t.Fatal("prepublication failure changed authority")
				}
				manifestPersistence = original
				manifestPersistenceFailed = false // Test models a fresh process reading disk.
				if err := loadManifest(); err != nil {
					t.Fatal(err)
				}
				if phase == "commit" {
					input, err := os.ReadFile(filepath.Join(fixture.outbox, request.AdmissionID, "input", request.Filename))
					if err != nil || !bytes.Equal(input, fixture.data) {
						t.Fatal("failed commit changed producer bytes")
					}
					plan, err := plannedAdmissionReservations(manifest)
					if err != nil || plan.OutboxBytes == 0 || plan.RegistryBytes == 0 {
						t.Fatal("failed commit released debit")
					}
				}
				replay := admissionCall(t, http.MethodPost, "/v2/admission/"+phase, payload, request.AdmissionID)
				want := http.StatusCreated
				if published {
					want = http.StatusOK
				}
				if replay.Code != want {
					t.Fatalf("exact retry after fault: %d %s", replay.Code, replay.Body.String())
				}
			})
		}
	}
}

func TestAdmissionTransactionExpiredOrNewBootNeverCopies(t *testing.T) {
	for _, changedBoot := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired", true: "new-boot"}[changedBoot], func(t *testing.T) {
			fixture := setupAdmissionFixture(t)
			request := fixture.prepare("demo")
			result := admissionCall(t, http.MethodPost, "/v2/admission/prepare", request, request.AdmissionID)
			if result.Code != 201 {
				t.Fatal(result.Body.String())
			}
			prepared := decodeAdmissionArtifact(t, result)
			commit := fixture.stage(t, prepared)
			admissionNow = func() (admissionTime, error) {
				now := admissionTime{BootID: prepared.Admission.PrepareReceipt.BootID, NS: prepared.Admission.PrepareReceipt.ExpiresBootNS}
				if changedBoot {
					now.BootID = "87654321-1234-1234-1234-123456789abc"
					now.NS = 100
				}
				return now, nil
			}
			result = admissionCall(t, http.MethodPost, "/v2/admission/commit", commit, request.AdmissionID)
			if result.Code != 409 || len(manifest.Events) != 2 {
				t.Fatal("expired preparation acquired trust")
			}
			if _, err := os.Lstat(filepath.Join(registryDir, "admission-data")); !os.IsNotExist(err) {
				t.Fatal("expired request created copy state")
			}
			replay := admissionCall(t, http.MethodPost, "/v2/admission/prepare", request, request.AdmissionID)
			if replay.Code != 200 || decodeAdmissionArtifact(t, replay).Admission.PrepareReceipt != prepared.Admission.PrepareReceipt {
				t.Fatal("prepare replay renewed authority")
			}
		})
	}
}

func TestAdmissionTransactionChangedBytesConflict(t *testing.T) {
	fixture := setupAdmissionFixture(t)
	request := fixture.prepare("demo")
	result := admissionCall(t, http.MethodPost, "/v2/admission/prepare", request, request.AdmissionID)
	if result.Code != 201 {
		t.Fatal(result.Body.String())
	}
	commit := fixture.stage(t, decodeAdmissionArtifact(t, result))
	for _, phase := range []string{"prepare", "commit"} {
		var payload any = request
		if phase == "commit" {
			payload = commit
			result = admissionCall(t, http.MethodPost, "/v2/admission/commit", commit, request.AdmissionID)
			if result.Code != 201 {
				t.Fatal(result.Body.String())
			}
		}
		before := len(manifest.Events)
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/v2/admission/"+phase, bytes.NewReader(append(raw, '\n')))
		req.Header.Set("Authorization", "Bearer "+serviceToken)
		req.Header.Set("Idempotency-Key", request.AdmissionID)
		response := httptest.NewRecorder()
		newRegistryMux().ServeHTTP(response, req)
		if response.Code != 409 || len(manifest.Events) != before {
			t.Fatal("changed request bytes reused receipt")
		}
	}
}
