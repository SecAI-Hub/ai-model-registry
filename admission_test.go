package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func admissionTestPrepare() AdmissionPrepareRequest {
	bundle := AdmissionPolicyBundle{Version: 1, Components: map[string]string{}}
	values := []string{}
	for _, name := range admissionPolicyNames {
		bundle.Components[name] = strings.Repeat("b", 64)
		values = append(values, name, bundle.Components[name])
	}
	bundle.SHA256 = admissionDigest("HelperAdmissionPolicy-v1", values...)
	return AdmissionPrepareRequest{ProtocolVersion: 2, AdmissionID: strings.Repeat("1", 64),
		Name: "demo", Filename: "demo.safetensors", ArtifactKind: "file", Format: "safetensors",
		SHA256: strings.Repeat("a", 64), SizeBytes: 4096, PolicyBundle: bundle, ContextSHA256: admissionContextDigest(bundle.SHA256, AdmissionScanContext{PipelineSHA256: strings.Repeat("f", 64), RequireBehavior: true}), EvidenceBudgetBytes: admissionEvidenceLimit}
}

func TestAdmissionStrictRequestJSON(t *testing.T) {
	request := admissionTestPrepare()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded AdmissionPrepareRequest
	if err := decodeAdmissionJSON(raw, admissionBodyLimit, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := validateAdmissionPrepare(decoded); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"unknown":              append([]byte(`{"unexpected":true,`), raw[1:]...),
		"duplicate":            append([]byte(`{"name":"other",`), raw[1:]...),
		"nested_duplicate":     []byte(strings.Replace(string(raw), `"components":{`, `"components":{"policy.yaml":"wrong",`, 1)),
		"trailing":             append(append([]byte{}, raw...), []byte(`{}`)...),
		"missing_local_source": []byte(strings.Replace(string(raw), `"source":"",`, "", 1)),
		"null_local_source":    []byte(strings.Replace(string(raw), `"source":""`, `"source":null`, 1)),
		"fractional_size":      []byte(strings.Replace(string(raw), `"size_bytes":4096`, `"size_bytes":1.5`, 1)),
		"oversized":            []byte(strings.Repeat(" ", admissionBodyLimit) + string(raw)),
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if err := decodeAdmissionJSON(bad, admissionBodyLimit, &decoded); err == nil {
				t.Fatal("accepted invalid wire request")
			}
		})
	}
	if admissionRequestDigest("prepare", raw) == admissionRequestDigest("prepare", append([]byte(" "), raw...)) {
		t.Fatal("wire bytes were normalized")
	}
	if admissionRequestDigest("prepare", raw) == admissionRequestDigest("commit", raw) {
		t.Fatal("request phases were not separated")
	}
}

func TestAdmissionPolicyAndSourceBindings(t *testing.T) {
	request := admissionTestPrepare()
	request.SourceRevision = strings.Repeat("a", 40)
	request.Source = "https://huggingface.co/example/repo/resolve/" + request.SourceRevision + "/demo.safetensors"
	if err := validateAdmissionPrepare(request); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{
		"https://huggingface.co.attacker.invalid/example/repo/resolve/" + request.SourceRevision + "/demo.safetensors",
		strings.Replace(request.Source, "/resolve/"+request.SourceRevision, "/resolve/main", 1),
		request.Source + "?token=unused", request.Source + "#fragment", strings.Replace(request.Source, "/demo", "/%64emo", 1),
		strings.Replace(request.Source, "https://", "http://", 1), strings.Replace(request.Source, "https://", "https://user@", 1),
		strings.Replace(request.Source, "/demo.safetensors", "/other.safetensors", 1),
	} {
		copy := request
		copy.Source = source
		if validateAdmissionPrepare(copy) == nil {
			t.Fatalf("accepted invalid source %q", source)
		}
	}
	request.Source = ""
	if validateAdmissionPrepare(request) == nil {
		t.Fatal("local source inherited remote revision")
	}
	request.SourceRevision = ""
	request.PolicyBundle.Components["policy.yaml"] = strings.Repeat("c", 64)
	if validateAdmissionPrepare(request) == nil {
		t.Fatal("accepted substituted policy component")
	}
}

func TestAdmissionIdentityAndEvidenceLimits(t *testing.T) {
	original := admissionTestPrepare()
	cases := map[string]func(*AdmissionPrepareRequest){
		"directory":          func(r *AdmissionPrepareRequest) { r.ArtifactKind = "directory" },
		"zero_size":          func(r *AdmissionPrepareRequest) { r.SizeBytes = 0 },
		"huge_size":          func(r *AdmissionPrepareRequest) { r.SizeBytes = admissionMaxArtifact + 1 },
		"unbounded_evidence": func(r *AdmissionPrepareRequest) { r.EvidenceBudgetBytes = admissionEvidenceLimit + 1 },
		"traversal":          func(r *AdmissionPrepareRequest) { r.Filename = "../demo.safetensors" },
		"format_mismatch":    func(r *AdmissionPrepareRequest) { r.Format = "gguf" },
		"old_version":        func(r *AdmissionPrepareRequest) { r.ProtocolVersion = 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value := original
			mutate(&value)
			if validateAdmissionPrepare(value) == nil {
				t.Fatal("invalid identity accepted")
			}
		})
	}
	commit := AdmissionCommitRequest{ProtocolVersion: 2, AdmissionID: original.AdmissionID,
		PrepareReceiptSHA256: strings.Repeat("c", 64), Evidence: []AdmissionEvidence{{Role: "pipeline-report", Filename: "pipeline.json", SHA256: strings.Repeat("d", 64), SizeBytes: 100}}}
	if err := validateAdmissionCommit(commit); err != nil {
		t.Fatal(err)
	}
	commit.Evidence = append(commit.Evidence, commit.Evidence[0])
	if validateAdmissionCommit(commit) == nil {
		t.Fatal("duplicate evidence accepted")
	}
}

func TestAdmissionReceiptBindsIdentityLifetimeAndPhase(t *testing.T) {
	req := admissionTestPrepare()
	receipt := AdmissionReceipt{Version: 2, Phase: "prepared", AdmissionID: req.AdmissionID,
		RequestSHA256: strings.Repeat("e", 64), BindingSHA256: admissionBinding(req),
		BootID: "12345678-1234-1234-1234-123456789abc", ExpiresBootNS: 1_800_000_000_000,
		ReservedRegistryBytes: req.SizeBytes + req.EvidenceBudgetBytes, ReservedOutboxBytes: req.SizeBytes + req.EvidenceBudgetBytes + admissionOutboxOverhead,
		EventSequence: 2, CreatedAt: "2026-09-06T00:00:00Z"}
	receipt.SHA256 = admissionReceiptDigest(receipt)
	if err := validateAdmissionReceipt(receipt, "prepared", req); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*AdmissionReceipt){
		"expiry":  func(r *AdmissionReceipt) { r.ExpiresBootNS++ },
		"debit":   func(r *AdmissionReceipt) { r.ReservedOutboxBytes++ },
		"phase":   func(r *AdmissionReceipt) { r.Phase = "committed" },
		"request": func(r *AdmissionReceipt) { r.RequestSHA256 = strings.Repeat("f", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			copy := receipt
			mutate(&copy)
			if validateAdmissionReceipt(copy, "prepared", req) == nil {
				t.Fatal("tampered receipt accepted")
			}
		})
	}
	req.Name = "other"
	if validateAdmissionReceipt(receipt, "prepared", req) == nil {
		t.Fatal("receipt rebound to another model")
	}
}

func TestAdmissionLegacyEventEncodingUnchanged(t *testing.T) {
	digest := strings.Repeat("a", 64)
	raw := []byte(`{"sequence":1,"timestamp":"2026-09-06T00:00:00Z","action":"acquire","name":"demo","to_state":"acquired","sha256":"` + digest + `","artifact":{"name":"demo","format":"safetensors","filename":"demo.safetensors","sha256":"` + digest + `","size_bytes":1,"promoted_at":"","state":"acquired"},"prev_hash":"genesis","hash":""}`)
	var event RegistryAuditEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != string(raw) {
		t.Fatalf("legacy event bytes changed: %s", encoded)
	}
	expected := sha256.Sum256(raw)
	if hashRegistryEvent(event) != hex.EncodeToString(expected[:]) {
		t.Fatal("legacy event hash changed")
	}
	event.Hash = hashRegistryEvent(event)
	for _, version := range []int{1, 2} {
		candidate := Manifest{Version: version, Models: []Artifact{event.Artifact}, Events: []RegistryAuditEvent{event}}
		if err := validateManifest(candidate); err != nil {
			t.Fatalf("legacy replay version%d: %v", version, err)
		}
	}
	invalid := Manifest{Version: 1, Models: []Artifact{{Admission: &AdmissionRecord{Version: 2}}}}
	if validateManifest(invalid) == nil {
		t.Fatal("admission silently stored under manifest v1")
	}
}

func TestAdmissionDisabledCapabilitiesFailClosed(t *testing.T) {
	t.Setenv("REGISTRY_ADMISSION_MODE", "")
	response := httptest.NewRecorder()
	handleAdmissionCapabilities(response, httptest.NewRequest(http.MethodGet, "/v2/admission/capabilities", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled capability status %d", response.Code)
	}
}

func TestAdmissionSharedPythonGoVectors(t *testing.T) {
	req := admissionTestPrepare()
	expected := map[string]string{
		"policy":  "947248c6ec383a8d8da90503ede34f809b2c28dca5759bdb478f4dc813ddc4b3",
		"context": "0c3d9affdfa135aed1db32e9b2491963f91449c0b57c3dbd0f00b6c4cca07d1d",
		"binding": "167058874bb02196ca286fbc7ca86afa590699505ec035be2578450189f76939",
		"request": "582cd85f99e1de71cda0f5f19df60a612a2d5ca2df36f53c2434bd44e6be88f8",
	}
	actual := map[string]string{"policy": req.PolicyBundle.SHA256, "context": req.ContextSHA256,
		"binding": admissionBinding(req), "request": admissionRequestDigest("prepare", []byte(`{"protocol_version":2}`))}
	for key, want := range expected {
		if actual[key] != want {
			t.Fatalf("%s codec differs: %s", key, actual[key])
		}
	}
	receipt := AdmissionReceipt{Version: 2, Phase: "prepared", AdmissionID: req.AdmissionID, RequestSHA256: strings.Repeat("e", 64), BindingSHA256: admissionBinding(req), BootID: "12345678-1234-1234-1234-123456789abc", ExpiresBootNS: 1800000000000, ReservedRegistryBytes: 1052672, ReservedOutboxBytes: 9441280, EventSequence: 2, CreatedAt: "2026-09-06T00:00:00Z"}
	if admissionReceiptDigest(receipt) != "d1e67413fc1ca19f1afbd52ae7dcad8fafe06c7a5134efd3aedb7673ab173361" {
		t.Fatal("receipt codec differs from Python vector")
	}
}

func admissionTestReport(req AdmissionPrepareRequest) AdmissionReport {
	context := AdmissionScanContext{PipelineSHA256: strings.Repeat("f", 64), RequireBehavior: true}
	report := AdmissionReport{Version: 2, AdmissionID: req.AdmissionID, Filename: req.Filename, SHA256: req.SHA256, SizeBytes: req.SizeBytes,
		Source: req.Source, SourceRevision: req.SourceRevision, PolicyBundle: req.PolicyBundle, PipelineSHA256: context.PipelineSHA256,
		Gates: map[string]AdmissionGate{}, Scanners: map[string]AdmissionScannerOutcome{}}
	for _, name := range []string{"source_policy", "format_gate", "hash_pin", "provenance", "polyglot_check", "entropy", "weight_stats", "smoke_test"} {
		gate := AdmissionGate{Verdict: "pass", Reason: "synthetic fixture gate"}
		if name == "weight_stats" {
			gate.Count = 1
		}
		if name == "smoke_test" && req.Format == "safetensors" {
			gate.Verdict = "not_applicable"
		}
		if name == "provenance" {
			gate.Assurance = "recorded"
			if req.Source == "" {
				gate.Assurance = "none"
			}
		}
		report.Gates[name] = gate
	}
	available, version := true, "synthetic-test-version"
	for key, name := range map[string]string{"modelscan": "modelscan", "fickling": "fickling", "modelaudit": "modelaudit", "gguf_guard": "gguf-guard"} {
		outcome := AdmissionScannerOutcome{SchemaVersion: 2, Scanner: name, Reason: "synthetic fixture outcome", Verdict: "not_applicable"}
		if key == "modelaudit" || (key == "gguf_guard" && req.Format == "gguf") {
			outcome.Verdict = "pass"
			outcome.Passed = true
			outcome.Available = &available
			outcome.ScannerVersion = &version
			outcome.ScannedCount = 1
		}
		report.Scanners[key] = outcome
	}
	return report
}

func TestAdmissionReportApplicabilityCannotBeWaived(t *testing.T) {
	request := admissionTestPrepare()
	context := AdmissionScanContext{PipelineSHA256: strings.Repeat("f", 64), RequireBehavior: true}
	if err := validateAdmissionReport(admissionTestReport(request), request, context); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*AdmissionReport){
		"NA_forged_pass": func(r *AdmissionReport) {
			x := r.Scanners["modelscan"]
			x.Passed = true
			x.Verdict = "pass"
			r.Scanners["modelscan"] = x
		},
		"required_NA": func(r *AdmissionReport) {
			x := r.Scanners["modelaudit"]
			x.Passed = false
			x.Verdict = "not_applicable"
			r.Scanners["modelaudit"] = x
		},
		"zero_coverage": func(r *AdmissionReport) {
			x := r.Scanners["modelaudit"]
			x.ScannedCount = 0
			r.Scanners["modelaudit"] = x
		},
		"missing_gate":       func(r *AdmissionReport) { delete(r.Gates, "entropy") },
		"zero_tensors":       func(r *AdmissionReport) { x := r.Gates["weight_stats"]; x.Count = 0; r.Gates["weight_stats"] = x },
		"fake_disabled_pass": func(r *AdmissionReport) { x := r.Gates["smoke_test"]; x.Verdict = "pass"; r.Gates["smoke_test"] = x },
		"false_signed_provenance": func(r *AdmissionReport) {
			x := r.Gates["provenance"]
			x.Assurance = "cosign-verified"
			r.Gates["provenance"] = x
		},
		"pipeline_substitution": func(r *AdmissionReport) { r.PipelineSHA256 = strings.Repeat("a", 64) },
		"artifact_substitution": func(r *AdmissionReport) { r.SHA256 = strings.Repeat("b", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := admissionTestReport(request)
			mutate(&r)
			if validateAdmissionReport(r, request, context) == nil {
				t.Fatal("invalid report admitted")
			}
		})
	}
	request.Format = "gguf"
	request.Filename = "demo.gguf"
	report := admissionTestReport(request)
	if err := validateAdmissionReport(report, request, context); err != nil {
		t.Fatal(err)
	}
	context.RequireBehavior = false
	request.ContextSHA256 = admissionContextDigest(request.PolicyBundle.SHA256, context)
	gate := report.Gates["smoke_test"]
	gate.Verdict = "not_required"
	report.Gates["smoke_test"] = gate
	if err := validateAdmissionReport(report, request, context); err != nil {
		t.Fatal(err)
	}
	context.RequireBehavior = true
	if validateAdmissionReport(report, request, context) == nil {
		t.Fatal("caller waived required behavior")
	}
}
