package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func capacityFixture(t *testing.T, states ...ArtifactState) {
	t.Helper()
	oldManifest, oldDir, oldPath := manifest, registryDir, manifestPath
	oldLimits, oldIO, oldFailed := manifestCapacityLimits, manifestPersistence, manifestPersistenceFailed
	t.Cleanup(func() {
		manifest = oldManifest
		registryDir = oldDir
		manifestPath = oldPath
		manifestCapacityLimits = oldLimits
		manifestPersistence = oldIO
		manifestPersistenceFailed = oldFailed
	})
	registryDir = t.TempDir()
	manifestPath = filepath.Join(registryDir, "manifest.json")
	manifestCapacityLimits = capacityLimits{maxManifestBytes, maxManifestEntries, maxManifestEntries}
	manifestPersistenceFailed = false
	manifest = Manifest{Version: 1, Models: []Artifact{}}
	for index, state := range states {
		name := fmt.Sprintf("model-%d", index)
		artifact := Artifact{Name: name, Filename: name + ".gguf", Format: "gguf", SHA256: strings.Repeat("a", 64), State: state}
		if state == StateTrusted {
			artifact.ObjectPath = "objects/sha256/aa/" + artifact.SHA256 + ".gguf"
			rel, err := contentAddressedObjectRel(artifact.SHA256, artifact.Format)
			if err != nil {
				t.Fatal(err)
			}
			artifact.ObjectPath = rel
		}
		manifest.Models = append(manifest.Models, artifact)
	}
	ensureRegistryEventBaseline()
	if err := saveManifest(); err != nil {
		t.Fatal(err)
	}
}
func capacityOf(t *testing.T) RegistryCapacity {
	t.Helper()
	c, err := registryCapacity(manifest, manifestCapacityLimits)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func safetyRequest(t *testing.T, name, action string) *httptest.ResponseRecorder {
	t.Helper()
	method := http.MethodPost
	handler := handleRevoke
	if action == "delete" {
		method = http.MethodDelete
		handler = handleDelete
	}
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(method, "/v1/model/"+action+"?name="+url.QueryEscape(name), nil))
	return w
}
func acquireCapacity(t *testing.T, name string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(AcquireRequest{Name: name, Filename: name + ".gguf", SHA256: strings.Repeat("b", 64)})
	w := httptest.NewRecorder()
	handleAcquire(w, httptest.NewRequest("POST", "/v1/model/acquire", bytes.NewReader(body)))
	return w
}
func verifySafetyDrain(t *testing.T) {
	t.Helper()
	names := make([]string, 0, len(manifest.Models))
	for _, model := range manifest.Models {
		names = append(names, model.Name)
	}
	for _, name := range names {
		for _, action := range []string{"revoke", "revoke", "delete", "delete"} {
			before := len(manifest.Events)
			state := manifest.Models[indexModel(name)].State
			w := safetyRequest(t, name, action)
			if state == StateDeleted && action == "revoke" {
				if w.Code != 409 {
					t.Fatal(w.Code)
				}
				continue
			}
			if w.Code != 200 {
				t.Fatalf("%s %s: %d %s", action, name, w.Code, w.Body.String())
			}
			if (state == StateRevoked && action == "revoke") || (state == StateDeleted && action == "delete") {
				if len(manifest.Events) != before {
					t.Fatal("idempotent request grew history")
				}
			}
			if !capacityOf(t).SafetyReserveSufficient {
				t.Fatal("safety operation consumed another model's reserve")
			}
		}
	}
	savedHead := manifest.Events[len(manifest.Events)-1].Hash
	if err := loadManifest(); err != nil {
		t.Fatal(err)
	}
	for _, model := range manifest.Models {
		if model.State != StateDeleted {
			t.Fatal("restart lost safety state")
		}
	}
	if manifest.Events[len(manifest.Events)-1].Hash != savedHead {
		t.Fatal("restart changed history")
	}
}
func indexModel(name string) int {
	for i, m := range manifest.Models {
		if m.Name == name {
			return i
		}
	}
	panic("missing fixture")
}

func TestCapacityReservesEveryRemainingSafetyTransition(t *testing.T) {
	for _, boundary := range []string{"bytes", "events"} {
		t.Run(boundary, func(t *testing.T) {
			capacityFixture(t, StateTrusted, StateAcquired, StateQuarantined, StateRevoked, StateDeleted)
			before := capacityOf(t)
			if before.SafetyReserveEvents != 7 {
				t.Fatal(before)
			}
			if boundary == "bytes" {
				manifestCapacityLimits.Bytes = before.ManifestBytes + before.SafetyReserveBytes
			} else {
				manifestCapacityLimits.Events = before.EventCount + before.SafetyReserveEvents
			}
			disk, _ := os.ReadFile(manifestPath)
			w := acquireCapacity(t, "blocked")
			if w.Code != 507 {
				t.Fatal(w.Code, w.Body.String())
			}
			after, _ := os.ReadFile(manifestPath)
			if !bytes.Equal(disk, after) {
				t.Fatal("rejected admission changed persisted history")
			}
			verifySafetyDrain(t)
		})
	}
}
func TestCapacityGatesQuarantineAndPromotion(t *testing.T) {
	capacityFixture(t, StateAcquired)
	c := capacityOf(t)
	manifestCapacityLimits.Events = c.EventCount + c.SafetyReserveEvents
	w := httptest.NewRecorder()
	handleQuarantine(w, httptest.NewRequest("POST", "/v1/model/quarantine?name=model-0", nil))
	if w.Code != 507 || manifest.Models[0].State != StateAcquired {
		t.Fatal(w.Code, w.Body.String())
	}
	// A direct ordinary lifecycle save cannot bypass the same reservation.
	before, _ := cloneManifest(manifest)
	manifest.Models[0].State = StateTrusted
	rel, _ := contentAddressedObjectRel(manifest.Models[0].SHA256, "gguf")
	manifest.Models[0].ObjectPath = rel
	appendRegistryEvent("promote", manifest.Models[0], StateAcquired)
	if err := saveAdmissionManifest(); !errors.Is(err, errSafetyCapacity) {
		t.Fatal(err)
	}
	manifest = before
	verifySafetyDrain(t)
}
func TestCapacityCountsWorstEscapingBootstrapAndSequenceWidths(t *testing.T) {
	capacityFixture(t, StateTrusted, StateAcquired, StateQuarantined, StateRevoked)
	// Populate maximum-size allowed metadata, including JSON-expanding characters.
	for i := range manifest.Models {
		a := &manifest.Models[i]
		a.Name = "model" + strings.Repeat("\"", 250) + fmt.Sprint(i)
		a.Source = strings.Repeat("\x01", 4096)
		a.PolicyVersion = strings.Repeat("<", 256)
		a.SourceRevision = strings.Repeat("&", 256)
		a.PromotedAt = "2000-01-01T00:00:00Z"
		a.ScanResults = map[string]string{}
		a.ScannerVersions = map[string]string{}
		for j := 0; j < 64; j++ {
			key := fmt.Sprintf("%03d", j) + strings.Repeat("<", 253)
			a.ScanResults[key] = strings.Repeat("\"", 1024)
			a.ScannerVersions[key] = strings.Repeat("&", 1024)
		}
		a.GGUFGuardFingerprint = map[string]any{"nested": []any{strings.Repeat("<", 4096), map[string]any{"value": strings.Repeat("\t", 4096)}}}
	}
	manifest.Events = nil
	if err := validateManifest(manifest); err != nil {
		t.Fatal(err)
	}
	projected := capacityOf(t)
	if projected.SafetyReserveEvents != 11 {
		t.Fatal(projected.SafetyReserveEvents)
	}
	// Baseline and safety events with widest allowed timestamp and sequence fields
	// are conservatively covered, including the originally omitted events property.
	ensureRegistryEventBaseline()
	for i := range manifest.Models {
		if manifest.Models[i].State != StateRevoked {
			from := manifest.Models[i].State
			manifest.Models[i].State = StateRevoked
			appendRegistryEvent("revoke", manifest.Models[i], from)
		}
		manifest.Models[i].State = StateDeleted
		appendRegistryEvent("delete", manifest.Models[i], StateRevoked)
	}
	for i := range manifest.Events {
		manifest.Events[i].Timestamp = "2000-01-01T00:00:00.123456789Z"
		manifest.Events[i].Sequence = maxManifestEntries
		manifest.Events[i].PrevHash = reservationHash
		manifest.Events[i].Hash = reservationHash
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > projected.ManifestBytes+projected.SafetyReserveBytes {
		t.Fatalf("reserved=%d actual=%d", projected.ManifestBytes+projected.SafetyReserveBytes, len(encoded))
	}
}
func TestLegacyWithoutReserveIsReportedAndNotSilentlyRepaired(t *testing.T) {
	capacityFixture(t, StateTrusted, StateTrusted)
	c := capacityOf(t)
	manifestCapacityLimits.Bytes = c.ManifestBytes + 1
	w := httptest.NewRecorder()
	handleCapacity(w, httptest.NewRequest("GET", "/v1/capacity", nil))
	var status RegistryCapacity
	json.Unmarshal(w.Body.Bytes(), &status)
	if status.SafetyReserveSufficient || !status.MaintenanceRequired {
		t.Fatal(status)
	}
	if err := loadManifest(); err != nil {
		t.Fatal("valid legacy history must remain readable", err)
	}
	if acquireCapacity(t, "blocked").Code != 507 {
		t.Fatal("legacy reserve gap allowed admission")
	}
	if safetyRequest(t, "model-0", "revoke").Code != 507 {
		t.Fatal("unavailable legacy capacity was concealed")
	}
	if manifest.Models[0].State != StateTrusted {
		t.Fatal("failed safety request reported a changed trust state")
	}
}
func TestCapacityModelLimitAndAuthenticatedStatus(t *testing.T) {
	capacityFixture(t, StateTrusted)
	manifestCapacityLimits.Models = 1
	if acquireCapacity(t, "blocked").Code != 507 {
		t.Fatal("model limit ignored")
	}
	oldToken, oldDev := serviceToken, insecureDevMode
	defer func() { serviceToken = oldToken; insecureDevMode = oldDev }()
	serviceToken = "synthetic"
	insecureDevMode = false
	w := httptest.NewRecorder()
	newRegistryMux().ServeHTTP(w, httptest.NewRequest("GET", "/v1/capacity", nil))
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	verifySafetyDrain(t)
}

func TestSafetyPersistenceFaultsDoNotReportSuccessOrRestoreEligibility(t *testing.T) {
	for _, action := range []string{"revoke", "delete"} {
		for _, fault := range []string{"enospc", "shortwrite", "filesync", "rename", "dirsync"} {
			t.Run(action+"/"+fault, func(t *testing.T) {
				capacityFixture(t, StateTrusted)
				original := manifestPersistence
				switch fault {
				case "enospc":
					manifestPersistence.write = func(*os.File, []byte) (int, error) { return 0, syscall.ENOSPC }
				case "shortwrite":
					manifestPersistence.write = func(f *os.File, b []byte) (int, error) { return f.Write(b[:len(b)/2]) }
				case "filesync":
					manifestPersistence.syncFile = func(*os.File) error { return syscall.EIO }
				case "rename":
					manifestPersistence.rename = func(string, string) error { return syscall.EIO }
				case "dirsync":
					manifestPersistence.syncDirectory = func(string) error { return syscall.EIO }
				}
				before, _ := os.ReadFile(manifestPath)
				w := safetyRequest(t, "model-0", action)
				if w.Code != 500 {
					t.Fatal(w.Code, w.Body.String())
				}
				if fault == "dirsync" {
					if !manifestPersistenceFailed || manifest.Models[0].State == StateTrusted {
						t.Fatal("ambiguous publication restored old eligibility")
					}
					if _, ok := registryArtifactByName("model-0"); ok {
						t.Fatal("runtime returned an artifact during ambiguous persistence")
					}
					h := httptest.NewRecorder()
					handleHealth(h, httptest.NewRequest("GET", "/health", nil))
					if h.Code != 503 {
						t.Fatal(h.Code)
					}
					if safetyRequest(t, "model-0", action).Code != 503 || acquireCapacity(t, "blocked").Code != 503 {
						t.Fatal("mutation cleared failure latch")
					}
				} else {
					after, _ := os.ReadFile(manifestPath)
					if !bytes.Equal(before, after) || manifest.Models[0].State != StateTrusted {
						t.Fatal("prepublication failure modified live/durable state")
					}
				}
				manifestPersistence = original
				manifestPersistenceFailed = false // Simulate a fresh process, not an online reload.
				if err := loadManifest(); err != nil {
					t.Fatal(err)
				}
				if fault == "dirsync" && manifest.Models[0].State == StateTrusted {
					t.Fatal("restart lost published deny state")
				}
				if fault != "dirsync" && safetyRequest(t, "model-0", action).Code != 200 {
					t.Fatal("safe retry failed")
				}
			})
		}
	}
}

func TestCapacityAtRealManifestByteBoundaryPreservesCheckpointHistory(t *testing.T) {
	capacityFixture(t, StateTrusted, StateTrusted)
	for i := range manifest.Models {
		manifest.Models[i].Source = strings.Repeat("x", 4096)
	}
	manifest.Events = nil
	ensureRegistryEventBaseline()
	reserve := capacityOf(t)
	used := reserve.ManifestBytes
	for {
		prior := len(manifest.Events)
		appendRegistryEvent("promote", manifest.Models[0], StateTrusted)
		encoded, err := json.MarshalIndent(manifest.Events[len(manifest.Events)-1], "    ", "  ")
		if err != nil {
			t.Fatal(err)
		}
		growth := len(encoded) + 6
		if used+growth+reserve.SafetyReserveBytes > maxManifestBytes {
			manifest.Events = manifest.Events[:prior]
			break
		}
		used += growth
	}
	c := capacityOf(t)
	if c.ManifestBytes != used || c.ManifestBytes < maxManifestBytes-65536 || !c.SafetyReserveSufficient {
		t.Fatal(c)
	}
	if err := saveAdmissionManifest(); err != nil {
		t.Fatal(err)
	}
	before, _ := cloneManifest(manifest)
	appendRegistryEvent("promote", manifest.Models[0], StateTrusted)
	if err := saveAdmissionManifest(); !errors.Is(err, errSafetyCapacity) {
		t.Fatal("admission consumed safety reservation", err)
	}
	manifest = before
	originalHead := manifest.Events[len(manifest.Events)-1].Hash
	verifySafetyDrain(t)
	for _, event := range manifest.Events {
		if event.Hash == originalHead {
			goto retained
		}
	}
	t.Fatal("safety drain discarded historical head")
retained:
	if fixture := os.Getenv("REGISTRY_CAPACITY_FIXTURE"); fixture != "" {
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("real byte boundary: before=%d reserve=%d events=%d final_bytes=%d final_events=%d", c.ManifestBytes, c.SafetyReserveBytes, c.EventCount, capacityOf(t).ManifestBytes, len(manifest.Events))
}

func TestPromotionHTTPHonorsSafetyReservation(t *testing.T) {
	capacityFixture(t, StateQuarantined)
	oldDev := insecureDevMode
	insecureDevMode = true
	defer func() { insecureDevMode = oldDev }()
	data := []byte("synthetic-model")
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	if err := os.WriteFile(filepath.Join(registryDir, "model-0.gguf"), data, 0600); err != nil {
		t.Fatal(err)
	}
	manifest.Models[0].SHA256 = digest
	manifest.Models[0].SizeBytes = int64(len(data))
	manifest.Events = nil
	ensureRegistryEventBaseline()
	if err := saveManifest(); err != nil {
		t.Fatal(err)
	}
	c := capacityOf(t)
	manifestCapacityLimits.Events = c.EventCount + c.SafetyReserveEvents
	body, _ := json.Marshal(PromoteRequest{Name: "model-0", Filename: "model-0.gguf", SHA256: digest, SizeBytes: int64(len(data))})
	w := httptest.NewRecorder()
	handlePromote(w, httptest.NewRequest("POST", "/v1/model/promote", bytes.NewReader(body)))
	if w.Code != 507 || manifest.Models[0].State != StateQuarantined {
		t.Fatal(w.Code, w.Body.String())
	}
	verifySafetyDrain(t)
}
func TestSafetyReserveCoversDirectDeletesInAnyOrder(t *testing.T) {
	capacityFixture(t, StateQuarantined, StateTrusted, StateAcquired, StateRevoked)
	c := capacityOf(t)
	manifestCapacityLimits.Bytes = c.ManifestBytes + c.SafetyReserveBytes
	manifestCapacityLimits.Events = c.EventCount + c.SafetyReserveEvents
	for _, i := range []int{3, 0, 2, 1} {
		w := safetyRequest(t, fmt.Sprintf("model-%d", i), "delete")
		if w.Code != 200 || !capacityOf(t).SafetyReserveSufficient {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if err := loadManifest(); err != nil {
		t.Fatal(err)
	}
	for _, model := range manifest.Models {
		if model.State != StateDeleted {
			t.Fatal("direct delete state lost")
		}
	}
}

func TestManifestLoadDoesNotInheritOmittedHistoryOrPublishRejectedState(t *testing.T) {
	capacityFixture(t, StateTrusted)
	before, _ := json.Marshal(manifest)
	incomplete := Manifest{Version: 1, Models: []Artifact{{Name: "new", Filename: "new.gguf", Format: "gguf", SHA256: strings.Repeat("b", 64), State: StateAcquired}}}
	encoded, _ := json.Marshal(incomplete)
	if err := os.WriteFile(manifestPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ALLOW_LEGACY_MANIFEST_MIGRATION", "")
	if err := loadManifest(); err == nil || !strings.Contains(err.Error(), "no replayable audit history") {
		t.Fatal("omitted history inherited stale events", err)
	}
	after, _ := json.Marshal(manifest)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected load published partial candidate")
	}
}
