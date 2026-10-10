package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

func admissionOperational() bool {
	return admissionEnabled() && configuredAdmission != nil && !insecureDevMode && admissionStoreCurrent()
}

func admissionArtifactBytes(artifact Artifact) ([]byte, error) {
	data, err := json.Marshal(artifact)
	if err != nil || len(data) > admissionRecordLimit {
		return nil, errors.New("admission response record unavailable")
	}
	return data, nil
}

func sendAdmissionArtifact(w http.ResponseWriter, status int, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func admissionByIDLocked(id string) (int, bool) {
	for index, artifact := range manifest.Models {
		if artifact.Admission != nil && artifact.Admission.Prepare.AdmissionID == id {
			return index, true
		}
	}
	return -1, false
}

func prepareReplayLocked(req AdmissionPrepareRequest, requestSHA string) ([]byte, bool, error) {
	if index, found := admissionByIDLocked(req.AdmissionID); found {
		existing := manifest.Models[index]
		if existing.Admission.PrepareReceipt.RequestSHA256 != requestSHA || !reflect.DeepEqual(existing.Admission.Prepare, req) {
			return nil, true, errors.New("admission ID already binds different request bytes")
		}
		data, err := admissionArtifactBytes(existing)
		return data, true, err
	}
	for _, artifact := range manifest.Models {
		if artifact.Name == req.Name || (artifact.Filename == req.Filename && artifact.State != StateDeleted) {
			return nil, true, errors.New("artifact name or active filename already registered")
		}
	}
	return nil, false, nil
}

func policyAllowsAdmission(policy admissionPolicy, config AdmissionConfig, req AdmissionPrepareRequest) error {
	context := AdmissionScanContext{PipelineSHA256: config.PipelineSHA256, RequireBehavior: policy.RequireBehavior}
	if !reflect.DeepEqual(req.PolicyBundle, policy.Bundle) || req.ContextSHA256 != admissionContextDigest(policy.Bundle.SHA256, context) {
		return errors.New("trusted policy or scan context changed")
	}
	if req.SizeBytes > config.MaxArtifactBytes || policy.Pins[req.Filename] != req.SHA256 || !policy.AllowedFormats[req.Format] {
		return errors.New("artifact is not a configured exact pin/format/size")
	}
	if req.Source == "" {
		if !policy.AllowLocal {
			return errors.New("pinned local imports are disabled by policy")
		}
		return nil
	}
	source, _ := url.Parse(req.Source)
	for _, prefix := range policy.SourcePrefixes {
		parsed, err := url.Parse(prefix)
		if err != nil || parsed.Scheme != "https" || parsed.Host != "huggingface.co" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(prefix, "%") {
			continue
		}
		path := strings.TrimSuffix(parsed.Path, "/")
		if source.Path == path || strings.HasPrefix(source.Path, path+"/") {
			return nil
		}
	}
	return errors.New("source is not allowed by the configured policy")
}

func newPreparationReceipt(req AdmissionPrepareRequest, requestSHA string, clock admissionTime, sequence int64) AdmissionReceipt {
	receipt := AdmissionReceipt{Version: 2, Phase: "prepared", AdmissionID: req.AdmissionID, RequestSHA256: requestSHA,
		BindingSHA256: admissionBinding(req), BootID: clock.BootID, ExpiresBootNS: clock.NS + int64(admissionLifetime),
		ReservedRegistryBytes: req.SizeBytes + req.EvidenceBudgetBytes, ReservedOutboxBytes: req.SizeBytes + req.EvidenceBudgetBytes + admissionOutboxOverhead,
		EventSequence: sequence, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	receipt.SHA256 = admissionReceiptDigest(receipt)
	return receipt
}

func handleAdmissionPrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !admissionOperational() {
		http.Error(w, "helper admission unavailable", http.StatusServiceUnavailable)
		return
	}
	var req AdmissionPrepareRequest
	raw, err := readAdmissionBody(w, r, &req)
	if err != nil || validateAdmissionPrepare(req) != nil || r.Header.Get("Idempotency-Key") != req.AdmissionID {
		http.Error(w, "invalid admission request/header", http.StatusBadRequest)
		return
	}
	requestSHA := admissionRequestDigest("prepare", raw)
	manifestMu.RLock()
	failed := manifestPersistenceFailed
	replay, handled, replayErr := prepareReplayLocked(req, requestSHA)
	manifestMu.RUnlock()
	if failed {
		http.Error(w, "manifest durability unavailable", http.StatusServiceUnavailable)
		return
	}
	if handled {
		if replayErr != nil {
			http.Error(w, replayErr.Error(), http.StatusConflict)
			return
		}
		sendAdmissionArtifact(w, http.StatusOK, replay)
		return
	}
	policy, err := loadAdmissionPolicy(*configuredAdmission)
	if err != nil {
		http.Error(w, "trusted policy unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := policyAllowsAdmission(policy, *configuredAdmission, req); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	clock, err := admissionNow()
	if err != nil {
		http.Error(w, "admission clock unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.Context().Err(); err != nil {
		http.Error(w, "request cancelled", http.StatusRequestTimeout)
		return
	}

	manifestMu.Lock()
	if manifestPersistenceFailed || !admissionStoreCurrent() {
		manifestMu.Unlock()
		http.Error(w, "manifest durability unavailable", http.StatusServiceUnavailable)
		return
	}
	replay, handled, replayErr = prepareReplayLocked(req, requestSHA)
	if handled {
		manifestMu.Unlock()
		if replayErr != nil {
			http.Error(w, replayErr.Error(), http.StatusConflict)
			return
		}
		sendAdmissionArtifact(w, http.StatusOK, replay)
		return
	}
	before, err := cloneManifest(manifest)
	if err != nil {
		manifestMu.Unlock()
		http.Error(w, "manifest snapshot unavailable", http.StatusServiceUnavailable)
		return
	}
	// No source/object/journal bytes are created by prepare. Candidate metadata
	// and every future safety transition are admitted before any copy can start.
	ensureRegistryEventBaseline()
	manifest.Version = 2
	receipt := newPreparationReceipt(req, requestSHA, clock, int64(len(manifest.Events)+2))
	artifact := Artifact{Name: req.Name, Filename: req.Filename, Format: req.Format, SHA256: req.SHA256, SizeBytes: req.SizeBytes,
		Source: req.Source, SourceRevision: req.SourceRevision, PolicyVersion: req.PolicyBundle.SHA256,
		PromotedAt: receipt.CreatedAt, State: StateAcquired,
		Admission: &AdmissionRecord{Version: 2, Context: AdmissionScanContext{PipelineSHA256: configuredAdmission.PipelineSHA256, RequireBehavior: policy.RequireBehavior}, Prepare: req, PrepareReceipt: receipt}}
	appendRegistryEvent("acquire", artifact, "")
	artifact.State = StateQuarantined
	appendRegistryEvent("quarantine", artifact, StateAcquired)
	manifest.Models = append(manifest.Models, artifact)
	plan, err := plannedAdmissionReservations(manifest)
	if err == nil {
		var space admissionFreeSpace
		space, err = admissionSpace(*configuredAdmission)
		if err == nil {
			err = checkAdmissionStoragePlan(plan, space, *configuredAdmission)
		}
	}
	if err == nil {
		err = r.Context().Err()
	}
	if err == nil {
		err = saveAdmissionManifestGuarded(func() error {
			if err := r.Context().Err(); err != nil {
				return err
			}
			if !admissionStoreCurrent() {
				return errors.New("registry directory changed")
			}
			now, err := admissionNow()
			if err != nil {
				return err
			}
			return validAdmissionLifetime(receipt, now)
		})
	}
	if err != nil {
		if !manifestPersistenceFailed {
			manifest = before
		}
		manifestMu.Unlock()
		manifestWriteError(w, err)
		return
	}
	data, err := admissionArtifactBytes(artifact)
	manifestMu.Unlock()
	if err != nil {
		http.Error(w, "durable receipt response unavailable; reconcile by lookup", http.StatusServiceUnavailable)
		return
	}
	sendAdmissionArtifact(w, http.StatusCreated, data)
}
