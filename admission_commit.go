package main

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"time"
)

var admissionCommitSlots = make(chan struct{}, 2)
var admissionWorkMu sync.Mutex
var admissionWorking = map[string]bool{}

func beginAdmissionWork(id string) bool {
	select {
	case admissionCommitSlots <- struct{}{}:
	default:
		return false
	}
	admissionWorkMu.Lock()
	defer admissionWorkMu.Unlock()
	if admissionWorking[id] {
		<-admissionCommitSlots
		return false
	}
	admissionWorking[id] = true
	return true
}
func endAdmissionWork(id string) {
	admissionWorkMu.Lock()
	delete(admissionWorking, id)
	admissionWorkMu.Unlock()
	<-admissionCommitSlots
}

func commitReplayLocked(req AdmissionCommitRequest, requestSHA string) (Artifact, []byte, bool, error) {
	index, found := admissionByIDLocked(req.AdmissionID)
	if !found {
		return Artifact{}, nil, true, errors.New("prepared admission not found")
	}
	artifact := manifest.Models[index]
	record := artifact.Admission
	if req.PrepareReceiptSHA256 != record.PrepareReceipt.SHA256 {
		return artifact, nil, true, errors.New("preparation receipt differs")
	}
	if record.Commit != nil {
		if record.CommitReceipt.RequestSHA256 != requestSHA || !reflect.DeepEqual(*record.Commit, req) {
			return artifact, nil, true, errors.New("admission ID already binds different commit bytes")
		}
		data, err := admissionArtifactBytes(artifact)
		return artifact, data, true, err
	}
	if artifact.State != StateQuarantined {
		return artifact, nil, true, errors.New("current deny state prevents commit")
	}
	return artifact, nil, false, nil
}

func handleAdmissionCommit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !admissionOperational() {
		http.Error(w, "helper admission unavailable", http.StatusServiceUnavailable)
		return
	}
	var req AdmissionCommitRequest
	raw, err := readAdmissionBody(w, r, &req)
	if err != nil || validateAdmissionCommit(req) != nil || r.Header.Get("Idempotency-Key") != req.AdmissionID {
		http.Error(w, "invalid commit request/header", http.StatusBadRequest)
		return
	}
	requestSHA := admissionRequestDigest("commit", raw)
	manifestMu.RLock()
	failed := manifestPersistenceFailed
	artifact, replay, handled, replayErr := commitReplayLocked(req, requestSHA)
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
	if !beginAdmissionWork(req.AdmissionID) {
		http.Error(w, "admission work capacity occupied", http.StatusTooManyRequests)
		return
	}
	defer endAdmissionWork(req.AdmissionID)
	select {
	case hashVerifySlots <- struct{}{}:
		defer func() { <-hashVerifySlots }()
	default:
		http.Error(w, "verification capacity occupied", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), admissionWorkLimit)
	defer cancel()
	started, err := admissionNow()
	if err != nil {
		http.Error(w, "admission clock unavailable", http.StatusServiceUnavailable)
		return
	}
	workEnd := started.NS + int64(admissionWorkLimit)
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		now, err := admissionNow()
		if err != nil {
			return err
		}
		if now.BootID != started.BootID || now.NS >= workEnd {
			return errors.New("suspend-inclusive commit work deadline reached")
		}
		if err := validAdmissionLifetime(artifact.Admission.PrepareReceipt, now); err != nil {
			return err
		}
		if !admissionStoreCurrent() {
			return errors.New("registry directory identity changed")
		}
		return nil
	}
	if err := check(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	policy, err := loadAdmissionPolicy(*configuredAdmission)
	if err != nil || policyAllowsAdmission(policy, *configuredAdmission, artifact.Admission.Prepare) != nil {
		http.Error(w, "trusted admission context changed", http.StatusConflict)
		return
	}
	manifestMu.RLock()
	plan, err := plannedAdmissionReservations(manifest)
	manifestMu.RUnlock()
	if err == nil {
		var space admissionFreeSpace
		space, err = admissionSpace(*configuredAdmission)
		if err == nil {
			err = checkAdmissionStoragePlan(plan, space, *configuredAdmission)
		}
	}
	if err != nil {
		manifestWriteError(w, err)
		return
	}
	report, guardPath, err := admissionCopyBundle(artifact, req, requestSHA, check)
	if err != nil {
		http.Error(w, "copy/evidence held without trust: "+err.Error(), http.StatusConflict)
		return
	}

	manifestMu.Lock()
	if manifestPersistenceFailed {
		manifestMu.Unlock()
		http.Error(w, "manifest durability unavailable", http.StatusServiceUnavailable)
		return
	}
	current, replay, handled, replayErr := commitReplayLocked(req, requestSHA)
	if handled {
		manifestMu.Unlock()
		if replayErr != nil {
			http.Error(w, replayErr.Error(), http.StatusConflict)
			return
		}
		sendAdmissionArtifact(w, http.StatusOK, replay)
		return
	}
	if !reflect.DeepEqual(current, artifact) {
		manifestMu.Unlock()
		http.Error(w, "prepared state changed during work", http.StatusConflict)
		return
	}
	publicationGuard := func() error {
		if err := check(); err != nil {
			return err
		}
		currentPolicy, err := loadAdmissionPolicy(*configuredAdmission)
		if err != nil {
			return err
		}
		if err := policyAllowsAdmission(currentPolicy, *configuredAdmission, artifact.Admission.Prepare); err != nil {
			return err
		}
		return check()
	}
	if err := publicationGuard(); err != nil {
		manifestMu.Unlock()
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	before, err := cloneManifest(manifest)
	if err != nil {
		manifestMu.Unlock()
		http.Error(w, "manifest snapshot unavailable", http.StatusServiceUnavailable)
		return
	}
	next := *artifact.Admission
	receipt := next.PrepareReceipt
	receipt.Phase = "committed"
	receipt.RequestSHA256 = requestSHA
	receipt.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	receipt.EventSequence = int64(len(manifest.Events) + 1)
	receipt.SHA256 = admissionReceiptDigest(receipt)
	next.Commit = &req
	next.CommitReceipt = &receipt
	next.Report = &report
	artifact.Admission = &next
	artifact.State = StateTrusted
	artifact.PromotedAt = receipt.CreatedAt
	artifact.ObjectPath, _ = contentAddressedObjectRel(artifact.SHA256, artifact.Format)
	artifact.GGUFGuardManifest = guardPath
	index, _ := admissionByIDLocked(req.AdmissionID)
	manifest.Models[index] = artifact
	appendRegistryEvent("promote", artifact, StateQuarantined)
	if err := saveAdmissionManifestGuarded(publicationGuard); err != nil {
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
