package main

import (
	"errors"
	"reflect"
)

func validateAdmissionHistory(candidate Manifest) error {
	seen := false
	for _, event := range candidate.Events {
		record := event.Artifact.Admission
		if record == nil {
			if seen && (event.Action == "acquire" || event.Action == "quarantine" || event.Action == "promote") {
				return errors.New("legacy admission cannot follow helper-v2 activation")
			}
			continue
		}
		seen = true
		if event.Action == "bootstrap" {
			return errors.New("v2 admission cannot be fabricated by a bootstrap event")
		}
		sequence := record.PrepareReceipt.EventSequence
		if sequence <= 0 || sequence > int64(len(candidate.Events)) {
			return errors.New("preparation receipt lacks its committed quarantine event")
		}
		prepared := candidate.Events[sequence-1]
		if prepared.Action != "quarantine" || prepared.Artifact.Admission == nil ||
			!reflect.DeepEqual(prepared.Artifact.Admission.Prepare, record.Prepare) ||
			!reflect.DeepEqual(prepared.Artifact.Admission.Context, record.Context) ||
			prepared.Artifact.Admission.PrepareReceipt != record.PrepareReceipt {
			return errors.New("preparation receipt/history identity mismatch")
		}
		if event.Action == "acquire" && sequence != event.Sequence+1 {
			return errors.New("acquire/quarantine must be one prepared transaction")
		}
		if event.Action == "quarantine" && sequence != event.Sequence {
			return errors.New("quarantine receipt sequence mismatch")
		}
		if record.Commit != nil {
			committedSequence := record.CommitReceipt.EventSequence
			if committedSequence <= 0 || committedSequence > event.Sequence || committedSequence > int64(len(candidate.Events)) {
				return errors.New("commit receipt references impossible history")
			}
			committed := candidate.Events[committedSequence-1]
			if committed.Action != "promote" || committed.Artifact.Admission == nil ||
				!reflect.DeepEqual(committed.Artifact.Admission.Commit, record.Commit) ||
				!reflect.DeepEqual(committed.Artifact.Admission.Report, record.Report) ||
				*committed.Artifact.Admission.CommitReceipt != *record.CommitReceipt {
				return errors.New("commit receipt/history mismatch")
			}
		}
		if event.Action == "promote" && (record.Commit == nil || record.CommitReceipt.EventSequence != event.Sequence || event.FromState != StateQuarantined) {
			return errors.New("v2 promotion must consume the exact prepared state")
		}
	}
	return nil
}

func admissionPromotionPreservesPreparation(previous, next Artifact) bool {
	if next.Admission == nil {
		return previous.Admission == nil
	}
	return previous.Admission != nil && previous.Admission.Commit == nil && previous.State == StateQuarantined &&
		reflect.DeepEqual(previous.Admission.Prepare, next.Admission.Prepare) &&
		reflect.DeepEqual(previous.Admission.Context, next.Admission.Context) &&
		previous.Admission.PrepareReceipt == next.Admission.PrepareReceipt
}
