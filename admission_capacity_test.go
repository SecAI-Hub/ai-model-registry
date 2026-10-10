package main

import (
	"strings"
	"testing"
)

func admissionPreparedArtifact() Artifact {
	request := admissionTestPrepare()
	context := AdmissionScanContext{PipelineSHA256: strings.Repeat("f", 64), RequireBehavior: true}
	receipt := AdmissionReceipt{Version: 2, Phase: "prepared", AdmissionID: request.AdmissionID, RequestSHA256: strings.Repeat("e", 64), BindingSHA256: admissionBinding(request), BootID: "12345678-1234-1234-1234-123456789abc", ExpiresBootNS: 1800000000000, ReservedRegistryBytes: request.SizeBytes + request.EvidenceBudgetBytes, ReservedOutboxBytes: request.SizeBytes + request.EvidenceBudgetBytes + admissionOutboxOverhead, EventSequence: 2, CreatedAt: "2026-09-06T00:00:00Z"}
	receipt.SHA256 = admissionReceiptDigest(receipt)
	return Artifact{Name: request.Name, Format: request.Format, Filename: request.Filename, SHA256: request.SHA256, SizeBytes: request.SizeBytes, Source: request.Source, SourceRevision: request.SourceRevision, PolicyVersion: request.PolicyBundle.SHA256, State: StateQuarantined, Admission: &AdmissionRecord{Version: 2, Context: context, Prepare: request, PrepareReceipt: receipt}}
}

func TestAdmissionCapacityPlansFutureTrustAndRetainsDenyDebits(t *testing.T) {
	artifact := admissionPreparedArtifact()
	plan, err := plannedAdmissionReservations(Manifest{Version: 2, Models: []Artifact{artifact}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Prepared != 1 || plan.FutureEvents != 1 || plan.FutureManifestBytes < 3*admissionRecordLimit || plan.OutboxBytes != plan.RegistryBytes+admissionOutboxOverhead {
		t.Fatalf("bad future reservation: %+v", plan)
	}
	for _, state := range []ArtifactState{StateRevoked, StateDeleted} {
		artifact.State = state
		denied, err := plannedAdmissionReservations(Manifest{Version: 2, Models: []Artifact{artifact}})
		if err != nil {
			t.Fatal(err)
		}
		if denied.Prepared != 0 || denied.FutureEvents != 0 || denied.RegistryBytes != plan.RegistryBytes || denied.OutboxBytes != plan.OutboxBytes {
			t.Fatalf("deny state released retained bytes: %+v", denied)
		}
	}
}

func TestAdmissionCapacityRefusesMalformedReservation(t *testing.T) {
	artifact := admissionPreparedArtifact()
	artifact.Admission.PrepareReceipt.ReservedOutboxBytes = -1
	if _, err := plannedAdmissionReservations(Manifest{Version: 2, Models: []Artifact{artifact}}); err == nil {
		t.Fatal("negative debit admitted")
	}
}
