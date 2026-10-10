package main

import (
	"encoding/json"
	"errors"
)

// Additional reservations are pure planning data. Wiring them into admission
// persistence/free-space checks is a separate transaction implementation step.
type admissionReservation struct {
	Prepared            int
	RegistryBytes       int64
	OutboxBytes         int64
	FutureManifestBytes int
	FutureEvents        int
}

// A pretty-encoded Artifact is bounded to64KiB. Nesting it one level deeper
// adds at most two spaces per existing byte/newline; event envelope is bounded
// separately. This intentionally overestimates rather than depending on future
// scanner string contents. Existing safety events are reserved by registryCapacity.
const admissionFutureEventBytes = 3*admissionRecordLimit + 2048

func plannedAdmissionReservations(candidate Manifest) (admissionReservation, error) {
	result := admissionReservation{}
	for _, artifact := range candidate.Models {
		record := artifact.Admission
		if record == nil {
			continue
		}
		if err := validateAdmissionMetadata(artifact); err != nil {
			return result, err
		}
		pretty, err := json.MarshalIndent(artifact, "    ", "  ")
		if err != nil || len(pretty) > admissionRecordLimit {
			return result, errors.New("pretty admission artifact exceeds reserved record limit")
		}
		result.RegistryBytes += record.PrepareReceipt.ReservedRegistryBytes
		result.OutboxBytes += record.PrepareReceipt.ReservedOutboxBytes
		// Deny-state transitions do not remove a retained-data debit. They do
		// remove future promotion authority, without modifying any receipt.
		if record.Commit == nil && (artifact.State == StateAcquired || artifact.State == StateQuarantined) {
			result.Prepared++
			result.FutureEvents++ // promote; existing reserve already includes revoke/delete
			result.FutureManifestBytes += admissionRecordLimit + 3*admissionFutureEventBytes
		}
	}
	if result.Prepared > admissionPreparedLimit {
		return result, errSafetyCapacity
	}
	return result, nil
}

type admissionFreeSpace struct {
	Registry int64
	Outbox   int64
	Shared   bool
}

// These are logical debits plus a current free-space check, not filesystem
// quota reservations against unrelated writers. Unknown retained data remains
// charged, and every storage failure is still nonpassing.
func checkAdmissionStoragePlan(plan admissionReservation, space admissionFreeSpace, config AdmissionConfig) error {
	if plan.RegistryBytes < 0 || plan.OutboxBytes < 0 || plan.RegistryBytes+plan.OutboxBytes > config.RetainedByteLimit {
		return errSafetyCapacity
	}
	if space.Shared {
		if space.Registry < plan.RegistryBytes+plan.OutboxBytes+int64(maxManifestBytes)+config.MinFreeBytes {
			return errSafetyCapacity
		}
	} else if space.Registry < plan.RegistryBytes+int64(maxManifestBytes)+config.MinFreeBytes || space.Outbox < plan.OutboxBytes+config.MinFreeBytes {
		return errSafetyCapacity
	}
	return nil
}
