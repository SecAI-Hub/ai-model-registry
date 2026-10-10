package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

const maxManifestEntries = 100_000

var errSafetyCapacity = errors.New("registry admission would consume reserved safety capacity; offline maintenance required")
var errManifestDurabilityUnknown = errors.New("manifest publication durability uncertain; restart and reconcile persisted evidence")

// Fixed production ceilings. Tests can reduce these in-process to exercise every
// boundary without allocating 100,000 historical snapshots for every test.
// No request or environment variable can raise the loader's hard ceilings.
type capacityLimits struct{ Bytes, Events, Models int }

var manifestCapacityLimits = capacityLimits{maxManifestBytes, maxManifestEntries, maxManifestEntries}

type RegistryCapacity struct {
	ManifestBytes                int   `json:"manifest_bytes"`
	EventCount                   int   `json:"event_count"`
	ModelCount                   int   `json:"model_count"`
	ByteLimit                    int   `json:"byte_limit"`
	EventLimit                   int   `json:"event_limit"`
	ModelLimit                   int   `json:"model_limit"`
	SafetyReserveBytes           int   `json:"safety_reserve_bytes"`
	SafetyReserveEvents          int   `json:"safety_reserve_events"`
	AdmissionHeadroomBytes       int   `json:"admission_headroom_bytes"`
	AdmissionHeadroomEvents      int   `json:"admission_headroom_events"`
	SafetyReserveSufficient      bool  `json:"safety_reserve_sufficient"`
	MaintenanceRequired          bool  `json:"maintenance_required"`
	CandidateReservationRequired bool  `json:"candidate_reservation_required"`
	PersistenceReady             bool  `json:"persistence_ready"`
	PreparedAdmissions           int   `json:"prepared_admissions,omitempty"`
	AdmissionFutureBytes         int   `json:"admission_future_bytes,omitempty"`
	AdmissionFutureEvents        int   `json:"admission_future_events,omitempty"`
	RegistryRetainedDebitBytes   int64 `json:"registry_retained_debit_bytes,omitempty"`
	OutboxRetainedDebitBytes     int64 `json:"outbox_retained_debit_bytes,omitempty"`
}

// The reservation overestimates serialized growth: maximum timestamp/sequence
// widths, fixed-width hashes and one full post-transition snapshot per event.
// Live Models are kept at their current sizes; revoke/delete never increase the
// length of the state string. Thus any order of remaining safety transitions fits.
// Existing history and chain bytes are never rewritten by this calculation.
func registryCapacity(candidate Manifest, limits capacityLimits) (RegistryCapacity, error) {
	data, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		return RegistryCapacity{}, err
	}
	report := RegistryCapacity{ManifestBytes: len(data), EventCount: len(candidate.Events), ModelCount: len(candidate.Models), ByteLimit: limits.Bytes, EventLimit: limits.Events, ModelLimit: limits.Models, CandidateReservationRequired: true, PersistenceReady: !manifestPersistenceFailed}
	reserve := func(action string, artifact Artifact, from ArtifactState) error {
		event := RegistryAuditEvent{Sequence: maxManifestEntries, Timestamp: "2000-01-01T00:00:00.123456789Z", Action: action, Name: artifact.Name, FromState: from, ToState: artifact.State, SHA256: artifact.SHA256, Artifact: artifact, PrevHash: reservationHash, Hash: reservationHash}
		encoded, err := json.MarshalIndent(event, "    ", "  ")
		if err != nil {
			return err
		}
		// Four spaces before the opening brace, plus comma/newline between events.
		report.SafetyReserveBytes += len(encoded) + 6
		report.SafetyReserveEvents++
		return nil
	}
	for _, artifact := range candidate.Models {
		if len(candidate.Events) == 0 {
			if err := reserve("bootstrap", artifact, ""); err != nil {
				return report, err
			}
		}
		if artifact.State == StateDeleted {
			continue
		}
		if artifact.State != StateRevoked {
			from := artifact.State
			artifact.State = StateRevoked
			if err := reserve("revoke", artifact, from); err != nil {
				return report, err
			}
		}
		artifact.State = StateDeleted
		if err := reserve("delete", artifact, StateRevoked); err != nil {
			return report, err
		}
	}
	if len(candidate.Events) == 0 && report.SafetyReserveEvents > 0 {
		// Adding an omitted events property requires the array framing as well.
		// The final event has no comma; retaining that byte is conservative.
		report.SafetyReserveBytes += len(",\n  \"events\": [\n") + len("  ]")
	}
	admissions, err := plannedAdmissionReservations(candidate)
	if err != nil {
		return report, err
	}
	report.PreparedAdmissions = admissions.Prepared
	report.AdmissionFutureBytes = admissions.FutureManifestBytes
	report.AdmissionFutureEvents = admissions.FutureEvents
	report.RegistryRetainedDebitBytes = admissions.RegistryBytes
	report.OutboxRetainedDebitBytes = admissions.OutboxBytes
	report.SafetyReserveBytes += admissions.FutureManifestBytes
	report.SafetyReserveEvents += admissions.FutureEvents
	report.AdmissionHeadroomBytes = limits.Bytes - report.ManifestBytes - report.SafetyReserveBytes
	report.AdmissionHeadroomEvents = limits.Events - report.EventCount - report.SafetyReserveEvents
	report.SafetyReserveSufficient = report.AdmissionHeadroomBytes >= 0 && report.AdmissionHeadroomEvents >= 0 && report.ModelCount <= limits.Models
	report.MaintenanceRequired = !report.SafetyReserveSufficient || report.AdmissionHeadroomBytes <= 0 || report.AdmissionHeadroomEvents <= 0 || report.ModelCount >= limits.Models || !report.PersistenceReady
	return report, nil
}

const reservationHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

func saveAdmissionManifest() error {
	return saveAdmissionManifestGuarded(nil)
}

func saveAdmissionManifestGuarded(guard func() error) error {
	if len(manifest.Models) > maxManifestEntries || len(manifest.Events) > maxManifestEntries {
		return errSafetyCapacity
	}
	report, err := registryCapacity(manifest, manifestCapacityLimits)
	if err != nil {
		return err
	}
	if !report.SafetyReserveSufficient {
		return errSafetyCapacity
	}
	return saveManifestBeforePublish(guard)
}
func manifestWriteError(w http.ResponseWriter, err error) {
	if errors.Is(err, errSafetyCapacity) {
		http.Error(w, err.Error(), http.StatusInsufficientStorage)
		return
	}
	http.Error(w, fmt.Sprintf("failed to save manifest: %v", err), http.StatusInternalServerError)
}
func handleCapacity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	manifestMu.RLock()
	defer manifestMu.RUnlock()
	report, err := registryCapacity(manifest, manifestCapacityLimits)
	if err != nil {
		http.Error(w, "capacity unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !report.PersistenceReady {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(report)
}
