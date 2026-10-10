# Standalone helper admission v2

The registry-side protocol is implemented; the companion producer path,
container sandbox and actual paired qualification are still in progress. This
document is an implementation contract, not a deployment-readiness claim.

This interface belongs to the standalone ai-model-registry/ai-quarantine pair.
The main appliance registry uses a different staged-promotion contract.

Explicit `REGISTRY_ADMISSION_MODE=helper-v2-required` requires a trusted
`ADMISSION_CONFIG_PATH` and an existing validated store. It disables new v1
acquire/quarantine/promote admission writes while preserving diagnostic reads
and revoke/delete safety operations. Missing or invalid configuration/state
fails closed. Legacy entries keep their histories without invented v2 receipts.

There are three new authenticated endpoints:

In scoped deployments the connected quarantine producer uses the registry's
`promote` credential for capability preflight, prepare, commit and exact
single-model receipt lookup. Capability preflight also accepts `read`; admission
mutations reject `read` and `verify`. Admin remains compatible and is required
for delete/revoke and audit administration. The configured policy, outbox,
idempotency, capacity and receipt validation still gate promotion; scope access
does not bypass those checks or re-enable v1 admission in required-v2 mode.
Legacy deployments with no scoped credential paths retain their all-service key
without scope separation.

| Endpoint | Method | Result |
| --- | --- | --- |
| `/v2/admission/capabilities` | GET | Service/protocol identity, trusted policy/context and fixed/configured bounds |
| `/v2/admission/prepare` | POST | One durable acquire+quarantine transaction and immutable preparation receipt |
| `/v2/admission/commit` | POST | Verified private copies/evidence and one durable promotion receipt |

The existing `/v1/model?name=X` returns the typed admission record and current
state. Unknown durability returns503; actual absence returns404. Exact replay
returns the original receipt/current state without another promotion. A revoked
or deleted row never regains trust through replay; runtime consumers must still
use the current-state/object verification path.

Requests are strict UTF-8 JSON with a64KiB body limit, no unknown/duplicate/missing
fields, and an `Idempotency-Key` equal to `admission_id`. The caller retains the
exact original prepare/commit bytes. A whitespace or key-order change under an
existing identifier conflicts. Current schemas define the complete DTOs; typed
`Artifact.admission` values also appear in the existing full event snapshots.
V2 records require explicit manifest version2, preserving legacy event encodings.

Initial source profiles are exact pinned local files and immutable HTTPS Hugging
Face commit/basename URLs. Only file GGUF/safetensors are admitted. Complete
versioned scanner/gate evidence is required; nonapplicable scanners remain
`passed:false`, `verdict:not_applicable`, with no positive coverage. The initial
bounded producer refuses GGUF policies requiring behavior beforeprepare because
that runtime is not yet qualified. Safetensors behavior is explicitly NA.

The administrator-owned configuration supplies exactly: version1, policy_dir,
policy_bundle_sha256, outbox_dir, pipeline_sha256, producer_uid, outbox_gid,
max_artifact_bytes, retained_byte_limit and min_free_bytes. Policy identity covers
the exact bytes of policy.yaml, models.lock.yaml and sources.allowlist.yaml.
The producer must use that immutable snapshot throughout its scan. Native units
whose ProcSubset hides the boot identifier additionally require a protected
per-boot credential through `ADMISSION_BOOT_ID_PATH`; hardening is not removed.

Explicit provisioning commands are `registry admission-init --kind registry
--path NEW_ABSOLUTE_CHILD` and the corresponding `--kind outbox`. Run them as
the intended owner/group under an already prepared private parent. Existing
paths are never adopted, reset or re-owned. This is not an automatic restart hook.
The intended pairing separates producer65532/outbox-reader-group65533 from
registry65534 plus that reader group, with producer-only writable outbox and
registry-only writable storage. Container DAC and native identity/hardening need
actual qualification before activation.

Original inputs remain intact. New copies, bounded evidence, journals and failed
or uncertain outcomes remain inventoried and charged; automatic cleanup/GC is
not implemented. [Capacity and recovery](CAPACITY_RECOVERY.md) explains these
logical reservations and the durability-unknown latch. Current handler/fault/
replay tests are synthetic filesystem/HTTP-handler evidence; they do not replace
real scanner, dropped-response/process-restart, sandbox or deployment acceptance.
