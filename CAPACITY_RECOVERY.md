# Capacity reservation and evidence-preserving maintenance

Legacy runtime manifests remain version 1. Explicit helper-v2 admission upgrades
the manifest to version 2 while preserving existing event hashes and the signed
checkpoint envelope. The hard loader ceilings remain 16 MiB,
100,000 model entries and 100,000 events. Soft-deleted model entries and their
full historical snapshots remain present; deleting artifact bytes does not
reclaim manifest history or permit reuse of the deleted name.

Legacy acquire, quarantine and promote check the entire candidate manifest before
publication. They must leave sufficient **serialized manifest bytes and event
slots** for every remaining nondeleted model to follow its complete safety path:
revoke, then delete. A revoked model reserves only delete; deleted models reserve
nothing. The reservation includes any pending bootstrap events, the widest
supported timestamp and sequence encodings, full post-transition snapshots,
JSON escaping and array framing. Existing Models remain at their original
serialized size during the estimate, conservatively ignoring safety state-string
shrinkage. Direct deletes consume less than the reserved revoke/delete path.
Repeating an already completed revoke/delete remains idempotent and appends no
new event. Every new promotion must replenish its full safety reservation.

A candidate that would consume this reserve returns HTTP 507 and leaves the
manifest and history unchanged. Acquire may also reach the model-entry ceiling;
all three ordinary operations may reach the byte/event ceilings. Safety
operations consume their reservation and retain every previous history record.
Successful mutations still require a full temporary-file write, file sync,
atomic rename and directory sync. Physical disk space, permissions, I/O errors
and OS/storage failures can still prevent persistence; the reservation is a
format-capacity guarantee, not a filesystem free-space guarantee. Promotion may
have already staged an immutable object before a final capacity rejection, as
with other existing manifest publication failures; this change does not add
object garbage collection or a filesystem quota.

## Helper-v2 retained reservations

The optional `helper-v2-required` mode reserves future typed Artifact growth,
promotion, and the enlarged revoke/delete snapshots before copying. Each v2
Artifact is bounded to64KiB, with at most32 preparations and2 simultaneous commit
workers. The preparation's1800-second authority uses CLOCK_BOOTTIME and a boot
identity; retries, expiry and restarts never renew it. Historical commit receipts
can remain present after revocation/deletion and do not authorize runtime use.

For model size S and evidence budget E<=1MiB, the registry retains a debit S+E
and the producer outbox S+E+8MiB. Free-space checks additionally reserve16MiB for
manifest scratch, summing filesystem needs when stores share a device. These
are conservative logical debits plus current free-space checks, not physical
quota reservations against other writers. Failed/unknown copies, expired
preparations and revoked/deleted records keep their debits and retained inventory.
Exhaustion requires reviewed maintenance; this does not implement reclamation.

The v2 initializer creates only a nonexistent target beneath a prepared private
parent. Daemon startup never initializes, resets, migrates or chowns v2 storage.
Existing targets, even empty ones, are refused. V2 state must remain with a
compatible binary; do not strip receipts, restore stale history over later deny
events, or invoke legacy watcher move/delete recovery. See [ADMISSION_V2.md](ADMISSION_V2.md)
for the current implementation and qualification boundary.

## Capacity status

Authenticated `GET /v1/capacity` reports current serialized bytes, counts, fixed
limits, required safety bytes/events and admission headroom. It distinguishes
`safety_reserve_sufficient`, `maintenance_required`, and `persistence_ready`.
`candidate_reservation_required:true` means headroom is not a promise to accept
an arbitrary-size request: each complete candidate is checked. Zero headroom,
a reached model ceiling, missing safety reserve or uncertain persistence signals
maintenance required. Small positive headroom can still reject a candidate that
does not fit, so operators should plan maintenance before it reaches zero.

A pre-upgrade manifest that has already consumed its safety reserve remains
readable and reports the deficit. Further ordinary mutations cannot make the
deficit worse. Revoke/delete remain best effort within the original hard caps;
**this change cannot guarantee all safety transitions in an already-full legacy
registry**. It neither silently raises limits nor rewrites/truncates history.
There is no on-disk migration and no online operation to reset the failure latch.

## Persistence failure and recovery

Pre-publication write/short-write/sync/rename errors return failure without
changing current manifest state. If rename completed but directory sync failed,
the disk outcome is ambiguous. The service returns failure, retains the candidate
in memory, latches readiness unavailable and refuses further mutations and
runtime artifact lookups. This avoids restoring an older trusted in-memory view
after a revoke/delete may already have been published. `/health` and capacity
status return 503. There is no success response before durable publication.
A fresh process reads and validates whichever complete manifest survived; inspect
its actual state and audit head before reconciling the failed client request.
Do not assume an HTTP failure means that no change reached disk.

1. Stop admission traffic and preserve access to available revoke/delete safety
   operations. For a persistence fault, stop the process before offline recovery.
   Do not delete manifests, drop history, lower counters or overwrite checkpoints.
2. Take an owner-only byte-for-byte offline copy and record its hash and full
   chain head. Preserve matching model objects, deployment configuration, trusted
   checkpoint public key and any independently retained heads. Keep old binary
   and matching complete state together for rollback.
3. Use `audit-checkpoint -manifest <offline-manifest> -key <private-key> -output
   <new-checkpoint>` and `audit-verify -checkpoint <checkpoint> -pubkey <trusted-key>
   -require-head <independently-retained-head>`. The existing tools refuse unsafe
   paths and overwrite. Export preserves the **entire** history; it does not free
   runtime capacity or turn an untrusted local head into an external anchor.
4. Recovery uses `audit-recover` into a **new** destination, with the trusted public
   key and independently retained head. Compare recovered bytes and trust states
   before any separately reviewed installation/restart. Never replace a newer
   restrictive history with an older trusted checkpoint merely to regain space.
5. If the current complete history cannot fit further operations, retain the
   verified checkpoint and await a reviewed archival/partition/continuity design.
   This release provides no automatic compaction, archival rotation or approved
   history-erasure procedure. Merely exporting a checkpoint and emptying the live
   manifest is not recovery and breaks the registry's evidence continuity.

Tests cover actual serialized bytes near 16 MiB, reduced independent event/model
ceilings, escaped maximum-size metadata, bootstrap reservation, arbitrary safety
ordering, idempotency, multiple remaining models, rejected ordinary mutations,
ENOSPC/short-write/sync/rename faults and restart. Existing full checkpoint
signature/replay/recovery tests remain mandatory. Archived live-history compaction,
external anchor operations, power-loss durability and a deployment-specific
maintenance procedure remain unqualified. No real registry, credentials or model
state is migrated by this change.
