# ai-model-registry

[![CI](https://github.com/SecAI-Hub/ai-model-registry/actions/workflows/ci.yml/badge.svg)](https://github.com/SecAI-Hub/ai-model-registry/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/SecAI-Hub/ai-model-registry)](https://goreportcard.com/report/github.com/SecAI-Hub/ai-model-registry)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Security-first AI artifact registry** — digest-based storage, policy-gated promotion, signed provenance, and reproducible trust metadata for local models, adapters, tokenizers, and related files.

## What it does

`ai-model-registry` is a lightweight HTTP service that manages the lifecycle of AI artifacts (models, adapters, tokenizers) with a strict trust model:

1. **Default-deny trust** — artifacts must be explicitly promoted through a policy-gated pipeline before they become available for runtime consumption.
2. **Explicit artifact states** — every artifact has a lifecycle state (`acquired`, `quarantined`, `trusted`, `revoked`, `deleted`) that determines whether it can be loaded. Only `trusted` artifacts are available for runtime.
3. **Fail-closed auth** — every registry API except `/health` requires a file-backed service token. Production startup fails if that credential is unavailable.
4. **Immutable digest storage** — promotion copies verified bytes to a no-replace `objects/sha256/...` path. Runtime resolution returns the path, digest, size, and storage-contract version together.
5. **Replayable state** — every event contains a complete post-transition artifact snapshot; startup replays the entire chain and requires it to reconstruct registry state exactly.
6. **Immutable boot fallback** — supports a baked-in `models.lock.yaml` for deterministic boot with pre-approved, content-addressed artifacts.

## Quick start

```bash
# Build. Production/container builds use the reviewed gguf-guard pin in
# build/gguf-guard.lock. Native builds must install that binary at
# /usr/local/bin/gguf-guard or inject a fixed path and binary digest:
GUARD=/absolute/path/to/reviewed/gguf-guard
GUARD_SHA256=$(sha256sum "$GUARD" | cut -d ' ' -f1)
go build -ldflags "-X main.ggufGuardBin=$GUARD -X main.ggufGuardSHA256=$GUARD_SHA256" -o registry .
go build -o securectl ./cmd/securectl/

# Create a service token (required for every non-health API)
mkdir -p /tmp/registry
openssl rand -hex 32 > /tmp/registry/service-token
chmod 600 /tmp/registry/service-token

# Run with authentication enabled (default, secure)
REGISTRY_DIR=/tmp/registry \
  SERVICE_TOKEN_PATH=/tmp/registry/service-token \
  ./registry

# In another terminal — use the same token for authenticated requests
TOKEN=$(cat /tmp/registry/service-token)
./securectl status
./securectl list

# After placing my-model.gguf in REGISTRY_DIR, record and quarantine it.
DIGEST=$(sha256sum /tmp/registry/my-model.gguf | cut -d ' ' -f1)
SIZE=$(wc -c < /tmp/registry/my-model.gguf | tr -d ' ')
curl -X POST http://127.0.0.1:8470/v1/model/acquire \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"my-model\",\"filename\":\"my-model.gguf\",\"sha256\":\"$DIGEST\",\"size_bytes\":$SIZE}"
curl -X POST 'http://127.0.0.1:8470/v1/model/quarantine?name=my-model' \
  -H "Authorization: Bearer $TOKEN"

# Promote only after the external quarantine scanners pass.
curl -X POST http://127.0.0.1:8470/v1/model/promote \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"my-model\",\"filename\":\"my-model.gguf\",\"sha256\":\"$DIGEST\",\"size_bytes\":$SIZE,\"scan_results\":{\"modelscan\":\"pass\"},\"scanner_versions\":{\"modelscan\":\"<version>\"},\"policy_version\":\"local-v1\"}"
```

## Container

```bash
podman build -f Containerfile -t ai-model-registry .

# Run with a service token mounted
podman run --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --user "$(id -u):$(id -g)" --pids-limit=64 \
  -p 127.0.0.1:8470:8470 \
  -v /path/to/models:/registry \
  -v /path/to/service-token:/run/secure-ai/service-token:ro \
  ai-model-registry
```

The image listens on `0.0.0.0:8470` inside its own network namespace so host
port publishing works. Keep the host publish address at `127.0.0.1`, as above,
unless a TLS/mTLS identity-aware proxy is the only external entry point. The
final image includes `gguf-guard` built from the commit and archive SHA-256 in
[`build/gguf-guard.lock`](build/gguf-guard.lock); registry startup verifies the
installed binary digest and fails if it is missing or replaced.

## API

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Minimal liveness check |
| `/v1/stats` | GET | Token | Artifact and lifecycle-state counts |
| `/v1/models` | GET | Token | List all artifacts (all states) |
| `/v1/model?name=X` | GET | Token | Get single artifact by name |
| `/v1/model/path?name=X` | GET | Token | Resolve a digest-bound content-addressed locator (trusted artifacts only) |
| `/v1/model/verify?name=X` | POST | Token | Verify artifact hash (returns `safe_to_use`) |
| `/v1/models/verify-all` | POST | Token | Batch integrity verification |
| `/v1/integrity/status` | GET | Token | Last integrity check result |
| `/v1/model/verify-manifest?name=X` | POST | Token | Verify GGUF per-tensor manifest via gguf-guard |
| `/v1/model/acquire` | POST | Token | Register newly received artifact (state: acquired) |
| `/v1/model/quarantine?name=X` | POST | Token | Move artifact to quarantine for scanning |
| `/v1/model/promote` | POST | Token | Promote artifact to trusted state |
| `/v1/model/revoke?name=X` | POST | Token | Revoke artifact (mark as untrusted) |
| `/v1/model/delete?name=X` | DELETE | Token | Soft-delete artifact (metadata retained for audit) |
| `/v1/audit` | GET | Token | Return hash-chained lifecycle events committed atomically with registry state |

See [schemas/openapi.yaml](schemas/openapi.yaml) for the full specification.

## Artifact lifecycle

```
[External source]
    |
    v
[POST /v1/model/acquire]  --> [State: acquired]
    |
    v
[POST /v1/model/quarantine] --> [State: quarantined]
    |
    v
[Quarantine pipeline: scan, verify, test]
    |
    v
[POST /v1/model/promote]  --> [State: trusted]  (service token + hash verified)
    |                              |
    |                              +---> GET /v1/model/path  (runtime consumption)
    |
    +---> [POST /v1/model/revoke]  --> [State: revoked]  (audit trail preserved)
    |
    +---> [DELETE /v1/model/delete] --> [State: deleted]  (soft-delete, metadata retained)
```

**Key invariant:** `/v1/model/path` only resolves `trusted` artifacts that have a
content-addressed object. Its response binds `path`, `sha256`, `size_bytes`, and
`storage_contract: content-addressed-v1`. Consumers must open the returned path
without following links and verify the returned digest and size on the opened
file immediately before parsing; a path string alone is never a trust decision.

## Artifact states

| State | Description | Path access | Can promote | Can revoke | Can delete |
|-------|-------------|-------------|-------------|------------|------------|
| `acquired` | Downloaded/received, not yet scanned | Blocked | No | Yes | Yes |
| `quarantined` | Being scanned by quarantine pipeline | Blocked | Yes | Yes | Yes |
| `trusted` | All checks passed, available for runtime | Allowed | No | Yes | Yes |
| `revoked` | Revoked, blocked from runtime use | Blocked | No | No-op | Yes |
| `deleted` | Soft-deleted, metadata retained for audit | Blocked | Blocked | Blocked | No-op |

## Metadata stored per artifact

The registry stores the following metadata for each artifact:

- **name** — human-readable artifact identifier
- **filename** — untrusted/quarantine input filename within the registry directory
- **object_path** — immutable digest-derived runtime path assigned at promotion
- **format** — file format (e.g., `gguf`, `safetensors`)
- **sha256** — SHA-256 digest of the artifact file
- **size_bytes** — file size in bytes
- **state** — lifecycle state (acquired, quarantined, trusted, revoked, deleted)
- **promoted_at** — timestamp of last state change (RFC 3339)
- **source** — optional provenance URL
- **scan_results** — summary of scan outcomes (pass/fail per scanner)
- **scanner_versions** — versions of scanners that produced results
- **policy_version** — version of the promotion policy applied
- **source_revision** — Git revision of the source (if applicable)
- **gguf_guard_fingerprint** — per-tensor fingerprint data (GGUF files only)
- **gguf_guard_manifest** — path to gguf-guard manifest file (GGUF files only)

**What is NOT stored:**

- Raw model weights are stored on disk, not in the manifest metadata
- No user identity or account information (no user accounts exist)
- No download IP addresses or client fingerprints
- No usage telemetry or analytics
- No external service tokens or credentials in the manifest

**Privacy note:** The registry is designed for localhost/appliance use. It does not phone home, collect telemetry, or communicate with any external service. All data remains on the local machine.

## Configuration

| Environment variable | Default | Description |
|---------------------|---------|-------------|
| `BIND_ADDR` | `127.0.0.1:8470` | HTTP listen address |
| `REGISTRY_DIR` | `/registry` | Absolute, non-symlink artifact storage directory |
| `REGISTRY_LOCK_PATH` | `/etc/secure-ai/policy/models.lock.yaml` | Baked-in fallback manifest |
| `SERVICE_TOKEN_PATH` | `/run/secure-ai/service-token` | Bearer token file for auth |
| `INTEGRITY_RESULT_PATH` | `/var/lib/secure-ai/logs/integrity-last.json` | Last integrity check result |
| `ALLOW_REMOTE_BIND` | unset | Must be exactly `true` before using a non-loopback `BIND_ADDR`; terminate TLS/mTLS in front |
| `ALLOW_LEGACY_MANIFEST_MIGRATION` | unset | Reserved one-time migration opt-in; validate legacy state offline before enabling |

### Legacy runtime-manifest migration

Writable manifests created before full event snapshots are rejected when they contain
models but no replayable history. After taking an offline backup and independently
reviewing the model states, scanner evidence, and expected digests, start once with
`ALLOW_LEGACY_MANIFEST_MIGRATION=true`. The registry verifies each trusted artifact,
copies it into content-addressed storage, writes bootstrap snapshots, and atomically
persists the upgraded manifest. Unset the variable immediately afterward. This opt-in
cannot establish the authenticity of legacy metadata; it only makes the reviewed
state replayable.

## Deployment profiles

### Appliance mode (default)

- Bind to `127.0.0.1` only
- Require a service token for every non-health request
- Use baked-in `models.lock.yaml` entries with valid `object_path` values for deterministic boot
- Enable periodic integrity checks via systemd timer
- No public network exposure

### General standalone mode

- Same secure defaults; a non-loopback bind additionally requires `ALLOW_REMOTE_BIND=true`
- Service token remains required for every non-health API
- Can be used outside the full appliance stack
- Does not by itself reproduce the full appliance threat model — the appliance provides additional protections (sealed runtime, quarantine, egress controls)

## securectl CLI

```
securectl list                     List all models (all states)
securectl info <name>              Show artifact details (JSON)
securectl verify <name>            Verify artifact hash + state
securectl path <name>              Print digest-bound locator JSON (trusted only)
securectl revoke <name>            Revoke artifact
securectl delete <name>            Soft-delete artifact (metadata retained)
securectl status                   Show registry health
```

## Signed registry checkpoints and recovery

These checkpoint commands and their filesystem guarantees are Fedora/Linux
production features. They rely on POSIX UID ownership, no-follow opens, hard
links, and directory `fsync`; POSIX macOS is suitable for development testing,
but Windows filesystems are not supported by this recovery boundary.

The registry binary can export the complete runtime manifest and replayable
event history as a provider-neutral, owner-only JSON checkpoint. The checkpoint
contains the exact manifest bytes, SHA-256 digest, event count and head, signed
timestamp and key identity, and an Ed25519 signature. Verification uses a
separately supplied public key and reruns strict manifest validation plus full
event replay.

Generate a dedicated checkpoint keypair once, keep it separate from service
credentials and artifact-signing keys, and stop the registry before each export.
In production, keep the private key under independent restricted custody and
make it available only for the stopped-writer checkpoint procedure:

```sh
install -d -m 0700 /registry/checkpoints
registry audit-keygen \
  -priv /etc/secure-ai/credentials/registry-checkpoint.key \
  -pub /etc/secure-ai/registry-checkpoint.pub

registry audit-checkpoint \
  -manifest /registry/manifest.json \
  -key /etc/secure-ai/credentials/registry-checkpoint.key \
  -output /registry/checkpoints/registry-20260802.json

registry audit-verify \
  -checkpoint /registry/checkpoints/registry-20260802.json \
  -pubkey /etc/secure-ai/registry-checkpoint.pub \
  -require-head PREVIOUSLY_RETAINED_CHAIN_HEAD
```

Run the exporter as the owner of both input and key. If the service uses a
different or dynamic UID, stop it and stage an exact owner-only manifest copy
under the export identity first. Inputs and outputs must live in trusted
root/export-user-owned directories that are not group/world-writable; never
relax the source or private-key mode.
All checkpoint source, key, checkpoint-output, and recovery-output paths must
be canonical absolute paths.

Export and recovery write and sync a randomized same-directory temporary file,
publish it with an atomic no-replace hard link, remove the temporary name, and
sync the parent directory. A failed pre-publication write is cleaned up and
cannot leave a partial final path blocking retry. After verification, copy the checkpoint to the deployment's chosen
immutable retention target and retain the reported chain head independently.
Local `O_EXCL` protection is not WORM storage, and the signed local timestamp is
not an external trusted timestamp.

Recovery requires an independently retained head to occur in the checkpoint and
only writes a new manifest path:

```sh
registry audit-recover \
  -checkpoint /recovery/registry-20260802.json \
  -pubkey /etc/secure-ai/registry-checkpoint.pub \
  -require-head INDEPENDENTLY_RETAINED_CHAIN_HEAD \
  -output /recovery/new-registry/manifest.json
```

Restore the matching content-addressed `objects/` tree into that fresh registry
directory, let normal startup verify the recovered manifest, and run authenticated
`/v1/models/verify-all` before switching consumers. A checkpoint intentionally
does not embed model bytes.

## Hardening

The [systemd unit](deploy/systemd/ai-model-registry.service) includes:

- `DynamicUser=yes` — no persistent system user
- `LoadCredential=` — copies the root-owned service token into the unit's private credential mount
- `ProtectSystem=strict` — read-only filesystem except registry directory
- Loopback-only TCP binding with restricted address families
- `MemoryDenyWriteExecute=yes` — no JIT or writable-executable pages
- `SystemCallFilter` — strict seccomp allowlist
- `CapabilityBoundingSet=` — no capabilities
- Resource limits: 512M memory, 50% CPU, 64 tasks

Provision the unit credential from a root-only source; do not create a shared runtime
file for the dynamic user:

```bash
sudo install -d -o root -g root -m 0700 /etc/secure-ai/credentials
sudo install -o root -g root -m 0400 /path/to/generated-token \
  /etc/secure-ai/credentials/ai-model-registry.service-token
sudo systemctl daemon-reload
sudo systemctl restart ai-model-registry.service
```

See [deploy/seccomp/ai-model-registry.json](deploy/seccomp/ai-model-registry.json) for the seccomp profile.

Releases accept only annotated `vMAJOR.MINOR.PATCH` SemVer tags (including valid
SemVer prerelease/build suffixes). The release workflow verifies that the peeled
tag target matches the event commit and is reachable from `origin/main`, then
reruns the security gates before any job receives publishing permissions.
Container releases publish only two immutable tags: the exact release SemVer
(mapping its `+` delimiter to `_`, which cannot occur in SemVer) and a full
commit-SHA tag. Moving major/minor and `latest` tags are intentionally omitted.

## Security considerations

This registry preserves the following trust invariants:

- **No implicit trust on upload** — promotion is policy-gated and requires authenticated requests
- **State isolation** — runtime can only consume `trusted` artifacts; all other states are blocked
- **Deterministic verification** — SHA-256 hash drives all admission and verification decisions
- **No insecure dev mode in production** — `INSECURE_DEV_MODE` must be explicitly set; default is fail-closed
- **Human-auditable decisions** — all state transitions are logged with artifact details
- **Atomic durable state** — bounded manifests are strictly parsed, synced to a private temporary file, and atomically renamed
- **Fully replayed lifecycle history** — complete event snapshots are hash chained, transition checked, and required to reconstruct manifest state exactly
- **Immutable runtime objects** — promotion publishes with no-replace semantics into digest-derived paths; resolution returns the digest contract, not a bare trusted path
- **Filesystem containment** — only local relative paths are accepted; escapes, symlinks, hard links, and files changing while hashed are rejected
- **Soft delete** — deleted artifacts retain metadata for audit trail; only the file is removed from disk
- **Portable audit checkpoints** — signed manifest exports bind exact bytes to the replayed event head; anchored recovery can create only a new path

---

## Appendix: Development-only mode

> **WARNING: Never use `INSECURE_DEV_MODE` in production. It bypasses authentication for every non-health API and is only suitable for isolated loopback development.**

For local development and testing only, you can bypass token authentication:

```bash
# DEVELOPMENT ONLY — do not use in production
mkdir -p /tmp/registry
REGISTRY_DIR=/tmp/registry INSECURE_DEV_MODE=true ./registry
```

When `INSECURE_DEV_MODE=true` is set:
- All non-health endpoints accept requests without a Bearer token
- A warning is logged on startup: `INSECURE_DEV_MODE=true — auth will not be enforced`
- The `/health` endpoint remains a minimal unauthenticated liveness response

When `INSECURE_DEV_MODE` is not set (the default):
- Startup fails if the token is missing, empty, weak, oversized, or a symbolic link
- Every non-health endpoint requires a valid Bearer token
- This is the correct and expected behavior for any non-development deployment

> **WARNING: Never set `INSECURE_DEV_MODE=true` in container images, systemd units, or any deployment configuration. The service is designed to fail closed — without authentication, no non-health registry API is available. This protects artifact metadata, paths, verification results, and lifecycle operations.**

See [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), and the
[security audit](SECURITY_AUDIT.md) before production deployment.

## License

Apache-2.0
