# ai-model-registry

[![CI](https://github.com/SecAI-Hub/ai-model-registry/actions/workflows/ci.yml/badge.svg)](https://github.com/SecAI-Hub/ai-model-registry/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/SecAI-Hub/ai-model-registry)](https://goreportcard.com/report/github.com/SecAI-Hub/ai-model-registry)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Security-first AI artifact registry** — digest-based storage, policy-gated promotion, signed provenance, and reproducible trust metadata for local models, adapters, tokenizers, and related files.

## What it does

`ai-model-registry` is a lightweight HTTP service that manages the lifecycle of AI artifacts (models, adapters, tokenizers) with a strict trust model:

1. **Default-deny trust** — artifacts must be explicitly promoted through a policy-gated pipeline before they become available for runtime consumption.
2. **Explicit artifact states** — every artifact has a lifecycle state (`acquired`, `quarantined`, `trusted`, `revoked`, `deleted`) that determines whether it can be loaded. Only `trusted` artifacts are available for runtime.
3. **Fail-closed auth** — mutating operations (acquire, quarantine, promote, delete, revoke) require a service token. If no token is configured, mutations are blocked by default.
4. **Digest-based verification** — SHA-256 hash verification on every promote, verify, and integrity check. Tampered artifacts are detected and flagged.
5. **Immutable boot fallback** — supports a baked-in `models.lock.yaml` for deterministic boot with pre-approved artifacts.

## Quick start

```bash
# Build
go build -o registry .
go build -o securectl ./cmd/securectl/

# Create a service token (required for all mutating operations)
mkdir -p /tmp/registry
openssl rand -hex 32 > /tmp/registry/service-token

# Run with authentication enabled (default, secure)
REGISTRY_DIR=/tmp/registry \
  SERVICE_TOKEN_PATH=/tmp/registry/service-token \
  ./registry

# In another terminal — use the same token for authenticated requests
TOKEN=$(cat /tmp/registry/service-token)
./securectl status
./securectl list

# Promote a model (requires Bearer token)
curl -X POST http://127.0.0.1:8470/v1/model/promote \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-model","filename":"my-model.gguf","sha256":"<digest>","size_bytes":0}'
```

## Container

```bash
podman build -f Containerfile -t ai-model-registry .

# Run with a service token mounted
podman run -p 8470:8470 \
  -v /path/to/models:/registry \
  -v /path/to/service-token:/run/secure-ai/service-token:ro \
  ai-model-registry
```

## API

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Service health check (model count, state counts, auth status) |
| `/v1/models` | GET | No | List all artifacts (all states) |
| `/v1/model?name=X` | GET | No | Get single artifact by name |
| `/v1/model/path?name=X` | GET | No | Get filesystem path (trusted artifacts only) |
| `/v1/model/verify?name=X` | POST | No | Verify artifact hash (returns `safe_to_use`) |
| `/v1/models/verify-all` | POST | No | Batch integrity verification |
| `/v1/integrity/status` | GET | No | Last integrity check result |
| `/v1/model/verify-manifest?name=X` | POST | No | Verify GGUF per-tensor manifest via gguf-guard |
| `/v1/model/acquire` | POST | Token | Register newly received artifact (state: acquired) |
| `/v1/model/quarantine?name=X` | POST | Token | Move artifact to quarantine for scanning |
| `/v1/model/promote` | POST | Token | Promote artifact to trusted state |
| `/v1/model/revoke?name=X` | POST | Token | Revoke artifact (mark as untrusted) |
| `/v1/model/delete?name=X` | DELETE | Token | Soft-delete artifact (metadata retained for audit) |

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

**Key invariant:** `/v1/model/path` only returns paths for artifacts in `trusted` state. All other states are blocked with `403 Forbidden`.

## Artifact states

| State | Description | Path access | Can promote | Can revoke | Can delete |
|-------|-------------|-------------|-------------|------------|------------|
| `acquired` | Downloaded/received, not yet scanned | Blocked | Yes | Yes | Yes |
| `quarantined` | Being scanned by quarantine pipeline | Blocked | Yes | Yes | Yes |
| `trusted` | All checks passed, available for runtime | Allowed | Yes (re-promote) | Yes | Yes |
| `revoked` | Revoked, blocked from runtime use | Blocked | Yes (re-promote) | No-op | Yes |
| `deleted` | Soft-deleted, metadata retained for audit | Blocked | Blocked | Blocked | No-op |

## Metadata stored per artifact

The registry stores the following metadata for each artifact:

- **name** — human-readable artifact identifier
- **filename** — on-disk filename within the registry directory
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
| `REGISTRY_DIR` | `/registry` | Artifact storage directory |
| `REGISTRY_LOCK_PATH` | `/etc/secure-ai/policy/models.lock.yaml` | Baked-in fallback manifest |
| `SERVICE_TOKEN_PATH` | `/run/secure-ai/service-token` | Bearer token file for auth |
| `INTEGRITY_RESULT_PATH` | `/var/lib/secure-ai/logs/integrity-last.json` | Last integrity check result |

## Deployment profiles

### Appliance mode (default)

- Bind to `127.0.0.1` only
- Require service token for all mutations
- Use baked-in `models.lock.yaml` for deterministic boot
- Enable periodic integrity checks via systemd timer
- No public network exposure

### General standalone mode

- Same secure defaults, but may bind to `0.0.0.0` when explicitly configured
- Service token still required for mutations
- Can be used outside the full appliance stack
- Does not by itself reproduce the full appliance threat model — the appliance provides additional protections (sealed runtime, quarantine, egress controls)

## securectl CLI

```
securectl list                     List all models (all states)
securectl info <name>              Show artifact details (JSON)
securectl verify <name>            Verify artifact hash + state
securectl path <name>              Print filesystem path (trusted only)
securectl revoke <name>            Revoke artifact
securectl delete <name>            Soft-delete artifact (metadata retained)
securectl status                   Show registry health
```

## Hardening

The [systemd unit](deploy/systemd/ai-model-registry.service) includes:

- `DynamicUser=yes` — no persistent system user
- `ProtectSystem=strict` — read-only filesystem except registry directory
- `PrivateNetwork=yes` — no external network access (localhost only via socket activation or AF_UNIX)
- `MemoryDenyWriteExecute=yes` — no JIT or writable-executable pages
- `SystemCallFilter` — strict seccomp allowlist
- `CapabilityBoundingSet=` — no capabilities
- Resource limits: 512M memory, 50% CPU, 64 tasks

See [deploy/seccomp/ai-model-registry.json](deploy/seccomp/ai-model-registry.json) for the seccomp profile.

## Security considerations

This registry preserves the following trust invariants:

- **No implicit trust on upload** — promotion is policy-gated and requires authenticated requests
- **State isolation** — runtime can only consume `trusted` artifacts; all other states are blocked
- **Deterministic verification** — SHA-256 hash drives all admission and verification decisions
- **No insecure dev mode in production** — `INSECURE_DEV_MODE` must be explicitly set; default is fail-closed
- **Human-auditable decisions** — all state transitions are logged with artifact details
- **Soft delete** — deleted artifacts retain metadata for audit trail; only the file is removed from disk

---

## Appendix: Development-only mode

> **WARNING: Never use `INSECURE_DEV_MODE` in production. All mutating operations (acquire, quarantine, promote, revoke, delete) will be rejected without a service token unless dev mode is explicitly enabled. This is by design — fail-closed auth is a core security property.**

For local development and testing only, you can bypass token authentication:

```bash
# DEVELOPMENT ONLY — do not use in production
mkdir -p /tmp/registry
REGISTRY_DIR=/tmp/registry INSECURE_DEV_MODE=true ./registry
```

When `INSECURE_DEV_MODE=true` is set:
- Mutating endpoints accept requests without a Bearer token
- A warning is logged on startup: `INSECURE_DEV_MODE=true — auth will not be enforced`
- The `/health` endpoint reports `auth_required: false`

When `INSECURE_DEV_MODE` is not set (the default):
- All mutating endpoints require a valid Bearer token
- If no token file is configured, mutations return `403 Forbidden`
- This is the correct and expected behavior for any non-development deployment

> **WARNING: Never set `INSECURE_DEV_MODE=true` in container images, systemd units, or any deployment configuration. The service is designed to fail closed — if you cannot authenticate, you cannot mutate the registry. This protects against unauthorized model promotion and state tampering.**

## License

Apache-2.0
