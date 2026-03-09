# ai-model-registry

[![CI](https://github.com/SecAI-Hub/ai-model-registry/actions/workflows/ci.yml/badge.svg)](https://github.com/SecAI-Hub/ai-model-registry/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/SecAI-Hub/ai-model-registry)](https://goreportcard.com/report/github.com/SecAI-Hub/ai-model-registry)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Security-first AI artifact registry** — digest-based storage, policy-gated promotion, signed provenance, and reproducible trust metadata for local models, adapters, tokenizers, and related files.

## What it does

`ai-model-registry` is a lightweight HTTP service that manages the lifecycle of AI artifacts (models, adapters, tokenizers) with a strict trust model:

1. **Default-deny trust** — artifacts must be explicitly promoted through a policy-gated pipeline before they become available for runtime consumption.
2. **Explicit artifact states** — every artifact has a state (`trusted`, `revoked`) that determines whether it can be loaded. Revoked artifacts remain in the manifest for audit purposes.
3. **Fail-closed auth** — mutating operations (promote, delete, revoke) require a service token. If no token is configured, mutations are blocked by default.
4. **Digest-based verification** — SHA-256 hash verification on every promote, verify, and integrity check. Tampered artifacts are detected and flagged.
5. **Immutable boot fallback** — supports a baked-in `models.lock.yaml` for deterministic boot with pre-approved artifacts.

## Quick start

```bash
# Build
go build -o registry .
go build -o securectl ./cmd/securectl/

# Run (dev mode)
mkdir -p /tmp/registry
REGISTRY_DIR=/tmp/registry INSECURE_DEV_MODE=true ./registry

# In another terminal
./securectl status
./securectl list
```

> **Production:** Set `SERVICE_TOKEN_PATH` to a file containing a shared secret. Do **not** set `INSECURE_DEV_MODE` in production.

## Container

```bash
podman build -f Containerfile -t ai-model-registry .
podman run -p 8470:8470 \
  -v /path/to/models:/registry \
  -e INSECURE_DEV_MODE=true \
  ai-model-registry
```

## API

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Service health check (model count, trusted count, auth status) |
| `/v1/models` | GET | No | List all artifacts |
| `/v1/model?name=X` | GET | No | Get single artifact by name |
| `/v1/model/path?name=X` | GET | No | Get filesystem path (trusted artifacts only) |
| `/v1/model/verify?name=X` | POST | No | Verify artifact hash (returns `safe_to_use`) |
| `/v1/models/verify-all` | POST | No | Batch integrity verification |
| `/v1/integrity/status` | GET | No | Last integrity check result |
| `/v1/model/verify-manifest?name=X` | POST | No | Verify GGUF per-tensor manifest via gguf-guard |
| `/v1/model/promote` | POST | Token | Promote artifact to trusted state |
| `/v1/model/revoke?name=X` | POST | Token | Revoke artifact (mark as untrusted) |
| `/v1/model/delete?name=X` | DELETE | Token | Remove artifact from registry and disk |

See [schemas/openapi.yaml](schemas/openapi.yaml) for the full specification.

## Artifact lifecycle

```
[Untrusted / External]
    |
    v
[Quarantine pipeline] -- scan, verify, test -->
    |
    v
[POST /v1/model/promote] -- service token required, hash verified
    |
    v
[State: trusted] -- available for runtime via /v1/model/path
    |
    +---> [POST /v1/model/revoke] --> [State: revoked] (audit trail preserved)
    |
    +---> [DELETE /v1/model/delete] --> removed from manifest + disk
```

**Key invariant:** `/v1/model/path` only returns paths for artifacts in `trusted` state. Revoked artifacts are blocked with `403 Forbidden`.

## Configuration

| Environment variable | Default | Description |
|---------------------|---------|-------------|
| `BIND_ADDR` | `127.0.0.1:8470` | HTTP listen address |
| `REGISTRY_DIR` | `/registry` | Artifact storage directory |
| `REGISTRY_LOCK_PATH` | `/etc/secure-ai/policy/models.lock.yaml` | Baked-in fallback manifest |
| `SERVICE_TOKEN_PATH` | `/run/secure-ai/service-token` | Bearer token file for auth |
| `INTEGRITY_RESULT_PATH` | `/var/lib/secure-ai/logs/integrity-last.json` | Last integrity check result |
| `INSECURE_DEV_MODE` | `false` | Set `true` to allow mutations without token (**dev only**) |

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
securectl list                     List all models
securectl info <name>              Show artifact details (JSON)
securectl verify <name>            Verify artifact hash + state
securectl path <name>              Print filesystem path (trusted only)
securectl revoke <name>            Revoke artifact
securectl delete <name>            Remove artifact from registry
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
- **State isolation** — runtime can only consume `trusted` artifacts; `revoked` artifacts are blocked
- **Deterministic verification** — SHA-256 hash drives all admission and verification decisions
- **No insecure dev mode in production** — `INSECURE_DEV_MODE` must be explicitly set; default is fail-closed
- **Human-auditable decisions** — all promote/revoke/delete actions are logged with artifact details

## License

Apache-2.0
