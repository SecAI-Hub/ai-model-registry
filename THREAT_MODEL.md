# Threat Model

This document describes trust boundaries, threats, mitigations, and residual risks for the ai-model-registry service.

## Trust boundaries

```
  Untrusted                        Trusted
  ┌──────────┐   ┌───────────────────────────────────────┐   ┌──────────────┐
  │ External │──▶│  ai-model-registry                    │──▶│ Runtime      │
  │ Artifact │   │  ┌──────────┐  ┌──────────┐  ┌─────┐ │   │ (inference)  │
  │ Source   │   │  │ Promote  │  │ Verify   │  │Audit│ │   │              │
  └──────────┘   │  │ (gated)  │  │ (SHA-256)│  │ Log │ │   └──────────────┘
                 │  └──────────┘  └──────────┘  └─────┘ │
                 └───────────────────────────────────────┘
```

| Boundary | Description |
|----------|-------------|
| **Artifact source** | Untrusted. Models arrive from external sources or local imports. No artifact is trusted until it has been promoted through the policy-gated pipeline. |
| **Registry service** | Trusted execution environment. Manages artifact lifecycle, enforces state transitions, and logs all mutations. |
| **Runtime (inference)** | Trusted consumer. Only artifacts in `trusted` state are served via `/v1/model/path`. All other states return 403. |
| **Admin / operator** | Privileged. Authenticated via service token. Can promote, revoke, and delete artifacts. |

## Artifact states

```
acquired ──▶ quarantined ──▶ trusted ──▶ revoked
                                    ──▶ deleted (soft)
```

- **acquired**: Downloaded/received, not yet scanned. Cannot be loaded.
- **quarantined**: Being scanned by the quarantine pipeline. Cannot be loaded.
- **trusted**: All checks passed. Available for runtime consumption.
- **revoked**: Blocked from runtime. Metadata retained for audit.
- **deleted**: Soft-deleted. File removed from disk, metadata retained for audit.

## Threats

### T1: Malicious artifact promotion

**Threat:** An attacker promotes a trojaned or backdoored artifact to trusted state, making it available for runtime consumption.

**Attack vectors:**
- Compromised service token (stolen or leaked)
- Bypassing the quarantine pipeline entirely
- Promoting an artifact that was modified after scanning

**Severity:** Critical

**Mitigations:**
- Fail-closed authentication: all mutating operations require a service token
- SHA-256 verification on promote: hash must match what was scanned
- State transition enforcement: only `quarantined` artifacts can be promoted to `trusted`
- Deleted artifacts cannot be re-promoted

### T2: Hash collision / substitution

**Threat:** An attacker crafts an artifact with the same SHA-256 hash as a legitimate model, substituting it post-verification.

**Attack vectors:**
- Hash collision (computationally infeasible for SHA-256)
- TOCTOU: replacing the file between hash verification and promotion
- Symlink attack: replacing the file content via a symlink

**Severity:** High

**Mitigations:**
- SHA-256 provides 128-bit collision resistance (no known practical attacks)
- Periodic integrity checks via systemd timer re-verify all artifacts
- Filesystem permissions restrict write access to the registry directory
- Systemd sandboxing (ProtectSystem=strict) limits filesystem access

### T3: Service token compromise

**Threat:** An attacker obtains the service token and performs unauthorized mutations (promote, revoke, delete).

**Attack vectors:**
- Reading the token file via path traversal in another service
- Token in process environment or memory dump
- Network sniffing (if not using TLS/localhost)

**Severity:** High

**Mitigations:**
- Token loaded from file (not environment variable)
- Constant-time comparison prevents timing attacks
- Localhost-only bind prevents network sniffing
- Token file should be root-owned with mode 0400
- Systemd `LoadCredential` can inject the token without filesystem exposure

### T4: Denial of service

**Threat:** An attacker floods the registry with requests or oversized payloads to exhaust resources.

**Attack vectors:**
- Rapid promote/delete cycles to cause disk churn
- Oversized artifact submissions to fill disk
- Request flooding

**Severity:** Medium

**Mitigations:**
- Authentication required for all mutating endpoints (limits attack surface to token holders)
- Systemd resource limits: 512M memory, 50% CPU, 64 tasks
- Registry directory quotas can be enforced at the filesystem level

### T5: Manifest tampering

**Threat:** An attacker with filesystem access modifies the manifest JSON to change artifact states or hashes.

**Attack vectors:**
- Direct file modification if filesystem permissions are weak
- Exploiting a race condition during manifest save

**Severity:** High

**Mitigations:**
- `sync.RWMutex` serializes all manifest reads and writes
- Atomic file writes (write to temp file, then rename)
- Systemd sandboxing limits filesystem access to the registry directory only
- Periodic integrity checks detect hash mismatches caused by manifest tampering

## Residual risks

| Risk | Severity | Notes |
|---|---|---|
| TOCTOU between scan and promote | Medium | File could be modified between quarantine scan and promotion. Mitigated by hash verification on promote, but a very narrow race window exists. |
| No encryption at rest | Low | Artifacts are stored in plaintext. Acceptable for appliance mode with full-disk encryption. For standalone deployments, use filesystem-level encryption. |
| Single-instance manifest | Low | Manifest is a single JSON file. Not suitable for distributed deployments without external coordination. Acceptable for single-appliance use. |
| No audit log chaining | Medium | The registry logs mutations but does not use a hash-chained audit log. The quarantine pipeline provides chained logging for the full admission flow. |
| Soft-delete metadata retention | Low | Deleted artifact metadata is retained indefinitely. Operators may need to implement external cleanup for compliance. |
