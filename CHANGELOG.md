# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-03-09

### Added

- Expanded artifact lifecycle states: `acquired`, `quarantined`, `trusted`, `revoked`, `deleted`
- `POST /v1/model/acquire` endpoint for registering newly received artifacts
- `POST /v1/model/quarantine` endpoint for moving artifacts to quarantine scanning
- Soft-delete behavior for `DELETE /v1/model/delete` (metadata retained for audit)
- State transition enforcement (quarantine requires acquired state; deleted artifacts block revoke/promote)
- `state_counts` field in `/health` response reporting per-state totals
- `THREAT_MODEL.md` with trust boundaries, threats, mitigations, and residual risks
- `CHANGELOG.md` for tracking project changes
- Metadata-minimization documentation in README (what is stored, what is not)
- Signed release workflow (`.github/workflows/release.yml`) with cosign keyless signing
- Tests for all new states, transitions, and the full acquire-to-delete lifecycle (34 tests total)
- securectl displays all five artifact states in help text

### Changed

- README restructured for secure-by-default: quick start uses `SERVICE_TOKEN` path first
- `INSECURE_DEV_MODE` usage moved to clearly marked appendix with prominent warnings
- Container quick start example uses mounted service token instead of dev mode
- `SECURITY.md` updated with supported versions table and disclosure timeline expectations
- `/v1/model/delete` now performs soft delete (sets state to `deleted`) instead of removing from manifest

### Security

- Default quick start no longer promotes `INSECURE_DEV_MODE=true` as the primary path
- Deleted artifacts cannot be re-promoted or revoked (state transition enforcement)
- All non-trusted states blocked from `/v1/model/path` with 403 Forbidden

## [0.1.0] - 2026-03-06

### Added

- Security-first AI artifact registry with digest-based storage
- Five-state artifact lifecycle: acquired, quarantined, trusted, revoked, deleted
- API endpoints: acquire, quarantine, promote, revoke, delete (soft)
- Fail-closed authentication for all mutating operations
- SHA-256 hash verification on promote, verify, and integrity checks
- Immutable boot fallback via baked-in `models.lock.yaml`
- Batch integrity verification across all registered artifacts
- GGUF per-tensor manifest verification via gguf-guard integration
- `securectl` CLI for artifact management
- Container image with multi-arch support (amd64/arm64)
- Systemd unit with strict sandboxing (DynamicUser, PrivateNetwork, seccomp)
- Seccomp profile for minimal syscall allowlist
- OpenAPI 3.0 specification
- Signed releases with cosign keyless signing and SLSA provenance
- Threat model documentation

### Security

- Default-deny trust: artifacts must be explicitly promoted
- Soft delete preserves audit trail (metadata retained, file removed)
- Revoked artifacts blocked from runtime with 403 Forbidden
- State transition enforcement (deleted artifacts cannot be promoted)
- Localhost-only bind by default (127.0.0.1:8470)
- Constant-time token comparison prevents timing attacks
