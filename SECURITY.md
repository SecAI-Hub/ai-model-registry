# Security Policy

## Supported versions

| Version | Supported          | Notes |
|---------|--------------------|-------|
| 0.1.x   | Yes                | Current stable release line |
| < 0.1   | No                 | Pre-release, not supported |

Security fixes are backported to the latest patch release of the current minor version.
When a new minor version is released, the previous minor version receives security fixes
for 90 days.

## Reporting a vulnerability

If you discover a security issue, please email **security@secai-hub.dev** with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Your suggested severity (Critical / High / Medium / Low)

### Disclosure expectations

- **Acknowledgment:** We will acknowledge receipt within **48 hours**.
- **Triage:** Initial severity assessment within **3 business days**.
- **Fix timeline:**
  - Critical / High: patch shipped within **7 days**
  - Medium: patch shipped within **14 days**
  - Low: addressed in the next scheduled release
- **Disclosure:** We follow coordinated disclosure. We will work with you on a
  disclosure timeline, typically 90 days from report. We will credit reporters
  unless anonymity is requested.
- **Updates:** We will provide status updates at least every 7 days until resolution.

**Please do not open public issues for security vulnerabilities.**

## Security model

This service enforces a default-deny trust model for AI artifacts:

- All mutating operations require bearer token authentication (fail-closed)
- Artifacts must pass through a policy-gated promotion pipeline
- Runtime consumption is restricted to `trusted` state artifacts only
- SHA-256 digest verification on every promote, verify, and integrity check
- Revocation preserves audit trail without allowing runtime access
- Soft delete retains metadata for forensic review

## Threat model scope

The standalone registry preserves the same trust-policy model as an integrated appliance
deployment, but it does **not** by itself provide the full appliance privacy posture. Full
posture requires additional controls (sealed runtime, quarantine pipeline, egress
restrictions) provided by the deployment environment.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the detailed threat model, including trust
boundaries, threats, mitigations, and residual risks.

## Security hardening

The following hardening measures are applied by default:

- **Localhost binding:** `127.0.0.1:8470` — no network exposure
- **Fail-closed auth:** mutations rejected without valid service token
- **Format allowlist:** only `gguf` and `safetensors` accepted (pickle blocked)
- **systemd sandboxing:** DynamicUser, ProtectSystem=strict, PrivateNetwork, seccomp
- **No external dependencies at runtime:** single static binary
- **No telemetry or phone-home:** all data stays on the local machine
