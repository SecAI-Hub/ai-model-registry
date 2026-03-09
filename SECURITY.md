# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

If you discover a security issue, please email **security@secai-hub.dev** with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact

We will acknowledge reports within 48 hours and aim to ship a fix within 7 days for critical issues.

**Please do not open public issues for security vulnerabilities.**

## Security model

This service enforces a default-deny trust model for AI artifacts:

- All mutating operations require bearer token authentication (fail-closed)
- Artifacts must pass through a policy-gated promotion pipeline
- Runtime consumption is restricted to `trusted` state artifacts only
- SHA-256 digest verification on every promote, verify, and integrity check
- Revocation preserves audit trail without allowing runtime access

## Threat model scope

The standalone registry preserves the same trust-policy model as an integrated appliance deployment, but it does **not** by itself provide the full appliance privacy posture. Full posture requires additional controls (sealed runtime, quarantine pipeline, egress restrictions) provided by the deployment environment.
