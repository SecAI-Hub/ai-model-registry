# Security and production-readiness audit

Audit date: 2026-08-02

## Scope and method

This review covered the Go service and CLI, artifact/manifest lifecycle, filesystem
handling, authentication, HTTP behavior, GGUF verification, container and systemd
deployment, CI/release workflows, schemas, tests, dependencies, and operational
documentation. It combined manual threat-oriented review with race-enabled tests,
`go vet`, `govulncheck`, secret scanning, dependency/misconfiguration scanning, and
container builds. It is a point-in-time engineering audit, not a formal certification.

## Findings addressed

| Severity | Finding | Remediation |
|---|---|---|
| Critical | Read and verification APIs were unauthenticated, while a missing token silently left part of the service exposed. | Authentication now covers every endpoint except `/health`; startup fails closed unless `INSECURE_DEV_MODE=true` is explicitly selected. |
| Critical | Artifact filenames could be absolute or escape the registry directory, and link-based substitution was insufficiently constrained. | Filenames must be local relative paths; descriptor-relative `os.Root` access, symlink/hardlink rejection, and pre/post file-identity checks constrain traversal and replacement. |
| Critical | Promotion left runtimes consuming a mutable caller-selected path, so replacement after admission could race consumers. | Promotion copies verified bytes into a SHA-256-derived object path using no-replace publication. Runtime resolution requires that object, re-verifies it, and returns path, digest, size, and contract version together. |
| High | Manifest corruption or malformed fields could be accepted or converted into an empty in-memory registry. | Manifest and lock files now use bounded, strict, single-document decoding plus complete semantic and hash-chain validation; startup fails on corruption. |
| High | Hash validation of only the latest event per artifact did not prove that earlier transitions were possible or that all metadata matched history. | Every event carries a complete artifact snapshot. Startup validates every transition, replays the whole chain, and requires exact ordered equality with `Manifest.Models`; writable state without history fails closed. |
| High | State changes and audit history were separate, non-transactional concerns. | Every lifecycle mutation appends a full-snapshot hash-chained event and persists state plus event in one synced temporary-file/rename operation with rollback on failure. |
| High | An internally valid older manifest could be replayed and there was no guarded recovery boundary. | The registry now exports owner-only Ed25519-signed checkpoints binding the exact manifest digest to the fully replayed event count/head. Verification uses an independent public key; recovery requires a separately retained head in the candidate chain and creates only a new fsynced path. |
| High | Promotion could bypass the acquired/quarantined lifecycle and evidence was too weak for production admission. | Non-development promotion now requires an existing matching quarantined record, a policy version, one-to-one scanner-version mappings, passed scan results, a verified SHA-256 digest, and declared-size consistency. |
| High | The GGUF verifier accepted paths without revalidating registry trust, had no execution deadline, and was absent from the final container. | Both inputs are reverified; execution has a timeout/concurrency cap; and the image builds `gguf-guard` from a commit plus archive-digest lock, embeds its binary digest in the registry, and fails startup/endpoint checks if it is absent or replaced. |
| Medium | JSON bodies, integrity results, token files, and CLI responses were not consistently bounded or strictly parsed. | Size limits, unknown/trailing-field rejection, regular non-symlink credential checks, minimum token entropy, and response caps are enforced. |
| Medium | The CLI could disclose its bearer credential through unsafe URLs or redirects. | Remote HTTP is rejected, user-info/query/fragment are rejected, redirects are disabled, and health probes omit authorization. |
| Medium | Remote listeners could be enabled accidentally. | Non-loopback binding requires explicit `ALLOW_REMOTE_BIND=true`; production guidance requires a TLS/mTLS identity-aware proxy. |
| Medium | The container's loopback-only internal listener made documented host-port publishing unusable. | The container explicitly opts into an internal wildcard listener while deployment examples publish only on host loopback; a hardened live host-port smoke test covers health and authenticated APIs. |
| Medium | `DynamicUser` could not reliably read a manually managed token under `/run`. | The systemd unit uses `LoadCredential=` and `%d/service-token`, giving the dynamic user a private, read-only credential mount. |
| Medium | The committed seccomp profile omitted the link operations used for no-replace content-addressed publication, so a hardened deployment could not promote artifacts. | Only `link` and `linkat` were added to the default-deny profile. CI now performs a real acquire-to-quarantine-to-promote-to-runtime-path lifecycle under that exact profile. |
| Medium | A pushed tag could bypass main-branch checks and publish untested bytes. | A read-only gate accepts only annotated strict-SemVer `v` tags, requires the tag object to point directly to the event commit, verifies that commit is reachable from `origin/main`, and rejects nested and lightweight tags in CI fixtures. It then reruns build, race, vet, formatting, vulnerability, workflow, secret, source, and image gates on that exact commit; publishing permissions exist only on publishing jobs. |
| Medium | Build/release dependencies and base images were mutable. | CI/release actions and container bases are immutable-pinned; CI includes race tests, formatting, vet, `govulncheck`, Gitleaks, Trivy, image scanning, signed releases, checksums, and provenance. |
| Medium | Automated SemVer container tags could collapse build metadata during OCI sanitization and published moving major/minor aliases, allowing distinct releases to collide or mutable tags to drift. | Release tags are derived and fixture-tested: SemVer `+` maps injectively to OCI-valid `_`, a full-SHA tag is also emitted, and moving major/minor/`latest` aliases are disabled. |
| Low | Batch verification tried to hash deliberately removed bytes for soft-deleted records, reporting normal retention metadata as an integrity failure. | Deleted records are now explicitly reported as `skipped` expected absence while all present artifact states remain hash-verified. |

## Remaining risks and recommendations

- The service uses one bearer credential and has no built-in RBAC, tenant identity, or
  mTLS. Keep it on loopback or add an identity-aware proxy; separate scanner, operator,
  and runtime roles before a multi-user deployment.
- The registry validates scanner evidence but does not execute scanners or prove their
  identity. Prefer signed attestations produced by separately authorized scanners.
- State is a single-node JSON manifest. Do not run active/active replicas against it;
  use a transactional database and external coordination before clustering.
- The checkpoint format is a provider-neutral local handoff, not WORM storage or
  trusted time. Choose immutable/object-lock storage, retention, replication,
  encryption, cadence, and independently controlled signing-key/head custody.
- Checkpoint filesystem hardening is supported for the Fedora/Linux production
  target and uses POSIX UID, no-follow, hard-link, and directory-sync semantics;
  it is not a Windows recovery implementation.
- The fixed GGUF verifier's returned response is truncated and time/concurrency bounded,
  but the child process output is buffered in memory. Retain OS/container memory limits.
- Artifacts and metadata are plaintext. Use encrypted storage and backups where model
  confidentiality or customer data requires it.
- GitHub secret scanning, push protection, Dependabot alerts/security updates, and
  default-branch deletion/non-fast-forward blocking are enabled. Strong PR status,
  independent-reviewer, and protected release-environment rules remain pending an
  independent reviewer; source changes cannot substitute for those controls.
- `build/gguf-guard.lock` intentionally matches SecAI_OS's reviewed immutable
  `17854ad9...` / `cef8f76a...` pin. Bump and re-audit it after the current gguf-guard
  hardening work is committed and pushed; do not replace it with a floating branch or
  an uncommitted sibling worktree.

## Validation evidence

The audited worktree's 62 top-level tests passed `go test -race -count=1 ./...`; `go vet
./...`, `go mod verify`, a full static build, `govulncheck@v1.3.0`, and
`gosec@v2.28.0 -severity medium -confidence medium ./...` also passed. Gosec's
11 suppressions are narrow, documented path/command false-positive
justifications adjacent to defensive identity checks. Gitleaks 8.30.1 reported
no worktree or history leaks, and Actionlint 1.7.7 accepted both workflows.
ShellCheck 0.10.0 accepted all committed shell scripts.
Trivy 0.70.0, using the locally available 2026-08-02 database snapshot, reported
no High/Critical source, dependency, configuration, container, or image findings.
All YAML/JSON parsed, all workflow actions are full-SHA pinned, and Fedora 44's
`systemd-analyze verify` accepted the supplied service unit. The final non-root,
read-only, capability-free image passed a live loopback host-port health and
authenticated API smoke test; replacing its pinned `gguf-guard` caused startup
to fail as required. A second container lifecycle smoke performed acquire,
quarantine, promotion, digest-bound runtime-path resolution, and verification
under the committed default-deny seccomp profile; no syscall relaxation beyond
the required `link` and `linkat` operations was made for content publication.
Checkpoint regressions additionally cover unknown CLI subcommands, canonical
absolute trust paths, decoded runtime-size limits, injected partial-write
cleanup, atomic no-replace publication, and successful retry after failure.

## Release gate

Before each release, run the committed CI workflow, review any new scanner findings,
exercise restore procedures for the manifest and artifacts, and verify published
checksums, Sigstore signatures, provenance, and container digests. Qualify the supplied
systemd restrictions on each target Fedora/RHEL release before rollout.
