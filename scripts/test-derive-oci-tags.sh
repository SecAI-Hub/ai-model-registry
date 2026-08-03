#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
derive="${script_dir}/derive-oci-tags.sh"
commit='ABCDEF0123456789ABCDEF0123456789ABCDEF01'
repository='ghcr.io/SecAI-Hub/ai-model-registry'

expect_output() {
    expected="$1"
    shift
    actual="$("${derive}" "$@")"
    if [[ "${actual}" != "${expected}" ]]; then
        printf 'unexpected OCI metadata for %s: %s\n' "$1" "${actual}" >&2
        exit 1
    fi
}

expect_failure() {
    if "${derive}" "$@" >/dev/null 2>&1; then
        printf 'expected OCI tag derivation failure for %s\n' "$1" >&2
        exit 1
    fi
}

metadata_prefix='repository=ghcr.io/secai-hub/ai-model-registry'
sha_line='sha=sha-abcdef0123456789abcdef0123456789abcdef01'
expect_output "$(printf '%s\nversion=v1.2.3\n%s' "${metadata_prefix}" "${sha_line}")" \
    "${repository}" v1.2.3 "${commit}"
build_output="$("${derive}" "${repository}" 'v1.2.3+build.5' "${commit}")"
prerelease_output="$("${derive}" "${repository}" 'v1.2.3-build.5' "${commit}")"
if [[ "${build_output}" != "$(printf '%s\nversion=v1.2.3_build.5\n%s' "${metadata_prefix}" "${sha_line}")" ||
      "${prerelease_output}" != "$(printf '%s\nversion=v1.2.3-build.5\n%s' "${metadata_prefix}" "${sha_line}")" ||
      "${build_output}" == "${prerelease_output}" ]]; then
    printf 'build metadata and prerelease OCI tags were not collision-free\n' >&2
    exit 1
fi

expect_output "$(printf '%s\nversion=v1.2.3-RC.1_META.A\n%s' "${metadata_prefix}" "${sha_line}")" \
    "${repository}" 'v1.2.3-RC.1+META.A' "${commit}"
expect_failure "${repository}" v01.2.3 "${commit}"
expect_failure 'ghcr.io/invalid repository' v1.2.3 "${commit}"

printf -v long_build '%*s' 130 ''
long_build="${long_build// /a}"
expect_failure "${repository}" "v1.2.3+${long_build}" "${commit}"

printf 'OCI tag derivation tests passed\n'
