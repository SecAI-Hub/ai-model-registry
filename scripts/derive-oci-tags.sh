#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/release-common.sh
source "${script_dir}/release-common.sh"

if [[ "$#" -ne 3 ]]; then
    printf 'usage: %s <image-repository> <release-tag> <release-commit>\n' "$0" >&2
    exit 2
fi

image_repository="$(printf '%s' "$1" | LC_ALL=C tr '[:upper:]' '[:lower:]')"
release_tag="$2"
release_commit="$3"
if [[ ! "${image_repository}" =~ ^[a-z0-9]+([.-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)+$ ]]; then
    printf 'invalid OCI image repository\n' >&2
    exit 1
fi
if ! is_release_semver_tag "${release_tag}"; then
    printf 'cannot derive an OCI tag from invalid release SemVer: %s\n' "${release_tag}" >&2
    exit 1
fi
if ! is_full_git_object_id "${release_commit}"; then
    printf 'release commit must be a full hexadecimal object ID\n' >&2
    exit 1
fi

# Underscore is OCI-tag-safe but invalid in SemVer, making this mapping
# collision-free for the otherwise-invalid '+' delimiter.
version_tag="${release_tag/+/_}"
if [[ "${#version_tag}" -gt 128 || ! "${version_tag}" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]]; then
    printf 'release SemVer cannot be represented as a valid OCI tag\n' >&2
    exit 1
fi

release_commit="$(printf '%s' "${release_commit}" | LC_ALL=C tr '[:upper:]' '[:lower:]')"
printf 'repository=%s\n' "${image_repository}"
printf 'version=%s\n' "${version_tag}"
printf 'sha=sha-%s\n' "${release_commit}"
