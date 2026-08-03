#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/release-common.sh
source "${script_dir}/release-common.sh"

usage() {
    printf 'usage: %s <tag> <release-commit> [main-ref]\n' "$0" >&2
    exit 2
}

if [[ "$#" -lt 2 || "$#" -gt 3 ]]; then
    usage
fi

release_tag="$1"
release_commit="$2"
main_ref="${3:-refs/remotes/origin/main}"

if ! is_release_semver_tag "${release_tag}"; then
    printf 'release tag must be strict SemVer with a v prefix: %s\n' "${release_tag}" >&2
    exit 1
fi
if ! is_full_git_object_id "${release_commit}"; then
    printf 'release commit must be a full hexadecimal object ID\n' >&2
    exit 1
fi
if [[ "${main_ref}" != refs/* ]]; then
    printf 'main ref must be a fully qualified refs/* name\n' >&2
    exit 1
fi

tag_ref="refs/tags/${release_tag}"
if [[ "$(git cat-file -t "${tag_ref}" 2>/dev/null || true)" != tag ]]; then
    printf 'release tag must be an annotated tag object: %s\n' "${release_tag}" >&2
    exit 1
fi
if ! git show-ref --verify --quiet "${main_ref}"; then
    printf 'trusted main ref is unavailable: %s\n' "${main_ref}" >&2
    exit 1
fi

tagged_type="$(git cat-file -p "${tag_ref}" | sed -n '2s/^type //p')"
tagged_commit="$(git cat-file -p "${tag_ref}" | sed -n '1s/^object //p')"
if [[ "${tagged_type}" != commit ]] || ! is_full_git_object_id "${tagged_commit}"; then
    printf 'annotated release tag must point directly to a commit\n' >&2
    exit 1
fi
if [[ "$(git cat-file -t "${release_commit}" 2>/dev/null || true)" != commit ]]; then
    printf 'release commit must identify a commit object directly\n' >&2
    exit 1
fi
checked_out_commit="$(git rev-parse --verify "${release_commit}^{commit}")"
if [[ "${tagged_commit}" != "${checked_out_commit}" ]]; then
    printf 'release commit does not match the annotated tag target\n' >&2
    exit 1
fi
if ! git merge-base --is-ancestor "${tagged_commit}" "${main_ref}"; then
    printf 'release tag target is not reachable from %s\n' "${main_ref}" >&2
    exit 1
fi

printf 'verified annotated SemVer release tag %s on %s\n' "${release_tag}" "${main_ref}"
