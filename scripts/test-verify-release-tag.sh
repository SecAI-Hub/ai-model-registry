#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gate="${script_dir}/verify-release-tag.sh"
fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT

git -C "${fixture}" init --initial-branch=main --quiet
git -C "${fixture}" config user.name 'Release Gate Test'
git -C "${fixture}" config user.email 'release-gate@example.invalid'
printf 'main\n' > "${fixture}/fixture.txt"
git -C "${fixture}" add fixture.txt
git -C "${fixture}" commit --quiet -m 'main fixture'
main_commit="$(git -C "${fixture}" rev-parse HEAD)"
git -C "${fixture}" update-ref refs/remotes/origin/main "${main_commit}"

run_gate() {
    (cd "${fixture}" && GIT_CONFIG_NOSYSTEM=1 "${gate}" "$@")
}

expect_failure() {
    if run_gate "$@" >/dev/null 2>&1; then
        printf 'expected release gate failure for tag %s\n' "$1" >&2
        exit 1
    fi
}

git -C "${fixture}" tag -a v1.2.3 -m 'valid release' "${main_commit}"
run_gate v1.2.3 "${main_commit}" >/dev/null

git -C "${fixture}" tag -a 'v1.2.3-rc.1+build.5' -m 'valid prerelease' "${main_commit}"
run_gate 'v1.2.3-rc.1+build.5' "${main_commit}" >/dev/null

git -C "${fixture}" tag -a v1.2.4 -m 'nested tag must fail' refs/tags/v1.2.3
expect_failure v1.2.4 "${main_commit}"

git -C "${fixture}" tag v2.0.0 "${main_commit}"
expect_failure v2.0.0 "${main_commit}"

git -C "${fixture}" tag -a v01.2.3 -m 'invalid semver' "${main_commit}"
expect_failure v01.2.3 "${main_commit}"
expect_failure v1.2 "${main_commit}"
expect_failure v1.2.3-01 "${main_commit}"

git -C "${fixture}" switch --quiet -c unmerged
printf 'side\n' >> "${fixture}/fixture.txt"
git -C "${fixture}" commit --quiet -am 'unmerged fixture'
side_commit="$(git -C "${fixture}" rev-parse HEAD)"
git -C "${fixture}" tag -a v3.0.0 -m 'off-main release' "${side_commit}"
expect_failure v3.0.0 "${side_commit}"
expect_failure v1.2.3 "${side_commit}"

printf 'release tag gate tests passed\n'
