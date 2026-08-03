#!/usr/bin/env bash

# SemVer 2.0.0 with the repository's required v prefix. Numeric identifiers
# cannot contain leading zeroes; prerelease/build identifiers cannot be empty.
release_semver_pattern='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*)|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.((0|[1-9][0-9]*)|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'

is_release_semver_tag() {
    [[ "${1:-}" =~ ${release_semver_pattern} ]]
}

is_full_git_object_id() {
    [[ "${1:-}" =~ ^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$ ]]
}
