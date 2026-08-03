#!/usr/bin/env sh
set -eu

image="${1:-ai-model-registry:ci}"
suffix="${GITHUB_RUN_ID:-local}-$$"
container_name="secai-registry-lifecycle-${suffix}"
volume_name="secai-registry-lifecycle-${suffix}"
profile="$(pwd)/deploy/seccomp/ai-model-registry.json"
service_token="$(head -c 48 /dev/zero | tr '\000' t)"

cleanup() {
    docker rm --force "${container_name}" >/dev/null 2>&1 || true
    if ! docker volume inspect "${volume_name}" >/dev/null 2>&1; then
        return
    fi
    attempt=1
    while [ "${attempt}" -le 10 ]; do
        if docker volume rm "${volume_name}" >/dev/null 2>&1; then
            return
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    docker volume rm "${volume_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

test -f "${profile}"
docker volume create "${volume_name}" >/dev/null
docker run --rm --user 0:0 \
    -e SMOKE_SERVICE_TOKEN="${service_token}" \
    -v "${volume_name}:/registry" \
    --entrypoint /bin/sh "${image}" -c '
        set -eu
        umask 077
        printf "%s" "${SMOKE_SERVICE_TOKEN}" > /registry/service-token
        printf "%s" "SecAI registry lifecycle smoke artifact" > /registry/lifecycle.safetensors
        chown -R 65534:65534 /registry
        chmod 0750 /registry
        chmod 0600 /registry/service-token /registry/lifecycle.safetensors
    '

artifact_sha256="$(docker run --rm -v "${volume_name}:/registry:ro" --entrypoint /bin/sh "${image}" -c \
    'sha256sum /registry/lifecycle.safetensors' | awk '{print $1}')"
artifact_size="$(docker run --rm -v "${volume_name}:/registry:ro" --entrypoint /bin/sh "${image}" -c \
    'wc -c < /registry/lifecycle.safetensors' | tr -d ' ')"

docker run --rm -d --name "${container_name}" \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --security-opt="seccomp=${profile}" \
    --pids-limit=64 \
    -p 127.0.0.1::8470 \
    -e SERVICE_TOKEN_PATH=/registry/service-token \
    -v "${volume_name}:/registry" \
    "${image}" >/dev/null

host_port="$(docker port "${container_name}" 8470/tcp | sed 's/.*://')"
ready=false
attempt=1
while [ "${attempt}" -le 15 ]; do
    if curl --fail --silent --show-error "http://127.0.0.1:${host_port}/health" >/dev/null 2>&1; then
        ready=true
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
if [ "${ready}" != true ]; then
    docker logs "${container_name}" >&2
    exit 1
fi

authorization="Authorization: Bearer ${service_token}"
base_url="http://127.0.0.1:${host_port}"
acquire_payload="$(printf \
    '{"name":"lifecycle","filename":"lifecycle.safetensors","sha256":"%s","size_bytes":%s}' \
    "${artifact_sha256}" "${artifact_size}")"
curl --fail --silent --show-error -X POST "${base_url}/v1/model/acquire" \
    -H "${authorization}" -H 'Content-Type: application/json' \
    --data "${acquire_payload}" >/dev/null
curl --fail --silent --show-error -X POST "${base_url}/v1/model/quarantine?name=lifecycle" \
    -H "${authorization}" >/dev/null

promote_payload="$(printf \
    '{"name":"lifecycle","filename":"lifecycle.safetensors","sha256":"%s","size_bytes":%s,"scan_results":{"modelscan":"pass"},"scanner_versions":{"modelscan":"smoke"},"policy_version":"seccomp-smoke-v1"}' \
    "${artifact_sha256}" "${artifact_size}")"
curl --fail --silent --show-error -X POST "${base_url}/v1/model/promote" \
    -H "${authorization}" -H 'Content-Type: application/json' \
    --data "${promote_payload}" >/dev/null

runtime_locator="$(curl --fail --silent --show-error \
    -H "${authorization}" "${base_url}/v1/model/path?name=lifecycle")"
expected_object="objects/sha256/$(printf '%s' "${artifact_sha256}" | cut -c1-2)/${artifact_sha256}.safetensors"
case "${runtime_locator}" in
    *"\"sha256\":\"${artifact_sha256}\""*) ;;
    *)
        printf '%s\n' "unexpected runtime locator: ${runtime_locator}" >&2
        exit 1
        ;;
esac
case "${runtime_locator}" in
    *'"storage_contract":"content-addressed-v1"'*) ;;
    *)
        printf '%s\n' "runtime locator omitted the content-addressed contract: ${runtime_locator}" >&2
        exit 1
        ;;
esac
case "${runtime_locator}" in
    *"${expected_object}"*) ;;
    *)
        printf '%s\n' "runtime locator did not use the expected digest path: ${runtime_locator}" >&2
        exit 1
        ;;
esac

verify_result="$(curl --fail --silent --show-error -X POST \
    -H "${authorization}" "${base_url}/v1/model/verify?name=lifecycle")"
case "${verify_result}" in
    *'"safe_to_use":"true"'*"\"sha256\":\"${artifact_sha256}\""*) ;;
    *)
        printf '%s\n' "unexpected verify result: ${verify_result}" >&2
        exit 1
        ;;
esac

printf '%s\n' "seccomp lifecycle smoke passed"
