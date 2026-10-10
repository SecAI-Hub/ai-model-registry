FROM docker.io/library/golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY build/gguf-guard.lock /tmp/gguf-guard.lock
RUN set -eu; \
    . /tmp/gguf-guard.lock; \
    mkdir -p /tmp/gguf-guard; \
    wget -qO /tmp/gguf-guard.tar.gz "${GGUF_GUARD_REPOSITORY}/archive/${GGUF_GUARD_COMMIT}.tar.gz"; \
    echo "${GGUF_GUARD_ARCHIVE_SHA256}  /tmp/gguf-guard.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gguf-guard.tar.gz --strip-components=1 -C /tmp/gguf-guard; \
    cd /tmp/gguf-guard; \
    go mod download; \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gguf-guard ./cmd/gguf-guard/; \
    cd /src; \
    guard_sha256="$(sha256sum /out/gguf-guard | awk '{print $1}')"; \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.ggufGuardSHA256=${guard_sha256}" -o /out/registry .; \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/securectl ./cmd/securectl/

FROM docker.io/library/alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
LABEL org.opencontainers.image.source="https://github.com/SecAI-Hub/ai-model-registry" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN install -d -m 0755 /etc/ssl/certs && \
    install -d -o 65534 -g 65534 -m 0750 /registry /var/lib/secure-ai/logs /run/secure-ai
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/registry /usr/local/bin/registry
COPY --from=build /out/securectl /usr/local/bin/securectl
COPY --from=build /out/gguf-guard /usr/local/bin/gguf-guard
ENV BIND_ADDR=0.0.0.0:8470 \
    ALLOW_REMOTE_BIND=true
USER 65534:65534
EXPOSE 8470
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD wget -q -T 3 -O - http://127.0.0.1:8470/health >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/registry"]
