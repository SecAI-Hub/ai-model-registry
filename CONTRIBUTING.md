# Contributing

Thank you for your interest in contributing to ai-model-registry.

## Getting started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-change`
3. Run tests: `go test -v -race ./...`
4. Commit your changes
5. Open a pull request

## Development setup

```bash
go build -o registry .
go build -o securectl ./cmd/securectl/

# Run tests
go test -v -race -count=1 ./...

# Lint
go vet ./...
```

## Guidelines

- All changes must include tests
- Run `go vet ./...` before submitting
- Follow existing code style
- Security-sensitive changes require review from a maintainer
- Do not weaken default security posture (fail-closed auth, state isolation, format allowlists)

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md) for reporting instructions. Do not open a public issue.
