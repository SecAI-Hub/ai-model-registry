# Support

## Getting help

- **Issues:** [GitHub Issues](https://github.com/SecAI-Hub/ai-model-registry/issues)
- **Discussions:** [GitHub Discussions](https://github.com/SecAI-Hub/ai-model-registry/discussions)
- **Security:** See [SECURITY.md](SECURITY.md) for vulnerability reports

## FAQ

**Q: Do I need the full SecAI_OS appliance to use this?**
A: No. The registry runs standalone as a single Go binary. The appliance provides additional protections (quarantine pipeline, egress controls, sealed runtime) but the registry enforces its own trust model independently.

**Q: What happens if I don't set a service token?**
A: The service refuses to start. Set `INSECURE_DEV_MODE=true` only for an isolated local-development instance; it disables authentication for every non-health endpoint.

**Q: Can I use formats other than GGUF and SafeTensors?**
A: Not by default. The format allowlist is `gguf` and `safetensors`. Unsafe formats like pickle are blocked by design.
