# Security policy

Open-Guardian is a local privacy and secret boundary. Treat defects involving model egress, credential handling, DLP bypass, network exposure, vault parsing/decryption, or rule integrity as security-sensitive.

## Supported versions

Security fixes are developed against the latest tagged release and the current `main` branch. Portable-vault writes, device pairing, recovery, and rollback protection remain explicitly outside the stable security boundary.

## Private reporting

Use GitHub's **Security > Report a vulnerability** flow for this repository when available. Do not open a public issue containing a real credential, private prompt, vault, identity, internal address, or exploit that puts deployed users at immediate risk.

Use only synthetic data in a reproduction. Include:

- Affected version or commit.
- Operating system and enabled Cargo features.
- Minimal configuration with opaque `SecretRef` values.
- Expected and observed boundary behavior.
- Whether a value reached a model body, URL, header, error, log, response, or another request.
- A small test or request that reproduces the issue without live secrets.

Maintainers should acknowledge a private report before discussing disclosure timing. Rotate any real credential that may have been exposed; deleting a message or ciphertext does not revoke a copied value.

## Security assumptions

Open-Guardian assumes the local operating system and unlocked process are trusted. It does not protect against malware with process-memory, clipboard, accessibility, screen, debugger, or native credential-store access.

Default deployments bind to loopback and route unmatched models locally. External egress must be configured explicitly. The proxy inspects text and never executes model-generated commands.

The portable vault is currently a read-only prototype. It has bounded authenticated age decryption but no rollback anchor, pairing, recovery, mutation, or revocation workflow. Do not use it as the sole store for unrecoverable credentials, and do not build production write paths until every gate in [ADR-0001](docs/adr/0001-portable-vault-format.md) is complete.

## Handling fixes

Security changes should follow [CONTRIBUTING.md](CONTRIBUTING.md): one auditable behavior per commit, a regression test proving data placement or fail-closed behavior, locked dependencies, cross-feature checks, and documentation updated in the same change.
