# ADR-0001: Portable vault built on the age v1 format

- Status: Accepted for prototyping; production writes remain gated
- Date: 2026-07-18
- Owners: Open-Guardian maintainers

## Context

Open-Guardian needs a `vault://` backend that can move encrypted secrets between a laptop, server, and eventually mobile devices. A copied vault must remain useless without an authorized device identity or recovery identity. The model, proxy logs, index, and generic chat API must never receive decrypted values.

Designing our own envelope format would require getting file-key generation, recipient wrapping, AEAD nonces, KDF parameters, framing, truncation detection, versioning, and interoperability right. That is outside this project's core competence and creates an unnecessary cryptographic maintenance burden.

## Decision

The portable vault will be an **age v1 compatible encrypted file**, not a custom cryptographic container.

- The encrypted payload uses the published age v1 file format.
- Each authorized device receives its own age recipient/identity pair.
- The vault is encrypted to all currently authorized recipients.
- A separate recovery identity is another recipient. If protected by a human passphrase, the recovery identity—not the vault payload—is wrapped using age's passphrase/scrypt mechanism.
- Device private identities live in the native OS credential store and never beside the vault.
- Adding or revoking a device decrypts and re-encrypts the complete vault to a new recipient set and fresh file key.
- The Rust implementation will use the `age` library behind a crate feature. The exact crate release will be pinned only after compatibility and security review because the crate remains pre-1.0 and labels itself beta.
- Native identity storage will use `keyring-core` plus an explicitly selected platform store rather than enabling every store through an all-in-one default.

The [age v1 specification](https://age-encryption.org/v1) defines a fresh random file key, independently wrapped recipient stanzas, an authenticated header, and a chunked ChaCha20-Poly1305 payload. The official Rust library supports multiple X25519 recipients through `Encryptor::with_recipients`; the `rage` CLI provides an independent interoperability target ([age Rust API](https://docs.rs/age/latest/age/), [rage repository](https://github.com/str4d/rage)). The keyring ecosystem provides platform-specific secure-store adapters and includes heap-leak testing guidance ([keyring-rs](https://github.com/open-source-cooperative/keyring-rs)).

## File and payload contract

The outer file is raw binary age ciphertext and uses the extension `.guardian.age`. ASCII armor is not used by default because it increases size without improving local storage security.

The encrypted plaintext is a versioned data document:

```text
VaultPayloadV1
  format_version
  vault_id
  generation
  created_at
  updated_at
  entries[]
    logical_path
    fields{}
    created_at
    updated_at
```

`logical_path` and field names obey the same canonical rules as `SecretRef`. The payload never stores device private keys. Recipient metadata is derived from the age header and a separately authenticated local device registry.

The first implementation may use a simple versioned serialization, but it must meet all of these gates before production use:

1. Strict size, count, nesting, and string-length limits before allocation.
2. Duplicate logical paths and fields rejected.
3. Unknown format versions rejected without mutation.
4. Plaintext buffers wrapped in zeroizing containers.
5. No `Debug`, error, telemetry, panic, or serialization path can include a value.
6. Golden compatibility tests decrypt with `rage` and decrypt a `rage` fixture.
7. Corruption, truncation, wrong-identity, stale-generation, and concurrent-write tests.
8. Fuzzing for the decrypted payload parser and `SecretRef` mapping.

## Identity and recovery lifecycle

### Initialize

1. Generate a device identity with the OS CSPRNG.
2. Store the private identity in the platform credential store.
3. Generate a separate recovery identity.
4. Encrypt an empty payload to the device and recovery recipients.
5. Present the recovery material once; never write it to logs or the vault directory.

### Pair a device

1. The new device generates its identity locally and sends only its recipient/public value.
2. An already-authorized device displays both recipient fingerprints for human verification.
3. After confirmation, it decrypts the current vault and atomically re-encrypts it to the expanded recipient set.

### Revoke a device

1. Remove the recipient from the authorized set.
2. Re-encrypt the entire payload, producing a fresh age file key and nonce.
3. Advance the generation counter and local rollback anchor.

Revocation cannot make an already downloaded historical ciphertext or a previously revealed secret disappear. High-risk underlying credentials must be rotated after device compromise.

## Rollback and concurrent writes

Age authenticates a file but cannot distinguish a valid old copy from the newest valid copy. Each device therefore stores the highest observed `(vault_id, generation, ciphertext_hash)` in its native credential store.

- A lower generation is rejected as rollback.
- The same generation with a different hash is rejected as a conflict.
- A write uses compare-and-swap against the generation it read.
- A device without a writable native rollback anchor may open read-only with a prominent degraded-security status; it may not mutate the vault.

This is local rollback detection, not global consensus. File synchronization conflicts are surfaced for explicit resolution and are never merged at field level automatically.

## Atomic persistence

Vault writes must:

1. Serialize into zeroizing memory.
2. Encrypt to a temporary file in the destination directory.
3. Set owner-only permissions where the platform supports them.
4. Flush and `fsync` the temporary file.
5. Atomically rename over the destination.
6. `fsync` the parent directory where supported.
7. Update the native rollback anchor only after the rename succeeds.

No plaintext temporary file is ever created.

## SecretBackend API

The implementation will add a backend with scheme `vault`:

```rust,ignore
let reference: SecretRef =
    "{{secret:vault://infrastructure/proxmox#password}}".parse()?;
let value = broker.resolve(&reference).await?;
```

Opening, unlocking, pairing, mutation, and recovery are separate administrative APIs. `SecretBackend::resolve` is read-only and cannot trigger pairing, migration, shell commands, network calls, or interactive prompts.

## Security boundaries

The design protects against:

- Theft or copying of a locked vault file.
- Accidental commit, backup, or sync of ciphertext.
- Corruption and modification without an authorized identity.
- A removed device decrypting future generations.
- Literal secret values entering provider configuration.

It does not protect against:

- A compromised device while the vault is unlocked.
- Malware reading process memory, clipboard contents, or UI pixels.
- A user intentionally exporting or revealing a value.
- Recovery material stored beside the ciphertext.
- An authorized device retaining an older vault or previously revealed values.

## Rejected alternatives

### Custom XChaCha20-Poly1305 envelope

Rejected. Even with sound primitives, format and lifecycle mistakes would become our responsibility and interoperability would be poor.

### One shared passphrase for every device

Rejected as the primary design. It prevents per-device revocation and encourages weak, reused human secrets. Passphrases are limited to protecting recovery material.

### Plain encrypted SQLite database

Rejected for the portable format. It couples storage layout, page-level crypto, migrations, and platform bindings. The vault is expected to be small enough for authenticated whole-file replacement.

### Environment variable containing the vault identity

Rejected for normal use. It remains acceptable only in explicit headless/test modes with a degraded-security warning because child processes and process inspection may expose environment variables.

## Implementation gates

Production `vault set`, `vault pair`, and `vault revoke` commands remain disabled until:

- The exact `age` and platform keyring versions are pinned.
- macOS, Windows, Linux desktop, and headless behavior are documented.
- Interoperability, fuzz, rollback, atomic-write, and heap-leak tests pass.
- A maintainer security review approves the payload schema and recovery UX.

Until then, `env://` is the only enabled SecretBroker backend and the vault work is non-destructive.
