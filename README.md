# KnexCoin Key Generator

Secure offline key generator for KnexCoin. Generates hybrid **Ed25519 + ML-DSA-65 (FIPS 204)** keypairs with post-quantum protection.

## Downloads

| Platform | Binary | Architecture |
|----------|--------|-------------|
| macOS | [`bin/macos/knex-keygen`](bin/macos/knex-keygen) | ARM64 (Apple Silicon) |
| Linux | [`bin/linux/knex-keygen`](bin/linux/knex-keygen) | x86_64 |
| Windows | [`bin/windows/knex-keygen.exe`](bin/windows/knex-keygen.exe) | x86_64 |

## Security Model

Private keys are **never** printed to the terminal. The generator:

1. Writes keys to an encrypted JSON file with `0600` permissions (owner-only)
2. Zeroizes all sensitive memory using the [`zeroize`](https://crates.io/crates/zeroize) crate
3. Clears the terminal screen and scrollback buffer on exit
4. Marks the output file as hidden on Windows

### Shell History Protection

Prefix the command with a space to prevent it from being recorded in shell history:

```bash
 knex-keygen    # note the leading space
```

Most shells (bash, zsh) skip history entries that start with a space when `HISTCONTROL=ignorespace` or `HISTCONTROL=ignoreboth` is set.

## Usage

```
knex-keygen [OPTIONS]

Options:
  -o, --output <path>  Output JSON file path (default: knex-keys-<timestamp>.json)
  --classical          Generate Ed25519 only (no ML-DSA-65)
  --no-clear           Don't clear terminal on exit (useful for scripting)
  -h, --help           Show help
```

### Generate Hybrid Keys (Recommended)

```bash
 knex-keygen
```

Output:
```
Generating hybrid keypair (Ed25519 + ML-DSA-65)...

=== KnexCoin Hybrid Key Generated (Ed25519 + ML-DSA-65) ===

  Address:  9tc3jrlk0ZQeMLQjS57AEjCsFKJDetKK3BWDp4pmxF9jNnjDjc
  Saved to: knex-keys-2026-02-22T04-26-27.json
  Mode:     owner read/write only

  Algorithms:
    Classical:    Ed25519
    Post-Quantum: ML-DSA-65 (FIPS 204)

  All keys are in the JSON file — NEVER share it.
  Bind the PQ key on-chain via a PqBind block.
  Transfer the file securely, then delete from this machine.

  Press ENTER to clear screen and exit...
```

### Generate Classical Keys Only

```bash
 knex-keygen --classical
```

### Custom Output Path

```bash
 knex-keygen -o /secure/usb/my-keys.json
```

## Output Format

The JSON file contains:

```json
{
  "generator": "KnexCoin Key Generator v3.1 (Hybrid PQ)",
  "generated": "2026-02-22T04:26:27.438Z",
  "network": "knexcoin-mainnet",
  "algorithms": {
    "classical": "Ed25519",
    "postQuantum": "ML-DSA-65 (FIPS 204)"
  },
  "address": "<50-char Base62>",
  "publicKeyHex": "<64 hex chars — 32 bytes>",
  "privateKey": "knexq1<50-char Base62>",
  "secretKeyHex": "<64 hex chars — 32 bytes>",
  "pqPublicKeyHex": "<3,904 hex chars — 1,952 bytes>",
  "pqSecretKeyHex": "<8,064 hex chars — 4,032 bytes>"
}
```

| Field | Size | Description |
|-------|------|-------------|
| `address` | 50 chars | Base62 account address (derived from Ed25519 public key) |
| `privateKey` | 56 chars | `knexq1` prefix + 50-char Base62 encoded secret key |
| `publicKeyHex` | 64 hex | Ed25519 public key (32 bytes) |
| `secretKeyHex` | 64 hex | Ed25519 secret key (32 bytes) |
| `pqPublicKeyHex` | 3,904 hex | ML-DSA-65 public key (1,952 bytes) |
| `pqSecretKeyHex` | 8,064 hex | ML-DSA-65 secret key (4,032 bytes) |

## Cryptography

| Algorithm | Standard | Key Sizes | Signature Size |
|-----------|----------|-----------|----------------|
| Ed25519 | RFC 8032 | 32 + 32 bytes | 64 bytes |
| ML-DSA-65 | FIPS 204 | 1,952 + 4,032 bytes | 3,309 bytes |

- **Address** is derived from the Ed25519 public key using SHA-256 checksum + Base62 encoding
- **ML-DSA-65** (formerly Dilithium) provides post-quantum resistance against Shor's algorithm
- Both keypairs are independently verified after generation before saving

## Post-Quantum Binding

After generating hybrid keys, the ML-DSA-65 public key must be bound to your account on-chain via a **PqBind block**. This creates a permanent association between your Ed25519 address and your post-quantum identity.

## Build from Source

Requires [Rust](https://rustup.rs/) 1.75+.

```bash
cargo build --release
```

The binary will be at `target/release/knex-keygen`.

### Cross-Compile for Windows (from Linux)

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64
cargo build --release --target x86_64-pc-windows-gnu
```

## Offline Best Practices

1. **Disconnect from the internet** before generating keys
2. Run the generator on an air-gapped machine if possible
3. Transfer the JSON file to a USB drive
4. Securely delete the key file from the generation machine:
   ```bash
   shred -vfz -n 5 knex-keys-*.json    # Linux
   rm -P knex-keys-*.json               # macOS
   ```
5. Store the USB drive in a secure location
6. Never email, upload, or paste your private keys anywhere

## License

MIT
