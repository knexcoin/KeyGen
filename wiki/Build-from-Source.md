# Build from Source

## Prerequisites

- [Rust](https://rustup.rs/) 1.75 or later
- Git

## Clone and Build

```bash
git clone https://github.com/knexcoin/KeyGen.git
cd KeyGen
cargo build --release
```

The binary will be at `target/release/knex-keygen` (or `knex-keygen.exe` on Windows).

## Platform-Specific Builds

### macOS (Apple Silicon)

```bash
cargo build --release
# Binary: target/release/knex-keygen
```

### macOS (Intel)

```bash
rustup target add x86_64-apple-darwin
cargo build --release --target x86_64-apple-darwin
```

### Linux (x86_64)

```bash
cargo build --release
# Binary: target/release/knex-keygen
```

### Windows (Native)

```cmd
cargo build --release
# Binary: target\release\knex-keygen.exe
```

### Windows (Cross-compile from Linux)

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64
cargo build --release --target x86_64-pc-windows-gnu
# Binary: target/x86_64-pc-windows-gnu/release/knex-keygen.exe
```

## Release Profile

The `Cargo.toml` includes an optimized release profile:

```toml
[profile.release]
opt-level = "z"     # Optimize for binary size
lto = true          # Link-time optimization
strip = true        # Strip debug symbols
codegen-units = 1   # Single codegen unit for better optimization
```

This produces compact binaries (~500 KB).

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `ed25519-dalek` | 2.x | Ed25519 key generation and signing |
| `fips204` | 0.4 | ML-DSA-65 (FIPS 204) post-quantum signatures |
| `sha2` | 0.10 | SHA-256 for address checksums |
| `zeroize` | 1.x | Secure memory zeroing |
| `num-bigint` | 0.4 | Big integer arithmetic for Base62 encoding |
| `rand` | 0.8 | Cryptographically secure random number generation |
| `chrono` | 0.4 | Timestamp for output filenames |
| `serde_json` | 1.x | JSON serialization |
| `hex` | 0.4 | Hexadecimal encoding |

All cryptographic operations use audited, well-maintained crates from the Rust ecosystem.
