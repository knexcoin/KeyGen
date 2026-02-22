# Installation

## Pre-built Binaries

Download the binary for your platform from the [`bin/`](https://github.com/knexcoin/KeyGen/tree/main/bin) directory:

| Platform | File | Architecture |
|----------|------|-------------|
| macOS | `bin/macos/knex-keygen` | ARM64 (Apple Silicon) |
| Linux | `bin/linux/knex-keygen` | x86_64 |
| Windows | `bin/windows/knex-keygen.exe` | x86_64 |

## macOS

```bash
# Download
curl -L -o knex-keygen https://github.com/knexcoin/KeyGen/raw/main/bin/macos/knex-keygen

# Make executable
chmod +x knex-keygen

# Run (bypass Gatekeeper for unsigned binary)
xattr -d com.apple.quarantine knex-keygen

# Generate keys (note the leading space to skip shell history)
 ./knex-keygen
```

## Linux

```bash
# Download
curl -L -o knex-keygen https://github.com/knexcoin/KeyGen/raw/main/bin/linux/knex-keygen

# Make executable
chmod +x knex-keygen

# Generate keys
 ./knex-keygen
```

## Windows

1. Download `knex-keygen.exe` from [`bin/windows/`](https://github.com/knexcoin/KeyGen/tree/main/bin/windows)
2. Open Command Prompt or PowerShell
3. Navigate to the download directory
4. Run:
```cmd
knex-keygen.exe
```

## Verify Integrity

After downloading, verify the binary by generating a test key with `--no-clear`:

```bash
 ./knex-keygen --classical --no-clear -o /tmp/test.json
cat /tmp/test.json
rm /tmp/test.json
```

The output should contain a valid `address` (50-char Base62) and `privateKey` (starting with `knexq1`).
