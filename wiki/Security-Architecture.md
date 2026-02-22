# Security Architecture

## Threat Model

The key generator is designed for **air-gapped offline use**. It assumes:

- The machine may be compromised after key generation
- Terminal scrollback and shell history are attack surfaces
- Memory forensics may recover sensitive data

## Protections

### 1. No Stdout Leakage

Private keys, secret keys, and PQ keys are **never** printed to stdout or stderr. Only the public address and output file path are displayed. This prevents:

- Terminal scrollback capture
- Screen recording leaks
- Process output logging by the OS

### 2. Memory Zeroization

All sensitive strings are securely overwritten in memory using the [`zeroize`](https://crates.io/crates/zeroize) crate before the process exits:

- `privateKey` (Base62-encoded secret key)
- `secretKeyHex` (raw Ed25519 secret bytes)
- `pqPublicKeyHex` (ML-DSA-65 public key)
- `pqSecretKeyHex` (ML-DSA-65 secret key)
- `json_str` (the full JSON content written to disk)

The `zeroize` crate uses compiler barriers to prevent dead-store elimination — the compiler cannot optimize away the zeroing.

### 3. Terminal Clearing

After the user presses ENTER, the generator clears:

- The visible terminal screen (`\x1b[2J`)
- The terminal scrollback buffer (`\x1b[3J`)
- Resets cursor to home position (`\x1b[H`)

On Windows, `cls` is used instead of ANSI escape codes.

Use `--no-clear` to disable this behavior (e.g., for scripting).

### 4. File Permissions

The output JSON file is created with `0600` permissions on Unix (owner read/write only). On Windows, the file is marked as hidden via `attrib +H`.

### 5. Shell History Avoidance

Prefix the command with a space to prevent shell history recording:

```bash
 knex-keygen    # leading space — not saved to history
```

This works when `HISTCONTROL=ignorespace` or `HISTCONTROL=ignoreboth` is set (default on most systems).

## Recommended Workflow

1. **Disconnect** from the internet
2. Run the generator on an air-gapped machine
3. Copy the JSON file to an encrypted USB drive
4. **Securely delete** the file from the machine:
   ```bash
   shred -vfz -n 5 knex-keys-*.json    # Linux
   rm -P knex-keys-*.json               # macOS
   ```
5. Store the USB drive in a physically secure location
6. Re-enter the address (public only) on your connected machine
