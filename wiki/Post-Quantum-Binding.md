# Post-Quantum Binding

## Overview

KnexCoin uses a **hybrid signature model**: accounts are identified by their Ed25519 public key (address), while post-quantum ML-DSA-65 keys provide protection against future quantum computers.

The ML-DSA-65 public key must be **bound** to the Ed25519 account on-chain via a special `PqBind` block. Once bound, all subsequent transactions from that account require dual signatures (Ed25519 + ML-DSA-65).

## Why Binding?

- **Backward compatibility**: Existing Ed25519-only accounts continue to work
- **Opt-in quantum protection**: Users choose when to upgrade
- **On-chain commitment**: The PQ public key is permanently associated with the account
- **Dual-signature enforcement**: After binding, transactions require both signatures

## PqBind Block

The `PqBind` block (type 7) registers a post-quantum public key for an account:

```
Block Type: PqBind (7)
Account:    <Ed25519 public key>
PQ Key:     <ML-DSA-65 public key — 1,952 bytes>
Ed25519 Sig: <signed by Ed25519 secret key>
ML-DSA Sig:  <signed by ML-DSA-65 secret key>
```

Both signatures must verify against the message, proving ownership of both key pairs.

## Workflow

1. **Generate** hybrid keys with `knex-keygen`
2. **Fund** the account using the Ed25519 address
3. **Submit** a `PqBind` block with the ML-DSA-65 public key
4. **All future** blocks from this account require dual signatures

## Security Considerations

- The PQ binding is **permanent** — it cannot be removed once confirmed
- The ML-DSA-65 secret key must be kept as secure as the Ed25519 secret key
- NFC cards use Ed25519 only (hardware constraints); wallet software handles dual signing
- The address never changes — it is always derived from the Ed25519 public key
