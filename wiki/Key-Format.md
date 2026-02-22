# Key Format

## JSON Structure

### Hybrid Keys (Ed25519 + ML-DSA-65)

```json
{
  "generator": "KnexCoin Key Generator v3.1 (Hybrid PQ)",
  "generated": "2026-02-22T04:26:27.438Z",
  "network": "knexcoin-mainnet",
  "encoding": "Base62 (0-9, A-Z, a-z)",
  "checksum": "5-byte prefix-bound SHA-256",
  "algorithms": {
    "classical": "Ed25519",
    "postQuantum": "ML-DSA-65 (FIPS 204)"
  },
  "verification": "Hybrid key pair verified (Ed25519 + ML-DSA-65)",
  "address": "<50-char Base62>",
  "publicKeyHex": "<64 hex>",
  "privateKey": "knexq1<50-char Base62>",
  "secretKeyHex": "<64 hex>",
  "pqPublicKeyHex": "<3,904 hex>",
  "pqSecretKeyHex": "<8,064 hex>"
}
```

### Classical Keys (Ed25519 only)

Generated with `--classical` flag. Same as above but without `pqPublicKeyHex`, `pqSecretKeyHex`, and `algorithms` fields.

## Field Reference

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `address` | Base62 | 50 chars | Account address derived from Ed25519 public key |
| `publicKeyHex` | Hex | 64 chars (32 bytes) | Ed25519 public key |
| `privateKey` | Base62 | 56 chars | `knexq1` + 50-char encoded secret with checksum |
| `secretKeyHex` | Hex | 64 chars (32 bytes) | Raw Ed25519 secret key bytes |
| `pqPublicKeyHex` | Hex | 3,904 chars (1,952 bytes) | ML-DSA-65 public key |
| `pqSecretKeyHex` | Hex | 8,064 chars (4,032 bytes) | ML-DSA-65 secret key |

## Address Encoding

The 50-character Base62 address is computed as:

```
payload = Ed25519_PublicKey (32 bytes) || SHA-256("knex" || PublicKey)[0:5]
address = Base62(payload).padStart(50, '0')
```

**Base62 alphabet:** `0-9 A-Z a-z` (62 characters, case-sensitive)

## Private Key Encoding

The 56-character private key is:

```
payload = Ed25519_SecretKey (32 bytes) || SHA-256("knexq1" || SecretKey)[0:5]
privateKey = "knexq1" + Base62(payload).padStart(50, '0')
```

The `knexq1` prefix identifies the key format version and enables checksum verification.

## Key Sizes Summary

| Algorithm | Public Key | Secret Key | Signature |
|-----------|-----------|------------|-----------|
| Ed25519 | 32 bytes | 32 bytes | 64 bytes |
| ML-DSA-65 | 1,952 bytes | 4,032 bytes | 3,309 bytes |
| **Total (Hybrid)** | **1,984 bytes** | **4,064 bytes** | **3,373 bytes** |
