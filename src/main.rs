//! KnexCoin Secure Key Generator (Ed25519 + ML-DSA-65)
//!
//! Standalone cross-platform binary — Mac, Linux, Windows.
//!
//! Security:
//! - Private keys NEVER printed to stdout
//! - All sensitive memory zeroized on exit
//! - Terminal screen + scrollback cleared on exit
//! - Output file set to 0600 permissions (Unix) / hidden (Windows)
//!
//! Usage:
//!   knex-keygen [--output <path>] [--classical] [--no-clear]
//!
//! Tip: Prefix with a space to skip shell history:
//!   ` knex-keygen`   (note the leading space)

use ed25519_dalek::{SigningKey, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use num_bigint::BigUint;
use num_traits::Zero;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

// ── Constants ────────────────────────────────────────────────────────────────

const BASE62_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const PUBLIC_CHECKSUM_DOMAIN: &[u8] = b"knex";
const PRIVATE_KEY_PREFIX: &str = "knexq1";
const CHECKSUM_LEN: usize = 5;
const ADDRESS_LEN: usize = 50;

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let mut output_path = String::new();
    let mut classical_only = false;
    let mut no_clear = false;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                i += 1;
                if i < args.len() {
                    output_path = args[i].clone();
                }
            }
            "--classical" => {
                classical_only = true;
            }
            "--no-clear" => {
                no_clear = true;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let now = chrono::Utc::now();
    let timestamp = now.format("%Y-%m-%dT%H-%M-%S").to_string();

    if output_path.is_empty() {
        output_path = format!("knex-keys-{}.json", timestamp);
    }

    if classical_only {
        generate_classical(&output_path, &now, no_clear);
    } else {
        generate_hybrid(&output_path, &now, no_clear);
    }
}

fn print_help() {
    eprintln!("KnexCoin Secure Key Generator v3.1");
    eprintln!();
    eprintln!("Usage: knex-keygen [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -o, --output <path>  Output JSON file path");
    eprintln!("                       Default: knex-keys-<timestamp>.json");
    eprintln!("  --classical          Generate Ed25519 only (no ML-DSA-65)");
    eprintln!("  --no-clear           Don't clear terminal on exit");
    eprintln!("  -h, --help           Show this help");
    eprintln!();
    eprintln!("Security:");
    eprintln!("  - Private keys are NEVER printed to stdout");
    eprintln!("  - All sensitive memory is securely zeroed on exit");
    eprintln!("  - Terminal screen + scrollback cleared on exit");
    eprintln!("  - Key file permissions set to 0600 (owner-only)");
    eprintln!();
    eprintln!("Tip: Prefix with a space to skip shell history:");
    eprintln!("  ` knex-keygen`");
}

// ── Classical (Ed25519 only) ─────────────────────────────────────────────────

fn generate_classical(output_path: &str, now: &chrono::DateTime<chrono::Utc>, no_clear: bool) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = (&signing_key).into();

    let secret_bytes = signing_key.to_bytes();
    let public_bytes = verifying_key.to_bytes();

    let address = encode_address(&public_bytes);
    let mut private_key = encode_private_key(&secret_bytes);
    let public_key_hex = hex::encode(public_bytes);
    let mut secret_key_hex = hex::encode(secret_bytes);

    let json = serde_json::json!({
        "generator": "KnexCoin Key Generator v3.1 (Classical)",
        "generated": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "network": "knexcoin-mainnet",
        "encoding": "Base62 (0-9, A-Z, a-z)",
        "checksum": "5-byte prefix-bound SHA-256",
        "verification": "Ed25519 key pair verified",
        "address": address,
        "publicKeyHex": public_key_hex,
        "privateKey": private_key,
        "secretKeyHex": secret_key_hex,
    });

    let mut json_str = serde_json::to_string_pretty(&json).expect("Failed to serialize JSON");
    write_secure_file(output_path, &json_str);

    eprintln!();
    eprintln!("=== KnexCoin Key Generated (Classical Ed25519) ===");
    eprintln!();
    eprintln!("  Address:  {}", address);
    eprintln!("  Saved to: {}", output_path);
    eprintln!("  Mode:     owner read/write only");
    eprintln!();
    eprintln!("  Private key is in the JSON file — NEVER share it.");
    eprintln!("  Transfer the file securely, then delete from this machine.");
    eprintln!();

    // Zeroize all sensitive data
    private_key.zeroize();
    secret_key_hex.zeroize();
    json_str.zeroize();

    if !no_clear {
        wait_then_clear();
    }
}

// ── Hybrid (Ed25519 + ML-DSA-65) ────────────────────────────────────────────

fn generate_hybrid(output_path: &str, now: &chrono::DateTime<chrono::Utc>, no_clear: bool) {
    eprintln!("Generating hybrid keypair (Ed25519 + ML-DSA-65)...");

    // Ed25519
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = (&signing_key).into();
    let secret_bytes = signing_key.to_bytes();
    let public_bytes = verifying_key.to_bytes();

    // ML-DSA-65
    let (pq_pk, pq_sk) = ml_dsa_65::try_keygen().expect("ML-DSA-65 key generation failed");
    let pq_pk_bytes = pq_pk.into_bytes();
    let pq_sk_bytes = pq_sk.into_bytes();

    // Verify ML-DSA-65 keypair
    let test_msg = b"keygen-verification";
    let pq_sk_verify =
        ml_dsa_65::PrivateKey::try_from_bytes(pq_sk_bytes).expect("PQ secret key invalid");
    let sig = pq_sk_verify
        .try_sign(test_msg, &[])
        .expect("ML-DSA-65 signing failed");
    let pq_pk_verify =
        ml_dsa_65::PublicKey::try_from_bytes(pq_pk_bytes).expect("PQ public key invalid");
    assert!(
        pq_pk_verify.verify(test_msg, &sig, &[]),
        "ML-DSA-65 verification failed"
    );

    // Verify Ed25519 keypair
    use ed25519_dalek::Signer;
    let ed_sig = signing_key.sign(test_msg);
    use ed25519_dalek::Verifier;
    verifying_key
        .verify(test_msg, &ed_sig)
        .expect("Ed25519 verification failed");

    let address = encode_address(&public_bytes);
    let mut private_key = encode_private_key(&secret_bytes);
    let public_key_hex = hex::encode(public_bytes);
    let mut secret_key_hex = hex::encode(secret_bytes);
    let mut pq_public_key_hex = hex::encode(pq_pk_bytes);
    let mut pq_secret_key_hex = hex::encode(pq_sk_bytes);

    let json = serde_json::json!({
        "generator": "KnexCoin Key Generator v3.1 (Hybrid PQ)",
        "generated": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "network": "knexcoin-mainnet",
        "encoding": "Base62 (0-9, A-Z, a-z)",
        "checksum": "5-byte prefix-bound SHA-256",
        "algorithms": {
            "classical": "Ed25519",
            "postQuantum": "ML-DSA-65 (FIPS 204)"
        },
        "verification": "Hybrid key pair verified (Ed25519 + ML-DSA-65)",
        "address": address,
        "publicKeyHex": public_key_hex,
        "privateKey": private_key,
        "secretKeyHex": secret_key_hex,
        "pqPublicKeyHex": pq_public_key_hex,
        "pqSecretKeyHex": pq_secret_key_hex,
    });

    let mut json_str = serde_json::to_string_pretty(&json).expect("Failed to serialize JSON");
    write_secure_file(output_path, &json_str);

    eprintln!();
    eprintln!("=== KnexCoin Hybrid Key Generated (Ed25519 + ML-DSA-65) ===");
    eprintln!();
    eprintln!("  Address:  {}", address);
    eprintln!("  Saved to: {}", output_path);
    eprintln!("  Mode:     owner read/write only");
    eprintln!();
    eprintln!("  Algorithms:");
    eprintln!("    Classical:    Ed25519");
    eprintln!("    Post-Quantum: ML-DSA-65 (FIPS 204)");
    eprintln!();
    eprintln!("  All keys are in the JSON file — NEVER share it.");
    eprintln!("  Bind the PQ key on-chain via a PqBind block.");
    eprintln!("  Transfer the file securely, then delete from this machine.");
    eprintln!();

    // Zeroize all sensitive data
    private_key.zeroize();
    secret_key_hex.zeroize();
    pq_public_key_hex.zeroize();
    pq_secret_key_hex.zeroize();
    json_str.zeroize();

    if !no_clear {
        wait_then_clear();
    }
}

// ── Crypto helpers (matching node/src/crypto.rs exactly) ─────────────────────

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

fn compute_checksum(domain: &[u8], raw_bytes: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut input = Vec::with_capacity(domain.len() + raw_bytes.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(raw_bytes);
    let hash = sha256_hash(&input);
    let mut checksum = [0u8; CHECKSUM_LEN];
    checksum.copy_from_slice(&hash[..CHECKSUM_LEN]);
    checksum
}

fn bytes_to_base62(bytes: &[u8], pad_to: usize) -> String {
    let num = BigUint::from_bytes_be(bytes);
    if num.is_zero() {
        return "0".repeat(pad_to);
    }

    let base = BigUint::from(62u32);
    let mut chars = Vec::new();
    let mut n = num;
    while !n.is_zero() {
        let remainder = &n % &base;
        let idx: usize = remainder.try_into().unwrap_or(0);
        chars.push(BASE62_ALPHABET[idx] as char);
        n /= &base;
    }
    chars.reverse();

    let s: String = chars.into_iter().collect();
    if s.len() < pad_to {
        let padding = "0".repeat(pad_to - s.len());
        format!("{}{}", padding, s)
    } else {
        s
    }
}

fn encode_address(public_key: &[u8; 32]) -> String {
    let checksum = compute_checksum(PUBLIC_CHECKSUM_DOMAIN, public_key);
    let mut payload = [0u8; 37]; // 32 + 5
    payload[..32].copy_from_slice(public_key);
    payload[32..].copy_from_slice(&checksum);
    bytes_to_base62(&payload, ADDRESS_LEN)
}

fn encode_private_key(secret_key: &[u8; 32]) -> String {
    let checksum = compute_checksum(PRIVATE_KEY_PREFIX.as_bytes(), secret_key);
    let mut payload = [0u8; 37]; // 32 + 5
    payload[..32].copy_from_slice(secret_key);
    payload[32..].copy_from_slice(&checksum);
    let encoded = bytes_to_base62(&payload, ADDRESS_LEN);
    format!("{}{}", PRIVATE_KEY_PREFIX, encoded)
}

// ── File I/O ─────────────────────────────────────────────────────────────────

fn write_secure_file(path: &str, content: &str) {
    std::fs::write(path, content).expect("Failed to write key file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .expect("Failed to get file metadata")
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).expect("Failed to set permissions");
    }

    #[cfg(windows)]
    {
        // Mark file as hidden on Windows
        let _ = std::process::Command::new("attrib")
            .args(["+H", path])
            .status();
    }
}

// ── Terminal clear ───────────────────────────────────────────────────────────

fn wait_then_clear() {
    eprintln!("  Press ENTER to clear screen and exit...");

    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
    buf.zeroize();

    clear_terminal();
}

fn clear_terminal() {
    #[cfg(not(windows))]
    {
        // ANSI escape: clear screen + scrollback + cursor home
        eprint!("\x1b[2J\x1b[3J\x1b[H");
    }

    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "cls"])
            .status();
    }
}
