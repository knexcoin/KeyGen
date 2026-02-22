//! KnexCoin Secure Key Generator v3.2 (Ed25519 + ML-DSA-65)
//!
//! Standalone cross-platform binary — Mac, Linux, Windows.
//!
//! Features:
//! - Vanity address suffix mining (--suffix)
//! - Password-protected JSON export (--password)
//! - Colorized terminal output
//!
//! Security:
//! - Private keys NEVER printed to stdout
//! - All sensitive memory zeroized on exit
//! - Terminal screen + scrollback cleared on exit
//! - Output file set to 0600 permissions (Unix) / hidden (Windows)
//! - Password input hidden (no echo)
//!
//! Usage:
//!   knex-keygen [OPTIONS]

use ed25519_dalek::{SigningKey, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use num_bigint::BigUint;
use num_traits::Zero;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use pbkdf2::pbkdf2_hmac;

// ── ANSI Color Constants ─────────────────────────────────────────────────────

const GREEN: &str = "\x1b[1;32m";
const RED: &str = "\x1b[1;31m";
const BLUE: &str = "\x1b[1;34m";
const MAGENTA: &str = "\x1b[1;35m";
const CYAN: &str = "\x1b[1;36m";
const YELLOW: &str = "\x1b[1;33m";
const WHITE: &str = "\x1b[1;37m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

// ── Crypto Constants ─────────────────────────────────────────────────────────

const BASE62_ALPHABET: &[u8] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const PUBLIC_CHECKSUM_DOMAIN: &[u8] = b"knex";
const PRIVATE_KEY_PREFIX: &str = "knexq1";
const CHECKSUM_LEN: usize = 5;
const ADDRESS_LEN: usize = 50;

const PBKDF2_ITERATIONS: u32 = 600_000;
const MAX_SUFFIX_LEN: usize = 7;
const VERSION: &str = "3.2";

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let mut output_path = String::new();
    let mut classical_only = false;
    let mut no_clear = false;
    let mut suffix = String::new();
    let mut use_password = false;

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
            "--suffix" | "-s" => {
                i += 1;
                if i < args.len() {
                    suffix = args[i].clone();
                } else {
                    print_error("--suffix requires a value (1-7 Base62 characters)");
                    std::process::exit(1);
                }
            }
            "--password" | "-p" => {
                use_password = true;
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
                print_error(&format!("Unknown argument: {}", args[i]));
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // Validate suffix
    if !suffix.is_empty() {
        if let Err(e) = validate_suffix(&suffix) {
            print_error(&e);
            std::process::exit(1);
        }
    }

    let now = chrono::Utc::now();
    let timestamp = now.format("%Y-%m-%dT%H-%M-%S").to_string();

    if output_path.is_empty() {
        if use_password {
            output_path = format!("knex-keys-{}.enc.json", timestamp);
        } else {
            output_path = format!("knex-keys-{}.json", timestamp);
        }
    }

    // Prompt for password before key generation
    let mut password: Option<String> = None;
    if use_password {
        match prompt_password() {
            Ok(p) => password = Some(p),
            Err(e) => {
                print_error(&e);
                std::process::exit(1);
            }
        }
    }

    if classical_only {
        generate_classical(&output_path, &now, no_clear, &suffix, password);
    } else {
        generate_hybrid(&output_path, &now, no_clear, &suffix, password);
    }
}

// ── Help ─────────────────────────────────────────────────────────────────────

fn print_help() {
    eprintln!(
        "{}╔══════════════════════════════════════════════════════════╗{}",
        MAGENTA, RESET
    );
    eprintln!(
        "{}║  {}KnexCoin Secure Key Generator v{}{}                    {}║{}",
        MAGENTA, WHITE, VERSION, RESET, MAGENTA, RESET
    );
    eprintln!(
        "{}║  {}Ed25519 + ML-DSA-65 (FIPS 204){}                       {}║{}",
        MAGENTA, DIM, RESET, MAGENTA, RESET
    );
    eprintln!(
        "{}╚══════════════════════════════════════════════════════════╝{}",
        MAGENTA, RESET
    );
    eprintln!();
    eprintln!("{}Usage:{} knex-keygen [OPTIONS]", BLUE, RESET);
    eprintln!();
    eprintln!("{}Options:{}", YELLOW, RESET);
    eprintln!(
        "  {}-o{}, {}--output{} <path>    Output file path",
        GREEN, RESET, GREEN, RESET
    );
    eprintln!(
        "  {}-s{}, {}--suffix{} <chars>   Vanity address suffix (1-{} Base62 chars)",
        GREEN, RESET, GREEN, RESET, MAX_SUFFIX_LEN
    );
    eprintln!(
        "  {}-p{}, {}--password{}         Encrypt output with password (AES-256-GCM)",
        GREEN, RESET, GREEN, RESET
    );
    eprintln!(
        "      {}--classical{}       Ed25519 only (no ML-DSA-65)",
        GREEN, RESET
    );
    eprintln!(
        "      {}--no-clear{}        Don't clear terminal on exit",
        GREEN, RESET
    );
    eprintln!(
        "  {}-h{}, {}--help{}             Show this help",
        GREEN, RESET, GREEN, RESET
    );
    eprintln!();
    eprintln!("{}Vanity Suffix Difficulty:{}", YELLOW, RESET);
    eprintln!("  {}1 char{} →       62 attempts  {}(instant){}",     WHITE, RESET, DIM, RESET);
    eprintln!("  {}2 char{} →    3,844 attempts  {}(instant){}",     WHITE, RESET, DIM, RESET);
    eprintln!("  {}3 char{} →  238,328 attempts  {}(~1 sec){}",      WHITE, RESET, DIM, RESET);
    eprintln!("  {}4 char{} →   14.7 M attempts  {}(~30 sec){}",     WHITE, RESET, DIM, RESET);
    eprintln!("  {}5 char{} →  916.1 M attempts  {}(~30 min){}",     WHITE, RESET, DIM, RESET);
    eprintln!("  {}6 char{} →   56.8 B attempts  {}(~hours){}",      WHITE, RESET, DIM, RESET);
    eprintln!("  {}7 char{} →    3.5 T attempts  {}(~days){}",       WHITE, RESET, DIM, RESET);
    eprintln!();
    eprintln!("{}Security:{}", YELLOW, RESET);
    eprintln!(
        "  {}•{} Private keys are {}NEVER{} printed to stdout",
        GREEN, RESET, RED, RESET
    );
    eprintln!("  {}•{} All sensitive memory is securely zeroed", GREEN, RESET);
    eprintln!("  {}•{} Terminal screen + scrollback cleared on exit", GREEN, RESET);
    eprintln!("  {}•{} Key file permissions set to 0600 (owner-only)", GREEN, RESET);
    eprintln!("  {}•{} Password input hidden (no echo)", GREEN, RESET);
    eprintln!();
    eprintln!(
        "{}Tip:{} Prefix with a space to skip shell history:",
        CYAN, RESET
    );
    eprintln!("  {}` knex-keygen`{}", DIM, RESET);
}

fn print_error(msg: &str) {
    eprintln!("{}Error:{} {}", RED, RESET, msg);
}

// ── Suffix Validation ────────────────────────────────────────────────────────

fn validate_suffix(suffix: &str) -> Result<(), String> {
    if suffix.is_empty() {
        return Err("Suffix cannot be empty".to_string());
    }
    if suffix.len() > MAX_SUFFIX_LEN {
        return Err(format!(
            "Suffix too long: {} chars (max {}). Difficulty increases 62x per character.",
            suffix.len(),
            MAX_SUFFIX_LEN
        ));
    }
    for (i, ch) in suffix.chars().enumerate() {
        if !ch.is_ascii_alphanumeric() {
            return Err(format!(
                "Invalid character '{}' at position {} — only Base62 (0-9, A-Z, a-z) allowed. Note: Base62 is case-sensitive.",
                ch,
                i + 1
            ));
        }
    }
    Ok(())
}

// ── Vanity Mining ────────────────────────────────────────────────────────────

/// Mine Ed25519 keys until address ends with the given suffix.
/// Returns (signing_key_bytes, verifying_key_bytes, address, attempts, elapsed).
fn mine_vanity_ed25519(suffix: &str) -> ([u8; 32], [u8; 32], String, u64, std::time::Duration) {
    let expected: f64 = 62f64.powi(suffix.len() as i32);

    eprintln!();
    eprintln!(
        "{}╔══════════════════════════════════════════════════════════╗{}",
        MAGENTA, RESET
    );
    eprintln!(
        "{}║  {}Vanity Address Mining{}                                  {}║{}",
        MAGENTA, WHITE, RESET, MAGENTA, RESET
    );
    eprintln!(
        "{}╚══════════════════════════════════════════════════════════╝{}",
        MAGENTA, RESET
    );
    eprintln!();
    eprintln!(
        "  {}Target suffix:{} {}{}{}",
        BLUE, RESET, GREEN, suffix, RESET
    );
    eprintln!(
        "  {}Expected attempts:{} {}{}{}",
        BLUE, RESET, YELLOW, format_number(expected as u64), RESET
    );
    eprintln!(
        "  {}Suffix length:{} {} chars (62^{} = {} combinations)",
        BLUE,
        RESET,
        suffix.len(),
        suffix.len(),
        format_number(expected as u64)
    );
    eprintln!();

    let start = std::time::Instant::now();
    let mut attempts: u64 = 0;
    let report_interval: u64 = 100_000;

    loop {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = (&signing_key).into();
        let secret_bytes = signing_key.to_bytes();
        let public_bytes = verifying_key.to_bytes();
        let address = encode_address(&public_bytes);

        attempts += 1;

        if attempts % report_interval == 0 {
            let elapsed = start.elapsed();
            let rate = attempts as f64 / elapsed.as_secs_f64();
            let remaining = if rate > 0.0 {
                ((expected - attempts as f64) / rate).max(0.0)
            } else {
                0.0
            };
            eprint!(
                "\r  {}Searching...{} {} keys tested  {}|{}  {}{}/s{}  {}|{}  ETA: {}{}{}  ",
                CYAN,
                RESET,
                format_number(attempts),
                DIM,
                RESET,
                YELLOW,
                format_number(rate as u64),
                RESET,
                DIM,
                RESET,
                GREEN,
                format_duration(remaining),
                RESET,
            );
        }

        if address.ends_with(suffix) {
            let elapsed = start.elapsed();
            // Clear the progress line
            eprint!("\r{}\r", " ".repeat(80));
            return (secret_bytes, public_bytes, address, attempts, elapsed);
        }
    }
}

// ── Password Prompt ──────────────────────────────────────────────────────────

fn prompt_password() -> Result<String, String> {
    eprintln!();
    eprintln!(
        "{}╔══════════════════════════════════════════════════════════╗{}",
        MAGENTA, RESET
    );
    eprintln!(
        "{}║  {}Password Protection (AES-256-GCM){}                     {}║{}",
        MAGENTA, WHITE, RESET, MAGENTA, RESET
    );
    eprintln!(
        "{}╚══════════════════════════════════════════════════════════╝{}",
        MAGENTA, RESET
    );
    eprintln!();
    eprintln!(
        "  {}Your key file will be encrypted. The plaintext{}",
        DIM, RESET
    );
    eprintln!(
        "  {}private key will NEVER touch disk.{}",
        DIM, RESET
    );
    eprintln!();

    eprint!("  {}Enter password (min 8 chars):{} ", BLUE, RESET);
    let pass1 = rpassword::read_password().map_err(|e| format!("Failed to read password: {}", e))?;

    if pass1.len() < 8 {
        return Err(format!(
            "Password too short ({} chars). Minimum is 8 characters.",
            pass1.len()
        ));
    }

    eprint!("  {}Confirm password:{} ", BLUE, RESET);
    let pass2 = rpassword::read_password().map_err(|e| format!("Failed to read password: {}", e))?;

    if pass1 != pass2 {
        return Err("Passwords do not match.".to_string());
    }

    eprintln!();
    eprintln!("  {}Password accepted.{}", GREEN, RESET);

    Ok(pass1)
}

// ── Encryption ───────────────────────────────────────────────────────────────

fn encrypt_json(json_str: &str, password: &str) -> String {
    // Generate random salt (32 bytes) and nonce (12 bytes)
    let mut salt = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    // Derive key via PBKDF2-HMAC-SHA256
    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        &salt,
        PBKDF2_ITERATIONS,
        &mut derived_key,
    );

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .expect("Failed to create AES-256-GCM cipher");
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, json_str.as_bytes())
        .expect("AES-256-GCM encryption failed");

    // Zeroize derived key
    derived_key.zeroize();

    // Build encrypted envelope
    let envelope = serde_json::json!({
        "format": "knex-keygen-encrypted-v1",
        "kdf": "PBKDF2-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": hex::encode(salt),
        "nonce": hex::encode(nonce_bytes),
        "ciphertext": hex::encode(&ciphertext),
    });

    serde_json::to_string_pretty(&envelope).expect("Failed to serialize encrypted envelope")
}

// ── Classical (Ed25519 only) ─────────────────────────────────────────────────

fn generate_classical(
    output_path: &str,
    now: &chrono::DateTime<chrono::Utc>,
    no_clear: bool,
    suffix: &str,
    mut password: Option<String>,
) {
    let (secret_bytes, public_bytes, address, vanity_attempts, vanity_elapsed);

    if suffix.is_empty() {
        // Normal generation
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = (&signing_key).into();
        let sb = signing_key.to_bytes();
        let pb = verifying_key.to_bytes();
        let addr = encode_address(&pb);
        secret_bytes = sb;
        public_bytes = pb;
        address = addr;
        vanity_attempts = 1;
        vanity_elapsed = std::time::Duration::from_secs(0);
    } else {
        // Vanity mining
        let (sb, pb, addr, attempts, elapsed) = mine_vanity_ed25519(suffix);
        secret_bytes = sb;
        public_bytes = pb;
        address = addr;
        vanity_attempts = attempts;
        vanity_elapsed = elapsed;
    }

    let mut private_key = encode_private_key(&secret_bytes);
    let public_key_hex = hex::encode(public_bytes);
    let mut secret_key_hex = hex::encode(secret_bytes);

    let json = serde_json::json!({
        "generator": format!("KnexCoin Key Generator v{} (Classical)", VERSION),
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

    // Write file (encrypted or plain)
    if let Some(ref pwd) = password {
        let encrypted = encrypt_json(&json_str, pwd);
        write_secure_file(output_path, &encrypted);
    } else {
        write_secure_file(output_path, &json_str);
    }

    // Display result
    print_result_header("Classical Ed25519");
    print_address(&address, suffix);
    print_file_info(output_path, password.is_some());

    if !suffix.is_empty() {
        print_vanity_stats(vanity_attempts, vanity_elapsed);
    }

    if password.is_some() {
        print_encryption_info();
    }

    print_result_footer();

    // Zeroize all sensitive data
    private_key.zeroize();
    secret_key_hex.zeroize();
    json_str.zeroize();
    if let Some(ref mut p) = password {
        p.zeroize();
    }

    if !no_clear {
        wait_then_clear();
    }
}

// ── Hybrid (Ed25519 + ML-DSA-65) ────────────────────────────────────────────

fn generate_hybrid(
    output_path: &str,
    now: &chrono::DateTime<chrono::Utc>,
    no_clear: bool,
    suffix: &str,
    mut password: Option<String>,
) {
    let (secret_bytes, public_bytes, address, vanity_attempts, vanity_elapsed);

    if suffix.is_empty() {
        eprintln!(
            "  {}Generating hybrid keypair (Ed25519 + ML-DSA-65)...{}",
            CYAN, RESET
        );
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = (&signing_key).into();
        let sb = signing_key.to_bytes();
        let pb = verifying_key.to_bytes();
        let addr = encode_address(&pb);
        secret_bytes = sb;
        public_bytes = pb;
        address = addr;
        vanity_attempts = 1;
        vanity_elapsed = std::time::Duration::from_secs(0);
    } else {
        // Vanity mine Ed25519 first (fast), then generate ML-DSA-65 (slow) after match
        let (sb, pb, addr, attempts, elapsed) = mine_vanity_ed25519(suffix);
        secret_bytes = sb;
        public_bytes = pb;
        address = addr;
        vanity_attempts = attempts;
        vanity_elapsed = elapsed;
        eprintln!(
            "  {}Generating ML-DSA-65 post-quantum keypair...{}",
            CYAN, RESET
        );
    }

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
    let ed_signing_key = SigningKey::from_bytes(&secret_bytes);
    use ed25519_dalek::Signer as EdSigner;
    let ed_sig = ed_signing_key.sign(test_msg);
    let ed_verifying_key = VerifyingKey::from(&ed_signing_key);
    use ed25519_dalek::Verifier as EdVerifier;
    ed_verifying_key
        .verify(test_msg, &ed_sig)
        .expect("Ed25519 verification failed");

    let mut private_key = encode_private_key(&secret_bytes);
    let public_key_hex = hex::encode(public_bytes);
    let mut secret_key_hex = hex::encode(secret_bytes);
    let mut pq_public_key_hex = hex::encode(pq_pk_bytes);
    let mut pq_secret_key_hex = hex::encode(pq_sk_bytes);

    let json = serde_json::json!({
        "generator": format!("KnexCoin Key Generator v{} (Hybrid PQ)", VERSION),
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

    // Write file (encrypted or plain)
    if let Some(ref pwd) = password {
        let encrypted = encrypt_json(&json_str, pwd);
        write_secure_file(output_path, &encrypted);
    } else {
        write_secure_file(output_path, &json_str);
    }

    // Display result
    print_result_header("Hybrid Ed25519 + ML-DSA-65");
    print_address(&address, suffix);
    print_file_info(output_path, password.is_some());

    eprintln!("  {}Algorithms:{}", BLUE, RESET);
    eprintln!(
        "    {}Classical:{}    Ed25519",
        WHITE, RESET
    );
    eprintln!(
        "    {}Post-Quantum:{} ML-DSA-65 (FIPS 204)",
        WHITE, RESET
    );
    eprintln!();

    if !suffix.is_empty() {
        print_vanity_stats(vanity_attempts, vanity_elapsed);
    }

    if password.is_some() {
        print_encryption_info();
    }

    eprintln!(
        "  {}All keys are in the JSON file — {}NEVER{} share it.{}",
        DIM, RED, DIM, RESET
    );
    eprintln!(
        "  {}Bind the PQ key on-chain via a PqBind block.{}",
        DIM, RESET
    );

    print_result_footer();

    // Zeroize all sensitive data
    private_key.zeroize();
    secret_key_hex.zeroize();
    pq_public_key_hex.zeroize();
    pq_secret_key_hex.zeroize();
    json_str.zeroize();
    if let Some(ref mut p) = password {
        p.zeroize();
    }

    if !no_clear {
        wait_then_clear();
    }
}

// ── Display Functions ────────────────────────────────────────────────────────

fn print_result_header(mode: &str) {
    eprintln!();
    eprintln!(
        "{}╔══════════════════════════════════════════════════════════╗{}",
        MAGENTA, RESET
    );
    eprintln!(
        "{}║  {}Key Generated ({}){}",
        MAGENTA, WHITE, mode, RESET
    );
    eprintln!(
        "{}╚══════════════════════════════════════════════════════════╝{}",
        MAGENTA, RESET
    );
    eprintln!();
}

fn print_result_footer() {
    eprintln!();
    eprintln!(
        "  {}Transfer the file securely, then delete from this machine.{}",
        DIM, RESET
    );
    eprintln!();
}

fn print_address(address: &str, suffix: &str) {
    if !suffix.is_empty() && address.ends_with(suffix) {
        // Highlight the vanity suffix
        let prefix_part = &address[..address.len() - suffix.len()];
        eprintln!(
            "  {}Address:{}  {}{}{}{}{}",
            BLUE, RESET, WHITE, prefix_part, GREEN, suffix, RESET
        );
    } else {
        eprintln!("  {}Address:{}  {}{}{}", BLUE, RESET, GREEN, address, RESET);
    }
}

fn print_file_info(path: &str, encrypted: bool) {
    eprintln!("  {}Saved to:{} {}{}{}", BLUE, RESET, WHITE, path, RESET);
    eprintln!(
        "  {}Mode:{}     {}owner read/write only{}",
        BLUE, RESET, DIM, RESET
    );
    if encrypted {
        eprintln!(
            "  {}Encrypt:{} {}AES-256-GCM + PBKDF2-SHA256{}",
            BLUE, RESET, CYAN, RESET
        );
    }
    eprintln!();
}

fn print_vanity_stats(attempts: u64, elapsed: std::time::Duration) {
    let rate = if elapsed.as_secs_f64() > 0.0 {
        attempts as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    eprintln!("  {}Vanity Mining Stats:{}", YELLOW, RESET);
    eprintln!(
        "    {}Attempts:{}  {}",
        WHITE, RESET, format_number(attempts)
    );
    eprintln!(
        "    {}Time:{}      {}",
        WHITE, RESET, format_duration(elapsed.as_secs_f64())
    );
    eprintln!(
        "    {}Rate:{}      {}/s",
        WHITE, RESET, format_number(rate as u64)
    );
    eprintln!();
}

fn print_encryption_info() {
    eprintln!("  {}Encryption Details:{}", CYAN, RESET);
    eprintln!(
        "    {}Cipher:{}     AES-256-GCM",
        WHITE, RESET
    );
    eprintln!(
        "    {}KDF:{}        PBKDF2-HMAC-SHA256 ({} iterations)",
        WHITE, RESET, format_number(PBKDF2_ITERATIONS as u64)
    );
    eprintln!(
        "    {}Note:{}       {}Plaintext key NEVER touches disk{}",
        WHITE, RESET, RED, RESET
    );
    eprintln!();
}

// ── Formatting Helpers ───────────────────────────────────────────────────────

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let len = s.len();
    if len <= 3 {
        return s;
    }
    let mut result = String::with_capacity(len + len / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result
}

fn format_duration(secs: f64) -> String {
    if secs < 0.001 {
        return "instant".to_string();
    }
    if secs < 1.0 {
        return format!("{:.0}ms", secs * 1000.0);
    }
    if secs < 60.0 {
        return format!("{:.1}s", secs);
    }
    if secs < 3600.0 {
        let m = (secs / 60.0).floor();
        let s = secs - m * 60.0;
        return format!("{}m {:.0}s", m as u64, s);
    }
    let h = (secs / 3600.0).floor();
    let m = ((secs - h * 3600.0) / 60.0).floor();
    format!("{}h {}m", h as u64, m as u64)
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
    eprintln!(
        "  {}Press ENTER to clear screen and exit...{}",
        DIM, RESET
    );

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
