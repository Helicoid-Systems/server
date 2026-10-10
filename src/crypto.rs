//! Password hashing, opaque tokens, TOTP, recovery codes, and Ed25519 proofs.
//!
//! Secrets never leave this module in plaintext logs. Passwords are hashed
//! with Argon2id (maintained `argon2` crate). Session tokens are high-entropy
//! random values; only a SHA-256 digest is stored. TOTP uses maintained
//! `totp-rs` (RFC 6238). Device proofs use `ed25519-dalek` `verify_strict`.

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, TOTP};
use zeroize::Zeroize;

use crate::error::{AppError, AppResult};

/// Bytes of entropy in an opaque session token.
const TOKEN_BYTES: usize = 32;
/// RFC 6238 recommended authenticator secret length (160 bits).
const TOTP_SECRET_BYTES: usize = 20;
/// RFC 6238 defaults: SHA-1, 6 digits, ±1 step skew, 30s step.
const TOTP_DIGITS: usize = 6;
const TOTP_SKEW: u8 = 1;
const TOTP_STEP_SECS: u64 = 30;
/// Recovery codes issued per administrator enrollment.
const RECOVERY_CODE_COUNT: usize = 10;
/// Alphanumeric alphabet for recovery codes (no ambiguous glyphs).
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Hash a password with Argon2id. The `argon2` 0.6 hasher generates a
/// per-password salt and returns a PHC-format string.
pub fn hash_password(password: &str) -> AppResult<String> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|err| AppError::PasswordHash(err.to_string()))
}

/// Verify a password against a stored PHC string. Returns `Ok(false)` on mismatch.
pub fn verify_password(password: &str, password_hash: &str) -> AppResult<bool> {
    let parsed =
        PasswordHash::new(password_hash).map_err(|err| AppError::PasswordHash(err.to_string()))?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generate an opaque bearer token (returned once to the caller).
/// Returns `(plaintext_token, sha256_hex_for_storage)`.
pub fn generate_token() -> AppResult<(String, String)> {
    let mut raw = [0u8; TOKEN_BYTES];
    rand::rng().fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    let token_hash = hash_token(&token);
    raw.zeroize();
    Ok((token, token_hash))
}

/// SHA-256 digest of a token, hex-encoded, for at-rest storage.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest)
}

/// Constant-time comparison of two hex digests of equal length.
pub fn token_hash_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

// ----- TOTP (maintained totp-rs) -----

/// Generate a fresh authenticator secret (160-bit, base32, unpadded RFC 4648).
pub fn generate_totp_secret() -> AppResult<String> {
    let mut raw = [0u8; TOTP_SECRET_BYTES];
    rand::rng().fill_bytes(&mut raw);
    let secret = base32_rfc4648(&raw);
    raw.zeroize();
    Ok(secret)
}

/// Build a `TOTP` handle from a stored base32 secret.
pub fn totp_from_secret(secret_base32: &str) -> AppResult<TOTP> {
    let bytes = base32_decode_rfc4648(secret_base32)?;
    TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP_SECS,
        bytes,
    )
    .map_err(|err| AppError::PasswordHash(format!("invalid totp secret: {err}")))
}

/// Current unix time in seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// RFC 6238 time step index for an instant.
pub fn totp_time_step(time_secs: u64) -> i64 {
    (time_secs / TOTP_STEP_SECS) as i64
}

/// Verify a TOTP code at `time_secs` and return the matched time step.
///
/// Returns `Ok(Some(step))` on match within skew, `Ok(None)` on mismatch.
/// Callers must consume the step transactionally to prevent replay.
pub fn verify_totp_at(secret_base32: &str, code: &str, time_secs: u64) -> AppResult<Option<i64>> {
    let totp = totp_from_secret(secret_base32)?;
    if !totp.check(code, time_secs) {
        return Ok(None);
    }
    // Recover the exact step the code matches (skew window).
    let base_step = time_secs / TOTP_STEP_SECS;
    for offset in 0..(TOTP_SKEW as u64) * 2 + 1 {
        let step = base_step
            .wrapping_sub(TOTP_SKEW as u64)
            .wrapping_add(offset);
        let step_time = step * TOTP_STEP_SECS;
        if totp.generate(step_time) == code {
            return Ok(Some(step as i64));
        }
    }
    Ok(Some(totp_time_step(time_secs)))
}

/// Generate the current code for a secret (tests / CLI confirmation helper).
pub fn totp_generate_at(secret_base32: &str, time_secs: u64) -> AppResult<String> {
    let totp = totp_from_secret(secret_base32)?;
    Ok(totp.generate(time_secs))
}

// ----- recovery codes -----

/// One freshly generated recovery code (plaintext, shown once).
pub struct GeneratedRecoveryCode {
    pub plaintext: String,
    pub code_hash: String,
}

/// Generate a bounded set of high-entropy recovery codes.
///
/// Codes are formatted `XXXX-XXXX-XXXX-XXXX` (16 chars from a 32-symbol
/// alphabet ≈ 80 bits). Only SHA-256 digests are stored; plaintexts are
/// returned once for independent operator storage.
pub fn generate_recovery_codes() -> AppResult<Vec<GeneratedRecoveryCode>> {
    let mut out = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut raw = [0u8; 16];
        rand::rng().fill_bytes(&mut raw);
        let mut body = String::with_capacity(16);
        for (i, byte) in raw.iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                body.push('-');
            }
            body.push(RECOVERY_ALPHABET[(*byte as usize) % RECOVERY_ALPHABET.len()] as char);
        }
        raw.zeroize();
        let code_hash = hash_recovery_code(&body);
        out.push(GeneratedRecoveryCode {
            plaintext: body,
            code_hash,
        });
    }
    Ok(out)
}

/// Normalize and hash a recovery code for storage/lookup.
pub fn hash_recovery_code(code: &str) -> String {
    let normalized = normalize_recovery_code(code);
    hash_token(&normalized)
}

/// Canonical form: uppercase, hyphens stripped, ASCII only.
pub fn normalize_recovery_code(code: &str) -> String {
    code.trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Constant-time compare of recovery-code hashes.
pub fn recovery_hash_eq(a: &str, b: &str) -> bool {
    token_hash_eq(a, b)
}

// ----- Ed25519 device proofs -----

/// Parse a 32-byte hex-encoded Ed25519 public key.
pub fn parse_ed25519_public_key(hex_key: &str) -> AppResult<VerifyingKey> {
    let bytes = hex_decode_len(hex_key, 32)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|_| AppError::bad_request("invalid manager public key"))
}

/// Parse a 64-byte hex-encoded Ed25519 signature.
pub fn parse_ed25519_signature(hex_sig: &str) -> AppResult<Signature> {
    let bytes = hex_decode_len(hex_sig, 64)?;
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(Signature::from_bytes(&arr))
}

/// Strict Ed25519 verification (rejects weak keys / malleable signatures).
pub fn verify_ed25519_strict(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> AppResult<bool> {
    let key = parse_ed25519_public_key(public_key_hex)?;
    let sig = parse_ed25519_signature(signature_hex)?;
    match key.verify_strict(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Domain-separated message for a v2 auth challenge completion proof.
///
/// Includes the server-owned deployment identity so a proof cannot be
/// replayed against another deployment. `deployment_id` is never
/// client-selected; the server supplies it from its persisted deployment row.
pub fn auth_challenge_proof_message(
    deployment_id: &str,
    challenge_id: &str,
    operation: &str,
    manager_public_key_hex: &str,
) -> Vec<u8> {
    format!(
        "hs-auth-v2|deployment:{deployment_id}|challenge:{challenge_id}|operation:{operation}|manager:{manager_public_key_hex}"
    )
    .into_bytes()
}

/// Domain-separated message for a v2 bootstrap manager-key proof.
///
/// Binds the proof to this deployment and this bootstrap token hash.
pub fn bootstrap_manager_proof_message(
    deployment_id: &str,
    bootstrap_token_hash: &str,
    manager_public_key_hex: &str,
) -> Vec<u8> {
    format!(
        "hs-bootstrap-v2|deployment:{deployment_id}|token:{bootstrap_token_hash}|manager:{manager_public_key_hex}"
    )
    .into_bytes()
}

// ----- helpers -----

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode_len(hex_str: &str, expected: usize) -> AppResult<Vec<u8>> {
    let trimmed = hex_str.trim();
    if trimmed.len() != expected * 2 {
        return Err(AppError::bad_request(format!(
            "expected {expected} bytes of hex ({expected}×2 chars), got {} chars",
            trimmed.len()
        )));
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::bad_request("value is not valid hex"));
    }
    hex::decode(trimmed).map_err(|err| AppError::bad_request(format!("invalid hex: {err}")))
}

fn base32_rfc4648(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode_rfc4648(input: &str) -> AppResult<Vec<u8>> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 5 / 8 + 1);
    for (idx, ch) in input.trim().chars().enumerate() {
        let value = match ch.to_ascii_uppercase() {
            'A'..='Z' => (ch as u8 - b'A') as u32,
            '2'..='7' => (ch as u8 - b'2') as u32 + 26,
            '=' => continue,
            _ => {
                return Err(AppError::bad_request(format!(
                    "invalid base32 character at position {idx}"
                )))
            }
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    if out.len() < TOTP_SECRET_BYTES {
        return Err(AppError::bad_request("totp secret too short"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let hash = hash_password("correct horse battery staple").expect("hash");
        assert!(verify_password("correct horse battery staple", &hash).expect("verify"));
        assert!(!verify_password("wrong", &hash).expect("verify"));
    }

    #[test]
    fn token_hash_is_stable_and_not_plaintext() {
        let (token, hash) = generate_token().expect("token");
        assert_ne!(token, hash);
        assert_eq!(hash_token(&token), hash);
        assert!(token_hash_eq(&hash, &hash_token(&token)));
        assert!(!token_hash_eq(&hash, &hash_token("other")));
    }

    #[test]
    fn totp_secret_roundtrip_and_code_check() {
        let secret = generate_totp_secret().expect("secret");
        assert!(secret.len() >= 26, "base32 secret should be long enough");
        let now = 1_760_000_000u64;
        let code = totp_generate_at(&secret, now).expect("code");
        assert_eq!(code.len(), 6);
        let matched = verify_totp_at(&secret, &code, now).expect("verify");
        assert_eq!(matched, Some(totp_time_step(now)));
        assert_eq!(
            verify_totp_at(&secret, "000000", now).expect("verify"),
            None
        );
    }

    #[test]
    fn totp_skew_window_matches_neighbor_steps() {
        let secret = generate_totp_secret().expect("secret");
        let now = 1_760_000_030u64;
        let prev = totp_generate_at(&secret, now - 30).expect("prev");
        assert_eq!(
            verify_totp_at(&secret, &prev, now).expect("verify"),
            Some(totp_time_step(now - 30))
        );
    }

    #[test]
    fn recovery_codes_are_unique_hashed_and_normalized() {
        let codes = generate_recovery_codes().expect("codes");
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        let mut seen = std::collections::HashSet::new();
        for code in &codes {
            assert!(code.plaintext.contains('-'));
            assert!(seen.insert(code.code_hash.clone()), "hash must be unique");
            let mut sorted = code.plaintext.replace('-', "");
            sorted = sorted.to_ascii_uppercase();
            assert_eq!(hash_recovery_code(&code.plaintext), code.code_hash);
            assert_eq!(hash_recovery_code(&sorted), code.code_hash);
        }
    }

    #[test]
    fn ed25519_strict_verify_rejects_wrong_key_and_garbage() {
        use ed25519_dalek::{Signer, SigningKey};
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let signer = SigningKey::from_bytes(&secret);
        let public = hex_encode(&signer.verifying_key().to_bytes());
        let msg = auth_challenge_proof_message("dep_1", "c1", "session", &public);
        let sig = signer.sign(&msg);
        let sig_hex = hex_encode(&sig.to_bytes());
        assert!(verify_ed25519_strict(&public, &msg, &sig_hex).expect("verify"));

        let mut other = [0u8; 32];
        rand::rng().fill_bytes(&mut other);
        let other_pub = hex_encode(&SigningKey::from_bytes(&other).verifying_key().to_bytes());
        assert!(!verify_ed25519_strict(&other_pub, &msg, &sig_hex).expect("verify"));
        assert!(!verify_ed25519_strict(&public, b"other", &sig_hex).expect("verify"));
    }

    #[test]
    fn proof_messages_are_domain_separated_and_deployment_bound() {
        let a = auth_challenge_proof_message("dep_1", "c1", "session", "aa");
        let b = bootstrap_manager_proof_message("dep_1", "th", "aa");
        let c = auth_challenge_proof_message("dep_2", "c1", "session", "aa");
        assert_ne!(a, b);
        assert_ne!(a, c, "deployment id must be part of the signed message");
        assert!(a.starts_with(b"hs-auth-v2|deployment:"));
        assert!(b.starts_with(b"hs-bootstrap-v2|deployment:"));
    }
}
