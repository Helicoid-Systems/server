//! Password hashing and opaque session-token helpers.
//!
//! Secrets never leave this module in plaintext logs. Passwords are hashed
//! with Argon2id (maintained `argon2` crate). Session tokens are high-entropy
//! random values; only a SHA-256 digest is stored.

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{AppError, AppResult};

/// Bytes of entropy in an opaque session token.
const TOKEN_BYTES: usize = 32;

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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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
}
