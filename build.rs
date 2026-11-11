//! Build-time trust pin for the development-only macOS installer feature.
//!
//! The normal build performs no extra work. With `macos-dev-install` enabled,
//! this script requires the caller to supply a 32-byte Ed25519 release
//! verifying key in `HELICOID_MACOS_DEV_TRUST_KEY` (64 hex characters) and
//! writes the exact key bytes into a generated constant. The runtime package
//! authorization then accepts only that pinned key; it never accepts a trust
//! key supplied by the installer command itself.
//!
//! This is a development acceptance mechanism, not a production release root.
//! A production build must remove this feature and pin a reviewed release key
//! through the normal signed-release process.

use std::env;
use std::fs;
use std::path::PathBuf;

const KEY_ENV: &str = "HELICOID_MACOS_DEV_TRUST_KEY";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed={KEY_ENV}");

    if env::var_os("CARGO_FEATURE_MACOS_DEV_INSTALL").is_none() {
        return;
    }

    let raw = env::var(KEY_ENV).unwrap_or_else(|_| {
        panic!(
            "feature macos-dev-install requires {KEY_ENV} to contain the 32-byte Ed25519 \
             release verifying key as 64 hex characters"
        )
    });
    let key = decode_hex_key(&raw)
        .unwrap_or_else(|error| panic!("{KEY_ENV} is not a usable Ed25519 key: {error}"));
    assert_ne!(
        key, [0u8; 32],
        "{KEY_ENV} must not be the all-zero Ed25519 key"
    );

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let mut source = String::from("[\n");
    for (index, byte) in key.iter().enumerate() {
        if index % 8 == 0 {
            source.push_str("    ");
        }
        source.push_str(&format!("0x{byte:02x},"));
        if index % 8 == 7 {
            source.push('\n');
        } else {
            source.push(' ');
        }
    }
    source.push_str("]\n");
    fs::write(out_dir.join("macos_dev_trust_key.rs"), source)
        .expect("write generated macOS development trust key");

    println!(
        "cargo:warning=macos-dev-install: embedded a development-only pinned release key; \
         this build is not a production trust root"
    );
}

fn decode_hex_key(raw: &str) -> Result<[u8; 32], String> {
    let value = raw.trim();
    if value.len() != 64 {
        return Err(format!(
            "expected 64 hex characters, observed {} characters",
            value.len()
        ));
    }
    let encoded = value.as_bytes();
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = hex_nibble(encoded[index * 2])?;
        let low = hex_nibble(encoded[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex character 0x{byte:02x}")),
    }
}
