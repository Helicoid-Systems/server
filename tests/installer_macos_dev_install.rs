//! Development-only macOS installer feature checks.
//!
//! These assertions are pure library checks. The real privileged install is
//! exercised by the dedicated GitHub Actions macOS acceptance workflow on a
//! disposable runner, never by a local `cargo test`.

#![cfg(all(target_os = "macos", feature = "macos-dev-install"))]

use hs_server::installer::macos_apply::{
    development_install_enabled, MacosApplyAdapter, MacosSystemApplyAdapter, TRUSTED_RELEASE_KEYS,
};
use hs_server::installer::macos_launchd;

#[test]
fn development_feature_is_explicit_and_has_one_build_pinned_key() {
    assert!(development_install_enabled());
    assert_eq!(TRUSTED_RELEASE_KEYS.len(), 1);
    assert_ne!(TRUSTED_RELEASE_KEYS[0], [0u8; 32]);
}

#[test]
fn development_key_must_match_the_build_pinned_key() {
    let adapter = MacosSystemApplyAdapter::new();
    let error = adapter
        .authorize_package_key(&"cd".repeat(32))
        .expect_err("a non-pinned key must be refused");
    assert!(
        error.contains("build-pinned development release key"),
        "unexpected error: {error}"
    );

    if let Ok(pinned) = std::env::var("HELICOID_MACOS_DEV_TRUST_KEY") {
        adapter
            .authorize_package_key(&pinned)
            .expect("the build-pinned key must authorize");
    }
}

#[test]
fn development_capabilities_do_not_claim_unimplemented_operations() {
    let capabilities = macos_launchd::capabilities_v2();
    assert!(capabilities.cancellation);
    assert!(capabilities.durable_operation_journal);
    assert!(!capabilities.online_update);
    assert!(!capabilities.backup_and_restore);
    assert!(!capabilities.public_edge_integration);
    assert!(capabilities
        .reasons_unavailable
        .get("macos_launchd")
        .is_some_and(|reason| reason.contains("development-only")));
}
