//! The macOS library capability report must match the install-capable adapter.
//!
//! This is a pure library assertion: no command, service, or system resource is
//! touched.

#![cfg(target_os = "macos")]

use hs_server::installer::lifecycle_v2::{DeploymentKind, LifecycleAction, NetworkScope};
use hs_server::installer::{machine, macos_launchd};

#[cfg(not(feature = "macos-dev-install"))]
#[test]
fn macos_library_capabilities_keep_install_gated_off() {
    let capabilities = machine::lifecycle_capabilities_v2();
    let adapter = macos_launchd::capabilities_v2();

    assert_eq!(
        capabilities.supported_deployment_kinds,
        vec![DeploymentKind::MacosLaunchd]
    );
    assert_eq!(
        capabilities.supported_actions,
        vec![LifecycleAction::Preflight, LifecycleAction::Plan]
    );
    assert_eq!(
        capabilities.supported_network_scopes,
        vec![NetworkScope::LoopbackDevelopment]
    );
    assert!(!capabilities.custom_storage_directories);
    assert!(!capabilities.durable_operation_journal);
    assert!(!capabilities.cancellation);
    assert!(!capabilities.online_update);
    assert!(!capabilities.backup_and_restore);
    assert!(!capabilities.public_edge_integration);
    assert_eq!(capabilities.supported_actions, adapter.supported_actions);
    assert_eq!(
        capabilities.supported_deployment_kinds,
        adapter.supported_deployment_kinds
    );
    assert!(!capabilities
        .supported_actions
        .contains(&LifecycleAction::Install));
    assert!(!capabilities
        .supported_actions
        .contains(&LifecycleAction::Resume));
    assert!(!capabilities
        .supported_actions
        .contains(&LifecycleAction::Remove));
    assert!(capabilities
        .reasons_unavailable
        .get("macos_launchd")
        .is_some_and(|reason| reason.contains("gated off")));
    assert!(capabilities
        .reasons_unavailable
        .get("enrollment_readiness")
        .is_some_and(|reason| reason.contains("development-only")));
}

#[cfg(feature = "macos-dev-install")]
#[test]
fn macos_library_capabilities_advertise_the_development_install_path() {
    let capabilities = machine::lifecycle_capabilities_v2();
    let adapter = macos_launchd::capabilities_v2();

    assert_eq!(
        capabilities.supported_deployment_kinds,
        vec![DeploymentKind::MacosLaunchd]
    );
    assert_eq!(
        capabilities.supported_actions,
        vec![
            LifecycleAction::Preflight,
            LifecycleAction::Plan,
            LifecycleAction::Install,
            LifecycleAction::Cancel,
            LifecycleAction::Inspect,
        ]
    );
    assert_eq!(
        capabilities.supported_network_scopes,
        vec![NetworkScope::LoopbackDevelopment]
    );
    assert!(!capabilities.custom_storage_directories);
    assert!(capabilities.durable_operation_journal);
    assert!(capabilities.cancellation);
    assert!(!capabilities.online_update);
    assert!(!capabilities.backup_and_restore);
    assert!(!capabilities.public_edge_integration);
    assert_eq!(capabilities.supported_actions, adapter.supported_actions);
    assert!(!capabilities
        .supported_actions
        .contains(&LifecycleAction::Resume));
    assert!(!capabilities
        .supported_actions
        .contains(&LifecycleAction::Remove));
    assert!(capabilities
        .reasons_unavailable
        .get("macos_launchd")
        .is_some_and(|reason| reason.contains("development-only")));
    assert!(capabilities
        .reasons_unavailable
        .get("enrollment_readiness")
        .is_some_and(|reason| reason.contains("development-only")));
}
