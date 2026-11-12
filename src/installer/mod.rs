//! Linux installer backend: preflight, plan, apply, inspect, resume, remove.
//!
//! Bounded versioned JSON contract consumed by the guided Mac wizard.
//! Package manifest verification with Ed25519 signatures.
//! Phase journal for atomic, idempotent, resumable operations.
//!
//! `macos_launchd` is the read-only macOS preflight and fixed-path adapter that
//! emits the existing v2 preflight/plan types. `macos_apply` implements the
//! guarded fresh-install apply, status, and rollback lifecycle. `macos_package`
//! is library-only signed-package verification against a caller-supplied key;
//! it is not authenticated trust. Readiness, enrollment, update, backup,
//! restore, and removal remain unavailable.

pub mod adapter;
pub mod lifecycle_v2;
pub mod machine;
pub mod macos_apply;
pub mod macos_identity;
pub mod macos_launchd;
pub mod macos_package;
#[cfg(all(target_os = "macos", feature = "macos-dev-install"))]
pub mod macos_tls;
pub mod manifest;
pub mod models;
pub mod package_fs;
pub mod tuf_update;

#[cfg(target_os = "linux")]
pub use adapter::LinuxAdapter;
pub use adapter::{CommandAdapter, TestAdapter};
pub use manifest::{verify_manifest, verify_manifest_for_target};
pub use models::{
    ApplyInput, ApplyResult, InspectInput, InspectResult, InstallPlan, InstallerTarget,
    PackageManifest, Phase, PhaseStatus, PlanInput, PlanResult, PreflightInput, PreflightResult,
    RemoveInput, RemoveResult, CONTRACT_VERSION,
};
