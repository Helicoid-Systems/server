//! Linux installer backend: preflight, plan, apply, inspect, resume, remove.
//!
//! Bounded versioned JSON contract consumed by the guided Mac wizard.
//! Package manifest verification with Ed25519 signatures.
//! Phase journal for atomic, idempotent, resumable operations.
//!
//! `macos_launchd` is a read-only macOS preflight and fixed-path adapter that
//! emits the existing v2 preflight/plan types. `macos_package` is library-only
//! signed-package verification against a caller-supplied key; it is not
//! authenticated trust or a working macOS installer. `package_fs` supplies
//! held, descriptor-relative package custody for verification. Apply/install,
//! service-account creation, launchd plist writing/loading, and readiness
//! remain unavailable.

pub mod adapter;
pub mod lifecycle_v2;
pub mod machine;
pub mod macos_identity;
pub mod macos_launchd;
pub mod macos_package;
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
