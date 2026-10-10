//! Linux installer backend: preflight, plan, apply, inspect, resume, remove.
//!
//! Bounded versioned JSON contract consumed by the guided Mac wizard.
//! Package manifest verification with Ed25519 signatures.
//! Phase journal for atomic, idempotent, resumable operations.

pub mod adapter;
pub mod machine;
pub mod manifest;
pub mod models;

#[cfg(target_os = "linux")]
pub use adapter::LinuxAdapter;
pub use adapter::{CommandAdapter, TestAdapter};
pub use models::{
    ApplyInput, ApplyResult, InspectInput, InspectResult, InstallPlan, PackageManifest, Phase,
    PhaseStatus, PlanInput, PlanResult, PreflightInput, PreflightResult, RemoveInput, RemoveResult,
    CONTRACT_VERSION,
};
