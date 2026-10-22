//! Installer data types: JSON contracts, manifest, phase journal.
//!
//! Wire shapes match the handoff document. All I/O is bounded versioned JSON.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Contract version
// ---------------------------------------------------------------------------

pub const CONTRACT_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightInput {
    pub contract_version: u32,
    pub target: PreflightTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightTarget {
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
}

fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightResult {
    pub contract_version: u32,
    pub ok: bool,
    pub checks: PreflightChecks,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightChecks {
    pub os: CheckResult,
    pub arch: CheckResult,
    pub privileges: PrivilegesCheck,
    pub storage: StorageCheck,
    pub ports: PortsCheck,
    pub paths: PathsCheck,
    pub services: ServicesCheck,
    pub existing_install: ExistingInstallCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub ok: bool,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegesCheck {
    pub ok: bool,
    pub is_root: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCheck {
    pub ok: bool,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub min_required_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortsCheck {
    pub ok: bool,
    pub listeners: Vec<PortListener>,
    pub conflicts: Vec<PortConflict>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortListener {
    pub port: u16,
    pub protocol: String,
    pub occupied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortConflict {
    pub port: u16,
    pub protocol: String,
    pub process: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsCheck {
    pub ok: bool,
    pub checked: Vec<PathCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCheck {
    pub path: String,
    pub exists: bool,
    pub owned_by_us: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesCheck {
    pub ok: bool,
    pub existing_units: Vec<String>,
    pub conflicts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExistingInstallCheck {
    pub detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanInput {
    pub contract_version: u32,
    pub preflight: PreflightResult,
    pub package_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanResult {
    pub contract_version: u32,
    pub ok: bool,
    pub manifest_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<InstallPlan>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallPlan {
    pub review_digest: String,
    pub product: String,
    pub version: String,
    pub service_user: ServiceUserSpec,
    pub directories: Vec<DirectorySpec>,
    pub files: Vec<FileSpec>,
    pub units: Vec<UnitSpec>,
    pub firewall: Vec<FirewallRule>,
    pub listeners: Vec<ListenerSpec>,
    pub migrations: MigrationSpec,
    pub not_implemented: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceUserSpec {
    pub name: String,
    pub create: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectorySpec {
    pub path: String,
    pub owner: String,
    pub mode: String,
    pub create: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSpec {
    pub source: String,
    pub destination: String,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitSpec {
    pub name: String,
    pub action: String,
    pub enabled: bool,
    pub restart_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub port: u16,
    pub protocol: String,
    pub action: String,
    pub comment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerSpec {
    pub port: u16,
    pub protocol: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationSpec {
    pub schema_version: i64,
    pub backup_required: bool,
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyInput {
    pub contract_version: u32,
    pub plan: InstallPlan,
    pub preflight: PreflightResult,
    pub confirm: bool,
    /// Path to the extracted package directory (for file copying).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_dir: Option<String>,
    /// Ed25519 verifying key (hex, 32 bytes) for independent re-verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    pub contract_version: u32,
    pub ok: bool,
    pub phase: String,
    pub phases_completed: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase_journal_path: Option<String>,
    pub service_installed: bool,
    pub bootstrap_ready: bool,
    pub server_ready_for_enrollment: bool,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Inspect
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectInput {
    pub contract_version: u32,
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
}

fn default_state_dir() -> String {
    "/opt/helicoid/.installer".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectResult {
    pub contract_version: u32,
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_user: Option<String>,
    #[serde(default)]
    pub directories: Vec<String>,
    #[serde(default)]
    pub units: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_operation: Option<String>,
    pub last_operation_ok: bool,
}

// ---------------------------------------------------------------------------
// Remove
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveInput {
    pub contract_version: u32,
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
    #[serde(default)]
    pub delete_data: bool,
    pub confirm: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveResult {
    pub contract_version: u32,
    pub ok: bool,
    #[serde(default)]
    pub removed: Vec<String>,
    pub data_preserved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_dir: Option<String>,
    #[serde(default)]
    pub errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// Phase journal
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    ServiceUser,
    Directories,
    Files,
    Units,
    Firewall,
    Completed,
    RolledBack,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::ServiceUser => "service_user",
            Phase::Directories => "directories",
            Phase::Files => "files",
            Phase::Units => "units",
            Phase::Firewall => "firewall",
            Phase::Completed => "completed",
            Phase::RolledBack => "rolled_back",
        }
    }

    /// Ordered execution sequence (excluding terminal states).
    pub fn execution_sequence() -> &'static [Phase] {
        &[
            Phase::ServiceUser,
            Phase::Directories,
            Phase::Files,
            Phase::Units,
            Phase::Firewall,
            Phase::Completed,
        ]
    }

    /// Reverse sequence for rollback (excluding terminal states and Completed).
    pub fn rollback_sequence() -> &'static [Phase] {
        &[
            Phase::Firewall,
            Phase::Units,
            Phase::Files,
            Phase::Directories,
            Phase::ServiceUser,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseEntry {
    pub status: PhaseStatus,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Journal {
    pub contract_version: u32,
    pub plan_digest: String,
    pub started_at: String,
    pub updated_at: String,
    pub current_phase: String,
    pub phases: std::collections::BTreeMap<String, PhaseEntry>,
    pub resources_created: ResourcesCreated,
    /// Per-resource write-ahead entries that survive partial phase failure.
    #[serde(default)]
    pub resources: Vec<ResourceEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourcesCreated {
    #[serde(default)]
    pub service_users: Vec<String>,
    #[serde(default)]
    pub directories: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub units: Vec<String>,
    #[serde(default)]
    pub firewall_rules: Vec<String>,
}

/// Per-resource write-ahead entry that survives partial phase failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry {
    pub resource_type: String,
    pub identity: String,
    pub status: ResourceStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceStatus {
    Intent,
    Completed,
    Failed,
    RolledBack,
}

// ---------------------------------------------------------------------------
// Package manifest
// ---------------------------------------------------------------------------

/// Trusted installer package target.
///
/// The verifier never infers this value: not from the untrusted package
/// `platform` field, and not from the verifier's own local OS. A trusted
/// server or native caller selects the target — including from authenticated
/// target-host or preflight platform facts for remote/native setup — and
/// passes it in. Frozen platform strings are documented in
/// `contracts/installer-package-targets-v1.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstallerTarget {
    LinuxX86_64,
    WindowsX86_64,
    MacosArm64,
    MacosX86_64,
}

impl InstallerTarget {
    /// Every supported target. Order is stable for diagnostics.
    pub const ALL: [InstallerTarget; 4] = [
        InstallerTarget::LinuxX86_64,
        InstallerTarget::WindowsX86_64,
        InstallerTarget::MacosArm64,
        InstallerTarget::MacosX86_64,
    ];

    /// Frozen package `platform` string for this target.
    pub const fn platform_str(self) -> &'static str {
        match self {
            InstallerTarget::LinuxX86_64 => "linux-x86_64",
            InstallerTarget::WindowsX86_64 => "windows-x86_64",
            InstallerTarget::MacosArm64 => "macos-arm64",
            InstallerTarget::MacosX86_64 => "macos-x86_64",
        }
    }

    /// OS component of the frozen platform string.
    pub const fn os_str(self) -> &'static str {
        match self {
            InstallerTarget::LinuxX86_64 => "linux",
            InstallerTarget::WindowsX86_64 => "windows",
            InstallerTarget::MacosArm64 | InstallerTarget::MacosX86_64 => "macos",
        }
    }

    /// Architecture component of the frozen platform string.
    pub const fn arch_str(self) -> &'static str {
        match self {
            InstallerTarget::LinuxX86_64
            | InstallerTarget::WindowsX86_64
            | InstallerTarget::MacosX86_64 => "x86_64",
            InstallerTarget::MacosArm64 => "arm64",
        }
    }

    /// Resolve a frozen platform string. Unknown strings yield `None`.
    pub fn from_platform_str(platform: &str) -> Option<InstallerTarget> {
        Self::ALL.into_iter().find(|t| t.platform_str() == platform)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    pub format_version: u32,
    pub product: String,
    pub version: String,
    pub platform: String,
    pub min_schema_version: i64,
    pub min_installer_version: String,
    pub artifacts: Vec<ArtifactEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}
