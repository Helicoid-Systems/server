//! Version 2 installer lifecycle wire types.
//!
//! This layer is deliberately separate from the frozen v1 request/response
//! structs. It makes deployment configuration and operation state explicit
//! without claiming that an unsupported host mode or network profile works.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::models::{InstallPlan, PhaseStatus};

pub const CONTRACT_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentKind {
    LinuxSystemd,
    LinuxCompose,
    MacosLaunchd,
    WindowsService,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkScope {
    LoopbackDevelopment,
    Lan,
    PrivateDns,
    PublicEdge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfiguration {
    pub scope: NetworkScope,
    pub authority_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfiguration {
    pub data_directory: String,
    pub backup_directory: String,
    pub preserve_data_on_remove: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfiguration {
    pub deployment_kind: DeploymentKind,
    pub network: NetworkConfiguration,
    pub storage: StorageConfiguration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    Preflight,
    Plan,
    Install,
    Resume,
    Cancel,
    Inspect,
    Update,
    Backup,
    Restore,
    Rollback,
    Remove,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleCapabilities {
    pub contract_version: u32,
    pub supported_deployment_kinds: Vec<DeploymentKind>,
    pub supported_network_scopes: Vec<NetworkScope>,
    pub supported_actions: Vec<LifecycleAction>,
    pub custom_storage_directories: bool,
    pub durable_operation_journal: bool,
    pub cancellation: bool,
    pub online_update: bool,
    pub backup_and_restore: bool,
    pub public_edge_integration: bool,
    pub reasons_unavailable: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightInput {
    pub contract_version: u32,
    pub configuration: DeploymentConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightResult {
    pub contract_version: u32,
    pub configuration: DeploymentConfiguration,
    pub ok: bool,
    pub host_checks: super::models::PreflightResult,
    /// SHA-256 of the validated public certificate PEM. The private key is
    /// validated but never copied into the review contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_certificate_sha256: Option<String>,
    /// True only when LAN or private-DNS preflight verified that the leaf
    /// certificate covers the configured Manager hostname or bind IP. Older
    /// v2 backends omit it.
    #[serde(default)]
    pub tls_subject_name_verified: bool,
    /// Present only for Compose deployments and included in the reviewed
    /// plan digest so apply requires the same verified runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker_compose_runtime: Option<DockerComposeRuntimeCheck>,
    pub capabilities: LifecycleCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerComposeRuntimeCheck {
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker_server_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanInput {
    pub contract_version: u32,
    pub configuration: DeploymentConfiguration,
    pub preflight: PreflightResult,
    pub package_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanResult {
    pub contract_version: u32,
    pub ok: bool,
    pub configuration: DeploymentConfiguration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<InstallPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_plan_digest: Option<String>,
    pub capabilities: LifecycleCapabilities,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyInput {
    pub contract_version: u32,
    pub configuration: DeploymentConfiguration,
    pub preflight: PreflightResult,
    pub plan: InstallPlan,
    pub reviewed_plan_digest: String,
    pub confirm: bool,
    pub package_dir: String,
    pub verify_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    NotInstalled,
    InProgress,
    AttentionRequired,
    Completed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    pub code: String,
    pub summary: String,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationOutcome {
    pub state: OperationState,
    pub result: OperationResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationStatus {
    pub contract_version: u32,
    pub configuration: DeploymentConfiguration,
    pub operation_id: Option<String>,
    pub action: Option<LifecycleAction>,
    pub state: OperationState,
    pub reviewed_plan_digest: Option<String>,
    pub current_phase: Option<String>,
    pub phases: BTreeMap<String, PhaseStatus>,
    pub cancellation_available: bool,
    pub resume_available: bool,
    pub service_installed: bool,
    pub bootstrap_ready: bool,
    pub server_ready_for_enrollment: bool,
    pub result: OperationResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelInput {
    pub contract_version: u32,
    pub configuration: DeploymentConfiguration,
    pub operation_id: String,
    pub confirm: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationRequest {
    pub contract_version: u32,
    pub operation_id: String,
    pub cleanup_operation_id: String,
    pub requested_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusInput {
    pub contract_version: u32,
    pub configuration: DeploymentConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRecord {
    pub contract_version: u32,
    pub operation_id: String,
    pub action: LifecycleAction,
    /// Install identity whose resources are being removed. A removal has its
    /// own operation ID while retaining this identity for ownership checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_operation_id: Option<String>,
    pub reviewed_plan_digest: String,
    pub configuration: DeploymentConfiguration,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<OperationOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveInput {
    pub contract_version: u32,
    pub configuration: DeploymentConfiguration,
    pub confirm: bool,
}
