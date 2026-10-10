//! API-facing value types (serde). Wire shapes match `contracts/http-v1.md`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub accepting_authorized_operations: bool,
    pub schema_version: i64,
    pub bootstrap_completed: bool,
    pub features: FeatureAvailability,
}

#[derive(Debug, Clone, Serialize)]
pub struct FeatureAvailability {
    pub local_accounts: bool,
    pub manager_enrollment: bool,
    pub scoped_inventory: bool,
    pub mfa: bool,
    pub file_jobs: bool,
    pub security_recovery: bool,
    pub remote_control: bool,
    pub screen_observation: bool,
}

impl FeatureAvailability {
    pub fn foundation() -> Self {
        FeatureAvailability {
            local_accounts: true,
            manager_enrollment: true,
            scoped_inventory: true,
            // Explicitly unavailable in this foundation build (not fake success).
            mfa: false,
            file_jobs: false,
            security_recovery: false,
            remote_control: false,
            screen_observation: false,
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct BootstrapRequest {
    /// Single-use bootstrap token created by `hs-server init`.
    pub bootstrap_token: String,
    pub username: String,
    pub password: String,
    /// Optional manager public identity claimed by the initiating manager device.
    #[serde(default)]
    pub manager_public_identity: Option<String>,
    #[serde(default)]
    pub manager_friendly_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootstrapResponse {
    pub account: AccountView,
    pub manager: Option<ManagerView>,
    pub server_state: &'static str,
}

#[derive(Clone, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    /// Optional manager public identity to bind to the session (must be approved).
    #[serde(default)]
    pub manager_public_identity: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginResponse {
    /// Opaque bearer token. Returned once; never logged.
    pub token: String,
    pub expires_at_unix: i64,
    pub account: AccountView,
    pub manager: Option<ManagerView>,
    pub mfa: MfaStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct MfaStatus {
    pub required: bool,
    pub available: bool,
    pub reason: &'static str,
}

impl MfaStatus {
    pub fn unavailable() -> Self {
        MfaStatus {
            required: false,
            available: false,
            reason: "mfa_not_implemented_in_this_foundation",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionResponse {
    pub account: AccountView,
    pub manager: Option<ManagerView>,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountView {
    pub id: String,
    pub username: String,
    pub state: String,
    pub capabilities: AccountCapabilities,
    pub revision: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountCapabilities {
    pub operate: bool,
    pub manage_enrollment: bool,
    pub manage_access: bool,
    pub manage_accounts: bool,
    pub manage_security: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagerView {
    pub id: String,
    pub public_identity: String,
    pub friendly_name: String,
    pub lifecycle_state: String,
    pub approved_at_unix: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterManagerRequest {
    pub public_identity: String,
    pub friendly_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApproveManagerRequest {
    /// Must name the approving account's confirmed intent; server derives actor from session.
    pub confirm: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComputerView {
    pub id: String,
    pub public_identity: String,
    pub friendly_name: String,
    pub platform: String,
    pub enrollment_state: String,
    pub enrollment_epoch: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateComputerRequest {
    pub public_identity: String,
    pub friendly_name: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComputerListResponse {
    pub computers: Vec<ComputerView>,
    /// True when the caller's scope is an explicit ID set rather than all.
    pub scope_is_explicit: bool,
    pub max_page_size: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessAssignmentView {
    pub id: String,
    pub capability: String,
    pub computer_scope_all: bool,
    pub computer_ids: Vec<String>,
    pub revision: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GrantAccessRequest {
    pub account_id: String,
    pub capability: String,
    #[serde(default)]
    pub computer_ids: Vec<String>,
    #[serde(default)]
    pub computer_scope_all: bool,
}
