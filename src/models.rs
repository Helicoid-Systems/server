//! API-facing value types (serde). Wire shapes match `contracts/http-v1.md`
//! and `contracts/http-v2.md`.
//!
//! `schema_version` on health is the **v1 HTTP wire contract version** (frozen
//! at 1 so existing native clients keep validating `== 1`). Storage schema is
//! independent and reported as `storage_schema_version`.

use serde::{Deserialize, Serialize};

/// Frozen v1 HTTP wire contract version reported as `schema_version`.
///
/// This is NOT the database storage version. Existing native clients assert
/// `/health.schema_version == 1`; changing this value breaks them.
pub const WIRE_CONTRACT_V1_VERSION: i64 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub accepting_authorized_operations: bool,
    /// v1 wire contract version (frozen at 1). Not the storage schema version.
    pub schema_version: i64,
    /// Database storage schema version (`db::SCHEMA_VERSION`).
    pub storage_schema_version: i64,
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
            // MFA is implemented in auth v2 (TOTP + recovery-only + device-key).
            mfa: true,
            // Explicitly unavailable in this foundation build (not fake success).
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
    /// v2 completion only: exact challenge-proven Ed25519 device key from the
    /// final approved-key transaction. Never client-selected and never taken
    /// from `manager.public_identity` (that is a display label, e.g.
    /// `key:<hex>`). `#[serde(skip_serializing_if = "Option::is_none")]` keeps
    /// frozen v1 wire output unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager_public_key: Option<String>,
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

// ----- auth v2 / MFA (contracts/http-v2.md) -----

/// Local-CLI / authenticated-tunnel bootstrap with real MFA enrollment.
/// Never accepts a manager identity without its Ed25519 proof.
#[derive(Clone, Deserialize)]
pub struct BootstrapV2Request {
    pub bootstrap_token: String,
    pub username: String,
    pub password: String,
    /// Exact initiating manager Ed25519 public key (hex, 32 bytes).
    #[serde(default)]
    pub manager_public_key: Option<String>,
    /// Hex Ed25519 signature over `hs-bootstrap-v2|token:<hash>|manager:<key>`.
    #[serde(default)]
    pub manager_proof: Option<String>,
    #[serde(default)]
    pub manager_friendly_name: Option<String>,
}

/// Secrets in this response are returned once. Never log this type.
pub struct BootstrapV2Response {
    pub account_id: String,
    pub username: String,
    pub mfa_enrollment_id: String,
    pub totp_secret_base32: String,
    pub recovery_codes: Vec<String>,
    pub manager_public_key: Option<String>,
    pub account_state: String,
    pub server_state: String,
}

/// Confirm pending TOTP enrollment and independently stored recovery material.
#[derive(Clone, Deserialize)]
pub struct MfaConfirmRequest {
    pub mfa_enrollment_id: String,
    pub totp_code: String,
    /// Operator attests recovery codes were stored outside the server.
    pub recovery_material_stored: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MfaConfirmResponse {
    pub account_id: String,
    pub mfa_status: String,
    pub account_state: String,
}

/// Cancel a bounded pending MFA enrollment (bootstrap cancellation).
#[derive(Clone, Deserialize)]
pub struct MfaEnrollCancelRequest {
    pub mfa_enrollment_id: String,
}

/// Start a bounded durable one-use auth challenge (password + operation + key).
#[derive(Clone, Deserialize)]
pub struct AuthChallengeBeginRequest {
    pub username: String,
    pub password: String,
    /// Intended operation the challenge binds to (`session`, …).
    pub operation: String,
    /// Exact approved manager Ed25519 public key (hex, 32 bytes).
    pub manager_public_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthChallengeBeginResponse {
    pub challenge_id: String,
    /// Opaque one-use challenge token. Returned once; never logged.
    pub challenge_token: String,
    pub operation: String,
    pub manager_public_key: String,
    /// Server-owned deployment identity. Included in the signed proof message.
    pub deployment_id: String,
    pub expires_at_unix: i64,
    /// Server-derived effective MFA requirement for this account at begin.
    /// Completion rechecks current policy, role, and factor state.
    pub mfa_required: bool,
}

/// Complete a challenge with device proof + optional TOTP. Consumes the
/// challenge. `totp_code` stays a JSON string for existing clients; it is
/// omitted only for an optional non-enrolled operator.
#[derive(Clone, Deserialize)]
pub struct AuthChallengeCompleteRequest {
    pub challenge_id: String,
    pub challenge_token: String,
    /// Hex Ed25519 signature over the domain-separated challenge message.
    pub manager_signature: String,
    /// Genuine TOTP factor. Required for administrators, `required` operator
    /// policy, and any already-active enrolled factor. A malformed supplied
    /// factor is refused — never silently ignored.
    #[serde(default)]
    pub totp_code: Option<String>,
}

/// Recovery-only factor re-enrollment. Never issues a session.
#[derive(Clone, Deserialize)]
pub struct FactorRecoveryBeginRequest {
    pub username: String,
    pub password: String,
    pub recovery_code: String,
}

/// TOTP secret for factor recovery only. Never log this type.
pub struct FactorRecoveryBeginResponse {
    pub mfa_enrollment_id: String,
    pub totp_secret_base32: String,
    pub account_id: String,
    pub purpose: String,
}

// ----- operator MFA policy (contracts/http-v2.md) -----

/// Deployment policy for non-administrator (operator) accounts.
///
/// New deployments default to `optional`. Administrator MFA stays mandatory
/// regardless of this value. An already-active enrolled factor remains
/// mandatory even under `optional`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorMfaPolicy {
    Optional,
    Required,
}

impl OperatorMfaPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            OperatorMfaPolicy::Optional => "optional",
            OperatorMfaPolicy::Required => "required",
        }
    }
}

/// `GET /v2/security/operator-mfa-policy`.
#[derive(Debug, Clone, Serialize)]
pub struct OperatorMfaPolicyResponse {
    pub policy: OperatorMfaPolicy,
    pub updated_at_unix: Option<i64>,
    /// True when a non-enrolled operator cannot complete challenge login.
    pub mfa_required_for_operators: bool,
}

/// `PUT /v2/security/operator-mfa-policy`. Strict bounded DTO: unknown
/// fields and non-enum policy values are refused by the parser.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorMfaPolicyUpdateRequest {
    pub policy: OperatorMfaPolicy,
}
