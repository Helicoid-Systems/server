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
    pub recovery_quarantined: bool,
    pub authority_state: String,
    pub authority_generation: i64,
    pub features: FeatureAvailability,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryQuarantineStatusResponse {
    pub deployment_id: String,
    pub recovery_quarantined: bool,
    pub quarantined_account_count: i64,
    pub revoked_manager_count: i64,
    pub quarantined_endpoint_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorityCutoverResponse {
    pub authority_id: String,
    pub authority_state: String,
    pub authority_generation: i64,
    pub predecessor_authority_id: Option<String>,
    pub cutover: Option<AuthorityCutoverView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorityCutoverView {
    pub id: String,
    pub predecessor_authority_id: String,
    pub replacement_authority_id: Option<String>,
    pub generation: i64,
    pub state: String,
    pub initiated_by_account_id: Option<String>,
    pub approved_by_account_id: Option<String>,
    pub fencing_method: Option<String>,
    pub fencing_evidence_reference: Option<String>,
    pub created_at: i64,
    pub approved_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginAuthorityCutoverRequest {
    pub confirmation_phrase: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveAuthorityCutoverRequest {
    pub cutover_id: String,
    pub expected_predecessor_authority_id: String,
    pub expected_replacement_authority_id: String,
    pub fencing_method: String,
    pub fencing_evidence_reference: String,
    pub confirmation_phrase: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelAuthorityCutoverRequest {
    pub cutover_id: String,
    pub confirmation_phrase: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRecoveryQuarantineRequest {
    pub expected_deployment_id: String,
    pub expected_quarantined_account_count: i64,
    pub expected_revoked_manager_count: i64,
    pub expected_quarantined_endpoint_count: i64,
    pub acknowledge_missing_post_backup_history: bool,
    pub acknowledge_restored_authorities_remain_quarantined: bool,
    pub confirmation_phrase: String,
}

/// Stable server-owned identity used by clients to scope sessions and work.
/// It is an identifier, not an authentication secret.
#[derive(Debug, Clone, Serialize)]
pub struct DeploymentInfoResponse {
    pub deployment_id: String,
}

/// Public verification key for deployment-issued endpoint grants. The secret
/// counterpart remains inside the deployment's private server store.
#[derive(Debug, Clone, Serialize)]
pub struct DeploymentAuthorityResponse {
    pub deployment_id: String,
    pub grant_signing_public_key: String,
    pub authority_generation: i64,
}

/// Request a short-lived observation admission for one enrolled computer.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueObservationGrantRequest {
    pub computer_id: String,
}

/// Signed grant returned once to an authenticated Manager session.
#[derive(Serialize)]
pub struct SignedObservationGrantResponse {
    pub grant_id: String,
    pub computer_id: String,
    pub expires_at_unix: i64,
    pub grant_token: String,
}

impl Drop for SignedObservationGrantResponse {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.grant_token.zeroize();
    }
}

/// A short-lived grant delivered to the endpoint session named by its claims.
#[derive(Serialize)]
pub struct EndpointPendingObservationGrant {
    pub grant_id: String,
    pub computer_id: String,
    pub expires_at_unix: i64,
    pub grant_token: String,
}

impl Drop for EndpointPendingObservationGrant {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.grant_token.zeroize();
    }
}

/// Bounded response for an endpoint session waiting on observation grants.
#[derive(Serialize)]
pub struct EndpointPendingObservationGrantsResponse {
    pub grants: Vec<EndpointPendingObservationGrant>,
}

/// Endpoint returns its fresh nonce, the current native WebRTC channel
/// binding, and the Manager device proof received over that channel. The grant
/// is single-use.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemObservationGrantRequest {
    pub grant_token: String,
    pub endpoint_nonce: String,
    pub channel_binding: String,
    pub manager_proof: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObservationAdmissionAcceptedResponse {
    pub grant_id: String,
    pub computer_id: String,
    pub endpoint_session_id: String,
    pub expires_at_unix: i64,
}

/// One bounded signaling value carried only while its observation grant lives.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSignalRequest {
    pub kind: String,
    pub payload: String,
}

/// A signaling value addressed to the other participant in one grant.
#[derive(Debug, Clone, Serialize)]
pub struct ObservationSignalMessage {
    pub sequence: u64,
    pub sender: &'static str,
    pub kind: String,
    pub payload: String,
}

/// Bounded cursor response for the other participant's signaling values.
#[derive(Debug, Clone, Serialize)]
pub struct ObservationSignalBatch {
    pub cursor: u64,
    pub messages: Vec<ObservationSignalMessage>,
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
            // v2 file jobs bind delivery to a fresh signed endpoint session
            // and the same verified local user, with bounded storage/expiry.
            file_jobs: true,
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
    pub recovery_quarantined: bool,
    pub capabilities: AccountCapabilities,
    pub revision: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountListResponse {
    pub accounts: Vec<AccountView>,
    pub max_page_size: usize,
}

/// Create an inactive account and one-time MFA enrollment material. Password
/// memory is cleared when the request value is dropped.
#[derive(Deserialize)]
pub struct CreateAccountV2Request {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub can_operate: bool,
    #[serde(default)]
    pub can_manage_enrollment: bool,
    #[serde(default)]
    pub can_manage_access: bool,
    #[serde(default)]
    pub can_manage_accounts: bool,
    #[serde(default)]
    pub can_manage_security: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateAccountCapabilitiesRequest {
    pub expected_revision: i64,
    #[serde(default)]
    pub can_operate: bool,
    #[serde(default)]
    pub can_manage_enrollment: bool,
    #[serde(default)]
    pub can_manage_access: bool,
    #[serde(default)]
    pub can_manage_accounts: bool,
    #[serde(default)]
    pub can_manage_security: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountLifecycleState {
    Active,
    Disabled,
}

impl AccountLifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAccountStateRequest {
    pub expected_revision: i64,
    pub state: AccountLifecycleState,
}

impl Drop for CreateAccountV2Request {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}

/// Sensitive one-time response. The HTTP layer must not log this value.
#[derive(Serialize)]
pub struct AccountProvisioningResponse {
    pub account: AccountView,
    pub mfa_enrollment_id: String,
    pub totp_secret_base32: String,
    pub recovery_codes: Vec<String>,
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

/// Register a manager key after an authenticated administrator verifies
/// possession of the key. The new manager remains pending until separately
/// approved by an enrollment administrator.
#[derive(Debug, Clone, Deserialize)]
pub struct ManagerKeyEnrollmentRequest {
    pub public_key: String,
    pub friendly_name: String,
    pub proof: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveManagerRequest {
    /// Must name the approving account's confirmed intent; server derives actor from session.
    pub confirm: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeManagerRequest {
    pub confirm: bool,
    /// Must exactly match the manager ID shown to the administrator.
    pub confirm_manager_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComputerView {
    pub id: String,
    pub public_identity: String,
    pub friendly_name: String,
    pub platform: String,
    pub enrollment_state: String,
    pub enrollment_epoch: i64,
    /// Organization labels only; membership never creates an access grant.
    pub groups: Vec<ComputerGroupRef>,
    /// Latest signed endpoint-session observation. Included only for
    /// computers inside the caller's current observe assignment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_session: Option<ComputerEndpointSessionView>,
}

/// Server view of the latest endpoint-authenticated session. A current
/// endpoint bearer session is not proof that a capture worker is connected
/// or permitted to send pixels.
#[derive(Debug, Clone, Serialize)]
pub struct ComputerEndpointSessionView {
    /// Unix time when the endpoint last completed key proof for this enrolled
    /// incarnation. May be present after that session has expired.
    pub last_authenticated_at_unix: Option<i64>,
    /// Expiration of the current endpoint session, when it remains valid.
    pub current_session_expires_at_unix: Option<i64>,
    /// Opaque current endpoint session identity, present only while unrevoked
    /// and unexpired. It can be used to correlate a short-lived admission.
    pub current_session_id: Option<String>,
    /// Whether that current session reported an eligible signed-in console
    /// user. None means there is no current endpoint session.
    pub console_user_reported: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComputerGroupRef {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComputerGroupView {
    pub id: String,
    pub name: String,
    pub revision: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComputerGroupListResponse {
    pub groups: Vec<ComputerGroupView>,
    pub max_page_size: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateComputerGroupRequest {
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameComputerGroupRequest {
    pub expected_revision: i64,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetComputerGroupMembershipRequest {
    pub expected_revision: i64,
    pub included: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteComputerGroupRequest {
    pub expected_revision: i64,
    /// Must exactly equal the group ID shown to the administrator.
    pub confirm_group_id: String,
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

/// The authenticated account's own observation assignment scope. This is
/// advisory UI state; every observation admission must recheck it server-side.
#[derive(Debug, Clone, Serialize)]
pub struct ObservationScopeResponse {
    pub scope_all: bool,
    pub computer_ids: Vec<String>,
}

/// Enrollment administrators can inspect bounded metadata without receiving
/// the endpoint public identity or gaining observe access.
#[derive(Debug, Clone, Serialize)]
pub struct EnrollmentComputerView {
    pub id: String,
    pub friendly_name: String,
    pub platform: String,
    pub enrollment_state: String,
    pub enrollment_epoch: i64,
    pub groups: Vec<ComputerGroupRef>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollmentComputerListResponse {
    pub computers: Vec<EnrollmentComputerView>,
    pub max_page_size: usize,
}

/// Create a short-lived, single-use invitation for one endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateEndpointInvitationRequest {
    pub friendly_name: String,
    pub platform: String,
}

/// Secret code is serialized once and zeroized when the response is dropped.
pub struct EnrollmentCode(String);

impl EnrollmentCode {
    pub fn new(code: String) -> Self {
        Self(code)
    }
}

impl Serialize for EnrollmentCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl Drop for EnrollmentCode {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

#[derive(Serialize)]
pub struct EndpointInvitationIssuedResponse {
    pub id: String,
    pub deployment_id: String,
    pub friendly_name: String,
    pub platform: String,
    pub enrollment_code: EnrollmentCode,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointInvitationView {
    pub id: String,
    pub friendly_name: String,
    pub platform: String,
    pub state: String,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    pub computer_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointInvitationListResponse {
    pub invitations: Vec<EndpointInvitationView>,
    pub max_page_size: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeEndpointInvitationRequest {
    /// Must exactly match the invitation ID shown to the administrator.
    pub confirm_invitation_id: String,
}

/// Public endpoint enrollment proves possession of the key being registered.
/// The request's code is zeroized immediately after service processing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointEnrollRequest {
    pub invitation_id: String,
    pub enrollment_code: String,
    pub public_key: String,
    pub proof: String,
}

impl Drop for EndpointEnrollRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.enrollment_code.zeroize();
        self.proof.zeroize();
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointEnrollResponse {
    pub computer: EnrollmentComputerView,
    pub state: &'static str,
}

/// Endpoint proves possession before the server allocates a durable challenge.
/// `client_nonce` is 32 random bytes encoded as canonical lowercase hex.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointSessionChallengeRequest {
    pub computer_id: String,
    /// Stable OS account identity from the eligible local user session.
    /// Optional for endpoint versions that do not implement file-recipient binding.
    pub local_user_id: Option<String>,
    /// OS-provided short account name, signed with the stable local identity.
    /// Display only; it never selects or authorizes the recipient.
    pub local_user_display_name: Option<String>,
    pub client_nonce: String,
    pub issued_at_unix: i64,
    pub proof: String,
}

impl Drop for EndpointSessionChallengeRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.proof.zeroize();
        if let Some(display_name) = &mut self.local_user_display_name {
            display_name.zeroize();
        }
    }
}

#[derive(Serialize)]
pub struct EndpointSessionChallengeResponse {
    pub challenge_id: String,
    /// Opaque single-use challenge token. Returned once and never logged.
    pub challenge_token: String,
    pub deployment_id: String,
    pub computer_id: String,
    pub enrollment_epoch: i64,
    pub expires_at_unix: i64,
}

impl Drop for EndpointSessionChallengeResponse {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.challenge_token.zeroize();
    }
}

/// Complete a fresh endpoint challenge with the enrolled key's signature.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointSessionCompleteRequest {
    pub challenge_id: String,
    pub challenge_token: String,
    pub signature: String,
}

impl Drop for EndpointSessionCompleteRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.challenge_token.zeroize();
        self.signature.zeroize();
    }
}

/// Short-lived endpoint bearer session, serialized once by the complete call.
#[derive(Serialize)]
pub struct EndpointSessionIssuedResponse {
    pub token: String,
    pub session_id: String,
    pub deployment_id: String,
    pub computer_id: String,
    pub enrollment_epoch: i64,
    pub expires_at_unix: i64,
}

impl Drop for EndpointSessionIssuedResponse {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.token.zeroize();
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointSelfResponse {
    pub computer_id: String,
    pub friendly_name: String,
    pub platform: String,
    pub enrollment_epoch: i64,
}

/// Create one durable manager-to-endpoint transfer with independently tracked
/// targets. The payload is uploaded separately in fixed-size binary chunks.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFileJobRequest {
    pub file_name: String,
    pub file_size_bytes: u64,
    pub sha256: String,
    pub computer_ids: Vec<String>,
    /// Session IDs shown by the recipient preflight and reconfirmed at create.
    pub expected_recipients: Vec<ExpectedFileJobRecipient>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedFileJobRecipient {
    pub computer_id: String,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileJobRecipientView {
    pub computer_id: String,
    pub session_id: String,
    pub display_name: String,
    pub verified_at_unix: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelFileJobRequest {
    /// Must exactly equal the job ID shown to the manager.
    pub confirm_job_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileJobTargetView {
    pub computer_id: String,
    pub friendly_name: String,
    pub recipient_display_name: Option<String>,
    pub state: String,
    pub result_detail: Option<String>,
    pub received_size_bytes: Option<u64>,
    pub received_sha256: Option<String>,
    pub started_at_unix: Option<i64>,
    pub finished_at_unix: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileJobView {
    pub id: String,
    pub direction: String,
    pub file_name: String,
    pub file_size_bytes: u64,
    pub sha256: String,
    pub chunk_size_bytes: u32,
    pub chunk_count: u32,
    pub state: String,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
    pub delivery_expires_at_unix: i64,
    pub targets: Vec<FileJobTargetView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileJobListResponse {
    pub jobs: Vec<FileJobView>,
    pub max_page_size: usize,
}

/// Aggregate logical file payload reservations for one server deployment.
#[derive(Debug, Clone, Serialize)]
pub struct FileStorageSummary {
    pub payload_limit_bytes: u64,
    pub delivery_payload_bytes: u64,
    pub request_payload_bytes: u64,
    pub reserved_payload_bytes: u64,
    pub available_payload_bytes: u64,
    pub active_file_jobs: u64,
    pub active_file_job_limit: u64,
    pub active_request_uploads: u64,
    pub active_request_upload_limit: u64,
    pub retained_received_files: u64,
    pub retained_received_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointFileJobView {
    pub id: String,
    pub file_name: String,
    pub file_size_bytes: u64,
    pub sha256: String,
    pub chunk_size_bytes: u32,
    pub chunk_count: u32,
    pub state: String,
    pub created_at_unix: i64,
    pub delivery_expires_at_unix: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointFileJobListResponse {
    pub jobs: Vec<EndpointFileJobView>,
    pub max_page_size: usize,
}

/// Create a bounded draft file request for explicitly eligible computers.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFileRequestRequest {
    pub title: String,
    pub instructions: String,
    pub computer_ids: Vec<String>,
    pub allowed_extensions: Vec<String>,
    pub max_file_count: u32,
    pub max_total_size_bytes: u64,
    pub closes_at_unix: i64,
    pub replacement_allowed: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRequestRevisionRequest {
    pub expected_revision: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseFileRequestRequest {
    pub expected_revision: i64,
    pub confirm_request_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteFileRequestSubmissionRequest {
    pub confirm_submission_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRequestView {
    pub id: String,
    pub title: String,
    pub instructions: String,
    pub revision: i64,
    pub state: String,
    pub computer_ids: Vec<String>,
    pub allowed_extensions: Vec<String>,
    pub max_file_count: u32,
    pub max_total_size_bytes: u64,
    pub closes_at_unix: i64,
    pub replacement_allowed: bool,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
    pub published_at_unix: Option<i64>,
    pub closed_at_unix: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRequestListResponse {
    pub requests: Vec<FileRequestView>,
    pub max_page_size: usize,
}

/// Open request metadata shown only to the authenticated eligible endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointFileRequestView {
    pub id: String,
    pub revision: i64,
    pub title: String,
    pub instructions: String,
    pub allowed_extensions: Vec<String>,
    pub max_file_count: u32,
    pub max_total_size_bytes: u64,
    pub closes_at_unix: i64,
    pub replacement_allowed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointFileRequestListResponse {
    pub requests: Vec<EndpointFileRequestView>,
    pub max_page_size: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFileRequestSubmissionRequest {
    pub request_revision: i64,
    pub files: Vec<FileRequestSubmissionFileManifest>,
    pub replace_submission_id: Option<String>,
    pub confirm_replacement: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRequestSubmissionFileManifest {
    pub file_name: String,
    pub file_size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRequestSubmissionFileView {
    pub id: String,
    pub file_name: String,
    pub file_size_bytes: u64,
    pub sha256: String,
    pub chunk_size_bytes: u32,
    pub chunk_count: u32,
    pub state: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRequestSubmissionView {
    pub id: String,
    pub request_id: String,
    pub request_revision: i64,
    pub computer_id: String,
    pub local_user_display_name: String,
    pub state: String,
    pub created_at_unix: i64,
    pub upload_expires_at_unix: i64,
    pub received_at_unix: Option<i64>,
    pub replaces_submission_id: Option<String>,
    pub content_deleted_at_unix: Option<i64>,
    pub content_deleted_by_account_id: Option<String>,
    pub files: Vec<FileRequestSubmissionFileView>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteFileRequestSubmissionRequest {
    pub request_revision: i64,
    pub confirm_submission_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRequestSubmissionChunkReceipt {
    pub submission_id: String,
    pub file_id: String,
    pub chunk_index: u32,
    pub sha256: String,
    pub already_present: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileJobChunkReceipt {
    pub job_id: String,
    pub chunk_index: u32,
    pub received_chunks: u32,
    pub chunk_count: u32,
    pub state: String,
    pub finalized: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointFileJobResultRequest {
    pub succeeded: bool,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub received_size_bytes: Option<u64>,
    #[serde(default)]
    pub received_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointFileJobResultResponse {
    pub job_id: String,
    pub target: FileJobTargetView,
}

pub struct FileJobChunkContent {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputerEnrollmentDecisionRequest {
    pub expected_enrollment_epoch: i64,
    /// Must exactly match the computer ID shown to the enrollment admin.
    pub confirm_computer_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessAssignmentView {
    pub id: String,
    pub account_id: String,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeAccessRequest {
    pub expected_revision: i64,
    pub confirm: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessRevocationResponse {
    pub id: String,
    pub account_id: String,
    pub capability: String,
    pub state: String,
    pub revoked_revision: i64,
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
#[derive(Deserialize)]
pub struct MfaConfirmRequest {
    pub mfa_enrollment_id: String,
    pub totp_code: String,
    /// Operator attests recovery codes were stored outside the server.
    pub recovery_material_stored: bool,
}

impl Drop for MfaConfirmRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.totp_code.zeroize();
    }
}

#[derive(Serialize)]
pub struct MfaEnrollmentBeginResponse {
    pub account_id: String,
    pub mfa_enrollment_id: String,
    pub totp_secret_base32: String,
    pub recovery_codes: Vec<String>,
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
#[derive(Deserialize)]
pub struct FactorRecoveryBeginRequest {
    pub username: String,
    pub password: String,
    pub recovery_code: String,
}

impl Drop for FactorRecoveryBeginRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.recovery_code.zeroize();
    }
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

#[derive(Debug, Clone, Serialize)]
pub struct AuditEventActor {
    pub account_id: String,
    pub manager_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEventView {
    pub id: String,
    pub actor: AuditEventActor,
    pub action: String,
    pub target_ids: Vec<String>,
    pub time_unix: i64,
    pub result: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEventCursor {
    pub before_unix: i64,
    pub before_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEventListResponse {
    pub events: Vec<AuditEventView>,
    pub next_cursor: Option<AuditEventCursor>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEventListQuery {
    pub limit: Option<usize>,
    pub before_unix: Option<i64>,
    pub before_id: Option<String>,
    pub actor_account_id: Option<String>,
    pub action: Option<String>,
    pub target_id: Option<String>,
    pub from_unix: Option<i64>,
    pub to_unix: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditRetentionResponse {
    pub retention_days: i64,
    pub updated_at_unix: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRetentionUpdateRequest {
    pub retention_days: i64,
}
