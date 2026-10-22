//! Auth v2: administrator TOTP MFA, recovery-only verification, device-key
//! challenge login.
//!
//! Trust boundary: password validation mints a bounded durable one-use
//! challenge bound to this deployment, the exact manager Ed25519 key, and the
//! intended operation. Completion proves the approved manager key and required
//! factor, then rechecks trust, consumes factor + challenge, and issues the
//! session **in one final IMMEDIATE transaction**. Pending/revoked managers,
//! replay, wrong key, wrong deployment, clock rollback, and required storage
//! failures all deny. TOTP time steps are consumed transactionally. Recovery
//! codes are hashed at rest and may only recover the TOTP factor — never a
//! normal session and never an operator-chosen target account.
//!
//! Rate-limit state is durable (`challenge_throttle`) and capacity-bounded so
//! restarts do not reset protection. Auth challenges and TOTP consumption rows
//! are pruned under explicit storage caps.

use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

use crate::audit::{record_successful_event, record_successful_event_as};
use crate::crypto::{
    auth_challenge_proof_message, bootstrap_manager_proof_message, generate_recovery_codes,
    generate_totp_secret, hash_password, hash_recovery_code, hash_token,
    manager_enrollment_proof_message, token_hash_eq, totp_time_step, unix_now,
    verify_ed25519_strict, verify_totp_at,
};
use crate::db::{deployment_key, now_unix};
use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::service::{
    require_current_admin_session, require_current_manager_session,
    require_current_recovery_admin_session, AdminCapability, AuthContext, Service,
};

/// Auth challenge lifetime (bounded durable one-use).
const CHALLENGE_TTL_SECS: i64 = 120;
/// Pending MFA enrollment lifetime (bounded; cannot mint a normal session).
const MFA_ENROLLMENT_TTL_SECS: i64 = 15 * 60;
const MFA_ENROLLMENT_RETENTION_SECS: i64 = 24 * 60 * 60;
const MAX_MFA_ENROLLMENTS: i64 = 2_000;
/// Short-lived token issued only after full v2 completion.
const V2_SESSION_TTL_SECS: i64 = 2 * 60 * 60;
/// Challenge rate-limit thresholds (no account enumeration).
const CHALLENGE_MAX_FAILURES: i64 = 5;
const CHALLENGE_LOCKOUT_SECS: i64 = 60;
/// Allowable backwards drift (in time steps) before clock-rollback denial.
/// One step equals 30s; a rollback beyond this window is denied.
const TOTP_MAX_BACKWARD_STEPS: i64 = 1;
/// Intended operations a challenge may bind to.
const ALLOWED_OPERATIONS: &[&str] = &["session", "enroll_manager", "manage_access"];

/// Session row for policy mutation recheck:
/// assurance, mfa_assured_at, expires_at, revoked_at, manager_id, account_id.
type PolicySessionRow = (
    String,
    Option<i64>,
    i64,
    Option<i64>,
    Option<String>,
    String,
);

/// Challenge row: id, token_hash, account_id, manager_public_key, operation,
/// expires_at, consumed_at, deployment_key.
type ChallengeRow = (
    String,
    String,
    String,
    String,
    String,
    i64,
    Option<i64>,
    String,
);

fn normalize_throttle_key(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn validate_operation(operation: &str) -> AppResult<()> {
    if ALLOWED_OPERATIONS.contains(&operation) {
        Ok(())
    } else {
        Err(AppError::bad_request(format!(
            "operation must be one of: {}",
            ALLOWED_OPERATIONS.join(", ")
        )))
    }
}

fn validate_totp_code(code: &str) -> AppResult<()> {
    let trimmed = code.trim();
    if trimmed.len() != 6 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::bad_request("totp code must be exactly 6 digits"));
    }
    Ok(())
}

/// Freshness window for an MFA-backed session that may mutate operator MFA policy.
pub(crate) const POLICY_MUTATION_MFA_FRESH_SECS: i64 = 120;

/// Load the deployment operator MFA policy.
///
/// Unknown or corrupt stored values deny authority (`unprocessable`) rather
/// than silently defaulting. Missing `security_policy` is equally fatal.
pub(crate) fn load_operator_mfa_policy(
    conn: &rusqlite::Connection,
) -> AppResult<OperatorMfaPolicy> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT operator_mfa_policy FROM security_policy WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    match raw.as_deref() {
        Some("optional") => Ok(OperatorMfaPolicy::Optional),
        Some("required") => Ok(OperatorMfaPolicy::Required),
        Some(_) => {
            // Never log the raw stored value — only safe failure metadata.
            tracing::error!("corrupt operator_mfa_policy; denying authority");
            Err(AppError::unprocessable(
                "operator mfa policy is corrupt; denying authority until repaired",
            ))
        }
        None => {
            tracing::error!("security_policy row missing; denying authority");
            Err(AppError::unprocessable(
                "operator mfa policy is missing; denying authority",
            ))
        }
    }
}

/// Effective mandatory MFA for one account.
///
/// Administrator (`can_manage_security`) OR operator policy `required` OR an
/// already-active enrolled factor. An `optional` policy never removes factor
/// protection from an account that already has an active factor.
fn effective_mfa_required(
    conn: &rusqlite::Connection,
    account_id: &str,
) -> AppResult<(bool, bool)> {
    let policy = load_operator_mfa_policy(conn)?;
    let is_admin: bool = conn.query_row(
        "SELECT can_manage_security FROM accounts WHERE id = ?1",
        params![account_id],
        |r| r.get(0),
    )?;
    let status: Option<String> = conn
        .query_row(
            "SELECT status FROM account_mfa WHERE account_id = ?1",
            params![account_id],
            |r| r.get(0),
        )
        .optional()?;
    let has_active_factor = status.as_deref() == Some("active");
    let required = is_admin || policy == OperatorMfaPolicy::Required || has_active_factor;
    Ok((required, has_active_factor))
}

fn load_recovery_quarantine_status(
    conn: &rusqlite::Connection,
) -> AppResult<RecoveryQuarantineStatusResponse> {
    let (deployment_id, recovery_quarantined): (String, bool) = conn.query_row(
        "SELECT deployment_key, recovery_quarantined FROM deployment WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let quarantined_account_count = conn.query_row(
        "SELECT COUNT(*) FROM accounts WHERE recovery_quarantined = 1",
        [],
        |row| row.get(0),
    )?;
    let revoked_manager_count = conn.query_row(
        "SELECT COUNT(*) FROM managers WHERE lifecycle_state = 'revoked'",
        [],
        |row| row.get(0),
    )?;
    let quarantined_endpoint_count = conn.query_row(
        "SELECT COUNT(*) FROM computers WHERE enrollment_state = 'quarantined'",
        [],
        |row| row.get(0),
    )?;

    Ok(RecoveryQuarantineStatusResponse {
        deployment_id,
        recovery_quarantined,
        quarantined_account_count,
        revoked_manager_count,
        quarantined_endpoint_count,
    })
}

impl Service {
    /// Register a new manager device key after an authorized administrator
    /// verifies possession. Approval remains a separate, explicit operation.
    pub fn enroll_manager_key(
        &self,
        auth: &AuthContext,
        req: ManagerKeyEnrollmentRequest,
    ) -> AppResult<ManagerView> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        if !auth.can_manage_enrollment {
            return Err(AppError::forbidden(
                "enrollment management permission is required to register a manager",
            ));
        }

        let public_key = req.public_key.trim().to_ascii_lowercase();
        if public_key.len() != 64 || !public_key.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError::bad_request("public_key must be 32 bytes of hex"));
        }
        let friendly_name = req.friendly_name.trim().to_string();
        if friendly_name.is_empty() || friendly_name.len() > 128 {
            return Err(AppError::bad_request(
                "manager friendly name must be 1–128 characters",
            ));
        }
        if req.proof.trim().is_empty() || req.proof.len() > 256 {
            return Err(AppError::bad_request("manager proof is required"));
        }

        let deployment_id = self.with_conn(deployment_key)?;
        let proof_message =
            manager_enrollment_proof_message(&deployment_id, &public_key, &friendly_name);
        if !verify_ed25519_strict(&public_key, &proof_message, req.proof.trim())? {
            return Err(AppError::forbidden(
                "manager device proof is invalid for this deployment",
            ));
        }

        let manager_id = Uuid::new_v4().to_string();
        let public_identity = format!("key:{public_key}");
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_admin_session(
                conn,
                auth,
                AdminCapability::Enrollment,
                now,
                false,
                true,
            )?;

            let manager_count: i64 =
                conn.query_row("SELECT COUNT(*) FROM managers", [], |row| row.get(0))?;
            if manager_count >= crate::service::MAX_PAGE_SIZE as i64 {
                return Err(AppError::conflict(
                    "manager device limit reached",
                    Some("max_page_size".to_string()),
                ));
            }

            conn.execute(
                "INSERT INTO managers (
                    id, public_identity, friendly_name, lifecycle_state,
                    approved_by_account_id, approved_at, created_at, updated_at, public_key
                 ) VALUES (?1, ?2, ?3, 'pending', NULL, NULL, ?4, ?4, ?5)",
                params![manager_id, public_identity, friendly_name, now, public_key],
            )
            .map_err(|err| crate::service::map_unique(err, "manager device key already exists"))?;
            record_successful_event(
                conn,
                auth,
                "manager.enrolled",
                std::slice::from_ref(&manager_id),
                "manager_key_proved",
                now,
            )?;
            Ok(())
        })?;

        self.load_manager_view(&manager_id)
    }

    /// Create a pending account with a one-time TOTP and recovery enrollment.
    /// The caller must use a recently MFA-assured, approved Manager session.
    pub fn create_account_v2(
        &self,
        auth: &AuthContext,
        req: CreateAccountV2Request,
    ) -> AppResult<AccountProvisioningResponse> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        if !auth.can_manage_accounts {
            return Err(AppError::forbidden(
                "account management permission is required to create an account",
            ));
        }

        let username = req.username.trim().to_string();
        crate::service::validate_username(&username)?;
        crate::service::validate_password(&req.password)?;
        let password_hash = hash_password(&req.password)?;
        let totp_secret = generate_totp_secret()?;
        let recovery = generate_recovery_codes()?;
        let account_id = Uuid::new_v4().to_string();
        let enrollment_id = Uuid::new_v4().to_string();
        let now = now_unix();
        let recovery_hashes: Vec<(String, String)> = recovery
            .iter()
            .map(|code| (Uuid::new_v4().to_string(), code.code_hash.clone()))
            .collect();

        self.with_tx(|conn| {
            require_current_admin_session(conn, auth, AdminCapability::Accounts, now, true, true)?;
            let actor_can_manage_security: bool = conn.query_row(
                "SELECT can_manage_security FROM accounts WHERE id = ?1",
                params![auth.account_id],
                |row| row.get(0),
            )?;
            if req.can_manage_security && !actor_can_manage_security {
                return Err(AppError::forbidden(
                    "only a security administrator can grant security administration",
                ));
            }
            let account_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM accounts WHERE recovery_quarantined = 0",
                [],
                |row| row.get(0),
            )?;
            if account_count >= crate::service::MAX_PAGE_SIZE as i64 {
                return Err(AppError::conflict(
                    "account limit reached",
                    Some("max_page_size".to_string()),
                ));
            }

            conn.execute(
                "INSERT INTO accounts (
                    id, username, password_hash, state,
                    can_operate, can_manage_enrollment, can_manage_access,
                    can_manage_accounts, can_manage_security,
                    revision, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, 'pending_mfa', ?4, ?5, ?6, ?7, ?8, 1, ?9, ?9)",
                params![
                    account_id,
                    username,
                    password_hash,
                    req.can_operate,
                    req.can_manage_enrollment,
                    req.can_manage_access,
                    req.can_manage_accounts,
                    req.can_manage_security,
                    now
                ],
            )
            .map_err(|err| crate::service::map_unique(err, "username already exists"))?;

            conn.execute(
                "INSERT INTO account_mfa (
                    account_id, totp_secret, totp_confirmed_at, recovery_stored_at,
                    status, created_at, updated_at
                 ) VALUES (?1, ?2, NULL, NULL, 'pending', ?3, ?3)",
                params![account_id, totp_secret, now],
            )?;
            for (code_id, code_hash) in &recovery_hashes {
                conn.execute(
                    "INSERT INTO recovery_codes (id, account_id, code_hash, created_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![code_id, account_id, code_hash, now],
                )?;
            }
            conn.execute(
                "INSERT INTO mfa_enrollments (
                    id, account_id, totp_secret, recovery_committed,
                    created_at, expires_at, consumed_at
                 ) VALUES (?1, ?2, ?3, 0, ?4, ?5, NULL)",
                params![
                    enrollment_id,
                    account_id,
                    totp_secret,
                    now,
                    now + MFA_ENROLLMENT_TTL_SECS
                ],
            )?;
            record_successful_event(
                conn,
                auth,
                "account.created",
                std::slice::from_ref(&account_id),
                "account_provisioned",
                now,
            )?;
            Ok(())
        })?;

        let account = AccountView {
            id: account_id.clone(),
            username: username.clone(),
            state: "pending_mfa".to_string(),
            recovery_quarantined: false,
            capabilities: AccountCapabilities {
                operate: req.can_operate,
                manage_enrollment: req.can_manage_enrollment,
                manage_access: req.can_manage_access,
                manage_accounts: req.can_manage_accounts,
                manage_security: req.can_manage_security,
            },
            revision: 1,
        };
        let recovery_codes = recovery.into_iter().map(|code| code.plaintext).collect();
        Ok(AccountProvisioningResponse {
            account,
            mfa_enrollment_id: enrollment_id,
            totp_secret_base32: totp_secret,
            recovery_codes,
        })
    }

    /// Update an active account's bounded capability set with current authority.
    pub fn update_account_capabilities_v2(
        &self,
        auth: &AuthContext,
        account_id: &str,
        req: UpdateAccountCapabilitiesRequest,
    ) -> AppResult<AccountView> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        if !auth.can_manage_accounts {
            return Err(AppError::forbidden(
                "account management permission is required to change capabilities",
            ));
        }
        if account_id.is_empty() || account_id.len() > 128 {
            return Err(AppError::bad_request("account id is invalid"));
        }
        if req.expected_revision < 1 {
            return Err(AppError::bad_request("expected_revision must be positive"));
        }

        let now = now_unix();
        self.with_tx(|conn| {
            require_current_admin_session(conn, auth, AdminCapability::Accounts, now, true, true)?;
            let actor_can_manage_security: bool = conn.query_row(
                "SELECT can_manage_security FROM accounts WHERE id = ?1",
                params![auth.account_id],
                |row| row.get(0),
            )?;
            let current: Option<(String, bool, i64)> = conn
                .query_row(
                    "SELECT state, can_manage_security, revision FROM accounts WHERE id = ?1",
                    params![account_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let (state, currently_security_admin, current_revision) =
                current.ok_or_else(|| AppError::not_found("target account not found"))?;
            if current_revision != req.expected_revision {
                return Err(AppError::conflict(
                    "target account revision changed; refresh before retrying",
                    Some("revision_changed".to_string()),
                ));
            }
            if state != "active" {
                return Err(AppError::forbidden(
                    "only an active account's capabilities can be changed",
                ));
            }
            if !actor_can_manage_security && (currently_security_admin || req.can_manage_security) {
                return Err(AppError::forbidden(
                    "only a security administrator can change security administration",
                ));
            }
            if req.can_manage_security && !currently_security_admin {
                let active_factor: bool = conn.query_row(
                    "SELECT EXISTS (
                        SELECT 1 FROM account_mfa
                         WHERE account_id = ?1 AND status = 'active'
                    )",
                    params![account_id],
                    |row| row.get(0),
                )?;
                if !active_factor {
                    return Err(AppError::conflict(
                        "target account must complete MFA before becoming a security administrator",
                        Some("mfa_required".to_string()),
                    ));
                }
            }
            if currently_security_admin && !req.can_manage_security {
                let active_security_admins: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM accounts
                     WHERE state = 'active' AND can_manage_security = 1",
                    [],
                    |row| row.get(0),
                )?;
                if active_security_admins <= 1 {
                    return Err(AppError::conflict(
                        "the last active security administrator cannot be removed",
                        Some("last_security_administrator".to_string()),
                    ));
                }
            }

            let changed = conn.execute(
                "UPDATE accounts
                 SET can_operate = ?1, can_manage_enrollment = ?2,
                     can_manage_access = ?3, can_manage_accounts = ?4,
                     can_manage_security = ?5, revision = revision + 1, updated_at = ?6
                 WHERE id = ?7 AND state = 'active' AND revision = ?8",
                params![
                    req.can_operate,
                    req.can_manage_enrollment,
                    req.can_manage_access,
                    req.can_manage_accounts,
                    req.can_manage_security,
                    now,
                    account_id,
                    req.expected_revision,
                ],
            )?;
            if changed != 1 {
                return Err(AppError::conflict(
                    "target account changed during capability update",
                    Some("revision_changed".to_string()),
                ));
            }
            record_successful_event(
                conn,
                auth,
                "account.capabilities_updated",
                &[account_id.to_string()],
                "capabilities_updated",
                now,
            )?;
            Ok(())
        })?;

        self.load_account_view(account_id)
    }

    /// Activate or disable an existing account with current administrator
    /// authority. Disabling revokes every session for the target account.
    pub fn update_account_state_v2(
        &self,
        auth: &AuthContext,
        account_id: &str,
        req: UpdateAccountStateRequest,
    ) -> AppResult<AccountView> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        if !auth.can_manage_accounts {
            return Err(AppError::forbidden(
                "account management permission is required to change account state",
            ));
        }
        if account_id.is_empty() || account_id.len() > 128 {
            return Err(AppError::bad_request("account id is invalid"));
        }
        if req.expected_revision < 1 {
            return Err(AppError::bad_request("expected_revision must be positive"));
        }

        let now = now_unix();
        self.with_tx(|conn| {
            require_current_admin_session(conn, auth, AdminCapability::Accounts, now, true, true)?;
            let actor_can_manage_security: bool = conn.query_row(
                "SELECT can_manage_security FROM accounts WHERE id = ?1",
                params![auth.account_id],
                |row| row.get(0),
            )?;
            let current: Option<(String, bool, i64, bool)> = conn
                .query_row(
                    "SELECT state, can_manage_security, revision, recovery_quarantined
                     FROM accounts WHERE id = ?1",
                    params![account_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let (current_state, target_is_security_admin, current_revision, recovery_quarantined) =
                current.ok_or_else(|| AppError::not_found("target account not found"))?;
            if recovery_quarantined {
                return Err(AppError::conflict(
                    "account authority from the restored backup remains quarantined",
                    Some("recovery_quarantined".to_string()),
                ));
            }
            if current_revision != req.expected_revision {
                return Err(AppError::conflict(
                    "target account revision changed; refresh before retrying",
                    Some("revision_changed".to_string()),
                ));
            }
            if current_state != "active" && current_state != "disabled" {
                return Err(AppError::conflict(
                    "only active or disabled accounts can change lifecycle state",
                    Some("account_state_conflict".to_string()),
                ));
            }
            let next_state = req.state.as_str();
            if current_state == next_state {
                return Ok(());
            }

            if next_state == "disabled" && target_is_security_admin {
                if !actor_can_manage_security {
                    return Err(AppError::forbidden(
                        "only a security administrator can disable a security administrator",
                    ));
                }
                let active_security_admins: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM accounts
                     WHERE state = 'active' AND can_manage_security = 1",
                    [],
                    |row| row.get(0),
                )?;
                if active_security_admins <= 1 {
                    return Err(AppError::conflict(
                        "the last active security administrator cannot be disabled",
                        Some("last_security_administrator".to_string()),
                    ));
                }
            }
            if next_state == "active" && target_is_security_admin {
                if !actor_can_manage_security {
                    return Err(AppError::forbidden(
                        "only a security administrator can reactivate a security administrator",
                    ));
                }
                let active_factor: bool = conn.query_row(
                    "SELECT EXISTS (
                        SELECT 1 FROM account_mfa
                         WHERE account_id = ?1 AND status = 'active'
                    )",
                    params![account_id],
                    |row| row.get(0),
                )?;
                if !active_factor {
                    return Err(AppError::conflict(
                        "a security administrator must have active MFA before activation",
                        Some("mfa_required".to_string()),
                    ));
                }
            }

            let changed = conn.execute(
                "UPDATE accounts
                 SET state = ?1, revision = revision + 1, updated_at = ?2
                 WHERE id = ?3 AND state = ?4 AND revision = ?5",
                params![
                    next_state,
                    now,
                    account_id,
                    current_state,
                    req.expected_revision
                ],
            )?;
            if changed != 1 {
                return Err(AppError::conflict(
                    "target account changed during lifecycle update",
                    Some("revision_changed".to_string()),
                ));
            }
            if next_state == "disabled" {
                conn.execute(
                    "UPDATE sessions SET revoked_at = ?1
                     WHERE account_id = ?2 AND revoked_at IS NULL",
                    params![now, account_id],
                )?;
            }
            record_successful_event(
                conn,
                auth,
                "account.state_updated",
                &[account_id.to_string()],
                if next_state == "disabled" {
                    "account_disabled"
                } else {
                    "account_activated"
                },
                now,
            )?;
            Ok(())
        })?;

        self.load_account_view(account_id)
    }

    /// Approve a pending Manager device from an independently authenticated
    /// enrollment administrator. The database rechecks fresh MFA and the
    /// approved key-bearing manager session inside the write transaction.
    pub fn approve_manager_v2(
        &self,
        auth: &AuthContext,
        manager_id: &str,
        req: ApproveManagerRequest,
    ) -> AppResult<ManagerView> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        if !auth.can_manage_enrollment {
            return Err(AppError::forbidden(
                "enrollment management permission is required to approve a manager",
            ));
        }
        if manager_id.is_empty()
            || manager_id.len() > 128
            || manager_id.chars().any(char::is_control)
        {
            return Err(AppError::bad_request("manager ID is invalid"));
        }
        if !req.confirm {
            return Err(AppError::bad_request(
                "confirm must be true to approve a manager identity",
            ));
        }

        let now = now_unix();
        let approving_account = auth.account_id.clone();
        self.with_tx(|conn| {
            require_current_admin_session(
                conn,
                auth,
                AdminCapability::Enrollment,
                now,
                true,
                true,
            )?;
            let lifecycle: Option<String> = conn
                .query_row(
                    "SELECT lifecycle_state FROM managers WHERE id = ?1",
                    params![manager_id],
                    |row| row.get(0),
                )
                .optional()?;
            match lifecycle.as_deref() {
                None => return Err(AppError::not_found("manager not found")),
                Some("revoked") => {
                    return Err(AppError::conflict(
                        "manager identity is revoked and must be replaced",
                        None,
                    ))
                }
                Some("approved") => {
                    return Err(AppError::conflict("manager already approved", None))
                }
                Some("pending") => {}
                Some(_) => {
                    return Err(AppError::unprocessable(
                        "manager lifecycle state is invalid",
                    ))
                }
            }
            conn.execute(
                "UPDATE managers
                 SET lifecycle_state = 'approved', approved_by_account_id = ?1,
                     approved_at = ?2, updated_at = ?2
                 WHERE id = ?3 AND lifecycle_state = 'pending'",
                params![approving_account, now, manager_id],
            )?;
            record_successful_event(
                conn,
                auth,
                "manager.approved",
                &[manager_id.to_string()],
                "manager_approved",
                now,
            )?;
            Ok(())
        })?;
        self.load_manager_view(manager_id)
    }

    /// Revoke a Manager device after an exact-ID confirmation. Its existing
    /// sessions are revoked in the same transaction as the lifecycle change.
    pub fn revoke_manager_v2(
        &self,
        auth: &AuthContext,
        manager_id: &str,
        req: RevokeManagerRequest,
    ) -> AppResult<ManagerView> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        if !auth.can_manage_enrollment {
            return Err(AppError::forbidden(
                "enrollment management permission is required to revoke a manager",
            ));
        }
        if manager_id.is_empty()
            || manager_id.len() > 128
            || manager_id.chars().any(char::is_control)
        {
            return Err(AppError::bad_request("manager ID is invalid"));
        }
        if !req.confirm || req.confirm_manager_id != manager_id {
            return Err(AppError::bad_request(
                "confirm must be true and confirm_manager_id must exactly match the manager ID",
            ));
        }

        let now = now_unix();
        self.with_tx(|conn| {
            require_current_admin_session(
                conn,
                auth,
                AdminCapability::Enrollment,
                now,
                true,
                true,
            )?;
            let changed = conn.execute(
                "UPDATE managers
                 SET lifecycle_state = 'revoked', updated_at = ?1
                 WHERE id = ?2 AND lifecycle_state IN ('pending', 'approved')",
                params![now, manager_id],
            )?;
            if changed == 0 {
                return Err(AppError::not_found("manager not found or already revoked"));
            }
            conn.execute(
                "UPDATE sessions SET revoked_at = ?1
                 WHERE manager_id = ?2 AND revoked_at IS NULL",
                params![now, manager_id],
            )?;
            record_successful_event(
                conn,
                auth,
                "manager.revoked",
                &[manager_id.to_string()],
                "manager_revoked",
                now,
            )?;
            Ok(())
        })?;
        self.load_manager_view(manager_id)
    }

    /// Begin optional TOTP enrollment for the authenticated account itself.
    /// This gives delegated operators a path to satisfy fresh-MFA write gates.
    pub fn begin_self_mfa_enrollment(
        &self,
        auth: &AuthContext,
    ) -> AppResult<MfaEnrollmentBeginResponse> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        let account_id = auth.account_id.clone();
        let enrollment_id = Uuid::new_v4().to_string();
        let totp_secret = generate_totp_secret()?;
        let recovery = generate_recovery_codes()?;
        let now = now_unix();
        let recovery_hashes: Vec<(String, String)> = recovery
            .iter()
            .map(|code| (Uuid::new_v4().to_string(), code.code_hash.clone()))
            .collect();

        self.with_tx(|conn| {
            let authority_state: String = conn.query_row(
                "SELECT authority_state FROM deployment WHERE id = 1",
                [],
                |row| row.get(0),
            )?;
            if authority_state != "active" {
                return Err(AppError::forbidden(
                    "authority is not Active; new MFA enrollment is paused during cutover",
                ));
            }
            require_current_manager_session(conn, auth, now)?;
            conn.execute(
                "UPDATE mfa_enrollments SET consumed_at = ?1
                 WHERE consumed_at IS NULL AND expires_at <= ?1",
                params![now],
            )?;
            conn.execute(
                "DELETE FROM mfa_enrollments
                 WHERE consumed_at IS NOT NULL AND consumed_at < ?1",
                params![now - MFA_ENROLLMENT_RETENTION_SECS],
            )?;
            let enrollment_count: i64 =
                conn.query_row("SELECT COUNT(*) FROM mfa_enrollments", [], |row| row.get(0))?;
            if enrollment_count >= MAX_MFA_ENROLLMENTS {
                return Err(AppError::conflict(
                    "MFA enrollment capacity reached; remove old enrollment history before retrying",
                    Some("enrollment_capacity".to_string()),
                ));
            }
            let factor_status: Option<String> = conn
                .query_row(
                    "SELECT status FROM account_mfa WHERE account_id = ?1",
                    params![account_id],
                    |row| row.get(0),
                )
                .optional()?;
            if factor_status.as_deref() == Some("active") {
                return Err(AppError::conflict(
                    "an active factor already exists; use recovery to replace it",
                    Some("factor_active".to_string()),
                ));
            }

            // Replace an abandoned pending enrollment for this same account.
            conn.execute(
                "UPDATE mfa_enrollments SET consumed_at = ?1
                 WHERE account_id = ?2 AND consumed_at IS NULL",
                params![now, account_id],
            )?;
            conn.execute(
                "DELETE FROM recovery_codes WHERE account_id = ?1 AND used_at IS NULL",
                params![account_id],
            )?;
            if factor_status.is_some() {
                conn.execute(
                    "UPDATE account_mfa
                     SET totp_secret = ?1, totp_confirmed_at = NULL,
                         recovery_stored_at = NULL, status = 'pending', updated_at = ?2
                     WHERE account_id = ?3 AND status = 'pending'",
                    params![totp_secret, now, account_id],
                )?;
            } else {
                conn.execute(
                    "INSERT INTO account_mfa (
                        account_id, totp_secret, totp_confirmed_at, recovery_stored_at,
                        status, created_at, updated_at
                     ) VALUES (?1, ?2, NULL, NULL, 'pending', ?3, ?3)",
                    params![account_id, totp_secret, now],
                )?;
            }
            for (code_id, code_hash) in &recovery_hashes {
                conn.execute(
                    "INSERT INTO recovery_codes (id, account_id, code_hash, created_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![code_id, account_id, code_hash, now],
                )?;
            }
            conn.execute(
                "INSERT INTO mfa_enrollments (
                    id, account_id, totp_secret, recovery_committed,
                    created_at, expires_at, consumed_at
                 ) VALUES (?1, ?2, ?3, 0, ?4, ?5, NULL)",
                params![
                    enrollment_id,
                    account_id,
                    totp_secret,
                    now,
                    now + MFA_ENROLLMENT_TTL_SECS
                ],
            )?;
            record_successful_event(
                conn,
                auth,
                "account.mfa_enrollment_started",
                &[account_id.clone(), enrollment_id.clone()],
                "self_enrollment_started",
                now,
            )?;
            Ok(())
        })?;

        Ok(MfaEnrollmentBeginResponse {
            account_id,
            mfa_enrollment_id: enrollment_id,
            totp_secret_base32: totp_secret,
            recovery_codes: recovery.into_iter().map(|code| code.plaintext).collect(),
        })
    }

    // ----- durable challenge throttle (capacity-bounded, restart-safe) -----

    /// Fail closed when the durable throttle says this key is locked.
    fn check_challenge_throttle(&self, key: &str) -> AppResult<()> {
        let key = normalize_throttle_key(key);
        let now = now_unix();
        self.with_conn(|conn| {
            crate::db::prune_challenge_throttle(conn, now)?;
            let row: Option<(i64, Option<i64>)> = conn
                .query_row(
                    "SELECT failure_count, locked_until FROM challenge_throttle WHERE throttle_key = ?1",
                    params![key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((_, locked_until)) = row {
                if locked_until.map(|until| until > now).unwrap_or(false) {
                    return Err(AppError::rate_limited(
                        "too many failed authentication attempts; try again shortly",
                    ));
                }
            }
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM challenge_throttle",
                [],
                |r| r.get(0),
            )?;
            if row.is_none() && count >= crate::db::MAX_CHALLENGE_THROTTLE_KEYS {
                return Err(AppError::rate_limited(
                    "authentication temporarily unavailable (throttle capacity)",
                ));
            }
            Ok(())
        })
    }

    /// Record a failure in the durable throttle (best-effort latch on error).
    fn record_challenge_failure(&self, key: &str) {
        let key = normalize_throttle_key(key);
        let now = now_unix();
        let _ = self.with_tx(|conn| {
            crate::db::prune_challenge_throttle(conn, now)?;
            let row: Option<(i64, Option<i64>)> = conn
                .query_row(
                    "SELECT failure_count, locked_until FROM challenge_throttle WHERE throttle_key = ?1",
                    params![key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (mut failures, _) = row.unwrap_or((0, None));
            if row.is_none() {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM challenge_throttle",
                    [],
                    |r| r.get(0),
                )?;
                if count >= crate::db::MAX_CHALLENGE_THROTTLE_KEYS {
                    return Ok(());
                }
            }
            failures += 1;
            let locked_until = if failures >= CHALLENGE_MAX_FAILURES {
                Some(now + CHALLENGE_LOCKOUT_SECS)
            } else {
                None
            };
            let reset_count = if locked_until.is_some() {
                0
            } else {
                failures
            };
            conn.execute(
                "INSERT INTO challenge_throttle (throttle_key, failure_count, locked_until, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (throttle_key) DO UPDATE SET
                    failure_count = excluded.failure_count,
                    locked_until = excluded.locked_until,
                    updated_at = excluded.updated_at",
                params![key, reset_count, locked_until, now],
            )?;
            Ok(())
        });
    }

    fn clear_challenge_failures(&self, key: &str) {
        let key = normalize_throttle_key(key);
        let _ = self.with_tx(|conn| {
            conn.execute(
                "DELETE FROM challenge_throttle WHERE throttle_key = ?1",
                params![key],
            )?;
            Ok(())
        });
    }

    // ----- bootstrap v2 (local CLI / authenticated tunnel) -----

    /// Transactional single-use bootstrap enrollment for the first administrator.
    ///
    /// Creates the account in `pending_mfa` (inactive). Returns the TOTP secret
    /// and recovery codes once so the operator can store them independently.
    /// An optional manager key is bound only after its Ed25519 proof over the
    /// bootstrap token hash — never from a claimed identity alone.
    pub fn bootstrap_v2(&self, req: BootstrapV2Request) -> AppResult<BootstrapV2Response> {
        // Deny NEW persisted v2 MFA credentials BEFORE the transaction when
        // this store cannot enforce a private credential store. Capability is
        // Db-owned: nonpersistent in-memory test stores still exercise real
        // crypto; persistent unverified stores deny. Legacy v1 loopback
        // development is unaffected; no TOTP is printed here.
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        crate::service::validate_username(&req.username)?;
        crate::service::validate_password(&req.password)?;

        if let Some(proof) = &req.manager_proof {
            if req.manager_public_key.is_none() {
                return Err(AppError::bad_request(
                    "manager_public_key is required when manager_proof is provided",
                ));
            }
            let _ = proof;
        }
        if req.manager_public_key.is_some() && req.manager_proof.is_none() {
            return Err(AppError::bad_request(
                "manager_proof is required to bind a manager device key",
            ));
        }

        let recovery_quarantined = self.with_conn(|conn| {
            let quarantined: bool = conn.query_row(
                "SELECT recovery_quarantined FROM deployment WHERE id = 1",
                [],
                |row| row.get(0),
            )?;
            Ok(quarantined)
        })?;
        if recovery_quarantined && req.manager_public_key.is_none() {
            return Err(AppError::bad_request(
                "restore recovery requires a fresh Manager device key and proof",
            ));
        }

        let password_hash = crate::crypto::hash_password(&req.password)?;
        let totp_secret = generate_totp_secret()?;
        let recovery = generate_recovery_codes()?;
        let now = now_unix();
        let account_id = Uuid::new_v4().to_string();
        let mfa_id = Uuid::new_v4().to_string();
        let token_hash = hash_token(&req.bootstrap_token);
        let dep_key = self.with_conn(deployment_key)?;

        // Verify manager proof against this deployment + bootstrap token hash
        // before any write. Deployment id is server-owned, never client-selected.
        let manager_public_key = match (&req.manager_public_key, &req.manager_proof) {
            (Some(public_key), Some(proof)) => {
                let message = bootstrap_manager_proof_message(&dep_key, &token_hash, public_key);
                let ok = verify_ed25519_strict(public_key, &message, proof)?;
                if !ok {
                    return Err(AppError::forbidden(
                        "manager device key proof is invalid for this deployment/bootstrap token",
                    ));
                }
                Some(public_key.trim().to_ascii_lowercase())
            }
            _ => None,
        };

        let manager_id = manager_public_key
            .as_ref()
            .map(|_| Uuid::new_v4().to_string());

        let recovery_hashes: Vec<(String, String)> = recovery
            .iter()
            .map(|c| (Uuid::new_v4().to_string(), c.code_hash.clone()))
            .collect();

        let outcome = self.with_tx(|conn| {
            let unconsumed: Option<String> = conn
                .query_row(
                    "SELECT token_hash FROM bootstrap_tokens
                     WHERE token_hash = ?1 AND consumed_at IS NULL",
                    params![token_hash],
                    |row| row.get(0),
                )
                .optional()?;
            let token_hash = match unconsumed {
                Some(hash) => hash,
                None => {
                    return Err(AppError::forbidden(
                        "bootstrap token is missing, already used, or invalid",
                    ))
                }
            };

            let (bootstrap_done, recovery_quarantined): (bool, bool) = conn.query_row(
                "SELECT bootstrap_completed, recovery_quarantined FROM deployment WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if bootstrap_done {
                return Err(AppError::conflict(
                    "bootstrap already completed",
                    Some("single_use".to_string()),
                ));
            }
            if recovery_quarantined && req.manager_public_key.is_none() {
                return Err(AppError::bad_request(
                    "restore recovery requires a fresh Manager device key and proof",
                ));
            }

            conn.execute(
                "INSERT INTO accounts (
                    id, username, password_hash, state,
                    can_operate, can_manage_enrollment, can_manage_access,
                    can_manage_accounts, can_manage_security,
                    revision, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, 'pending_mfa', 1, 1, 1, 1, 1, 1, ?4, ?4)",
                params![account_id, req.username, password_hash, now],
            )
            .map_err(|err| crate::service::map_unique(err, "username already exists"))?;

            conn.execute(
                "INSERT INTO account_mfa (
                    account_id, totp_secret, totp_confirmed_at, recovery_stored_at,
                    status, created_at, updated_at
                 ) VALUES (?1, ?2, NULL, NULL, 'pending', ?3, ?3)",
                params![account_id, totp_secret, now],
            )?;

            for (code_id, code_hash) in &recovery_hashes {
                conn.execute(
                    "INSERT INTO recovery_codes (id, account_id, code_hash, created_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![code_id, account_id, code_hash, now],
                )?;
            }

            conn.execute(
                "INSERT INTO mfa_enrollments (
                    id, account_id, totp_secret, recovery_committed,
                    created_at, expires_at, consumed_at
                 ) VALUES (?1, ?2, ?3, 0, ?4, ?5, NULL)",
                params![
                    mfa_id,
                    account_id,
                    totp_secret,
                    now,
                    now + MFA_ENROLLMENT_TTL_SECS
                ],
            )?;

            if let (Some(manager_id), Some(public_key)) = (&manager_id, &manager_public_key) {
                let friendly = req
                    .manager_friendly_name
                    .clone()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| "Bootstrap manager".to_string());
                let identity = format!("key:{public_key}");
                conn.execute(
                    "INSERT INTO managers (
                        id, public_identity, friendly_name, lifecycle_state,
                        approved_by_account_id, approved_at, created_at, updated_at, public_key
                     ) VALUES (?1, ?2, ?3, 'approved', ?4, ?5, ?5, ?5, ?6)",
                    params![manager_id, identity, friendly, account_id, now, public_key],
                )
                .map_err(|err| {
                    crate::service::map_unique(err, "manager device key already exists")
                })?;
            }

            conn.execute(
                "UPDATE deployment
                 SET bootstrap_completed = 1, bootstrap_completed_at = ?1
                 WHERE id = 1",
                params![now],
            )?;
            conn.execute(
                "UPDATE bootstrap_tokens SET consumed_at = ?1 WHERE token_hash = ?2",
                params![now, token_hash],
            )?;

            let mut audit_targets = vec![account_id.clone()];
            if let Some(manager_id) = &manager_id {
                audit_targets.push(manager_id.clone());
            }
            record_successful_event_as(
                conn,
                &account_id,
                manager_id.as_deref(),
                "account.bootstrap_completed",
                &audit_targets,
                "bootstrap_token_consumed",
                now,
            )?;

            Ok(())
        });
        outcome?;

        let plaintext_recovery: Vec<String> =
            recovery.iter().map(|c| c.plaintext.clone()).collect();
        Ok(BootstrapV2Response {
            account_id,
            username: req.username,
            mfa_enrollment_id: mfa_id,
            totp_secret_base32: totp_secret,
            recovery_codes: plaintext_recovery,
            manager_public_key,
            account_state: "pending_mfa".to_string(),
            server_state: "awaiting_mfa_confirmation".to_string(),
        })
    }

    /// Confirm pending MFA enrollment: valid TOTP + independently stored recovery.
    ///
    /// Installs the verified enrollment TOTP secret into `account_mfa` and
    /// activates the administrator. The enrollment is single-use and bounded.
    /// This path never mints an ordinary session — confirmation only.
    pub fn confirm_mfa_enrollment(&self, req: MfaConfirmRequest) -> AppResult<MfaConfirmResponse> {
        // Enrollment confirm activates/copies reusable TOTP material into the
        // durable account_mfa row. Same store gate as creation: deny before
        // the transaction on a persistent unverified store.
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        validate_totp_code(&req.totp_code)?;
        if !req.recovery_material_stored {
            return Err(AppError::bad_request(
                "recovery_material_stored must be true; recovery codes must be stored independently before activation",
            ));
        }

        let now = now_unix();
        let time_step = totp_time_step(unix_now());

        let outcome = self.with_tx(|conn| {
            let row: Option<(String, String, i64, Option<i64>, bool)> = conn
                .query_row(
                    "SELECT id, totp_secret, expires_at, consumed_at, recovery_committed
                     FROM mfa_enrollments WHERE id = ?1",
                    params![req.mfa_enrollment_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            let (enrollment_id, totp_secret, expires_at, consumed_at, recovery_only) = match row {
                Some(row) => row,
                None => return Err(AppError::not_found("mfa enrollment not found")),
            };
            if consumed_at.is_some() {
                return Err(AppError::conflict(
                    "mfa enrollment already consumed",
                    Some("single_use".to_string()),
                ));
            }
            if expires_at <= now {
                return Err(AppError::conflict(
                    "mfa enrollment expired",
                    Some("expired".to_string()),
                ));
            }

            let account_id: String = conn.query_row(
                "SELECT account_id FROM mfa_enrollments WHERE id = ?1",
                params![enrollment_id],
                |r| r.get(0),
            )?;
            let (account_state, account_recovery_quarantined): (String, bool) = conn.query_row(
                "SELECT state, recovery_quarantined FROM accounts WHERE id = ?1",
                params![account_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if account_recovery_quarantined {
                return Err(AppError::forbidden(
                    "MFA enrollment cannot activate a quarantined restored account",
                ));
            }
            if account_state != "active" && account_state != "pending_mfa" {
                return Err(AppError::forbidden(
                    "MFA enrollment cannot activate a disabled account",
                ));
            }

            // Verify TOTP and consume the time step in the same transaction.
            let matched_step = verify_totp_at(&totp_secret, &req.totp_code, unix_now())?
                .ok_or_else(|| AppError::unauthorized("invalid totp code"))?;
            Self::consume_totp_step(conn, &account_id, matched_step, time_step)?;

            let consumed = conn.execute(
                "UPDATE mfa_enrollments
                 SET consumed_at = ?1, recovery_committed = 1
                 WHERE id = ?2 AND consumed_at IS NULL",
                params![now, enrollment_id],
            )?;
            if consumed != 1 {
                return Err(AppError::conflict(
                    "MFA enrollment changed during confirmation",
                    Some("single_use".to_string()),
                ));
            }
            let factor_updated = conn.execute(
                "UPDATE account_mfa
                 SET totp_secret = ?1, totp_confirmed_at = ?2, recovery_stored_at = ?2,
                     status = 'active', updated_at = ?2
                 WHERE account_id = ?3",
                params![totp_secret, now, account_id],
            )?;
            if factor_updated != 1 {
                return Err(AppError::unprocessable(
                    "MFA account record is missing; enrollment was not activated",
                ));
            }
            if account_state == "pending_mfa" {
                let activated = conn.execute(
                    "UPDATE accounts
                     SET state = 'active', revision = revision + 1, updated_at = ?1
                     WHERE id = ?2 AND state = 'pending_mfa'",
                    params![now, account_id],
                )?;
                if activated != 1 {
                    return Err(AppError::conflict(
                        "account changed during MFA activation",
                        Some("account_state_conflict".to_string()),
                    ));
                }
            }
            if recovery_only {
                conn.execute(
                    "UPDATE sessions SET revoked_at = ?1
                     WHERE account_id = ?2 AND revoked_at IS NULL",
                    params![now, account_id],
                )?;
            }
            record_successful_event_as(
                conn,
                &account_id,
                None,
                "account.mfa_activated",
                std::slice::from_ref(&account_id),
                if recovery_only {
                    "recovery_factor_replaced"
                } else {
                    "mfa_enrollment_confirmed"
                },
                now,
            )?;
            Ok(account_id)
        });
        let account_id = outcome?;

        Ok(MfaConfirmResponse {
            account_id,
            mfa_status: "active".to_string(),
            account_state: "active".to_string(),
        })
    }

    /// Report retained authority that remains inactive after database restore.
    pub fn recovery_quarantine_status_v2(
        &self,
        auth: &AuthContext,
    ) -> AppResult<RecoveryQuarantineStatusResponse> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        if !auth.can_manage_accounts {
            return Err(AppError::forbidden(
                "account management permission is required to review recovery quarantine",
            ));
        }
        let now = now_unix();
        self.with_conn(|conn| {
            require_current_recovery_admin_session(
                conn,
                auth,
                AdminCapability::Accounts,
                now,
                false,
                true,
            )?;
            load_recovery_quarantine_status(conn)
        })
    }

    /// Release the deployment-level restore gate only after fresh IT review.
    /// Historical accounts and endpoints remain individually quarantined.
    pub fn release_recovery_quarantine_v2(
        &self,
        auth: &AuthContext,
        req: ReleaseRecoveryQuarantineRequest,
    ) -> AppResult<RecoveryQuarantineStatusResponse> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        if !auth.can_manage_accounts || !auth.can_manage_security {
            return Err(AppError::forbidden(
                "a security administrator must release restore recovery quarantine",
            ));
        }
        if req.expected_deployment_id.is_empty()
            || req.expected_deployment_id.len() > 128
            || req.expected_quarantined_account_count < 0
            || req.expected_revoked_manager_count < 0
            || req.expected_quarantined_endpoint_count < 0
        {
            return Err(AppError::bad_request(
                "recovery review identity or counts are invalid",
            ));
        }
        if !req.acknowledge_missing_post_backup_history
            || !req.acknowledge_restored_authorities_remain_quarantined
        {
            return Err(AppError::bad_request(
                "recovery release requires acknowledging missing history and retained quarantined identities",
            ));
        }

        let now = now_unix();
        self.with_tx(|conn| {
            require_current_recovery_admin_session(
                conn,
                auth,
                AdminCapability::Accounts,
                now,
                true,
                true,
            )?;
            let actor_can_manage_security: bool = conn.query_row(
                "SELECT can_manage_security FROM accounts WHERE id = ?1",
                params![auth.account_id],
                |row| row.get(0),
            )?;
            if !actor_can_manage_security {
                return Err(AppError::forbidden(
                    "a security administrator must release restore recovery quarantine",
                ));
            }

            let current = load_recovery_quarantine_status(conn)?;
            if !current.recovery_quarantined {
                return Err(AppError::conflict(
                    "deployment is not in restore recovery quarantine",
                    Some("recovery_not_quarantined".to_string()),
                ));
            }
            let authority_state: String = conn.query_row(
                "SELECT authority_state FROM deployment WHERE id = 1",
                [],
                |row| row.get(0),
            )?;
            if authority_state != "active" {
                return Err(AppError::conflict(
                    "replacement authority must pass independent cutover review before recovery release",
                    Some("cutover_review_required".to_string()),
                ));
            }
            if current.deployment_id != req.expected_deployment_id
                || current.quarantined_account_count != req.expected_quarantined_account_count
                || current.revoked_manager_count != req.expected_revoked_manager_count
                || current.quarantined_endpoint_count != req.expected_quarantined_endpoint_count
            {
                return Err(AppError::conflict(
                    "recovery records changed; reload the quarantine summary before release",
                    Some("recovery_review_changed".to_string()),
                ));
            }
            let expected_phrase = format!("release restored deployment {}", current.deployment_id);
            if req.confirmation_phrase != expected_phrase {
                return Err(AppError::bad_request(
                    "confirmation_phrase must exactly identify the restored deployment",
                ));
            }

            let changed = conn.execute(
                "UPDATE deployment SET recovery_quarantined = 0
                 WHERE id = 1 AND recovery_quarantined = 1 AND bootstrap_completed = 1",
                [],
            )?;
            if changed != 1 {
                return Err(AppError::conflict(
                    "fresh MFA bootstrap must be completed before recovery quarantine release",
                    Some("bootstrap_incomplete".to_string()),
                ));
            }
            record_successful_event(
                conn,
                auth,
                "recovery.quarantine_released",
                std::slice::from_ref(&current.deployment_id),
                "review_acknowledged",
                now,
            )?;
            load_recovery_quarantine_status(conn)
        })
    }

    /// Cancel a pending MFA enrollment (bootstrap cancellation / timeout).
    ///
    /// Consumes the enrollment. Rolls the account back to disabled if it
    /// never completed MFA (`pending_mfa` only). Never deactivates or
    /// replaces an established active factor (recovery cancellation).
    /// Fail-closed: errors deny the cancel.
    pub fn cancel_mfa_enrollment(&self, enrollment_id: &str) -> AppResult<()> {
        self.require_security_ok()?;
        let now = now_unix();
        self.with_tx(|conn| {
            let row: Option<(String, Option<i64>)> = conn
                .query_row(
                    "SELECT account_id, consumed_at FROM mfa_enrollments WHERE id = ?1",
                    params![enrollment_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (account_id, consumed_at) = match row {
                Some(row) => row,
                None => return Err(AppError::not_found("mfa enrollment not found")),
            };
            if consumed_at.is_some() {
                return Err(AppError::conflict(
                    "mfa enrollment already consumed",
                    Some("single_use".to_string()),
                ));
            }
            conn.execute(
                "UPDATE mfa_enrollments SET consumed_at = ?1 WHERE id = ?2 AND consumed_at IS NULL",
                params![now, enrollment_id],
            )?;
            // Never deactivate an established active factor. Only pending
            // material (bootstrap cancellation / timeout) is restated pending;
            // recovery cancellation leaves the winning factor installed.
            conn.execute(
                "UPDATE account_mfa SET status = 'pending', updated_at = ?1
                 WHERE account_id = ?2 AND status = 'pending'",
                params![now, account_id],
            )?;
            conn.execute(
                "UPDATE accounts SET state = 'disabled', updated_at = ?1
                 WHERE id = ?2 AND state = 'pending_mfa'",
                params![now, account_id],
            )?;
            Ok(())
        })
    }

    // ----- auth v2 challenge -----

    /// Password validation + bounded durable one-use challenge.
    ///
    /// The challenge is bound to this deployment, the exact manager Ed25519
    /// public key, and the intended operation. The account is derived later
    /// from the password-validated challenge — the client never re-supplies it.
    pub fn begin_auth_challenge(
        &self,
        req: AuthChallengeBeginRequest,
    ) -> AppResult<AuthChallengeBeginResponse> {
        self.require_security_ok()?;
        crate::service::validate_username(&req.username)?;
        if req.password.is_empty() || req.password.len() > 256 {
            return Err(AppError::bad_request("password is required"));
        }
        validate_operation(&req.operation)?;
        if req.manager_public_key.trim().is_empty() {
            return Err(AppError::bad_request("manager_public_key is required"));
        }
        let manager_public_key = req.manager_public_key.trim().to_ascii_lowercase();
        if manager_public_key.len() != 64
            || !manager_public_key.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(AppError::bad_request(
                "manager_public_key must be 32 bytes of hex",
            ));
        }

        self.check_challenge_throttle(&req.username)?;

        // Same failure shape for unknown user and bad password — no enumeration.
        let account_row = self.with_conn(|conn| {
            let row: Option<(String, String, String)> = conn
                .query_row(
                    "SELECT id, password_hash, state FROM accounts
                     WHERE username = ?1 COLLATE NOCASE AND recovery_quarantined = 0",
                    params![req.username],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            Ok(row)
        });

        let (account_id, password_hash, state) = match account_row {
            Ok(Some(row)) => row,
            Ok(None) => {
                self.record_challenge_failure(&req.username);
                self.record_login_failure(&req.username);
                return Err(AppError::unauthorized("invalid credentials"));
            }
            Err(err) => return Err(err),
        };

        let valid = crate::crypto::verify_password(&req.password, &password_hash)?;
        if !valid {
            self.record_challenge_failure(&req.username);
            self.record_login_failure(&req.username);
            return Err(AppError::unauthorized("invalid credentials"));
        }
        if state != "active" {
            // Distinct from invalid credentials, but still no enumeration of
            // whether the username exists for pending/disabled accounts beyond
            // the already-authenticated password path.
            return Err(AppError::forbidden("account is not active"));
        }

        // Manager must be approved and own exactly this device key.
        let manager_approved = self.with_conn(|conn| {
            let row: Option<(String, String)> = conn
                .query_row(
                    "SELECT id, lifecycle_state FROM managers WHERE public_key = ?1",
                    params![manager_public_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match row {
                Some((_, lifecycle)) if lifecycle == "approved" => Ok(true),
                Some(_) => Err(AppError::forbidden(
                    "manager identity is not approved for this deployment",
                )),
                None => Err(AppError::forbidden(
                    "manager identity is not approved for this deployment",
                )),
            }
        })?;
        if !manager_approved {
            return Err(AppError::forbidden(
                "manager identity is not approved for this deployment",
            ));
        }

        // Effective mandatory MFA: administrator OR operator policy required
        // OR an already-active enrolled factor. Optional policy still allows
        // begin for a non-enrolled operator (password + manager proof only).
        let (mfa_required, has_active_factor) =
            self.with_conn(|conn| effective_mfa_required(conn, &account_id))?;
        if mfa_required && !has_active_factor {
            return Err(AppError::forbidden(
                "multi-factor enrollment is required before challenge login",
            ));
        }

        self.clear_challenge_failures(&req.username);
        self.clear_login_failures(&req.username);

        let (challenge_token, challenge_token_hash) = crate::crypto::generate_token()?;
        let challenge_id = Uuid::new_v4().to_string();
        let now = now_unix();
        let expires_at = now + CHALLENGE_TTL_SECS;
        let dep_key = self.with_conn(deployment_key)?;

        self.with_tx(|conn| {
            crate::db::prune_auth_challenges(conn, now)?;
            conn.execute(
                "INSERT INTO auth_challenges (
                    id, token_hash, account_id, manager_public_key, operation,
                    created_at, expires_at, consumed_at, deployment_key
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)",
                params![
                    challenge_id,
                    challenge_token_hash,
                    account_id,
                    manager_public_key,
                    req.operation,
                    now,
                    expires_at,
                    dep_key
                ],
            )?;
            Ok(())
        })?;

        Ok(AuthChallengeBeginResponse {
            challenge_id,
            challenge_token,
            operation: req.operation,
            manager_public_key,
            deployment_id: dep_key,
            expires_at_unix: expires_at,
            mfa_required,
        })
    }

    /// Complete a challenge: prove the bound manager key + required TOTP factor.
    ///
    /// Crypto verification runs first (signature over the deployment-bound
    /// message). Then **one final IMMEDIATE transaction** rechecks account +
    /// manager + MFA state, consumes the TOTP time step and the challenge, and
    /// inserts the session. No separate read/commit window can bypass
    /// revocation. Wrong key, wrong deployment, replay, revoked manager, clock
    /// rollback, and storage failure all deny without issuing a token.
    pub fn complete_auth_challenge(
        &self,
        req: AuthChallengeCompleteRequest,
    ) -> AppResult<LoginResponse> {
        self.require_security_ok()?;
        // A malformed supplied factor is refused — never silently ignored.
        if let Some(code) = &req.totp_code {
            validate_totp_code(code)?;
        }
        if req.manager_signature.trim().is_empty() {
            return Err(AppError::bad_request("manager_signature is required"));
        }

        self.check_challenge_throttle(&req.challenge_id)?;

        let now = now_unix();
        let challenge_token_hash = hash_token(&req.challenge_token);

        // Read-only pre-check to obtain binding inputs for signature verification.
        // These values are revalidated inside the final transaction.
        let pre = self.with_conn(|conn| {
            let row: Option<ChallengeRow> = conn
                .query_row(
                    "SELECT id, token_hash, account_id, manager_public_key, operation,
                            expires_at, consumed_at, deployment_key
                     FROM auth_challenges WHERE id = ?1",
                    params![req.challenge_id],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                        ))
                    },
                )
                .optional()?;
            Ok(row)
        });

        let (
            _id,
            stored_hash,
            account_id,
            manager_public_key,
            operation,
            expires_at,
            consumed_at,
            dep_key,
        ) = match pre {
            Ok(Some(row)) => row,
            Ok(None) => {
                self.record_challenge_failure(&req.challenge_id);
                return Err(AppError::unauthorized("invalid challenge"));
            }
            Err(err) => {
                self.record_challenge_failure(&req.challenge_id);
                return Err(err);
            }
        };

        if !token_hash_eq(&challenge_token_hash, &stored_hash) {
            self.record_challenge_failure(&req.challenge_id);
            return Err(AppError::unauthorized("invalid challenge"));
        }
        if consumed_at.is_some() {
            self.record_challenge_failure(&req.challenge_id);
            return Err(AppError::unauthorized("challenge already consumed"));
        }
        if expires_at <= now {
            self.record_challenge_failure(&req.challenge_id);
            return Err(AppError::unauthorized("challenge expired"));
        }

        // Verify device proof over the deployment-bound message before the
        // final transaction. Deployment id comes from the persisted row, never
        // from the client request.
        let message = auth_challenge_proof_message(
            &dep_key,
            &req.challenge_id,
            &operation,
            &manager_public_key,
        );
        let proof_ok =
            verify_ed25519_strict(&manager_public_key, &message, req.manager_signature.trim())?;
        if !proof_ok {
            self.record_challenge_failure(&req.challenge_id);
            return Err(AppError::forbidden("manager device proof is invalid"));
        }

        // Generate the session material before the final transaction so a
        // post-commit failure cannot leave a half-issued token.
        let (token, token_hash) = crate::crypto::generate_token()?;
        let session_id = Uuid::new_v4().to_string();
        let expires_at_unix = now + V2_SESSION_TTL_SECS;
        let current_step = totp_time_step(unix_now());

        // FINAL IMMEDIATE TRANSACTION: recheck trust, consume factor + challenge,
        // issue session. Any error rolls back everything.
        let outcome = self.with_tx(|conn| {
            // Re-read challenge under the transaction and consume it atomically.
            let row: Option<ChallengeRow> = conn
                .query_row(
                    "SELECT id, token_hash, account_id, manager_public_key, operation,
                            expires_at, consumed_at, deployment_key
                     FROM auth_challenges WHERE id = ?1",
                    params![req.challenge_id],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                        ))
                    },
                )
                .optional()?;
            let (ch_id, ch_hash, ch_account, ch_key, ch_op, ch_expires, ch_consumed, ch_dep) =
                match row {
                    Some(row) => row,
                    None => return Err(AppError::unauthorized("invalid challenge")),
                };
            if !token_hash_eq(&challenge_token_hash, &ch_hash) {
                return Err(AppError::unauthorized("invalid challenge"));
            }
            if ch_consumed.is_some() {
                return Err(AppError::unauthorized("challenge already consumed"));
            }
            if ch_expires <= now {
                return Err(AppError::unauthorized("challenge expired"));
            }
            // Binding must still match the pre-checked values and this deployment.
            if ch_account != account_id
                || ch_key != manager_public_key
                || ch_op != operation
                || ch_dep != dep_key
            {
                return Err(AppError::unauthorized("challenge binding mismatch"));
            }
            let current_dep = deployment_key(conn)?;
            if current_dep != ch_dep {
                return Err(AppError::forbidden("challenge deployment mismatch"));
            }

            let changed = conn.execute(
                "UPDATE auth_challenges SET consumed_at = ?1 WHERE id = ?2 AND consumed_at IS NULL",
                params![now, ch_id],
            )?;
            if changed != 1 {
                return Err(AppError::unauthorized("challenge already consumed"));
            }

            // Manager must still be approved inside this transaction.
            let manager_row: Option<(String, String)> = conn
                .query_row(
                    "SELECT id, lifecycle_state FROM managers WHERE public_key = ?1",
                    params![ch_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let manager_id = match manager_row {
                Some((id, lifecycle)) if lifecycle == "approved" => id,
                _ => {
                    return Err(AppError::forbidden(
                        "manager identity is no longer approved",
                    ))
                }
            };

            // Account must still be active.
            let state: Option<String> = conn
                .query_row(
                    "SELECT state FROM accounts WHERE id = ?1",
                    params![ch_account],
                    |r| r.get(0),
                )
                .optional()?;
            match state {
                Some(ref s) if s == "active" => {}
                Some(_) => return Err(AppError::forbidden("account is not active")),
                None => return Err(AppError::unauthorized("invalid challenge")),
            }

            // Recheck current policy, role, and factor state inside the final
            // transaction. A challenge started under optional policy cannot
            // finish factor-free after policy becomes required. Corrupt or
            // missing policy denies authority.
            let (mfa_required, has_active_factor) = effective_mfa_required(conn, &ch_account)?;
            let mfa_row: Option<(String, String)> = conn
                .query_row(
                    "SELECT totp_secret, status FROM account_mfa WHERE account_id = ?1",
                    params![ch_account],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let active_secret = match mfa_row {
                Some((secret, status)) if status == "active" => Some(secret),
                Some(_) => {
                    return Err(AppError::forbidden("multi-factor enrollment is not active"))
                }
                None => None,
            };
            if has_active_factor != active_secret.is_some() {
                return Err(AppError::forbidden("multi-factor enrollment is not active"));
            }

            // Factor handling: a supplied code is always verified; a missing
            // code is accepted only when effective MFA is not required.
            let (assurance, mfa_assured_at) = match (&req.totp_code, mfa_required) {
                (Some(code), _) => {
                    let secret = match &active_secret {
                        Some(secret) => secret,
                        None => {
                            return Err(AppError::forbidden(
                                "totp code supplied but no active multi-factor enrollment",
                            ))
                        }
                    };
                    let matched_step = match verify_totp_at(secret, code, unix_now())? {
                        Some(step) => step,
                        None => return Err(AppError::unauthorized("invalid totp code")),
                    };
                    Self::consume_totp_step(conn, &ch_account, matched_step, current_step)?;
                    crate::db::prune_totp_consumptions(conn, &ch_account)?;
                    ("mfa", Some(now))
                }
                (None, true) => return Err(AppError::unauthorized("totp code is required")),
                (None, false) => ("password", None),
            };

            // Issue the session only after every recheck + consumption succeeded.
            conn.execute(
                "INSERT INTO sessions (
                    id, account_id, manager_id, token_hash, created_at, expires_at,
                    assurance, mfa_assured_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    session_id,
                    ch_account,
                    manager_id,
                    token_hash,
                    now,
                    expires_at_unix,
                    assurance,
                    mfa_assured_at
                ],
            )?;

            // Bind the exact challenge-proven device key for the v2 response.
            // Source of truth is the persisted approved manager row matched to
            // the challenge key — never a client field or display identity.
            let proven_key: String = conn.query_row(
                "SELECT public_key FROM managers WHERE id = ?1 AND public_key IS NOT NULL",
                params![manager_id],
                |r| r.get(0),
            )?;
            if proven_key.trim().to_ascii_lowercase() != ch_key {
                return Err(AppError::forbidden("manager device key binding mismatch"));
            }

            Ok((
                ch_account,
                manager_id,
                ch_op,
                mfa_required,
                has_active_factor,
                proven_key,
            ))
        });

        let (account_id, manager_id, operation, mfa_required, has_active_factor, proven_key) =
            match outcome {
                Ok(values) => values,
                Err(err) => {
                    // Storage uncertainty already latches; other errors are denials.
                    if !matches!(
                        err,
                        AppError::Api {
                            code: crate::error::ErrorCode::SecurityStateUnavailable,
                            ..
                        }
                    ) {
                        self.record_challenge_failure(&req.challenge_id);
                    }
                    return Err(err);
                }
            };

        let account_view = self.load_account_view(&account_id)?;
        let manager_view = self.load_manager_view(&manager_id)?;
        tracing::info!(
            account_id = %account_id,
            manager_id = %manager_id,
            operation = %operation,
            "auth v2 challenge completed"
        );

        let reason = if has_active_factor {
            "totp_active"
        } else {
            "operator_policy_optional_no_factor"
        };
        Ok(LoginResponse {
            token,
            expires_at_unix,
            account: account_view,
            manager: Some(manager_view),
            mfa: MfaStatus {
                required: mfa_required,
                available: has_active_factor,
                reason,
            },
            // v2-only: exact challenge-proven device key from the final
            // transaction. Never display identity (`key:<hex>`).
            manager_public_key: Some(proven_key),
        })
    }

    // ----- operator MFA policy -----

    /// `GET /v2/security/operator-mfa-policy`. Administrator only.
    pub fn get_operator_mfa_policy(
        &self,
        auth: &AuthContext,
    ) -> AppResult<OperatorMfaPolicyResponse> {
        self.require_security_ok()?;
        if !auth.can_manage_security {
            return Err(AppError::forbidden(
                "administrator credentials are required to read operator MFA policy",
            ));
        }
        self.with_conn(|conn| {
            let policy = load_operator_mfa_policy(conn)?;
            let updated_at: Option<i64> = conn
                .query_row(
                    "SELECT updated_at FROM security_policy WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(OperatorMfaPolicyResponse {
                policy,
                updated_at_unix: updated_at,
                mfa_required_for_operators: policy == OperatorMfaPolicy::Required,
            })
        })
    }

    /// `PUT /v2/security/operator-mfa-policy`.
    ///
    /// Requires administrator and a fresh successful MFA-backed v2 session
    /// (stored assurance `mfa`, no older than [`POLICY_MUTATION_MFA_FRESH_SECS`]),
    /// an approved manager device, and trusted private persistence. Missing
    /// assurance never authorizes change. Operator, legacy, or recovery-only
    /// credentials cannot change the policy. Authenticate + mutation run in
    /// one IMMEDIATE transaction: session, role, account, device approval and
    /// assurance freshness are rechecked before the write. Enabling
    /// `required` invalidates factor-free operator sessions.
    pub fn set_operator_mfa_policy(
        &self,
        auth: &AuthContext,
        req: OperatorMfaPolicyUpdateRequest,
    ) -> AppResult<OperatorMfaPolicyResponse> {
        self.require_security_ok()?;
        self.require_persisted_v2_credentials()?;
        if auth.manager_id.is_none() {
            return Err(AppError::forbidden(
                "approved manager device binding is required to change operator MFA policy",
            ));
        }
        let now = now_unix();
        let policy = req.policy;
        let session_id = auth.session_id.clone();

        self.with_tx(|conn| {
            let session: Option<PolicySessionRow> = conn
                    .query_row(
                        "SELECT assurance, mfa_assured_at, expires_at, revoked_at, manager_id, account_id
                         FROM sessions WHERE id = ?1",
                        params![session_id],
                        |r| {
                            Ok((
                                r.get(0)?,
                                r.get(1)?,
                                r.get(2)?,
                                r.get(3)?,
                                r.get(4)?,
                                r.get(5)?,
                            ))
                        },
                    )
                    .optional()?;
            let (assurance, mfa_assured_at, expires_at, revoked_at, manager_id, account_id) =
                match session {
                    Some(row) => row,
                    None => return Err(AppError::unauthorized("invalid session")),
                };
            if revoked_at.is_some() {
                return Err(AppError::unauthorized("session revoked"));
            }
            if expires_at <= now {
                return Err(AppError::unauthorized("session expired"));
            }
            if account_id != auth.account_id {
                return Err(AppError::unauthorized("invalid session"));
            }
            // Real stored session assurance/time — never a caller assertion.
            if assurance != "mfa" {
                return Err(AppError::forbidden(
                    "a fresh MFA-backed session is required to change operator MFA policy",
                ));
            }
            // Age must be in 0..=fresh window. Future assurance timestamps
            // (clock rollback / planted future) and stale assurance both deny.
            match mfa_assured_at.and_then(|at| now.checked_sub(at)) {
                Some(age) if (0..=POLICY_MUTATION_MFA_FRESH_SECS).contains(&age) => {}
                _ => {
                    return Err(AppError::forbidden(
                        "a fresh MFA-backed session is required to change operator MFA policy",
                    ))
                }
            }
            // Administrator + active account, rechecked transactionally.
            let account: Option<(String, bool)> = conn
                .query_row(
                    "SELECT state, can_manage_security FROM accounts WHERE id = ?1",
                    params![account_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match account {
                Some((ref state, true)) if state == "active" => {}
                Some((_, true)) => return Err(AppError::forbidden("account is not active")),
                Some((_, false)) => {
                    return Err(AppError::forbidden(
                        "administrator credentials are required to change operator MFA policy",
                    ))
                }
                None => return Err(AppError::unauthorized("invalid session")),
            }
            // Approved manager device must still be bound and approved.
            let manager_id = manager_id.ok_or_else(|| {
                AppError::forbidden(
                    "approved manager device binding is required to change operator MFA policy",
                )
            })?;
            let lifecycle: Option<String> = conn
                .query_row(
                    "SELECT lifecycle_state FROM managers WHERE id = ?1",
                    params![manager_id],
                    |r| r.get(0),
                )
                .optional()?;
            match lifecycle {
                Some(ref state) if state == "approved" => {}
                _ => {
                    return Err(AppError::forbidden(
                        "manager identity is no longer approved",
                    ))
                }
            }

            let changed = conn.execute(
                "UPDATE security_policy
                 SET operator_mfa_policy = ?1, updated_at = ?2
                 WHERE id = 1",
                params![policy.as_str(), now],
            )?;
            if changed != 1 {
                return Err(AppError::unprocessable(
                    "operator mfa policy is missing; denying authority",
                ));
            }
            if policy == OperatorMfaPolicy::Required {
                conn.execute(
                    "UPDATE sessions SET revoked_at = ?1
                     WHERE revoked_at IS NULL
                       AND (assurance IS NULL OR assurance != 'mfa')
                       AND account_id IN (
                           SELECT id FROM accounts WHERE can_manage_security = 0
                       )",
                    params![now],
                )?;
            }
            record_successful_event(
                conn,
                auth,
                "security.operator_mfa_policy_updated",
                &["deployment".to_string()],
                if policy == OperatorMfaPolicy::Required {
                    "policy_required"
                } else {
                    "policy_optional"
                },
                now,
            )?;
            Ok(())
        })?;

        self.get_operator_mfa_policy(auth)
    }

    // ----- recovery-only verification -----

    /// Consume a recovery code to re-enroll TOTP. Recovery-only: this path
    /// never issues a session and cannot target an arbitrary account.
    ///
    /// Requires the same username + password as a normal challenge start, so
    /// an IT operator cannot use a recovery code against someone else's login.
    pub fn begin_factor_recovery(
        &self,
        req: FactorRecoveryBeginRequest,
    ) -> AppResult<FactorRecoveryBeginResponse> {
        // Recovery writes a new persisted TOTP secret; same Db-owned store gate.
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        crate::service::validate_username(&req.username)?;
        if req.password.is_empty() || req.password.len() > 256 {
            return Err(AppError::bad_request("password is required"));
        }
        if req.recovery_code.trim().is_empty() {
            return Err(AppError::bad_request("recovery_code is required"));
        }

        self.check_challenge_throttle(&req.username)?;

        let account_row = self.with_conn(|conn| {
            let row: Option<(String, String, String)> = conn
                .query_row(
                    "SELECT id, password_hash, state FROM accounts
                     WHERE username = ?1 COLLATE NOCASE AND recovery_quarantined = 0",
                    params![req.username],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            Ok(row)
        });
        let (account_id, password_hash, state) = match account_row {
            Ok(Some(row)) => row,
            Ok(None) => {
                self.record_challenge_failure(&req.username);
                return Err(AppError::unauthorized("invalid credentials"));
            }
            Err(err) => return Err(err),
        };
        let valid = crate::crypto::verify_password(&req.password, &password_hash)?;
        if !valid {
            self.record_challenge_failure(&req.username);
            return Err(AppError::unauthorized("invalid credentials"));
        }
        if state != "active" {
            return Err(AppError::forbidden("account is not active"));
        }

        let code_hash = hash_recovery_code(&req.recovery_code);
        let now = now_unix();
        let enrollment_id = Uuid::new_v4().to_string();
        let totp_secret = generate_totp_secret()?;

        let outcome = self.with_tx(|conn| {
            let current_state: String = conn.query_row(
                "SELECT state FROM accounts WHERE id = ?1",
                params![account_id],
                |row| row.get(0),
            )?;
            if current_state != "active" {
                return Err(AppError::forbidden("account is not active"));
            }
            let used: Option<(String, Option<i64>)> = conn
                .query_row(
                    "SELECT id, used_at FROM recovery_codes
                     WHERE account_id = ?1 AND code_hash = ?2",
                    params![account_id, code_hash],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (code_id, used_at) = match used {
                Some(row) => row,
                None => {
                    return Err(AppError::unauthorized("invalid recovery code"));
                }
            };
            if used_at.is_some() {
                return Err(AppError::unauthorized("recovery code already used"));
            }
            conn.execute(
                "UPDATE recovery_codes SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL",
                params![now, code_id],
            )?;

            // Recovery only re-enrolls TOTP. No session is created here.
            conn.execute(
                "INSERT INTO mfa_enrollments (
                    id, account_id, totp_secret, recovery_committed,
                    created_at, expires_at, consumed_at
                 ) VALUES (?1, ?2, ?3, 1, ?4, ?5, NULL)",
                params![
                    enrollment_id,
                    account_id,
                    totp_secret,
                    now,
                    now + MFA_ENROLLMENT_TTL_SECS
                ],
            )?;
            Ok(())
        });
        match outcome {
            Ok(()) => {}
            Err(
                error @ AppError::Api {
                    code: crate::error::ErrorCode::Unauthorized,
                    ..
                },
            ) => {
                self.record_challenge_failure(&req.username);
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        self.clear_challenge_failures(&req.username);

        Ok(FactorRecoveryBeginResponse {
            mfa_enrollment_id: enrollment_id,
            totp_secret_base32: totp_secret,
            account_id,
            purpose: "totp_factor_recovery_only".to_string(),
        })
    }

    /// Finish factor recovery: confirm the new TOTP secret. No session issued.
    pub fn complete_factor_recovery(
        &self,
        req: MfaConfirmRequest,
    ) -> AppResult<MfaConfirmResponse> {
        // Recovery confirmations re-use the same bounded enrollment path.
        // `recovery_material_stored` must still be true (codes already exist).
        self.confirm_mfa_enrollment(req)
    }

    // ----- shared TOTP consumption -----

    /// Atomically consume a TOTP time step. Replay and clock rollback deny.
    ///
    /// Must run inside an open transaction. Inserts the step under a unique
    /// primary key so racing use of the same step fails; rejects steps older
    /// than `current - TOTP_MAX_BACKWARD_STEPS`.
    fn consume_totp_step(
        conn: &rusqlite::Connection,
        account_id: &str,
        matched_step: i64,
        current_step: i64,
    ) -> AppResult<()> {
        let floor = current_step - TOTP_MAX_BACKWARD_STEPS;
        if matched_step < floor {
            return Err(AppError::forbidden(
                "totp time step rejected (possible clock rollback)",
            ));
        }
        let now = now_unix();
        // Primary key (account_id, time_step) makes replay a constraint failure.
        conn.execute(
            "INSERT INTO totp_consumptions (account_id, time_step, consumed_at)
             VALUES (?1, ?2, ?3)",
            params![account_id, matched_step, now],
        )
        .map_err(|err| {
            if matches!(
                &err,
                rusqlite::Error::SqliteFailure(inner, _)
                    if inner.code == rusqlite::ErrorCode::ConstraintViolation
            ) {
                AppError::forbidden("totp code already used for this time step")
            } else {
                AppError::Storage(err)
            }
        })?;
        Ok(())
    }

    /// Durable challenge-throttle key count (test/ops visibility).
    #[doc(hidden)]
    pub fn challenge_throttle_len(&self) -> usize {
        self.with_conn(|conn| {
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM challenge_throttle", [], |r| r.get(0))?;
            Ok(count as usize)
        })
        .unwrap_or(0)
    }
}

/// Test helper: recover a recovery-code hash without revealing plaintext.
pub fn recovery_code_hash_for_test(code: &str) -> String {
    hash_recovery_code(code)
}

/// Test helper: constant-time recovery hash equality.
pub fn recovery_hash_eq_for_test(a: &str, b: &str) -> bool {
    crate::crypto::recovery_hash_eq(a, b)
}
