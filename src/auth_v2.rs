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

use crate::crypto::{
    auth_challenge_proof_message, bootstrap_manager_proof_message, generate_recovery_codes,
    generate_totp_secret, hash_recovery_code, hash_token, token_hash_eq, totp_time_step, unix_now,
    verify_ed25519_strict, verify_totp_at,
};
use crate::db::{deployment_key, now_unix};
use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::service::Service;

/// Auth challenge lifetime (bounded durable one-use).
const CHALLENGE_TTL_SECS: i64 = 120;
/// Pending MFA enrollment lifetime (bounded; cannot mint a normal session).
const MFA_ENROLLMENT_TTL_SECS: i64 = 15 * 60;
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

impl Service {
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

            let bootstrap_done: bool = conn.query_row(
                "SELECT bootstrap_completed FROM deployment WHERE id = 1",
                [],
                |row| row.get(0),
            )?;
            if bootstrap_done {
                return Err(AppError::conflict(
                    "bootstrap already completed",
                    Some("single_use".to_string()),
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
    /// Activates the administrator. The enrollment is single-use and bounded.
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
            let row: Option<(String, String, i64, Option<i64>)> = conn
                .query_row(
                    "SELECT id, totp_secret, expires_at, consumed_at
                     FROM mfa_enrollments WHERE id = ?1",
                    params![req.mfa_enrollment_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            let (enrollment_id, totp_secret, expires_at, consumed_at) = match row {
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

            // Verify TOTP and consume the time step in the same transaction.
            let matched_step = verify_totp_at(&totp_secret, &req.totp_code, unix_now())?
                .ok_or_else(|| AppError::unauthorized("invalid totp code"))?;
            Self::consume_totp_step(conn, &account_id, matched_step, time_step)?;

            conn.execute(
                "UPDATE mfa_enrollments SET consumed_at = ?1 WHERE id = ?2 AND consumed_at IS NULL",
                params![now, enrollment_id],
            )?;
            conn.execute(
                "UPDATE account_mfa
                 SET totp_confirmed_at = ?1, recovery_stored_at = ?1,
                     status = 'active', updated_at = ?1
                 WHERE account_id = ?2",
                params![now, account_id],
            )?;
            conn.execute(
                "UPDATE accounts
                 SET state = 'active', updated_at = ?1
                 WHERE id = ?2 AND state = 'pending_mfa'",
                params![now, account_id],
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

    /// Cancel a pending MFA enrollment (bootstrap cancellation / timeout).
    ///
    /// Rolls the account back to disabled if it never completed MFA and no
    /// other active MFA factor exists. Fail-closed: errors deny the cancel.
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
            // Account stays inactive; wipe pending MFA material.
            conn.execute(
                "UPDATE account_mfa SET status = 'pending', updated_at = ?1 WHERE account_id = ?2",
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
                    "SELECT id, password_hash, state FROM accounts WHERE username = ?1 COLLATE NOCASE",
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

        // MFA must be active for v2 challenge login.
        let mfa_active: bool = self.with_conn(|conn| {
            let status: Option<String> = conn
                .query_row(
                    "SELECT status FROM account_mfa WHERE account_id = ?1",
                    params![account_id],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(status.as_deref() == Some("active"))
        })?;
        if !mfa_active {
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
        validate_totp_code(&req.totp_code)?;
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

            // MFA must still be active; load secret inside the transaction.
            let mfa_row: Option<(String, String)> = conn
                .query_row(
                    "SELECT totp_secret, status FROM account_mfa WHERE account_id = ?1",
                    params![ch_account],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let totp_secret = match mfa_row {
                Some((secret, status)) if status == "active" => secret,
                Some(_) => {
                    return Err(AppError::forbidden("multi-factor enrollment is not active"))
                }
                None => return Err(AppError::forbidden("multi-factor enrollment is required")),
            };

            // Verify + consume TOTP time step in the same transaction.
            let matched_step = match verify_totp_at(&totp_secret, &req.totp_code, unix_now())? {
                Some(step) => step,
                None => return Err(AppError::unauthorized("invalid totp code")),
            };
            Self::consume_totp_step(conn, &ch_account, matched_step, current_step)?;
            crate::db::prune_totp_consumptions(conn, &ch_account)?;

            // Issue the session only after every recheck + consumption succeeded.
            conn.execute(
                "INSERT INTO sessions (
                    id, account_id, manager_id, token_hash, created_at, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    session_id,
                    ch_account,
                    manager_id,
                    token_hash,
                    now,
                    expires_at_unix
                ],
            )?;

            Ok((ch_account, manager_id, ch_op))
        });

        let (account_id, manager_id, operation) = match outcome {
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

        Ok(LoginResponse {
            token,
            expires_at_unix,
            account: account_view,
            manager: Some(manager_view),
            mfa: MfaStatus {
                required: true,
                available: true,
                reason: "totp_active",
            },
        })
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
                    "SELECT id, password_hash, state FROM accounts WHERE username = ?1 COLLATE NOCASE",
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
        outcome?;
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
