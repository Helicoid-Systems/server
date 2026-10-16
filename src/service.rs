//! Domain operations: bootstrap, login, managers, computers, access.
//!
//! Authorization is enforced here from session state — never from request
//! body owner fields. Administration capability does not imply observe/operate.

use std::collections::HashMap;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, Row};
use uuid::Uuid;

use crate::crypto::{generate_token, hash_password, hash_token, token_hash_eq, verify_password};
use crate::db::{now_unix, Db};
use crate::error::{AppError, AppResult};
use crate::models::*;

/// Session lifetime for this foundation (24h). B03/E07 will freeze production policy.
const SESSION_TTL_SECS: i64 = 24 * 60 * 60;
/// Login failure lockout threshold.
const LOGIN_MAX_FAILURES: i64 = 5;
const LOGIN_LOCKOUT_SECS: i64 = 60;
/// Hard cap for inventory pages (lists and fan-out bound).
pub const MAX_PAGE_SIZE: usize = 100;
/// Development login-throttle budget (bounded map; not production rate policy).
const LOGIN_THROTTLE_MAX_KEYS: usize = 1024;
/// Prune throttle entries idle longer than this when pruning.
const LOGIN_THROTTLE_IDLE_SECS: i64 = 15 * 60;

/// Session row for authority checks: id, account_id, token_hash, manager_id,
/// expires_at, revoked_at, assurance, mfa_assured_at.
type AuthoritySessionRow = (
    String,
    String,
    String,
    Option<String>,
    i64,
    Option<i64>,
    String,
    Option<i64>,
);
/// Account auth row: id, password_hash, state
type AccountAuthRow = (String, String, String);

#[derive(Debug, Clone, Copy)]
struct ThrottleEntry {
    failure_count: i64,
    locked_until: Option<i64>,
    last_failure_at: i64,
}

pub struct Service {
    db: Db,
    /// In-memory login throttle (process lifetime). Not durable rate-limit policy.
    login_throttle: Mutex<HashMap<String, ThrottleEntry>>,
    /// Latched when a required storage commit/read leaves trust state uncertain.
    /// Memory is authoritative if persisting the latch itself fails. Never auto-recovers.
    security_state: Mutex<SecurityState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityState {
    Ok,
    Unavailable,
}

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub account_id: String,
    pub username: String,
    pub session_id: String,
    pub manager_id: Option<String>,
    pub can_operate: bool,
    pub can_manage_enrollment: bool,
    pub can_manage_access: bool,
    pub can_manage_accounts: bool,
    pub can_manage_security: bool,
    pub revision: i64,
}

/// Normalize a login identity key the same way the DB compares usernames
/// (`COLLATE NOCASE` is ASCII case-insensitive).
fn normalize_login_key(username: &str) -> String {
    username.trim().to_ascii_lowercase()
}

fn prune_login_throttle(map: &mut HashMap<String, ThrottleEntry>, now: i64) {
    map.retain(|_, entry| {
        let locked_active = entry.locked_until.map(|until| until > now).unwrap_or(false);
        locked_active || (now - entry.last_failure_at) < LOGIN_THROTTLE_IDLE_SECS
    });
}

/// Hydrate the durable security latch. Absent/unreadable/invalid trusted state
/// fails closed (`Unavailable`). Restart never resets a latched deployment.
///
/// `security_state_ok` must be exactly integer `0` or `1`. Any other stored
/// value (including SQLite's usual nonzero-as-true trap) is invalid → Unavailable.
fn hydrate_security_state(db: &Db) -> SecurityState {
    let result: AppResult<SecurityState> = (|| {
        let conn = db.lock()?;
        let ok: Option<i64> = conn
            .query_row(
                "SELECT security_state_ok FROM deployment WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match ok {
            Some(1) => Ok(SecurityState::Ok),
            Some(0) => Ok(SecurityState::Unavailable),
            Some(other) => {
                tracing::error!(
                    value = other,
                    "invalid deployment.security_state_ok (require exact 0/1); failing closed"
                );
                Ok(SecurityState::Unavailable)
            }
            None => {
                tracing::error!("deployment trust row missing; failing closed");
                Ok(SecurityState::Unavailable)
            }
        }
    })();
    match result {
        Ok(state) => state,
        Err(err) => {
            tracing::error!(error = %err, "failed to hydrate durable security state; failing closed");
            SecurityState::Unavailable
        }
    }
}

impl Service {
    pub fn new(db: Db) -> Self {
        let security_state = hydrate_security_state(&db);
        Service {
            db,
            login_throttle: Mutex::new(HashMap::new()),
            security_state: Mutex::new(security_state),
        }
    }

    pub fn security_state(&self) -> SecurityState {
        *self
            .security_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Test-only store handle for fault injection. Not part of the HTTP contract.
    #[doc(hidden)]
    pub fn db_handle(&self) -> &Db {
        &self.db
    }

    /// Latch Security State Unavailable. In-memory state is set first and stays
    /// authoritative if the durable write fails. Never auto-recovers.
    pub fn latch_security_state_unavailable(&self, note: &str) {
        {
            let mut state = self
                .security_state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *state = SecurityState::Unavailable;
        }
        tracing::error!(note, "latched Security State Unavailable");
        // Best-effort durable note; memory latch already holds if this fails.
        if let Ok(conn) = self.db.lock() {
            let _ = conn.execute(
                "UPDATE deployment SET security_state_ok = 0, security_state_note = ?1 WHERE id = 1",
                params![note],
            );
        }
    }

    pub(crate) fn require_security_ok(&self) -> AppResult<()> {
        if self.security_state() != SecurityState::Ok {
            return Err(AppError::security_state_unavailable(
                "required trusted persistence cannot be read or committed reliably; new authority is paused",
            ));
        }
        Ok(())
    }

    /// Deny NEW persisted v2 MFA credentials when this store cannot keep
    /// them confidential. Capability is owned by the [`Db`] (never
    /// request-supplied): nonpersistent in-memory test stores still exercise
    /// real crypto; persistent unverified stores deny before the transaction.
    pub(crate) fn require_persisted_v2_credentials(&self) -> AppResult<()> {
        if !self.db.persisted_v2_credentials_allowed() {
            return Err(AppError::not_implemented(
                "NEW persisted v2 MFA credentials are not supported on this store \
                 (no native-verified private credential store); refusing before transaction. \
                 Legacy v1 loopback development remains available without MFA claims.",
            ));
        }
        Ok(())
    }

    /// Apply the security-state policy to a completed storage result.
    ///
    /// Call only after releasing any Db mutex so the latch persist cannot deadlock.
    /// Required persistence failure latches and returns 503, never a silent success
    /// and never a bare 500 that could be mistaken for a non-authority error.
    ///
    /// `AppError::Storage` and lock/poison `Internal` failures are both treated
    /// as persistence uncertainty and fail closed.
    fn finish_storage<T>(&self, result: AppResult<T>) -> AppResult<T> {
        match result {
            Ok(value) => Ok(value),
            Err(AppError::Storage(err)) => {
                tracing::error!(error = %err, "required storage operation failed");
                self.latch_security_state_unavailable("storage_operation_failed");
                Err(AppError::security_state_unavailable(
                    "required trusted persistence cannot be read or committed reliably; new authority is paused",
                ))
            }
            Err(
                err @ AppError::Api {
                    code: crate::error::ErrorCode::Internal,
                    ..
                },
            ) => {
                tracing::error!(error = %err, "required storage lock/internal failure");
                self.latch_security_state_unavailable("storage_lock_or_internal_failure");
                Err(AppError::security_state_unavailable(
                    "required trusted persistence cannot be read or committed reliably; new authority is paused",
                ))
            }
            Err(err) => Err(err),
        }
    }

    /// Required trust read on the connection. Lock acquisition errors are part
    /// of the guarded result (IIFE) so they cannot skip `finish_storage`.
    /// The Db mutex is released before the guard runs.
    pub(crate) fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> AppResult<T>) -> AppResult<T> {
        let result = (|| -> AppResult<T> {
            let conn = self.db.lock()?;
            f(&conn)
        })();
        self.finish_storage(result)
    }

    /// Required trust commit/transaction. Commits on success; rolls back on error.
    /// Applies `finish_storage` after the transaction lock is released.
    /// `Db::transaction` lock failures surface as `Internal` and are mapped to
    /// uncertainty by `finish_storage` (same policy as `with_conn`).
    pub(crate) fn with_tx<T>(&self, f: impl FnOnce(&Connection) -> AppResult<T>) -> AppResult<T> {
        let result = self.db.transaction(f);
        self.finish_storage(result)
    }

    // ----- health / init -----

    /// Health is fail-closed.
    ///
    /// `accepting_authorized_operations` is true only when the durable trust
    /// record is healthy **and** bootstrap has completed. A missing deployment
    /// row latches Security State Unavailable (it must not leave memory `Ok`
    /// while later logins could still issue authority). When the durable record
    /// is readable, `bootstrap_completed` is reported as stored — never
    /// fabricated. Never auto-recovers a latch.
    pub fn health(&self) -> AppResult<HealthResponse> {
        let memory_latched = self.security_state() != SecurityState::Ok;

        let result = self.with_conn(|conn| {
            let row: Option<(i64, i64)> = conn
                .query_row(
                    "SELECT bootstrap_completed, security_state_ok FROM deployment WHERE id = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            Ok(row)
        });

        let degraded = |bootstrap_completed: bool| HealthResponse {
            status: "degraded",
            accepting_authorized_operations: false,
            schema_version: crate::models::WIRE_CONTRACT_V1_VERSION,
            storage_schema_version: crate::db::SCHEMA_VERSION,
            bootstrap_completed,
            features: FeatureAvailability::foundation(),
        };

        match result {
            Ok(Some((bootstrap_completed, security_state_ok))) => {
                let boot = bootstrap_completed != 0;
                // Exact 0/1 required; any other value is invalid trust state.
                let durable_ok = security_state_ok == 1;
                if !durable_ok {
                    self.latch_security_state_unavailable("durable_record_latched_or_invalid");
                }
                // Memory latch is authoritative even if a stale durable row reads ok.
                let accepting = durable_ok && !memory_latched && boot;
                if accepting {
                    Ok(HealthResponse {
                        status: "ok",
                        accepting_authorized_operations: true,
                        schema_version: crate::models::WIRE_CONTRACT_V1_VERSION,
                        storage_schema_version: crate::db::SCHEMA_VERSION,
                        bootstrap_completed: true,
                        features: FeatureAvailability::foundation(),
                    })
                } else {
                    Ok(degraded(boot))
                }
            }
            Ok(None) => {
                // Missing deployment row is uncertainty — latch, do not only
                // return degraded while memory stays Ok.
                self.latch_security_state_unavailable("deployment_row_missing");
                Ok(degraded(false))
            }
            Err(_) => {
                // Unreadable health fails closed (finish_storage already latched
                // Storage/Internal uncertainty).
                Ok(degraded(false))
            }
        }
    }

    /// Create a single-use bootstrap token. Printed by the CLI; stored hashed.
    pub fn create_bootstrap_token(&self) -> AppResult<String> {
        self.require_security_ok()?;
        let (token, token_hash) = generate_token()?;
        let now = now_unix();
        self.with_tx(|conn| {
            conn.execute(
                "INSERT INTO bootstrap_tokens (token_hash, created_at) VALUES (?1, ?2)",
                params![token_hash, now],
            )?;
            Ok(())
        })?;
        Ok(token)
    }

    // ----- bootstrap -----

    pub fn bootstrap(&self, req: BootstrapRequest) -> AppResult<BootstrapResponse> {
        self.require_security_ok()?;
        validate_username(&req.username)?;
        validate_password(&req.password)?;

        let password_hash = hash_password(&req.password)?;
        let now = now_unix();
        let account_id = Uuid::new_v4().to_string();
        let manager_id = req
            .manager_public_identity
            .as_ref()
            .map(|_| Uuid::new_v4().to_string());
        let token_hash = hash_token(&req.bootstrap_token);

        let outcome = self.with_tx(|conn| {
            let consumed: Option<String> = conn
                .query_row(
                    "SELECT token_hash FROM bootstrap_tokens
                     WHERE token_hash = ?1 AND consumed_at IS NULL",
                    params![token_hash],
                    |row| row.get(0),
                )
                .optional()?;

            let token_hash = match consumed {
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

            // Competing unique claims: username.
            conn.execute(
                "INSERT INTO accounts (
                    id, username, password_hash, state,
                    can_operate, can_manage_enrollment, can_manage_access,
                    can_manage_accounts, can_manage_security,
                    revision, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, 'active', 1, 1, 1, 1, 1, 1, ?4, ?4)",
                params![account_id, req.username, password_hash, now],
            )
            .map_err(|err| map_unique(err, "username already exists"))?;

            if let (Some(public_identity), Some(manager_id)) =
                (&req.manager_public_identity, &manager_id)
            {
                let friendly = req
                    .manager_friendly_name
                    .clone()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| "Bootstrap manager".to_string());
                conn.execute(
                    "INSERT INTO managers (
                        id, public_identity, friendly_name, lifecycle_state,
                        approved_by_account_id, approved_at, created_at, updated_at
                     ) VALUES (?1, ?2, ?3, 'approved', ?4, ?5, ?5, ?5)",
                    params![manager_id, public_identity, friendly, account_id, now],
                )
                .map_err(|err| map_unique(err, "manager public identity already exists"))?;
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

        let account = self.load_account_view(&account_id)?;
        let manager = match &manager_id {
            Some(id) => Some(self.load_manager_view(id)?),
            None => None,
        };
        Ok(BootstrapResponse {
            account,
            manager,
            server_state: "ready_for_enrollment",
        })
    }

    // ----- auth -----

    pub fn login(&self, req: LoginRequest) -> AppResult<LoginResponse> {
        self.require_security_ok()?;
        // Cheap input validation before password hashing or throttle growth.
        validate_username(&req.username)?;
        if req.password.is_empty() {
            return Err(AppError::bad_request("password is required"));
        }
        if req.password.len() > 256 {
            return Err(AppError::bad_request(
                "password must be at most 256 characters",
            ));
        }
        self.check_login_throttle(&req.username)?;

        let account_id;
        let password_hash;
        let state;
        {
            let row = self.with_conn(|conn| {
                let row: Option<AccountAuthRow> = conn
                    .query_row(
                        "SELECT id, password_hash, state FROM accounts WHERE username = ?1 COLLATE NOCASE",
                        params![req.username],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                Ok(row)
            })?;
            match row {
                Some((id, hash, st)) => {
                    account_id = id;
                    password_hash = hash;
                    state = st;
                }
                None => {
                    // Same failure shape as bad password — no account enumeration.
                    self.record_login_failure(&req.username);
                    return Err(AppError::unauthorized("invalid credentials"));
                }
            }
        }

        let valid = verify_password(&req.password, &password_hash)?;
        if !valid {
            self.record_login_failure(&req.username);
            return Err(AppError::unauthorized("invalid credentials"));
        }
        if state != "active" {
            return Err(AppError::forbidden("account is disabled"));
        }
        self.clear_login_failures(&req.username);

        // Cheap early refusal when DB already records an MFA requirement.
        // The final IMMEDIATE transaction rechecks this; enrollment between
        // here and session insertion cannot mint a password-only session.
        if self.with_conn(|conn| account_has_mfa_requirement(conn, &account_id))? {
            return Err(mfa_required_error());
        }

        // Manager binding is a separate approval check (D20).
        //
        // A v1 display label never establishes authority for an approved
        // cryptographic device: key-bearing managers (non-null `public_key`)
        // require an Ed25519 proof via v2 challenge completion. Label-only
        // legacy dev fixtures (`public_key IS NULL`) remain bindable here.
        let manager_id = if let Some(public_identity) = &req.manager_public_identity {
            let row = self.with_conn(|conn| {
                let row: Option<(String, String, Option<String>)> = conn
                    .query_row(
                        "SELECT id, lifecycle_state, public_key FROM managers WHERE public_identity = ?1",
                        params![public_identity],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                Ok(row)
            })?;
            match row {
                Some((id, lifecycle, public_key)) if lifecycle == "approved" => {
                    if public_key.is_some() {
                        return Err(AppError::forbidden(
                            "manager device key requires a signed proof; display identity cannot bind a cryptographic device",
                        ));
                    }
                    Some(id)
                }
                Some(_) => {
                    return Err(AppError::forbidden(
                        "manager identity is not approved for this deployment",
                    ))
                }
                None => {
                    return Err(AppError::forbidden(
                        "manager identity is not approved for this deployment",
                    ))
                }
            }
        } else {
            None
        };

        let (token, token_hash) = generate_token()?;
        let session_id = Uuid::new_v4().to_string();
        let now = now_unix();
        let expires_at = now + SESSION_TTL_SECS;

        // FINAL IMMEDIATE TRANSACTION: recheck account + verified password
        // hash snapshot + manager approval + DB-owned MFA requirement, then
        // insert the session. Enrollment/account changes after password
        // verification cannot bypass the MFA denial.
        self.with_tx(|conn| {
            let row: Option<(String, String)> = conn
                .query_row(
                    "SELECT password_hash, state FROM accounts WHERE id = ?1",
                    params![account_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let (current_hash, current_state) = match row {
                Some(row) => row,
                None => return Err(AppError::unauthorized("invalid credentials")),
            };
            if current_state != "active" {
                return Err(AppError::forbidden("account is disabled"));
            }
            // Snapshot must still be the verified hash (password change/reset).
            if current_hash != password_hash {
                return Err(AppError::unauthorized("invalid credentials"));
            }
            if let Some(manager_id) = &manager_id {
                let manager: Option<(String, Option<String>)> = conn
                    .query_row(
                        "SELECT lifecycle_state, public_key FROM managers WHERE id = ?1",
                        params![manager_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                match manager {
                    Some((ref state, public_key)) if state == "approved" => {
                        // Recheck device-binding provenance: a key added
                        // between validation and issuance must deny.
                        if public_key.is_some() {
                            return Err(AppError::forbidden(
                                "manager device key requires a signed proof; display identity cannot bind a cryptographic device",
                            ));
                        }
                    }
                    _ => {
                        return Err(AppError::forbidden(
                            "manager identity is not approved for this deployment",
                        ))
                    }
                }
            }
            if account_has_mfa_requirement(conn, &account_id)? {
                return Err(mfa_required_error());
            }
            conn.execute(
                "INSERT INTO sessions (
                    id, account_id, manager_id, token_hash, created_at, expires_at,
                    assurance, mfa_assured_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'password', NULL)",
                params![session_id, account_id, manager_id, token_hash, now, expires_at],
            )?;
            Ok(())
        })?;

        let account = self.load_account_view(&account_id)?;
        let manager = match &manager_id {
            Some(id) => Some(self.load_manager_view(id)?),
            None => None,
        };

        // Never log token/password. Response carries the token once.
        tracing::info!(
            account_id = %account_id,
            manager_bound = manager_id.is_some(),
            "login succeeded"
        );

        Ok(LoginResponse {
            token,
            expires_at_unix: expires_at,
            account,
            manager,
            mfa: MfaStatus::unavailable(),
            // v1 responses omit manager_public_key (frozen wire output).
            manager_public_key: None,
        })
    }

    pub fn logout(&self, auth: &AuthContext) -> AppResult<()> {
        let now = now_unix();
        let outcome = self.with_tx(|conn| {
            conn.execute(
                "UPDATE sessions SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
                params![now, auth.session_id],
            )?;
            Ok(())
        });
        outcome?;
        Ok(())
    }

    /// Cleanup-only logout: revoke the session that owns this bearer token.
    ///
    /// Does **not** grant authority. Used so weaker historical sessions can be
    /// dismissed even when current mandatory MFA refuses `authenticate_token`.
    /// Still requires a live (unrevoked, unexpired) session match — never a
    /// new identity.
    pub fn logout_token(&self, token: &str) -> AppResult<()> {
        self.require_security_ok()?;
        if token.trim().is_empty() {
            return Err(AppError::unauthorized("missing bearer token"));
        }
        let token_hash = hash_token(token);
        let now = now_unix();
        self.with_tx(|conn| {
            let session_id: Option<String> = conn
                .query_row(
                    "SELECT id FROM sessions
                     WHERE token_hash = ?1 AND revoked_at IS NULL AND expires_at > ?2",
                    params![token_hash, now],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(session_id) = session_id else {
                return Err(AppError::unauthorized("invalid session"));
            };
            conn.execute(
                "UPDATE sessions SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
                params![now, session_id],
            )?;
            Ok(())
        })
    }

    pub fn authenticate_token(&self, token: &str) -> AppResult<AuthContext> {
        self.require_security_ok()?;
        if token.trim().is_empty() {
            return Err(AppError::unauthorized("missing bearer token"));
        }
        let token_hash = hash_token(token);
        let now = now_unix();

        self.with_conn(|conn| {
            let row: Option<AuthoritySessionRow> =
                conn
                    .query_row(
                        "SELECT s.id, s.account_id, s.token_hash, s.manager_id, s.expires_at, s.revoked_at,
                                s.assurance, s.mfa_assured_at
                         FROM sessions s
                         WHERE s.token_hash = ?1",
                        params![token_hash],
                        |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                                row.get(5)?,
                                row.get(6)?,
                                row.get(7)?,
                            ))
                        },
                    )
                    .optional()?;

            let (
                session_id,
                account_id,
                stored_hash,
                manager_id,
                expires_at,
                revoked_at,
                assurance,
                mfa_assured_at,
            ) = match row {
                Some(row) => row,
                None => return Err(AppError::unauthorized("invalid session")),
            };

            if !token_hash_eq(&token_hash, &stored_hash) {
                return Err(AppError::unauthorized("invalid session"));
            }
            if revoked_at.is_some() {
                return Err(AppError::unauthorized("session revoked"));
            }
            if expires_at <= now {
                return Err(AppError::unauthorized("session expired"));
            }

            let account = conn.query_row(
                "SELECT username, state, can_operate, can_manage_enrollment, can_manage_access,
                        can_manage_accounts, can_manage_security, revision
                 FROM accounts WHERE id = ?1",
                params![account_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, bool>(5)?,
                        row.get::<_, bool>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )?;

            let (
                username,
                state,
                can_operate,
                can_manage_enrollment,
                can_manage_access,
                can_manage_accounts,
                can_manage_security,
                revision,
            ) = account;
            if state != "active" {
                return Err(AppError::forbidden("account is disabled"));
            }

            // If a manager is bound to the session, it must still be approved.
            if let Some(manager_id) = &manager_id {
                let lifecycle: String = conn.query_row(
                    "SELECT lifecycle_state FROM managers WHERE id = ?1",
                    params![manager_id],
                    |row| row.get(0),
                )?;
                if lifecycle != "approved" {
                    return Err(AppError::forbidden(
                        "bound manager identity is no longer approved",
                    ));
                }
            }

            // Authority-use boundary: current mandatory MFA cannot be bypassed
            // by a persisted weaker session (historical/schema-migrated
            // password rows, role promotion, or policy activation). Real
            // stored assurance is required — never client flags or MFA status
            // alone. Password/legacy sessions are never MFA-assured.
            if account_has_mfa_requirement(conn, &account_id)?
                && (assurance != "mfa" || mfa_assured_at.is_none())
            {
                return Err(AppError::forbidden(
                    "multi-factor authentication is required; password-only session authority is refused",
                ));
            }

            Ok(AuthContext {
                account_id,
                username,
                session_id,
                manager_id,
                can_operate,
                can_manage_enrollment,
                can_manage_access,
                can_manage_accounts,
                can_manage_security,
                revision,
            })
        })
    }

    pub fn session_info(&self, auth: &AuthContext) -> AppResult<SessionResponse> {
        let expires_at = self.with_conn(|conn| {
            let expires_at: i64 = conn.query_row(
                "SELECT expires_at FROM sessions WHERE id = ?1",
                params![auth.session_id],
                |row| row.get(0),
            )?;
            Ok(expires_at)
        })?;
        let account = self.load_account_view(&auth.account_id)?;
        let manager = match &auth.manager_id {
            Some(id) => Some(self.load_manager_view(id)?),
            None => None,
        };
        Ok(SessionResponse {
            account,
            manager,
            expires_at_unix: expires_at,
        })
    }

    // ----- managers -----

    pub fn register_manager(
        &self,
        auth: &AuthContext,
        req: RegisterManagerRequest,
    ) -> AppResult<ManagerView> {
        self.require_security_ok()?;
        if !auth.can_manage_enrollment {
            return Err(AppError::forbidden(
                "enrollment management permission is required to register a manager",
            ));
        }
        let public_identity = req.public_identity.trim().to_string();
        if public_identity.is_empty() || public_identity.len() > 256 {
            return Err(AppError::bad_request(
                "manager public identity must be 1–256 characters",
            ));
        }
        let friendly_name = req.friendly_name.trim().to_string();
        if friendly_name.is_empty() || friendly_name.len() > 128 {
            return Err(AppError::bad_request(
                "manager friendly name must be 1–128 characters",
            ));
        }

        let id = Uuid::new_v4().to_string();
        let now = now_unix();
        let outcome = self.with_tx(|conn| {
            // New managers are pending; they cannot approve themselves (D20).
            conn.execute(
                "INSERT INTO managers (
                    id, public_identity, friendly_name, lifecycle_state,
                    approved_by_account_id, approved_at, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, 'pending', NULL, NULL, ?4, ?4)",
                params![id, public_identity, friendly_name, now],
            )
            .map_err(|err| map_unique(err, "manager public identity already exists"))?;
            Ok(())
        });
        outcome?;
        self.load_manager_view(&id)
    }

    pub fn list_managers(&self, auth: &AuthContext) -> AppResult<Vec<ManagerView>> {
        self.require_security_ok()?;
        if !auth.can_manage_enrollment {
            return Err(AppError::forbidden(
                "enrollment management permission is required to list managers",
            ));
        }
        let ids = self.with_conn(|conn| {
            let mut stmt =
                conn.prepare("SELECT id FROM managers ORDER BY created_at ASC LIMIT ?1")?;
            let ids: Vec<String> = stmt
                .query_map(params![MAX_PAGE_SIZE as i64], |row| row.get(0))?
                .collect::<Result<_, _>>()?;
            Ok(ids)
        })?;
        ids.iter().map(|id| self.load_manager_view(id)).collect()
    }

    pub fn approve_manager(
        &self,
        auth: &AuthContext,
        manager_id: &str,
        req: ApproveManagerRequest,
    ) -> AppResult<ManagerView> {
        self.require_security_ok()?;
        if !auth.can_manage_enrollment {
            return Err(AppError::forbidden(
                "enrollment management permission is required to approve a manager",
            ));
        }
        if !req.confirm {
            return Err(AppError::bad_request(
                "confirm must be true to approve a manager identity",
            ));
        }

        let now = now_unix();
        let approving_account = auth.account_id.clone();
        let target = manager_id.to_string();
        let outcome = self.with_tx(|conn| {
            let lifecycle: Option<String> = conn
                .query_row(
                    "SELECT lifecycle_state FROM managers WHERE id = ?1",
                    params![target],
                    |row| row.get(0),
                )
                .optional()?;
            let lifecycle = lifecycle.ok_or_else(|| AppError::not_found("manager not found"))?;
            if lifecycle == "revoked" {
                return Err(AppError::conflict(
                    "manager identity is revoked and must be replaced",
                    None,
                ));
            }
            if lifecycle == "approved" {
                return Err(AppError::conflict("manager already approved", None));
            }
            // A pending manager cannot approve itself: actor is an authenticated
            // enrollment admin account, never the manager identity alone.
            conn.execute(
                "UPDATE managers
                 SET lifecycle_state = 'approved',
                     approved_by_account_id = ?1,
                     approved_at = ?2,
                     updated_at = ?2
                 WHERE id = ?3 AND lifecycle_state = 'pending'",
                params![approving_account, now, target],
            )?;
            Ok(())
        });
        outcome?;
        self.load_manager_view(manager_id)
    }

    pub fn revoke_manager(&self, auth: &AuthContext, manager_id: &str) -> AppResult<ManagerView> {
        self.require_security_ok()?;
        if !auth.can_manage_enrollment {
            return Err(AppError::forbidden(
                "enrollment management permission is required to revoke a manager",
            ));
        }
        let now = now_unix();
        let target = manager_id.to_string();
        let outcome = self.with_tx(|conn| {
            let changed = conn.execute(
                "UPDATE managers
                 SET lifecycle_state = 'revoked', updated_at = ?1
                 WHERE id = ?2 AND lifecycle_state IN ('pending', 'approved')",
                params![now, target],
            )?;
            if changed == 0 {
                return Err(AppError::not_found("manager not found or already revoked"));
            }
            // Revoked manager sessions cannot retain bound approval.
            conn.execute(
                "UPDATE sessions SET revoked_at = ?1 WHERE manager_id = ?2 AND revoked_at IS NULL",
                params![now, target],
            )?;
            Ok(())
        });
        outcome?;
        self.load_manager_view(manager_id)
    }

    // ----- computers / inventory -----

    pub fn create_computer(
        &self,
        auth: &AuthContext,
        req: CreateComputerRequest,
    ) -> AppResult<ComputerView> {
        self.require_security_ok()?;
        if !auth.can_manage_enrollment {
            return Err(AppError::forbidden(
                "enrollment management permission is required to add a computer",
            ));
        }
        let public_identity = req.public_identity.trim().to_string();
        let friendly_name = req.friendly_name.trim().to_string();
        let platform = req.platform.trim().to_lowercase();
        if public_identity.is_empty() || public_identity.len() > 256 {
            return Err(AppError::bad_request(
                "computer public identity must be 1–256 characters",
            ));
        }
        if friendly_name.is_empty() || friendly_name.len() > 128 {
            return Err(AppError::bad_request(
                "computer friendly name must be 1–128 characters",
            ));
        }
        if !matches!(platform.as_str(), "macos" | "windows" | "linux") {
            return Err(AppError::bad_request(
                "platform must be one of: macos, windows, linux",
            ));
        }

        let id = Uuid::new_v4().to_string();
        let now = now_unix();
        let outcome = self.with_tx(|conn| {
            conn.execute(
                "INSERT INTO computers (
                    id, public_identity, friendly_name, platform, enrollment_state,
                    enrollment_epoch, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, 'pending', 1, ?5, ?5)",
                params![id, public_identity, friendly_name, platform, now],
            )
            .map_err(|err| map_unique(err, "computer public identity already exists"))?;
            Ok(())
        });
        outcome?;
        self.load_computer_view(&id)
    }

    /// Bounded inventory read. Scope comes from the session's access assignments.
    pub fn list_computers(&self, auth: &AuthContext) -> AppResult<ComputerListResponse> {
        self.require_security_ok()?;
        self.with_conn(|conn| {
            // Union of the account's access scopes. Administration alone does not
            // grant inventory pixels; there is no screen data here either way.
            let (scope_all, explicit_ids) = self.load_scope(conn, &auth.account_id)?;

            let computers: Vec<ComputerView> = if scope_all {
                let mut stmt = conn.prepare(
                    "SELECT id, public_identity, friendly_name, platform, enrollment_state, enrollment_epoch
                     FROM computers
                     ORDER BY friendly_name ASC
                     LIMIT ?1",
                )?;
                let rows = stmt.query_map(params![MAX_PAGE_SIZE as i64], map_computer_row)?;
                rows.collect::<Result<Vec<_>, _>>()?
            } else if explicit_ids.is_empty() {
                Vec::new()
            } else {
                let placeholders = explicit_ids
                    .iter()
                    .map(|_| "?")
                    .collect::<Vec<_>>()
                    .join(",");
                let sql = format!(
                    "SELECT id, public_identity, friendly_name, platform, enrollment_state, enrollment_epoch
                     FROM computers
                     WHERE id IN ({placeholders})
                     ORDER BY friendly_name ASC
                     LIMIT ?{max}",
                    max = explicit_ids.len() + 1
                );
                let mut values: Vec<Box<dyn rusqlite::ToSql>> = explicit_ids
                    .iter()
                    .map(|id| Box::new(id.clone()) as Box<dyn rusqlite::ToSql>)
                    .collect();
                values.push(Box::new(MAX_PAGE_SIZE as i64));
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map(
                    rusqlite::params_from_iter(values.iter().map(|b| b.as_ref())),
                    map_computer_row,
                )?;
                rows.collect::<Result<Vec<_>, _>>()?
            };

            Ok(ComputerListResponse {
                computers,
                scope_is_explicit: !scope_all,
                max_page_size: MAX_PAGE_SIZE,
            })
        })
    }

    pub fn get_computer(&self, auth: &AuthContext, computer_id: &str) -> AppResult<ComputerView> {
        self.require_security_ok()?;
        self.require_computer_in_scope(auth, computer_id)?;
        self.load_computer_view(computer_id)
    }

    pub fn require_computer_in_scope(
        &self,
        auth: &AuthContext,
        computer_id: &str,
    ) -> AppResult<()> {
        self.with_conn(|conn| {
            let (scope_all, explicit_ids) = self.load_scope(conn, &auth.account_id)?;
            if scope_all {
                let exists: bool = conn
                    .query_row(
                        "SELECT 1 FROM computers WHERE id = ?1",
                        params![computer_id],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false);
                if !exists {
                    return Err(AppError::not_found("computer not found"));
                }
                return Ok(());
            }
            if explicit_ids.iter().any(|id| id == computer_id) {
                // Scope membership is not enrollment; still require the row to exist.
                let exists: bool = conn
                    .query_row(
                        "SELECT 1 FROM computers WHERE id = ?1",
                        params![computer_id],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false);
                if !exists {
                    return Err(AppError::not_found("computer not found"));
                }
                return Ok(());
            }
            Err(AppError::forbidden(
                "computer is outside the account access scope",
            ))
        })
    }

    // ----- access assignments -----

    pub fn grant_access(
        &self,
        auth: &AuthContext,
        req: GrantAccessRequest,
    ) -> AppResult<AccessAssignmentView> {
        self.require_security_ok()?;
        if !auth.can_manage_access {
            return Err(AppError::forbidden(
                "access management permission is required to grant capabilities",
            ));
        }
        // Administration must not silently grant screen permissions: 'observe'
        // is a real capability that still does not produce pixels in this build.
        let capability = match req.capability.as_str() {
            "operate" | "observe" | "install_maintain" => req.capability.clone(),
            other => {
                return Err(AppError::bad_request(format!(
                    "unknown capability '{other}' (expected operate, observe, or install_maintain)"
                )))
            }
        };
        if req.computer_scope_all && !req.computer_ids.is_empty() {
            return Err(AppError::bad_request(
                "use either computer_scope_all or explicit computer_ids, not both",
            ));
        }
        if !req.computer_scope_all && req.computer_ids.is_empty() {
            return Err(AppError::bad_request(
                "explicit computer_ids or computer_scope_all is required",
            ));
        }
        if req.computer_ids.len() > MAX_PAGE_SIZE {
            return Err(AppError::bad_request(format!(
                "computer_ids exceeds max page size {MAX_PAGE_SIZE}"
            )));
        }

        let id = Uuid::new_v4().to_string();
        let now = now_unix();
        let account_id = req.account_id.clone();
        let computer_ids = req.computer_ids.clone();
        let scope_all = req.computer_scope_all;

        let outcome = self.with_tx(|conn| {
            let exists: bool = conn
                .query_row(
                    "SELECT 1 FROM accounts WHERE id = ?1",
                    params![account_id],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false);
            if !exists {
                return Err(AppError::not_found("target account not found"));
            }

            conn.execute(
                "INSERT INTO access_assignments (
                    id, account_id, capability, computer_scope_all, revision, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)
                 ON CONFLICT (account_id, capability) DO UPDATE SET
                    computer_scope_all = excluded.computer_scope_all,
                    revision = access_assignments.revision + 1,
                    updated_at = excluded.updated_at",
                params![id, account_id, capability, scope_all as i64, now],
            )?;

            // Resolve the effective assignment id (insert or conflict-update).
            let assignment_id: String = conn.query_row(
                "SELECT id FROM access_assignments WHERE account_id = ?1 AND capability = ?2",
                params![account_id, capability],
                |row| row.get(0),
            )?;

            conn.execute(
                "DELETE FROM access_computer_scope WHERE assignment_id = ?1",
                params![assignment_id],
            )?;
            for computer_id in &computer_ids {
                let exists: bool = conn
                    .query_row(
                        "SELECT 1 FROM computers WHERE id = ?1",
                        params![computer_id],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false);
                if !exists {
                    return Err(AppError::not_found(format!(
                        "computer '{computer_id}' not found"
                    )));
                }
                conn.execute(
                    "INSERT INTO access_computer_scope (assignment_id, computer_id) VALUES (?1, ?2)",
                    params![assignment_id, computer_id],
                )?;
            }
            Ok(assignment_id)
        });
        let assignment_id = outcome?;
        self.load_assignment_view(&assignment_id)
    }

    pub fn list_access(&self, auth: &AuthContext) -> AppResult<Vec<AccessAssignmentView>> {
        self.require_security_ok()?;
        if !auth.can_manage_access {
            return Err(AppError::forbidden(
                "access management permission is required to list access assignments",
            ));
        }
        let ids = self.with_conn(|conn| {
            let mut stmt =
                conn.prepare("SELECT id FROM access_assignments ORDER BY created_at ASC LIMIT ?1")?;
            let ids: Vec<String> = stmt
                .query_map(params![MAX_PAGE_SIZE as i64], |row| row.get(0))?
                .collect::<Result<_, _>>()?;
            Ok(ids)
        })?;
        ids.iter().map(|id| self.load_assignment_view(id)).collect()
    }

    // ----- explicitly unavailable surfaces -----

    pub fn feature_unavailable(feature: &str) -> AppError {
        AppError::not_implemented(format!(
            "{feature} is not available in this foundation build; see contracts/http-v1.md and BUILD-REPORT.md"
        ))
    }

    // ----- helpers -----

    fn load_scope(
        &self,
        conn: &rusqlite::Connection,
        account_id: &str,
    ) -> AppResult<(bool, Vec<String>)> {
        let mut scope_all = false;
        let mut explicit: Vec<String> = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT id, computer_scope_all FROM access_assignments WHERE account_id = ?1",
        )?;
        let assignments = stmt.query_map(params![account_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?))
        })?;
        for assignment in assignments {
            let (assignment_id, all) = assignment?;
            if all {
                scope_all = true;
            } else {
                let mut stmt = conn.prepare(
                    "SELECT computer_id FROM access_computer_scope WHERE assignment_id = ?1",
                )?;
                let ids = stmt.query_map(params![assignment_id], |row| row.get(0))?;
                for id in ids {
                    let id: String = id?;
                    if !explicit.contains(&id) {
                        explicit.push(id);
                    }
                }
            }
        }
        Ok((scope_all, explicit))
    }

    pub(crate) fn load_account_view(&self, account_id: &str) -> AppResult<AccountView> {
        self.with_conn(|conn| {
            let row = conn.query_row(
                "SELECT id, username, state, can_operate, can_manage_enrollment, can_manage_access,
                        can_manage_accounts, can_manage_security, revision
                 FROM accounts WHERE id = ?1",
                params![account_id],
                map_account_row,
            )?;
            Ok(row)
        })
    }

    pub(crate) fn load_manager_view(&self, manager_id: &str) -> AppResult<ManagerView> {
        self.with_conn(|conn| {
            let row = conn.query_row(
                "SELECT id, public_identity, friendly_name, lifecycle_state, approved_at
                 FROM managers WHERE id = ?1",
                params![manager_id],
                map_manager_row,
            )?;
            Ok(row)
        })
    }

    fn load_computer_view(&self, computer_id: &str) -> AppResult<ComputerView> {
        self.with_conn(|conn| {
            let row = conn.query_row(
                "SELECT id, public_identity, friendly_name, platform, enrollment_state, enrollment_epoch
                 FROM computers WHERE id = ?1",
                params![computer_id],
                map_computer_row,
            )?;
            Ok(row)
        })
    }

    fn load_assignment_view(&self, assignment_id: &str) -> AppResult<AccessAssignmentView> {
        self.with_conn(|conn| {
            let (id, capability, computer_scope_all, revision) = conn.query_row(
                "SELECT id, capability, computer_scope_all, revision
                 FROM access_assignments WHERE id = ?1",
                params![assignment_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?;
            let mut stmt = conn.prepare(
                "SELECT computer_id FROM access_computer_scope WHERE assignment_id = ?1",
            )?;
            let computer_ids = stmt
                .query_map(params![assignment_id], |row| row.get(0))?
                .collect::<Result<Vec<String>, _>>()?;
            Ok(AccessAssignmentView {
                id,
                capability,
                computer_scope_all,
                computer_ids,
                revision,
            })
        })
    }

    pub(crate) fn check_login_throttle(&self, username: &str) -> AppResult<()> {
        let key = normalize_login_key(username);
        let now = now_unix();
        let mut guard = self
            .login_throttle
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        prune_login_throttle(&mut guard, now);
        if let Some(entry) = guard.get(&key) {
            if entry.locked_until.map(|until| until > now).unwrap_or(false) {
                return Err(AppError::rate_limited(
                    "too many failed sign-in attempts; try again shortly",
                ));
            }
            return Ok(());
        }
        // Fail closed when the throttle budget is saturated with live keys.
        if guard.len() >= LOGIN_THROTTLE_MAX_KEYS {
            return Err(AppError::rate_limited(
                "sign-in temporarily unavailable (throttle capacity)",
            ));
        }
        Ok(())
    }

    pub(crate) fn record_login_failure(&self, username: &str) {
        let key = normalize_login_key(username);
        let now = now_unix();
        let mut guard = self
            .login_throttle
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        prune_login_throttle(&mut guard, now);
        if !guard.contains_key(&key) && guard.len() >= LOGIN_THROTTLE_MAX_KEYS {
            // Cannot track a new key at capacity; unknown keys stay denied by check.
            return;
        }
        let entry = guard.entry(key).or_insert(ThrottleEntry {
            failure_count: 0,
            locked_until: None,
            last_failure_at: now,
        });
        entry.failure_count += 1;
        entry.last_failure_at = now;
        if entry.failure_count >= LOGIN_MAX_FAILURES {
            entry.locked_until = Some(now + LOGIN_LOCKOUT_SECS);
            entry.failure_count = 0;
        }
    }

    pub(crate) fn clear_login_failures(&self, username: &str) {
        let key = normalize_login_key(username);
        let mut guard = self
            .login_throttle
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.remove(&key);
    }
}

pub(crate) fn validate_username(username: &str) -> AppResult<()> {
    let name = username.trim();
    if name.len() < 3 || name.len() > 64 {
        return Err(AppError::bad_request("username must be 3–64 characters"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(AppError::bad_request(
            "username may contain only letters, digits, dot, underscore, or hyphen",
        ));
    }
    Ok(())
}

pub(crate) fn validate_password(password: &str) -> AppResult<()> {
    if password.len() < 12 {
        return Err(AppError::bad_request(
            "password must be at least 12 characters",
        ));
    }
    if password.len() > 256 {
        return Err(AppError::bad_request(
            "password must be at most 256 characters",
        ));
    }
    Ok(())
}

/// Database-owned MFA requirement for any session mint without a genuine factor.
///
/// True when effective mandatory MFA applies (administrator OR operator policy
/// `required` OR an already-active enrolled factor) **or** the account still
/// carries pending MFA material (factor row or unconsumed enrollment). This is
/// the shared decision for every session-issuance entry path (v1 password login
/// and v2 challenge completion). Unknown/corrupt policy fails closed via
/// `load_operator_mfa_policy`. Never a client flag.
fn account_has_mfa_requirement(conn: &Connection, account_id: &str) -> AppResult<bool> {
    // Fail closed on unknown/corrupt/missing policy.
    let policy = crate::auth_v2::load_operator_mfa_policy(conn)?;
    let is_admin: bool = conn.query_row(
        "SELECT can_manage_security FROM accounts WHERE id = ?1",
        params![account_id],
        |row| row.get(0),
    )?;
    if is_admin || policy == crate::models::OperatorMfaPolicy::Required {
        return Ok(true);
    }
    let present: i64 = conn.query_row(
        "SELECT EXISTS (
            SELECT 1 FROM account_mfa WHERE account_id = ?1
            UNION ALL
            SELECT 1 FROM mfa_enrollments
             WHERE account_id = ?1 AND consumed_at IS NULL
        )",
        params![account_id],
        |row| row.get(0),
    )?;
    Ok(present != 0)
}

fn mfa_required_error() -> AppError {
    AppError::forbidden("multi-factor authentication is required; password-only login is refused")
}

pub(crate) fn map_unique(err: rusqlite::Error, message: &str) -> AppError {
    match &err {
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            AppError::conflict(message, Some("unique_claim".to_string()))
        }
        _ => AppError::Storage(err),
    }
}

fn map_account_row(row: &Row<'_>) -> rusqlite::Result<AccountView> {
    Ok(AccountView {
        id: row.get(0)?,
        username: row.get(1)?,
        state: row.get(2)?,
        capabilities: AccountCapabilities {
            operate: row.get(3)?,
            manage_enrollment: row.get(4)?,
            manage_access: row.get(5)?,
            manage_accounts: row.get(6)?,
            manage_security: row.get(7)?,
        },
        revision: row.get(8)?,
    })
}

fn map_manager_row(row: &Row<'_>) -> rusqlite::Result<ManagerView> {
    Ok(ManagerView {
        id: row.get(0)?,
        public_identity: row.get(1)?,
        friendly_name: row.get(2)?,
        lifecycle_state: row.get(3)?,
        approved_at_unix: row.get(4)?,
    })
}

fn map_computer_row(row: &Row<'_>) -> rusqlite::Result<ComputerView> {
    Ok(ComputerView {
        id: row.get(0)?,
        public_identity: row.get(1)?,
        friendly_name: row.get(2)?,
        platform: row.get(3)?,
        enrollment_state: row.get(4)?,
        enrollment_epoch: row.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_storage_uncertainty_fails_closed() {
        let service = Service::new(crate::db::open_in_memory().expect("db"));
        assert_eq!(service.security_state(), SecurityState::Ok);
        let result: AppResult<()> =
            service.finish_storage(Err(AppError::internal("database lock poisoned")));
        assert!(result.is_err());
        assert_eq!(service.security_state(), SecurityState::Unavailable);
    }

    #[test]
    fn invalid_security_state_ok_integer_fails_closed() {
        let db = crate::db::open_in_memory().expect("db");
        {
            let conn = db.lock().expect("lock");
            conn.execute(
                "UPDATE deployment SET security_state_ok = 2 WHERE id = 1",
                [],
            )
            .expect("update");
        }
        let service = Service::new(db);
        assert_eq!(service.security_state(), SecurityState::Unavailable);
    }

    #[test]
    fn security_state_ok_one_hydrates_ok() {
        let db = crate::db::open_in_memory().expect("db");
        let service = Service::new(db);
        assert_eq!(service.security_state(), SecurityState::Ok);
    }
}
