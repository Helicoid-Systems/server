//! Domain operations: bootstrap, login, accounts, managers, computers, access.
//!
//! Authorization is enforced here from session state — never from request
//! body owner fields. Administration capability does not imply observe/operate.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, MutexGuard};

use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OptionalExtension, Row};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::{
    endpoint_enrollment_proof_message, generate_token, hash_password, hash_token, token_hash_eq,
    verify_ed25519_strict, verify_password,
};
use crate::db::{now_unix, Db};
use crate::error::{AppError, AppResult};
use crate::models::*;

/// One short-lived, in-memory dispatch copy. The database stores only the
/// grant hash; this copy exists only until the exact endpoint session polls
/// it or the grant expires.
pub(crate) struct DispatchedObservationGrant {
    pub(crate) grant_id: String,
    pub(crate) computer_id: String,
    pub(crate) expires_at_unix: i64,
    pub(crate) grant_token: String,
}

impl Drop for DispatchedObservationGrant {
    fn drop(&mut self) {
        self.grant_token.zeroize();
    }
}

/// Session lifetime for this foundation (24h). B03/E07 will freeze production policy.
const SESSION_TTL_SECS: i64 = 24 * 60 * 60;
/// Login failure lockout threshold.
const LOGIN_MAX_FAILURES: i64 = 5;
const LOGIN_LOCKOUT_SECS: i64 = 60;
/// Hard cap for inventory pages (lists and fan-out bound).
pub const MAX_PAGE_SIZE: usize = 100;
/// Flat groups are bounded so group administration and filter metadata stay finite.
pub const MAX_COMPUTER_GROUPS: usize = 100;
/// Active endpoint invitations retained per deployment.
pub const MAX_ENDPOINT_INVITATIONS: usize = 100;
/// Endpoint enrollment invitations expire after fifteen minutes.
const ENDPOINT_INVITATION_TTL_SECS: i64 = 15 * 60;
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
/// Current session and scoped admin authority selected for a privileged write.
type CurrentAdminSessionRow = (
    String,
    i64,
    Option<i64>,
    Option<String>,
    String,
    Option<i64>,
    String,
    bool,
    bool,
    bool,
    bool,
);
/// Current account and approved manager key selected for MFA enrollment.
type CurrentManagerSessionRow = (
    String,
    i64,
    Option<i64>,
    String,
    Option<String>,
    Option<String>,
);
/// Invitation fields needed to confirm one-time revocation.
type RevokableInvitationRow = (String, String, i64, i64, Option<i64>, Option<i64>);
/// Secret-bearing invitation fields rechecked during endpoint enrollment.
type EndpointEnrollmentInvitationRow = (String, String, String, i64, Option<i64>, Option<i64>);

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
    /// Process-local, short-lived WebRTC signaling. Offers, answers and ICE
    /// candidates are never persisted in the authority database.
    pub(crate) observation_signals: Mutex<HashMap<String, ObservationSignalMailbox>>,
    /// Process-local grant delivery, keyed by exact authenticated endpoint
    /// session. Grant tokens are never persisted in the authority database.
    pub(crate) observation_grants: Mutex<HashMap<String, VecDeque<DispatchedObservationGrant>>>,
    /// Session IDs are wake hints only; every wake rechecks endpoint authority
    /// against the database before returning a grant.
    pub(crate) observation_grant_notifier: tokio::sync::broadcast::Sender<String>,
    /// Latched when a required storage commit/read leaves trust state uncertain.
    /// Memory is authoritative if persisting the latch itself fails. Never auto-recovers.
    security_state: Mutex<SecurityState>,
}

type LatestEndpointSession = (String, i64, i64, Option<i64>, Option<String>);

#[derive(Default)]
pub(crate) struct ObservationSignalMailbox {
    pub(crate) expires_at: i64,
    pub(crate) next_sequence: u64,
    pub(crate) messages: Vec<ObservationSignalMessage>,
    pub(crate) bytes: usize,
    pub(crate) offer_sent: bool,
    pub(crate) challenge_sent: bool,
    pub(crate) answer_sent: bool,
    pub(crate) closed: bool,
}

pub(crate) fn lock_observation_grants(
    service: &Service,
) -> Result<MutexGuard<'_, HashMap<String, VecDeque<DispatchedObservationGrant>>>, ()> {
    service.observation_grants.lock().map_err(|_| ())
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

/// Server-derived authority for one enrolled endpoint session. The context is
/// created only after bearer verification and carries the enrollment epoch so
/// endpoint operations can recheck the same fence in their final transaction.
#[derive(Debug, Clone)]
pub struct EndpointAuthContext {
    pub(crate) session_id: String,
    pub(crate) computer_id: String,
    pub(crate) enrollment_epoch: i64,
    pub(crate) local_user_id: Option<String>,
    pub(crate) local_user_display_name: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum AdminCapability {
    Enrollment,
    Accounts,
    Access,
    Security,
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
    /// Return the stable server-owned deployment identity for client-side
    /// scoping. It grants no authority and is never accepted from requests.
    pub fn deployment_id(&self) -> AppResult<String> {
        self.with_conn(crate::db::deployment_key)
    }

    /// Return the public half of the deployment-local endpoint-grant signer.
    /// The private half is read only from the owner-private database and is
    /// never serialized or returned to callers.
    pub fn grant_signing_public_key(&self) -> AppResult<String> {
        if !self.db.persisted_v2_credentials_allowed() {
            return Err(AppError::not_implemented(
                "deployment authority keys require a verified private store",
            ));
        }
        let mut secret = self.with_conn(crate::db::grant_signing_secret)?;
        let signing_key = SigningKey::from_bytes(&secret);
        secret.zeroize();
        Ok(hex::encode(signing_key.verifying_key().to_bytes()))
    }

    /// Return the persisted authority checkpoint for peers performing an
    /// explicit, independently verified trust update.
    pub fn authority_generation(&self) -> AppResult<i64> {
        self.with_conn(|conn| {
            let generation: i64 = conn.query_row(
                "SELECT authority_generation FROM deployment WHERE id = 1",
                [],
                |row| row.get(0),
            )?;
            if generation <= 0 {
                return Err(AppError::security_state_unavailable(
                    "deployment authority checkpoint is unavailable",
                ));
            }
            Ok(generation)
        })
    }

    pub fn new(db: Db) -> Self {
        let security_state = hydrate_security_state(&db);
        let (observation_grant_notifier, _) = tokio::sync::broadcast::channel(256);
        Service {
            db,
            login_throttle: Mutex::new(HashMap::new()),
            observation_signals: Mutex::new(HashMap::new()),
            observation_grants: Mutex::new(HashMap::new()),
            observation_grant_notifier,
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
            let row: Option<(i64, i64, i64, String, i64)> = conn
                .query_row(
                    "SELECT bootstrap_completed, security_state_ok, recovery_quarantined,
                            authority_state, authority_generation
                     FROM deployment WHERE id = 1",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()?;
            Ok(row)
        });

        let degraded = |bootstrap_completed: bool,
                        recovery_quarantined: bool,
                        authority_state: String,
                        authority_generation: i64| HealthResponse {
            status: "degraded",
            accepting_authorized_operations: false,
            schema_version: crate::models::WIRE_CONTRACT_V1_VERSION,
            storage_schema_version: crate::db::SCHEMA_VERSION,
            bootstrap_completed,
            recovery_quarantined,
            authority_state,
            authority_generation,
            features: FeatureAvailability::foundation(),
        };

        match result {
            Ok(Some((
                bootstrap_completed,
                security_state_ok,
                recovery_quarantined,
                authority_state,
                authority_generation,
            ))) => {
                let boot = bootstrap_completed != 0;
                let recovery = recovery_quarantined == 1;
                // Exact 0/1 required; any other value is invalid trust state.
                let durable_ok = security_state_ok == 1
                    && matches!(recovery_quarantined, 0 | 1)
                    && matches!(
                        authority_state.as_str(),
                        "active" | "draining" | "awaiting_cutover" | "retired" | "needs_review"
                    )
                    && authority_generation > 0;
                if !durable_ok {
                    self.latch_security_state_unavailable("durable_record_latched_or_invalid");
                }
                // Memory latch is authoritative even if a stale durable row reads ok.
                let accepting = durable_ok
                    && !memory_latched
                    && boot
                    && !recovery
                    && authority_state == "active";
                if accepting {
                    Ok(HealthResponse {
                        status: "ok",
                        accepting_authorized_operations: true,
                        schema_version: crate::models::WIRE_CONTRACT_V1_VERSION,
                        storage_schema_version: crate::db::SCHEMA_VERSION,
                        bootstrap_completed: true,
                        recovery_quarantined: false,
                        authority_state,
                        authority_generation,
                        features: FeatureAvailability::foundation(),
                    })
                } else {
                    Ok(degraded(
                        boot,
                        recovery,
                        authority_state,
                        authority_generation,
                    ))
                }
            }
            Ok(None) => {
                // Missing deployment row is uncertainty — latch, do not only
                // return degraded while memory stays Ok.
                self.latch_security_state_unavailable("deployment_row_missing");
                Ok(degraded(false, false, "needs_review".to_string(), 0))
            }
            Err(_) => {
                // Unreadable health fails closed (finish_storage already latched
                // Storage/Internal uncertainty).
                Ok(degraded(false, false, "needs_review".to_string(), 0))
            }
        }
    }

    /// Create a single-use bootstrap token. Printed by the CLI; stored hashed.
    /// Issuance rotates older unused tokens and stops after bootstrap completes.
    pub fn create_bootstrap_token(&self) -> AppResult<String> {
        self.require_security_ok()?;
        let (token, token_hash) = generate_token()?;
        let now = now_unix();
        let mut durable_state_invalid = false;
        let result = self.with_tx(|conn| {
            let (bootstrap_completed, security_state_ok): (i64, i64) = conn.query_row(
                "SELECT bootstrap_completed, security_state_ok FROM deployment WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if !matches!(bootstrap_completed, 0 | 1) || security_state_ok != 1 {
                durable_state_invalid = true;
                return Err(AppError::security_state_unavailable(
                    "trusted deployment state is latched or invalid; bootstrap token issuance is refused",
                ));
            }
            if bootstrap_completed == 1 {
                return Err(AppError::conflict(
                    "bootstrap already completed",
                    Some("single_use".to_string()),
                ));
            }

            // Only the newest unconsumed token remains valid. This lets an
            // operator safely recover from losing the one-time output without
            // leaving earlier copies usable. The immediate transaction also
            // serializes token rotation against bootstrap consumption.
            conn.execute(
                "UPDATE bootstrap_tokens SET consumed_at = ?1 WHERE consumed_at IS NULL",
                params![now],
            )?;
            conn.execute(
                "INSERT INTO bootstrap_tokens (token_hash, created_at) VALUES (?1, ?2)",
                params![token_hash, now],
            )?;
            Ok(())
        });
        if durable_state_invalid {
            self.latch_security_state_unavailable("durable_record_latched_or_invalid");
        }
        result?;
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
            if recovery_quarantined {
                return Err(AppError::forbidden(
                    "restore recovery requires the MFA and fresh Manager identity bootstrap flow",
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
                        "SELECT id, password_hash, state FROM accounts
                         WHERE username = ?1 COLLATE NOCASE AND recovery_quarantined = 0",
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
            let row: Option<(String, String, bool)> = conn
                .query_row(
                    "SELECT password_hash, state, recovery_quarantined
                     FROM accounts WHERE id = ?1",
                    params![account_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let (current_hash, current_state, recovery_quarantined) = match row {
                Some(row) => row,
                None => return Err(AppError::unauthorized("invalid credentials")),
            };
            if recovery_quarantined {
                return Err(AppError::forbidden(
                    "account authority from the restored backup remains quarantined",
                ));
            }
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

    pub fn list_accounts(&self, auth: &AuthContext) -> AppResult<AccountListResponse> {
        self.require_security_ok()?;
        if !auth.can_manage_accounts {
            return Err(AppError::forbidden(
                "account management permission is required to list accounts",
            ));
        }
        let ids = self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id FROM accounts
                 ORDER BY recovery_quarantined ASC, created_at ASC, id ASC LIMIT ?1",
            )?;
            let ids: Vec<String> = stmt
                .query_map(params![MAX_PAGE_SIZE as i64], |row| row.get(0))?
                .collect::<Result<_, _>>()?;
            Ok(ids)
        })?;
        let accounts = ids
            .iter()
            .map(|id| self.load_account_view(id))
            .collect::<AppResult<Vec<_>>>()?;
        Ok(AccountListResponse {
            accounts,
            max_page_size: MAX_PAGE_SIZE,
        })
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
            require_current_admin_session(
                conn,
                auth,
                AdminCapability::Enrollment,
                now,
                false,
                false,
            )?;
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
            require_current_admin_session(
                conn,
                auth,
                AdminCapability::Enrollment,
                now,
                false,
                false,
            )?;
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

            let mut computers: Vec<ComputerView> = if scope_all {
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

            let ids = computers
                .iter()
                .map(|computer| computer.id.clone())
                .collect::<Vec<_>>();
            let groups_by_computer = load_computer_group_refs(conn, &ids)?;
            for computer in &mut computers {
                computer.groups = groups_by_computer
                    .get(&computer.id)
                    .cloned()
                    .unwrap_or_default();
            }

            Ok(ComputerListResponse {
                computers,
                scope_is_explicit: !scope_all,
                max_page_size: MAX_PAGE_SIZE,
            })
        })
    }

    /// Return the authorized inventory with endpoint-authentication timestamps
    /// only for computers in the caller's current observe assignment. These
    /// timestamps report successful endpoint key proof; they do not claim a
    /// live capture worker or authorize pixels.
    pub fn list_computers_with_endpoint_sessions(
        &self,
        auth: &AuthContext,
    ) -> AppResult<ComputerListResponse> {
        let mut response = self.list_computers(auth)?;
        self.require_security_ok()?;
        let now = now_unix();
        self.with_conn(|conn| {
            require_current_manager_session(conn, auth, now)?;
            let assignment: Option<(String, bool)> = conn
                .query_row(
                    "SELECT id, computer_scope_all FROM access_assignments
                     WHERE account_id = ?1 AND capability = 'observe'",
                    params![auth.account_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((assignment_id, scope_all)) = assignment else {
                return Ok(response);
            };

            let response_ids: HashSet<String> = response
                .computers
                .iter()
                .filter(|computer| computer.enrollment_state == "enrolled")
                .map(|computer| computer.id.clone())
                .collect();
            let observable_ids: HashSet<String> = if scope_all {
                response_ids
            } else {
                let mut statement = conn.prepare(
                    "SELECT s.computer_id FROM access_computer_scope s
                     JOIN computers c ON c.id = s.computer_id
                     WHERE s.assignment_id = ?1 AND c.enrollment_state = 'enrolled'
                     ORDER BY s.computer_id ASC LIMIT ?2",
                )?;
                let rows = statement
                    .query_map(params![assignment_id, (MAX_PAGE_SIZE + 1) as i64], |row| {
                        row.get::<_, String>(0)
                    })?;
                let ids = rows.collect::<Result<HashSet<_>, _>>()?;
                if ids.len() > MAX_PAGE_SIZE {
                    return Err(AppError::unprocessable(
                        "observation assignment scope exceeds its bound",
                    ));
                }
                ids.intersection(&response_ids).cloned().collect()
            };

            for computer in &mut response.computers {
                if !observable_ids.contains(&computer.id) {
                    continue;
                }
                let latest: Option<LatestEndpointSession> = conn
                    .query_row(
                        "SELECT s.id, s.created_at, s.expires_at, s.revoked_at, s.local_user_id
                         FROM endpoint_sessions s
                         JOIN computers c ON c.id = s.computer_id
                         WHERE s.computer_id = ?1
                           AND s.enrollment_epoch = c.enrollment_epoch
                         ORDER BY s.created_at DESC, s.id DESC LIMIT 1",
                        params![computer.id],
                        |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                            ))
                        },
                    )
                    .optional()?;
                let (
                    last_authenticated_at_unix,
                    current_session_expires_at_unix,
                    current_session_id,
                    console_user_reported,
                ) = match latest {
                    Some((session_id, created_at, expires_at, revoked_at, local_user_id)) => {
                        let current = revoked_at.is_none() && expires_at > now;
                        (
                            Some(created_at),
                            current.then_some(expires_at),
                            current.then_some(session_id),
                            current.then_some(local_user_id.is_some()),
                        )
                    }
                    None => (None, None, None, None),
                };
                computer.endpoint_session = Some(ComputerEndpointSessionView {
                    last_authenticated_at_unix,
                    current_session_expires_at_unix,
                    current_session_id,
                    console_user_reported,
                });
            }
            Ok(response)
        })
    }

    /// Return only this session account's explicit `observe` assignment scope.
    /// The client may use it to avoid opening unavailable viewers, but this
    /// response never authorizes capture; admission must recheck the database.
    pub fn observation_scope(&self, auth: &AuthContext) -> AppResult<ObservationScopeResponse> {
        self.require_security_ok()?;
        self.with_conn(|conn| {
            let assignment: Option<(String, bool)> = conn
                .query_row(
                    "SELECT id, computer_scope_all FROM access_assignments
                     WHERE account_id = ?1 AND capability = 'observe'",
                    params![auth.account_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((assignment_id, scope_all)) = assignment else {
                return Ok(ObservationScopeResponse {
                    scope_all: false,
                    computer_ids: Vec::new(),
                });
            };
            if scope_all {
                return Ok(ObservationScopeResponse {
                    scope_all: true,
                    computer_ids: Vec::new(),
                });
            }

            let mut statement = conn.prepare(
                "SELECT computer_id FROM access_computer_scope
                 WHERE assignment_id = ?1 ORDER BY computer_id ASC LIMIT ?2",
            )?;
            let computer_ids: Vec<String> = statement
                .query_map(params![assignment_id, (MAX_PAGE_SIZE + 1) as i64], |row| {
                    row.get(0)
                })?
                .collect::<Result<_, _>>()?;
            if computer_ids.is_empty() || computer_ids.len() > MAX_PAGE_SIZE {
                return Err(AppError::unprocessable(
                    "observation assignment scope is empty or exceeds its bound",
                ));
            }
            Ok(ObservationScopeResponse {
                scope_all: false,
                computer_ids,
            })
        })
    }

    pub fn get_computer(&self, auth: &AuthContext, computer_id: &str) -> AppResult<ComputerView> {
        self.require_security_ok()?;
        self.require_computer_in_scope(auth, computer_id)?;
        self.load_computer_view(computer_id)
    }

    /// Bounded metadata inventory for current enrollment administrators. This
    /// does not expose endpoint identity keys or create observe access.
    pub fn list_enrollment_computers(
        &self,
        auth: &AuthContext,
    ) -> AppResult<EnrollmentComputerListResponse> {
        self.require_security_ok()?;
        require_cached_enrollment_capability(auth)?;
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
            let mut stmt = conn.prepare(
                "SELECT id, friendly_name, platform, enrollment_state, enrollment_epoch
                 FROM computers
                 ORDER BY friendly_name COLLATE NOCASE ASC, id ASC
                 LIMIT ?1",
            )?;
            let mut computers = stmt
                .query_map(params![MAX_PAGE_SIZE as i64], map_enrollment_computer_row)?
                .collect::<Result<Vec<_>, _>>()?;
            let ids = computers
                .iter()
                .map(|computer| computer.id.clone())
                .collect::<Vec<_>>();
            let groups_by_computer = load_computer_group_refs(conn, &ids)?;
            for computer in &mut computers {
                computer.groups = groups_by_computer
                    .get(&computer.id)
                    .cloned()
                    .unwrap_or_default();
            }
            Ok(EnrollmentComputerListResponse {
                computers,
                max_page_size: MAX_PAGE_SIZE,
            })
        })
    }

    /// Create a one-time endpoint enrollment invitation. The plaintext code is
    /// returned once; only its digest is persisted.
    pub fn create_endpoint_invitation(
        &self,
        auth: &AuthContext,
        req: CreateEndpointInvitationRequest,
    ) -> AppResult<EndpointInvitationIssuedResponse> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        require_cached_enrollment_capability(auth)?;

        let friendly_name = req.friendly_name.trim().to_string();
        if friendly_name.is_empty()
            || friendly_name.chars().count() > 128
            || friendly_name.chars().any(char::is_control)
        {
            return Err(AppError::bad_request(
                "friendly_name must contain 1 to 128 non-control characters",
            ));
        }
        let platform = req.platform.trim().to_ascii_lowercase();
        if !matches!(platform.as_str(), "macos" | "windows" | "linux") {
            return Err(AppError::bad_request(
                "platform must be one of: macos, windows, linux",
            ));
        }

        let (mut enrollment_code, code_hash) = generate_token()?;
        let id = Uuid::new_v4().to_string();
        let now = now_unix();
        let expires_at = now + ENDPOINT_INVITATION_TTL_SECS;
        let deployment_id = self.with_tx(|conn| {
            require_current_admin_session(
                conn,
                auth,
                AdminCapability::Enrollment,
                now,
                true,
                true,
            )?;

            conn.execute(
                "DELETE FROM computer_enrollment_invitations
                 WHERE redeemed_at IS NULL AND revoked_at IS NULL AND expires_at <= ?1",
                params![now],
            )?;
            let active_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM computer_enrollment_invitations
                 WHERE redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > ?1",
                params![now],
                |row| row.get(0),
            )?;
            if active_count >= MAX_ENDPOINT_INVITATIONS as i64 {
                return Err(AppError::conflict(
                    "the deployment has reached the active endpoint invitation limit",
                    Some("invitation_limit".into()),
                ));
            }

            conn.execute(
                "INSERT INTO computer_enrollment_invitations (
                    id, code_hash, friendly_name, platform, created_by_account_id,
                    created_at, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    code_hash,
                    friendly_name,
                    platform,
                    auth.account_id,
                    now,
                    expires_at
                ],
            )?;
            crate::audit::record_successful_event(
                conn,
                auth,
                "enrollment.invitation_created",
                std::slice::from_ref(&id),
                "one_time_code_issued",
                now,
            )?;
            crate::db::deployment_key(conn)
        });
        let deployment_id = match deployment_id {
            Ok(value) => value,
            Err(err) => {
                use zeroize::Zeroize;
                enrollment_code.zeroize();
                return Err(err);
            }
        };

        Ok(EndpointInvitationIssuedResponse {
            id,
            deployment_id,
            friendly_name,
            platform,
            enrollment_code: EnrollmentCode::new(enrollment_code),
            created_at_unix: now,
            expires_at_unix: expires_at,
        })
    }

    /// Bounded invitation metadata for endpoint enrollment administrators.
    /// Secret codes and their stored hashes are never returned.
    pub fn list_endpoint_invitations(
        &self,
        auth: &AuthContext,
    ) -> AppResult<EndpointInvitationListResponse> {
        self.require_security_ok()?;
        require_cached_enrollment_capability(auth)?;
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
            let mut stmt = conn.prepare(
                "SELECT id, friendly_name, platform,
                        CASE
                            WHEN redeemed_at IS NOT NULL THEN 'redeemed'
                            WHEN revoked_at IS NOT NULL THEN 'revoked'
                            WHEN expires_at <= ?1 THEN 'expired'
                            ELSE 'pending'
                        END,
                        created_at, expires_at, computer_id
                 FROM computer_enrollment_invitations
                 ORDER BY created_at DESC, id ASC LIMIT ?2",
            )?;
            let invitations = stmt
                .query_map(params![now, MAX_ENDPOINT_INVITATIONS as i64], |row| {
                    Ok(EndpointInvitationView {
                        id: row.get(0)?,
                        friendly_name: row.get(1)?,
                        platform: row.get(2)?,
                        state: row.get(3)?,
                        created_at_unix: row.get(4)?,
                        expires_at_unix: row.get(5)?,
                        computer_id: row.get(6)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(EndpointInvitationListResponse {
                invitations,
                max_page_size: MAX_ENDPOINT_INVITATIONS,
            })
        })
    }

    /// Revoke an unredeemed invitation after a lost or exposed setup code.
    pub fn revoke_endpoint_invitation(
        &self,
        auth: &AuthContext,
        invitation_id: &str,
        req: RevokeEndpointInvitationRequest,
    ) -> AppResult<EndpointInvitationView> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        require_cached_enrollment_capability(auth)?;
        let invitation_id = bounded_entity_id(invitation_id, "invitation")?;
        if req.confirm_invitation_id != invitation_id {
            return Err(AppError::bad_request(
                "the displayed invitation ID must be confirmed",
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
            let current: Option<RevokableInvitationRow> = conn
                .query_row(
                    "SELECT friendly_name, platform, created_at, expires_at,
                            redeemed_at, revoked_at
                     FROM computer_enrollment_invitations WHERE id = ?1",
                    params![invitation_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .optional()?;
            let (friendly_name, platform, created_at, expires_at, redeemed_at, revoked_at) =
                current.ok_or_else(|| AppError::not_found("invitation not found"))?;
            if redeemed_at.is_some() || revoked_at.is_some() {
                return Err(AppError::conflict(
                    "only an unredeemed invitation can be revoked",
                    Some("invitation_not_pending".into()),
                ));
            }
            let changed = conn.execute(
                "UPDATE computer_enrollment_invitations
                 SET revoked_at = ?1
                 WHERE id = ?2 AND redeemed_at IS NULL AND revoked_at IS NULL",
                params![now, invitation_id],
            )?;
            if changed != 1 {
                return Err(AppError::conflict(
                    "invitation changed before revocation",
                    Some("invitation_not_pending".into()),
                ));
            }
            crate::audit::record_successful_event(
                conn,
                auth,
                "enrollment.invitation_revoked",
                std::slice::from_ref(&invitation_id),
                "invitation_revoked",
                now,
            )?;
            Ok(EndpointInvitationView {
                id: invitation_id,
                friendly_name,
                platform,
                state: "revoked".into(),
                created_at_unix: created_at,
                expires_at_unix: expires_at,
                computer_id: None,
            })
        })
    }

    /// Public endpoint proof exchange. Invitation validation, key registration,
    /// and single-use consumption share one immediate database transaction.
    pub fn enroll_endpoint(&self, req: EndpointEnrollRequest) -> AppResult<EndpointEnrollResponse> {
        self.require_security_ok()?;
        let invitation_id = Uuid::parse_str(&req.invitation_id)
            .map_err(|_| AppError::bad_request("invitation_id must be a UUID"))?
            .to_string();
        if req.invitation_id != invitation_id {
            return Err(AppError::bad_request(
                "invitation_id must use its canonical lowercase form",
            ));
        }
        if req.enrollment_code.len() != 43
            || !req
                .enrollment_code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(AppError::unauthorized(
                "invalid or expired enrollment invitation",
            ));
        }
        let public_key = req.public_key.trim().to_ascii_lowercase();
        if public_key.len() != 64 || !public_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AppError::bad_request("public_key must be 32 bytes of hex"));
        }
        let identity = format!("key:{public_key}");
        let supplied_code_hash = hash_token(&req.enrollment_code);
        let computer_id = Uuid::new_v4().to_string();
        let now = now_unix();

        self.with_tx(|conn| {
            let invitation: Option<EndpointEnrollmentInvitationRow> = conn
                .query_row(
                    "SELECT code_hash, friendly_name, platform, expires_at, redeemed_at, revoked_at
                     FROM computer_enrollment_invitations WHERE id = ?1",
                    params![invitation_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .optional()?;
            let (stored_code_hash, friendly_name, platform, expires_at, redeemed_at, revoked_at) =
                invitation.ok_or_else(invalid_endpoint_invitation)?;
            if !token_hash_eq(&stored_code_hash, &supplied_code_hash)
                || expires_at <= now
                || redeemed_at.is_some()
                || revoked_at.is_some()
            {
                return Err(invalid_endpoint_invitation());
            }

            let deployment_id = crate::db::deployment_key(conn)?;
            let proof_message = endpoint_enrollment_proof_message(
                &deployment_id,
                &invitation_id,
                &stored_code_hash,
                &public_key,
            );
            if !verify_ed25519_strict(&public_key, &proof_message, &req.proof)? {
                return Err(AppError::unauthorized(
                    "endpoint enrollment proof is invalid",
                ));
            }

            conn.execute(
                "INSERT INTO computers (
                    id, public_identity, friendly_name, platform, enrollment_state,
                    enrollment_epoch, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, 'pending', 1, ?5, ?5)",
                params![computer_id, identity, friendly_name, platform, now],
            )
            .map_err(|err| map_unique(err, "endpoint key is already enrolled"))?;

            let consumed = conn.execute(
                "UPDATE computer_enrollment_invitations
                 SET redeemed_at = ?1, computer_id = ?2
                 WHERE id = ?3 AND code_hash = ?4 AND expires_at > ?1
                   AND redeemed_at IS NULL AND revoked_at IS NULL",
                params![now, computer_id, invitation_id, stored_code_hash],
            )?;
            if consumed != 1 {
                return Err(invalid_endpoint_invitation());
            }

            Ok(EndpointEnrollResponse {
                computer: EnrollmentComputerView {
                    id: computer_id.clone(),
                    friendly_name,
                    platform,
                    enrollment_state: "pending".into(),
                    enrollment_epoch: 1,
                    groups: Vec::new(),
                },
                state: "pending_approval",
            })
        })
    }

    /// Approve the exact pending computer currently displayed to this admin.
    /// Approval advances the enrollment epoch and binds the approved key.
    pub fn approve_computer_enrollment(
        &self,
        auth: &AuthContext,
        computer_id: &str,
        req: ComputerEnrollmentDecisionRequest,
    ) -> AppResult<EnrollmentComputerView> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        require_cached_enrollment_capability(auth)?;
        let computer_id = bounded_entity_id(computer_id, "computer")?;
        validate_computer_enrollment_decision(&computer_id, &req)?;
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
            let current: Option<(String, String, i64)> = conn
                .query_row(
                    "SELECT public_identity, enrollment_state, enrollment_epoch
                     FROM computers WHERE id = ?1",
                    params![computer_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let (identity, state, epoch) =
                current.ok_or_else(|| AppError::not_found("computer not found"))?;
            if epoch != req.expected_enrollment_epoch {
                return Err(stale_computer_enrollment());
            }
            if state != "pending" || !identity.starts_with("key:") {
                return Err(AppError::conflict(
                    "computer is not an identity-proven pending endpoint",
                    Some("computer_not_pending".into()),
                ));
            }
            let invitation_proved: bool = conn.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM computer_enrollment_invitations
                    WHERE computer_id = ?1 AND redeemed_at IS NOT NULL
                )",
                params![computer_id],
                |row| row.get(0),
            )?;
            if !invitation_proved {
                return Err(AppError::conflict(
                    "computer has no completed one-time enrollment proof",
                    Some("enrollment_proof_missing".into()),
                ));
            }
            let changed = conn.execute(
                "UPDATE computers
                 SET enrollment_state = 'enrolled', enrollment_epoch = enrollment_epoch + 1,
                     approved_incarnation_identity = public_identity, updated_at = ?1
                 WHERE id = ?2 AND enrollment_state = 'pending' AND enrollment_epoch = ?3",
                params![now, computer_id, req.expected_enrollment_epoch],
            )?;
            if changed != 1 {
                return Err(stale_computer_enrollment());
            }
            crate::audit::record_successful_event(
                conn,
                auth,
                "enrollment.computer_approved",
                std::slice::from_ref(&computer_id),
                "endpoint_enrolled",
                now,
            )?;
            load_enrollment_computer_view(conn, &computer_id)
        })
    }

    /// Revoke an endpoint and increment its fencing epoch in the same
    /// transaction that rechecks fresh administrator authority.
    pub fn revoke_computer_enrollment(
        &self,
        auth: &AuthContext,
        computer_id: &str,
        req: ComputerEnrollmentDecisionRequest,
    ) -> AppResult<EnrollmentComputerView> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        require_cached_enrollment_capability(auth)?;
        let computer_id = bounded_entity_id(computer_id, "computer")?;
        validate_computer_enrollment_decision(&computer_id, &req)?;
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
            let current_epoch: Option<i64> = conn
                .query_row(
                    "SELECT enrollment_epoch FROM computers WHERE id = ?1 AND enrollment_state <> 'revoked'",
                    params![computer_id],
                    |row| row.get(0),
                )
                .optional()?;
            let epoch = current_epoch.ok_or_else(|| {
                AppError::not_found("computer not found or already revoked")
            })?;
            if epoch != req.expected_enrollment_epoch {
                return Err(stale_computer_enrollment());
            }
            let changed = conn.execute(
                "UPDATE computers
                 SET enrollment_state = 'revoked', enrollment_epoch = enrollment_epoch + 1,
                     updated_at = ?1
                 WHERE id = ?2 AND enrollment_state <> 'revoked' AND enrollment_epoch = ?3",
                params![now, computer_id, req.expected_enrollment_epoch],
            )?;
            if changed != 1 {
                return Err(stale_computer_enrollment());
            }
            crate::file_jobs::fail_file_jobs_for_revoked_endpoint(conn, &computer_id, now)?;
            crate::audit::record_successful_event(
                conn,
                auth,
                "enrollment.computer_revoked",
                std::slice::from_ref(&computer_id),
                "endpoint_revoked",
                now,
            )?;
            load_enrollment_computer_view(conn, &computer_id)
        })
    }

    /// Group names are visible to enrollment administrators. Computer
    /// memberships are returned only alongside computers already in the
    /// caller's authorized inventory response.
    pub fn list_computer_groups(&self, auth: &AuthContext) -> AppResult<ComputerGroupListResponse> {
        self.require_security_ok()?;
        if !auth.can_manage_enrollment {
            return Err(AppError::forbidden(
                "enrollment management permission is required to list computer groups",
            ));
        }
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, name, revision FROM computer_groups
                 ORDER BY name COLLATE NOCASE ASC, id ASC LIMIT ?1",
            )?;
            let groups = stmt
                .query_map(params![MAX_COMPUTER_GROUPS as i64], map_computer_group_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ComputerGroupListResponse {
                groups,
                max_page_size: MAX_COMPUTER_GROUPS,
            })
        })
    }

    pub fn create_computer_group(
        &self,
        auth: &AuthContext,
        req: CreateComputerGroupRequest,
    ) -> AppResult<ComputerGroupView> {
        self.require_security_ok()?;
        require_cached_enrollment_capability(auth)?;
        let name = validate_computer_group_name(&req.name)?;
        let id = Uuid::new_v4().to_string();
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
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM computer_groups", [], |row| row.get(0))?;
            if count >= MAX_COMPUTER_GROUPS as i64 {
                return Err(AppError::conflict(
                    "the deployment has reached the computer group limit",
                    Some("group_limit".into()),
                ));
            }
            conn.execute(
                "INSERT INTO computer_groups (id, name, revision, created_at, updated_at)
                 VALUES (?1, ?2, 1, ?3, ?3)",
                params![id, name, now],
            )
            .map_err(|err| map_unique(err, "a computer group with this name already exists"))?;
            crate::audit::record_successful_event(
                conn,
                auth,
                "groups.created",
                std::slice::from_ref(&id),
                "group_created",
                now,
            )?;
            load_computer_group_view(conn, &id)
        })
    }

    pub fn rename_computer_group(
        &self,
        auth: &AuthContext,
        group_id: &str,
        req: RenameComputerGroupRequest,
    ) -> AppResult<ComputerGroupView> {
        self.require_security_ok()?;
        require_cached_enrollment_capability(auth)?;
        let name = validate_computer_group_name(&req.name)?;
        if req.expected_revision <= 0 || req.expected_revision == i64::MAX {
            return Err(AppError::bad_request("expected_revision is invalid"));
        }
        let group_id = bounded_entity_id(group_id, "group")?;
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
            let current = load_computer_group_view_optional(conn, &group_id)?
                .ok_or_else(|| AppError::not_found("computer group not found"))?;
            if current.revision != req.expected_revision {
                return Err(stale_group_revision());
            }
            if current.name == name {
                return Ok(current);
            }
            conn.execute(
                "UPDATE computer_groups
                 SET name = ?1, revision = revision + 1, updated_at = ?2
                 WHERE id = ?3 AND revision = ?4",
                params![name, now, group_id, req.expected_revision],
            )
            .map_err(|err| map_unique(err, "a computer group with this name already exists"))?;
            crate::audit::record_successful_event(
                conn,
                auth,
                "groups.renamed",
                std::slice::from_ref(&group_id),
                "group_renamed",
                now,
            )?;
            load_computer_group_view(conn, &group_id)
        })
    }

    /// Atomically changes one group's membership. Membership is metadata only;
    /// it never modifies the account's computer access assignments.
    pub fn set_computer_group_membership(
        &self,
        auth: &AuthContext,
        group_id: &str,
        computer_id: &str,
        req: SetComputerGroupMembershipRequest,
    ) -> AppResult<ComputerGroupView> {
        self.require_security_ok()?;
        require_cached_enrollment_capability(auth)?;
        if req.expected_revision <= 0 || req.expected_revision == i64::MAX {
            return Err(AppError::bad_request("expected_revision is invalid"));
        }
        let group_id = bounded_entity_id(group_id, "group")?;
        let computer_id = bounded_entity_id(computer_id, "computer")?;
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
            let current = load_computer_group_view_optional(conn, &group_id)?
                .ok_or_else(|| AppError::not_found("computer group not found"))?;
            if current.revision != req.expected_revision {
                return Err(stale_group_revision());
            }
            let computer_exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM computers WHERE id = ?1)",
                params![computer_id],
                |row| row.get(0),
            )?;
            if !computer_exists {
                return Err(AppError::not_found("computer not found"));
            }
            let included: bool = conn.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM computer_group_members
                    WHERE group_id = ?1 AND computer_id = ?2
                 )",
                params![group_id, computer_id],
                |row| row.get(0),
            )?;
            if included == req.included {
                return Ok(current);
            }
            if req.included {
                conn.execute(
                    "INSERT INTO computer_group_members (group_id, computer_id)
                     VALUES (?1, ?2)",
                    params![group_id, computer_id],
                )?;
            } else {
                conn.execute(
                    "DELETE FROM computer_group_members
                     WHERE group_id = ?1 AND computer_id = ?2",
                    params![group_id, computer_id],
                )?;
            }
            let changed = conn.execute(
                "UPDATE computer_groups
                 SET revision = revision + 1, updated_at = ?1
                 WHERE id = ?2 AND revision = ?3",
                params![now, group_id, req.expected_revision],
            )?;
            if changed != 1 {
                return Err(stale_group_revision());
            }
            crate::audit::record_successful_event(
                conn,
                auth,
                "groups.membership_updated",
                &[group_id.clone(), computer_id.clone()],
                if req.included {
                    "computer_included"
                } else {
                    "computer_excluded"
                },
                now,
            )?;
            load_computer_group_view(conn, &group_id)
        })
    }

    pub fn delete_computer_group(
        &self,
        auth: &AuthContext,
        group_id: &str,
        req: DeleteComputerGroupRequest,
    ) -> AppResult<()> {
        self.require_security_ok()?;
        require_cached_enrollment_capability(auth)?;
        let group_id = bounded_entity_id(group_id, "group")?;
        if req.expected_revision <= 0
            || req.confirm_group_id.len() > 128
            || req.confirm_group_id != group_id
        {
            return Err(AppError::bad_request(
                "the displayed group ID and current revision must be confirmed",
            ));
        }
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
            let current = load_computer_group_view_optional(conn, &group_id)?
                .ok_or_else(|| AppError::not_found("computer group not found"))?;
            if current.revision != req.expected_revision {
                return Err(stale_group_revision());
            }
            let changed = conn.execute(
                "DELETE FROM computer_groups WHERE id = ?1 AND revision = ?2",
                params![group_id, req.expected_revision],
            )?;
            if changed != 1 {
                return Err(stale_group_revision());
            }
            crate::audit::record_successful_event(
                conn,
                auth,
                "groups.deleted",
                std::slice::from_ref(&group_id),
                "group_deleted",
                now,
            )?;
            Ok(())
        })
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
        self.grant_access_inner(auth, req, false)
    }

    /// v2 access changes require a current approved Manager session and recent MFA.
    pub(crate) fn grant_access_v2(
        &self,
        auth: &AuthContext,
        req: GrantAccessRequest,
    ) -> AppResult<AccessAssignmentView> {
        self.require_persisted_v2_credentials()?;
        self.grant_access_inner(auth, req, true)
    }

    /// v2 access revocation requires a current approved Manager session,
    /// recent MFA, explicit confirmation, and the assignment revision shown
    /// to the administrator.
    pub(crate) fn revoke_access_v2(
        &self,
        auth: &AuthContext,
        assignment_id: &str,
        req: RevokeAccessRequest,
    ) -> AppResult<AccessRevocationResponse> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        if !auth.can_manage_access {
            return Err(AppError::forbidden(
                "access management permission is required to revoke assignments",
            ));
        }
        if assignment_id.is_empty() || assignment_id.len() > 128 {
            return Err(AppError::bad_request("access assignment id is invalid"));
        }
        if req.expected_revision < 1 {
            return Err(AppError::bad_request("expected_revision must be positive"));
        }
        if !req.confirm {
            return Err(AppError::bad_request(
                "confirm must be true to revoke a computer access assignment",
            ));
        }

        let now = now_unix();
        let target = assignment_id.to_string();
        let outcome = self.with_tx(|conn| {
            require_current_admin_session(conn, auth, AdminCapability::Access, now, true, true)?;
            let current: Option<(String, String, i64)> = conn
                .query_row(
                    "SELECT account_id, capability, revision
                     FROM access_assignments WHERE id = ?1",
                    params![target],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let (account_id, capability, current_revision) =
                current.ok_or_else(|| AppError::not_found("access assignment not found"))?;
            if current_revision != req.expected_revision {
                return Err(AppError::conflict(
                    "access assignment revision changed; refresh before retrying",
                    Some("revision_changed".to_string()),
                ));
            }
            conn.execute(
                "DELETE FROM access_computer_scope WHERE assignment_id = ?1",
                params![target],
            )?;
            let changed = conn.execute(
                "DELETE FROM access_assignments WHERE id = ?1 AND revision = ?2",
                params![target, req.expected_revision],
            )?;
            if changed != 1 {
                return Err(AppError::conflict(
                    "access assignment changed during revocation",
                    Some("revision_changed".to_string()),
                ));
            }
            crate::audit::record_successful_event(
                conn,
                auth,
                "access.revoked",
                &[target.clone(), account_id.clone()],
                &format!("capability_{capability}"),
                now,
            )?;
            Ok((account_id, capability))
        })?;

        Ok(AccessRevocationResponse {
            id: target,
            account_id: outcome.0,
            capability: outcome.1,
            state: "revoked".to_string(),
            revoked_revision: req.expected_revision,
        })
    }

    fn grant_access_inner(
        &self,
        auth: &AuthContext,
        req: GrantAccessRequest,
        require_fresh_mfa: bool,
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
        if req.account_id.is_empty() || req.account_id.len() > 128 {
            return Err(AppError::bad_request("account_id is invalid"));
        }
        let unique_computers: HashSet<&str> = req.computer_ids.iter().map(String::as_str).collect();
        if unique_computers.len() != req.computer_ids.len()
            || req
                .computer_ids
                .iter()
                .any(|id| id.is_empty() || id.len() > 128)
        {
            return Err(AppError::bad_request(
                "computer_ids must be unique valid identifiers",
            ));
        }

        let id = Uuid::new_v4().to_string();
        let now = now_unix();
        let account_id = req.account_id.clone();
        let computer_ids = req.computer_ids.clone();
        let scope_all = req.computer_scope_all;

        let outcome = self.with_tx(|conn| {
            if require_fresh_mfa {
                require_current_admin_session(
                    conn,
                    auth,
                    AdminCapability::Access,
                    now,
                    true,
                    true,
                )?;
            }
            let account_state: Option<String> = conn
                .query_row(
                    "SELECT state FROM accounts WHERE id = ?1",
                    params![account_id],
                    |row| row.get(0),
                )
                .optional()?;
            let account_state = account_state
                .ok_or_else(|| AppError::not_found("target account not found"))?;
            if account_state != "active" {
                return Err(AppError::forbidden("target account is not active"));
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
            let mut targets = Vec::with_capacity(computer_ids.len() + 2);
            targets.push(assignment_id.clone());
            targets.push(account_id.clone());
            targets.extend(computer_ids.iter().cloned());
            crate::audit::record_successful_event(
                conn,
                auth,
                "access.granted",
                &targets,
                &format!("capability_{capability}"),
                now,
            )?;
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
                "SELECT id, username, state, recovery_quarantined, can_operate,
                        can_manage_enrollment, can_manage_access, can_manage_accounts,
                        can_manage_security, revision
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
            let mut row = conn.query_row(
                "SELECT id, public_identity, friendly_name, platform, enrollment_state, enrollment_epoch
                 FROM computers WHERE id = ?1",
                params![computer_id],
                map_computer_row,
            )?;
            let group_map = load_computer_group_refs(conn, &[computer_id.to_string()])?;
            row.groups = group_map.get(computer_id).cloned().unwrap_or_default();
            Ok(row)
        })
    }

    fn load_assignment_view(&self, assignment_id: &str) -> AppResult<AccessAssignmentView> {
        self.with_conn(|conn| {
            let (id, account_id, capability, computer_scope_all, revision) = conn.query_row(
                "SELECT id, account_id, capability, computer_scope_all, revision
                 FROM access_assignments WHERE id = ?1",
                params![assignment_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, i64>(4)?,
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
                account_id,
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

/// Recheck a bearer session and its current account authority in the same
/// transaction as a privileged write. Cached claims in `AuthContext` are only
/// an early routing decision; the database state owns the final decision.
pub(crate) fn require_current_admin_session(
    conn: &Connection,
    auth: &AuthContext,
    capability: AdminCapability,
    now: i64,
    require_fresh_mfa: bool,
    require_manager_key: bool,
) -> AppResult<()> {
    require_current_admin_session_inner(
        conn,
        auth,
        capability,
        now,
        require_fresh_mfa,
        require_manager_key,
        false,
    )
}

pub(crate) fn require_current_recovery_admin_session(
    conn: &Connection,
    auth: &AuthContext,
    capability: AdminCapability,
    now: i64,
    require_fresh_mfa: bool,
    require_manager_key: bool,
) -> AppResult<()> {
    require_current_admin_session_inner(
        conn,
        auth,
        capability,
        now,
        require_fresh_mfa,
        require_manager_key,
        true,
    )
}

fn require_current_admin_session_inner(
    conn: &Connection,
    auth: &AuthContext,
    capability: AdminCapability,
    now: i64,
    require_fresh_mfa: bool,
    require_manager_key: bool,
    allow_recovery_quarantine: bool,
) -> AppResult<()> {
    if !allow_recovery_quarantine {
        let (recovery_quarantined, authority_state): (bool, String) = conn.query_row(
            "SELECT recovery_quarantined, authority_state FROM deployment WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if recovery_quarantined {
            return Err(AppError::forbidden(
                "restored deployment is quarantined; review and explicitly release recovery first",
            ));
        }
        if authority_state != "active" {
            return Err(AppError::forbidden(
                "authority is not Active; ordinary authorization is paused during cutover",
            ));
        }
    }

    let row: Option<CurrentAdminSessionRow> = conn
        .query_row(
            "SELECT s.account_id, s.expires_at, s.revoked_at, s.manager_id,
                    s.assurance, s.mfa_assured_at, a.state,
                    a.can_manage_enrollment, a.can_manage_accounts, a.can_manage_access,
                    a.can_manage_security
             FROM sessions s JOIN accounts a ON a.id = s.account_id
             WHERE s.id = ?1",
            params![auth.session_id],
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
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )
        .optional()?;
    let (
        account_id,
        expires_at,
        revoked_at,
        manager_id,
        assurance,
        mfa_assured_at,
        account_state,
        can_manage_enrollment,
        can_manage_accounts,
        can_manage_access,
        can_manage_security,
    ) = row.ok_or_else(|| AppError::unauthorized("invalid session"))?;
    if account_id != auth.account_id || revoked_at.is_some() || expires_at <= now {
        return Err(AppError::unauthorized("session is no longer active"));
    }
    if account_state != "active" {
        return Err(AppError::forbidden("account is not active"));
    }
    let has_capability = match capability {
        AdminCapability::Enrollment => can_manage_enrollment,
        AdminCapability::Accounts => can_manage_accounts,
        AdminCapability::Access => can_manage_access,
        AdminCapability::Security => can_manage_security,
    };
    if !has_capability {
        return Err(AppError::forbidden(
            "required account management permission is missing",
        ));
    }

    let manager_id = match manager_id {
        Some(id) => id,
        None if require_manager_key => {
            return Err(AppError::forbidden(
                "an approved manager device session is required",
            ));
        }
        None => String::new(),
    };
    if !manager_id.is_empty() {
        let manager: Option<(String, Option<String>)> = conn
            .query_row(
                "SELECT lifecycle_state, public_key FROM managers WHERE id = ?1",
                params![manager_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match manager {
            Some((state, public_key))
                if state == "approved" && (!require_manager_key || public_key.is_some()) => {}
            _ => {
                return Err(AppError::forbidden(
                    "manager identity is no longer approved",
                ))
            }
        }
    }

    if account_has_mfa_requirement(conn, &account_id)?
        && (assurance != "mfa" || mfa_assured_at.is_none())
    {
        return Err(mfa_required_error());
    }
    if require_fresh_mfa
        && (assurance != "mfa"
            || mfa_assured_at
                .map(|at| at < now - crate::auth_v2::POLICY_MUTATION_MFA_FRESH_SECS || at > now)
                .unwrap_or(true))
    {
        return Err(AppError::forbidden(
            "fresh multi-factor authentication is required for this change",
        ));
    }
    Ok(())
}

/// Recheck that a session still belongs to an active account and approved
/// key-bearing Manager before allowing the account holder to enroll MFA.
pub(crate) fn require_current_manager_session(
    conn: &Connection,
    auth: &AuthContext,
    now: i64,
) -> AppResult<()> {
    let recovery_quarantined: bool = conn.query_row(
        "SELECT recovery_quarantined FROM deployment WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    if recovery_quarantined {
        return Err(AppError::forbidden(
            "restored deployment is quarantined; review and explicitly release recovery first",
        ));
    }
    let row: Option<CurrentManagerSessionRow> = conn
        .query_row(
            "SELECT s.account_id, s.expires_at, s.revoked_at, a.state,
                    m.lifecycle_state, m.public_key
             FROM sessions s
             JOIN accounts a ON a.id = s.account_id
             LEFT JOIN managers m ON m.id = s.manager_id
             WHERE s.id = ?1",
            params![auth.session_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let (account_id, expires_at, revoked_at, account_state, manager_state, public_key) =
        row.ok_or_else(|| AppError::unauthorized("invalid session"))?;
    if account_id != auth.account_id || revoked_at.is_some() || expires_at <= now {
        return Err(AppError::unauthorized("session is no longer active"));
    }
    if account_state != "active" {
        return Err(AppError::forbidden("account is not active"));
    }
    if manager_state.as_deref() != Some("approved") || public_key.is_none() {
        return Err(AppError::forbidden(
            "an approved key-bearing Manager session is required",
        ));
    }
    Ok(())
}

type CurrentOperatorSessionRow = (
    String,
    i64,
    Option<i64>,
    Option<String>,
    String,
    Option<i64>,
    String,
    bool,
    Option<String>,
    Option<String>,
);

/// Recheck current operator authority for queued endpoint work. The caller
/// still verifies a capability-specific computer assignment in the same
/// transaction before committing each job action.
pub(crate) fn require_current_operator_session(
    conn: &Connection,
    auth: &AuthContext,
    now: i64,
) -> AppResult<()> {
    let (recovery_quarantined, authority_state): (bool, String) = conn.query_row(
        "SELECT recovery_quarantined, authority_state FROM deployment WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if recovery_quarantined {
        return Err(AppError::forbidden(
            "restored deployment is quarantined; review and explicitly release recovery first",
        ));
    }
    if authority_state != "active" {
        return Err(AppError::forbidden(
            "authority is not Active; operator operations are paused during cutover",
        ));
    }

    let row: Option<CurrentOperatorSessionRow> = conn
        .query_row(
            "SELECT s.account_id, s.expires_at, s.revoked_at, s.manager_id,
                    s.assurance, s.mfa_assured_at, a.state, a.can_operate,
                    m.lifecycle_state, m.public_key
             FROM sessions s
             JOIN accounts a ON a.id = s.account_id
             LEFT JOIN managers m ON m.id = s.manager_id
             WHERE s.id = ?1",
            params![auth.session_id],
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
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .optional()?;
    let Some((
        account_id,
        expires_at,
        revoked_at,
        manager_id,
        assurance,
        mfa_assured_at,
        account_state,
        can_operate,
        manager_state,
        manager_public_key,
    )) = row
    else {
        return Err(AppError::unauthorized("invalid session"));
    };
    if account_id != auth.account_id || revoked_at.is_some() || expires_at <= now {
        return Err(AppError::unauthorized("session is no longer active"));
    }
    if account_state != "active" {
        return Err(AppError::forbidden("account is not active"));
    }
    if !can_operate {
        return Err(AppError::forbidden(
            "computer operation permission is required",
        ));
    }
    if manager_id.is_none()
        || manager_state.as_deref() != Some("approved")
        || manager_public_key.is_none()
    {
        return Err(AppError::forbidden(
            "an approved key-bearing Manager session is required",
        ));
    }
    if account_has_mfa_requirement(conn, &account_id)?
        && (assurance != "mfa" || mfa_assured_at.is_none())
    {
        return Err(mfa_required_error());
    }
    Ok(())
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

fn require_cached_enrollment_capability(auth: &AuthContext) -> AppResult<()> {
    if auth.can_manage_enrollment {
        Ok(())
    } else {
        Err(AppError::forbidden(
            "enrollment management permission is required to change computer groups",
        ))
    }
}

fn validate_computer_group_name(value: &str) -> AppResult<String> {
    let name = value.trim();
    let character_count = name.chars().count();
    if character_count == 0 || character_count > 64 || name.chars().any(char::is_control) {
        return Err(AppError::bad_request(
            "computer group name must contain 1 to 64 non-control characters",
        ));
    }
    Ok(name.to_string())
}

fn bounded_entity_id(value: &str, kind: &str) -> AppResult<String> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(AppError::bad_request(format!("{kind} ID is invalid")));
    }
    Ok(value.to_string())
}

fn stale_group_revision() -> AppError {
    AppError::conflict(
        "computer group changed; reload it before retrying",
        Some("stale_revision".into()),
    )
}

fn load_computer_group_view(conn: &Connection, group_id: &str) -> AppResult<ComputerGroupView> {
    load_computer_group_view_optional(conn, group_id)?
        .ok_or_else(|| AppError::not_found("computer group not found"))
}

fn load_computer_group_view_optional(
    conn: &Connection,
    group_id: &str,
) -> AppResult<Option<ComputerGroupView>> {
    conn.query_row(
        "SELECT id, name, revision FROM computer_groups WHERE id = ?1",
        params![group_id],
        map_computer_group_row,
    )
    .optional()
    .map_err(AppError::Storage)
}

/// Load membership labels only for a bounded set of already-authorized
/// computer IDs. The global group cap bounds the maximum result to 10,000
/// rows; no unauthorized computer ID enters this query from the request.
fn load_computer_group_refs(
    conn: &Connection,
    computer_ids: &[String],
) -> AppResult<HashMap<String, Vec<ComputerGroupRef>>> {
    let mut result = computer_ids
        .iter()
        .map(|id| (id.clone(), Vec::new()))
        .collect::<HashMap<_, _>>();
    if computer_ids.is_empty() {
        return Ok(result);
    }
    let placeholders = (1..=computer_ids.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT member.computer_id, groups.id, groups.name
         FROM computer_group_members AS member
         JOIN computer_groups AS groups ON groups.id = member.group_id
         WHERE member.computer_id IN ({placeholders})
         ORDER BY member.computer_id ASC, groups.name COLLATE NOCASE ASC, groups.id ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(computer_ids.iter()), |row| {
        Ok((
            row.get::<_, String>(0)?,
            ComputerGroupRef {
                id: row.get(1)?,
                name: row.get(2)?,
            },
        ))
    })?;
    for row in rows {
        let (computer_id, group) = row?;
        if let Some(groups) = result.get_mut(&computer_id) {
            groups.push(group);
        }
    }
    Ok(result)
}

fn map_account_row(row: &Row<'_>) -> rusqlite::Result<AccountView> {
    Ok(AccountView {
        id: row.get(0)?,
        username: row.get(1)?,
        state: row.get(2)?,
        recovery_quarantined: row.get(3)?,
        capabilities: AccountCapabilities {
            operate: row.get(4)?,
            manage_enrollment: row.get(5)?,
            manage_access: row.get(6)?,
            manage_accounts: row.get(7)?,
            manage_security: row.get(8)?,
        },
        revision: row.get(9)?,
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
        groups: Vec::new(),
        endpoint_session: None,
    })
}

fn map_enrollment_computer_row(row: &Row<'_>) -> rusqlite::Result<EnrollmentComputerView> {
    Ok(EnrollmentComputerView {
        id: row.get(0)?,
        friendly_name: row.get(1)?,
        platform: row.get(2)?,
        enrollment_state: row.get(3)?,
        enrollment_epoch: row.get(4)?,
        groups: Vec::new(),
    })
}

fn load_enrollment_computer_view(
    conn: &Connection,
    computer_id: &str,
) -> AppResult<EnrollmentComputerView> {
    let mut computer = conn.query_row(
        "SELECT id, friendly_name, platform, enrollment_state, enrollment_epoch
         FROM computers WHERE id = ?1",
        params![computer_id],
        map_enrollment_computer_row,
    )?;
    let groups = load_computer_group_refs(conn, std::slice::from_ref(&computer.id))?;
    computer.groups = groups.get(&computer.id).cloned().unwrap_or_default();
    Ok(computer)
}

fn validate_computer_enrollment_decision(
    computer_id: &str,
    req: &ComputerEnrollmentDecisionRequest,
) -> AppResult<()> {
    if req.expected_enrollment_epoch <= 0 || req.expected_enrollment_epoch == i64::MAX {
        return Err(AppError::bad_request(
            "expected_enrollment_epoch is invalid",
        ));
    }
    if req.confirm_computer_id != computer_id {
        return Err(AppError::bad_request(
            "the displayed computer ID and current enrollment epoch must be confirmed",
        ));
    }
    Ok(())
}

fn invalid_endpoint_invitation() -> AppError {
    AppError::unauthorized("invalid or expired enrollment invitation")
}

fn stale_computer_enrollment() -> AppError {
    AppError::conflict(
        "computer enrollment changed; reload it before retrying",
        Some("stale_enrollment_epoch".into()),
    )
}

fn map_computer_group_row(row: &Row<'_>) -> rusqlite::Result<ComputerGroupView> {
    Ok(ComputerGroupView {
        id: row.get(0)?,
        name: row.get(1)?,
        revision: row.get(2)?,
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
    fn bootstrap_token_issuance_rechecks_durable_security_latch() {
        let db = crate::db::open_in_memory().expect("db");
        let service = Service::new(db);
        assert_eq!(service.security_state(), SecurityState::Ok);

        {
            let conn = service.db_handle().lock().expect("lock");
            conn.execute(
                "UPDATE deployment SET security_state_ok = 0 WHERE id = 1",
                [],
            )
            .expect("latch durable state");
        }

        let error = service
            .create_bootstrap_token()
            .expect_err("latched durable state must not issue a token");
        assert!(matches!(
            error,
            AppError::Api {
                code: crate::error::ErrorCode::SecurityStateUnavailable,
                ..
            }
        ));
        assert_eq!(service.security_state(), SecurityState::Unavailable);

        let conn = service.db_handle().lock().expect("lock");
        let token_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM bootstrap_tokens", [], |row| {
                row.get(0)
            })
            .expect("token count");
        assert_eq!(
            token_count, 0,
            "no token may be inserted into a latched store"
        );
    }

    #[test]
    fn security_state_ok_one_hydrates_ok() {
        let db = crate::db::open_in_memory().expect("db");
        let service = Service::new(db);
        assert_eq!(service.security_state(), SecurityState::Ok);
    }
}
