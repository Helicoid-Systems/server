//! Durable reservation boundary for shared interaction transitions.
//!
//! This module persists a server-owned per-computer revision and interaction
//! claim after rechecking the current operator session and operation-specific
//! access assignment in the same immediate transaction. A reservation is not
//! endpoint admission, a signed grant, or proof that capture/input has started.
//! Network authority remains gated on the separately frozen E03 protocol.

use hs_core::{
    plan_transition, AccountId, ComputerId, InteractionClaim, InteractionId, InteractionKind,
    InteractionState, ManagerId, OperationFingerprint, TransitionActor, TransitionDisposition,
    TransitionOperation, TransitionPlan, TransitionRequest,
};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::db::now_unix;
use crate::error::{AppError, AppResult};
use crate::service::{require_current_operator_session, AuthContext, Service};

/// An authenticated operation passed from a server-owned adapter into the
/// transition planner. The server derives its stable-ID replay fingerprint
/// from the typed operation and target; callers cannot choose it.
#[derive(Debug, Clone)]
pub struct InteractionTransitionInput {
    pub operation: TransitionOperation,
    pub computer_id: String,
    pub expected_revision: u64,
}

/// Planned transition and whether a new durable claim was reserved.
#[derive(Debug, Clone)]
pub struct InteractionTransitionResult {
    pub plan: TransitionPlan,
    pub current_revision: u64,
    pub reservation_created: bool,
}

type StoredClaim = (
    String,
    Vec<u8>,
    String,
    String,
    String,
    String,
    String,
    String,
);

impl Service {
    /// Plan one interaction against durable state and reserve it atomically
    /// only when the shared planner returns `Proceed`.
    ///
    /// Review-required transitions are returned without side effects. This
    /// method does not accept a confirmation flag: reviewed-plan digests and
    /// exact consequence confirmation belong to the versioned network
    /// contract, which is still gated by E03.
    pub fn reserve_interaction_transition(
        &self,
        auth: &AuthContext,
        input: InteractionTransitionInput,
    ) -> AppResult<InteractionTransitionResult> {
        self.require_security_ok()?;
        if matches!(&input.operation, TransitionOperation::MachineAction(_, _)) {
            return Err(AppError::not_implemented(
                "machine actions require the durable action journal and reconciliation contract",
            ));
        }

        let interaction_id = operation_interaction_id(&input.operation)
            .ok_or_else(|| AppError::bad_request("interaction operation has no interaction ID"))?;
        let interaction_kind = operation_interaction_kind(&input.operation)
            .ok_or_else(|| AppError::bad_request("unsupported interaction operation"))?;
        let required_capability = operation_capability(&input.operation)?;
        let computer_id = ComputerId::new(input.computer_id.clone())
            .map_err(|_| AppError::bad_request("computer_id is invalid"))?;
        let operation_fingerprint =
            canonical_operation_fingerprint(&input.operation, &computer_id)?;
        let now = now_unix();

        self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            require_current_interaction_scope(
                conn,
                &auth.account_id,
                &input.computer_id,
                required_capability,
            )?;

            // Derive the actor from the live session row in this transaction.
            let session_manager: Option<String> = conn.query_row(
                "SELECT manager_id FROM sessions WHERE id = ?1 AND account_id = ?2",
                params![auth.session_id, auth.account_id],
                |row| row.get(0),
            )?;
            let Some(session_manager) = session_manager else {
                return Err(AppError::unauthorized("invalid manager session"));
            };
            if auth.manager_id.as_deref() != Some(session_manager.as_str()) {
                return Err(AppError::unauthorized("manager session identity changed"));
            }

            let owner_account_id = AccountId::new(auth.account_id.clone())
                .map_err(|_| AppError::unprocessable("stored account identity is invalid"))?;
            let owner_manager_id = ManagerId::new(session_manager.clone())
                .map_err(|_| AppError::unprocessable("stored manager identity is invalid"))?;

            let stored_revision: Option<i64> = conn
                .query_row(
                    "SELECT revision FROM computer_interaction_revisions WHERE computer_id = ?1",
                    params![input.computer_id],
                    |row| row.get(0),
                )
                .optional()?;
            let current_revision = stored_revision.unwrap_or(0);
            let current_revision = u64::try_from(current_revision)
                .map_err(|_| AppError::unprocessable("stored interaction revision is invalid"))?;

            let existing_on_other_computer: bool = conn.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM interaction_claims
                    WHERE id = ?1 AND computer_id <> ?2
                 )",
                params![interaction_id.as_str(), input.computer_id],
                |row| row.get(0),
            )?;
            let claims =
                load_interaction_claims(conn, &input.computer_id, interaction_id.as_str())?;
            let exact_active_replay = claims.iter().any(|claim| {
                &claim.id == interaction_id
                    && claim.owner_account_id == owner_account_id
                    && claim.owner_manager_id == owner_manager_id
                    && claim.kind == interaction_kind
                    && claim.operation_fingerprint == operation_fingerprint
                    && !matches!(
                        claim.state,
                        InteractionState::Ended | InteractionState::Failed
                    )
            });

            let request = TransitionRequest {
                operation: input.operation.clone(),
                operation_fingerprint,
                actor: TransitionActor {
                    account_id: owner_account_id.clone(),
                    manager_id: owner_manager_id.clone(),
                },
                computer_id: computer_id.clone(),
                operation_permitted: true,
                // No capability currently grants scoped IT stop authority.
                // Foreign claims therefore remain protected by the planner.
                scoped_it_stop: false,
                // A caller retrying the exact same still-active stable ID may
                // retrieve its existing reservation after losing the first
                // response, even though that reservation advanced the revision.
                expected_revision: if exact_active_replay {
                    current_revision
                } else {
                    input.expected_revision
                },
            };
            let mut plan = plan_transition(request, current_revision, &claims, None);
            if existing_on_other_computer
                && matches!(
                    plan.disposition,
                    TransitionDisposition::Proceed | TransitionDisposition::ReuseExisting
                )
            {
                plan.disposition = TransitionDisposition::Refused(hs_core::ReasonCode::Replayed);
                plan.impacts.clear();
            }

            let mut reservation_created = false;
            let result_revision = if plan.disposition == TransitionDisposition::Proceed {
                let next_revision = current_revision
                    .checked_add(1)
                    .filter(|value| *value <= i64::MAX as u64)
                    .ok_or_else(|| {
                        AppError::conflict(
                            "interaction revision is exhausted",
                            Some("revision_exhausted".to_string()),
                        )
                    })?;
                let affected_computers = serde_json::to_string(&Vec::<String>::new())
                    .map_err(|_| AppError::internal("could not encode interaction recipients"))?;
                conn.execute(
                    "INSERT INTO interaction_claims (
                        id, computer_id, owner_account_id, owner_manager_id, kind,
                        operation_fingerprint, state, affected_computer_ids_json,
                        created_at, updated_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'requested', ?7, ?8, ?8)",
                    params![
                        interaction_id.as_str(),
                        input.computer_id,
                        owner_account_id.as_str(),
                        owner_manager_id.as_str(),
                        interaction_kind_to_db(interaction_kind)?,
                        &operation_fingerprint.0[..],
                        affected_computers,
                        now,
                    ],
                )?;
                if stored_revision.is_none() {
                    conn.execute(
                        "INSERT INTO computer_interaction_revisions (computer_id, revision)
                         VALUES (?1, ?2)",
                        params![input.computer_id, next_revision as i64],
                    )?;
                } else {
                    let changed = conn.execute(
                        "UPDATE computer_interaction_revisions SET revision = ?1
                         WHERE computer_id = ?2 AND revision = ?3",
                        params![
                            next_revision as i64,
                            input.computer_id,
                            current_revision as i64
                        ],
                    )?;
                    if changed != 1 {
                        return Err(AppError::conflict(
                            "interaction state changed; refresh and retry",
                            Some("conflict_changed".to_string()),
                        ));
                    }
                }
                reservation_created = true;
                let action = match interaction_kind {
                    InteractionKind::Observation => "interaction.observation_reserved",
                    InteractionKind::Control => "interaction.control_reserved",
                    InteractionKind::ShareSource => "interaction.share_source_reserved",
                    InteractionKind::ShareReceiver => "interaction.share_receiver_reserved",
                    InteractionKind::Attention => "interaction.attention_reserved",
                    _ => {
                        return Err(AppError::not_implemented(
                            "this interaction kind is not supported by the audit contract",
                        ));
                    }
                };
                crate::audit::record_successful_event(
                    conn,
                    auth,
                    action,
                    &[interaction_id.to_string(), input.computer_id.clone()],
                    "transition_reserved",
                    now,
                )?;
                next_revision
            } else {
                current_revision
            };

            Ok(InteractionTransitionResult {
                plan,
                current_revision: result_revision,
                reservation_created,
            })
        })
    }
}

fn operation_interaction_id(operation: &TransitionOperation) -> Option<&InteractionId> {
    match operation {
        TransitionOperation::Observe(id)
        | TransitionOperation::TakeControl(id)
        | TransitionOperation::ShareSource(id)
        | TransitionOperation::ShareReceiver(id)
        | TransitionOperation::Attention(id) => Some(id),
        TransitionOperation::MachineAction(_, _) => None,
    }
}

/// Hash the exact server-accepted typed operation and computer using a small,
/// versioned binary encoding. This digest is an internal replay key; it is not
/// a signed grant or an admission credential.
fn canonical_operation_fingerprint(
    operation: &TransitionOperation,
    computer_id: &ComputerId,
) -> AppResult<OperationFingerprint> {
    let (opcode, interaction_id) = match operation {
        TransitionOperation::Observe(id) => (1u8, id),
        TransitionOperation::TakeControl(id) => (2u8, id),
        TransitionOperation::ShareSource(id) => (3u8, id),
        TransitionOperation::ShareReceiver(id) => (4u8, id),
        TransitionOperation::Attention(id) => (5u8, id),
        TransitionOperation::MachineAction(_, _) => {
            return Err(AppError::not_implemented(
                "machine actions require the durable action journal and reconciliation contract",
            ));
        }
    };

    let mut bytes = Vec::with_capacity(300);
    bytes.extend_from_slice(b"hs-interaction-operation-v1\0");
    bytes.push(opcode);
    append_fingerprint_field(&mut bytes, computer_id.as_str())?;
    append_fingerprint_field(&mut bytes, interaction_id.as_str())?;
    Ok(OperationFingerprint(Sha256::digest(bytes).into()))
}

fn append_fingerprint_field(bytes: &mut Vec<u8>, value: &str) -> AppResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| AppError::bad_request("interaction operation field is too long"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn operation_interaction_kind(operation: &TransitionOperation) -> Option<InteractionKind> {
    match operation {
        TransitionOperation::Observe(_) => Some(InteractionKind::Observation),
        TransitionOperation::TakeControl(_) => Some(InteractionKind::Control),
        TransitionOperation::ShareSource(_) => Some(InteractionKind::ShareSource),
        TransitionOperation::ShareReceiver(_) => Some(InteractionKind::ShareReceiver),
        TransitionOperation::Attention(_) => Some(InteractionKind::Attention),
        TransitionOperation::MachineAction(_, _) => None,
    }
}

fn operation_capability(operation: &TransitionOperation) -> AppResult<&'static str> {
    match operation {
        TransitionOperation::Observe(_) => Ok("observe"),
        TransitionOperation::TakeControl(_)
        | TransitionOperation::ShareSource(_)
        | TransitionOperation::ShareReceiver(_)
        | TransitionOperation::Attention(_) => Ok("operate"),
        TransitionOperation::MachineAction(_, _) => Err(AppError::not_implemented(
            "machine actions require the durable action journal and reconciliation contract",
        )),
    }
}

pub(crate) fn require_current_interaction_scope(
    conn: &Connection,
    account_id: &str,
    computer_id: &str,
    capability: &str,
) -> AppResult<()> {
    if !matches!(capability, "observe" | "operate") {
        return Err(AppError::internal("unsupported interaction capability"));
    }
    let assignment: Option<(String, bool)> = conn
        .query_row(
            "SELECT id, computer_scope_all FROM access_assignments
             WHERE account_id = ?1 AND capability = ?2",
            params![account_id, capability],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((assignment_id, scope_all)) = assignment else {
        let message = match capability {
            "observe" => "observe access is required",
            "operate" => "operate access is required",
            _ => return Err(AppError::internal("unsupported interaction capability")),
        };
        return Err(AppError::forbidden(message));
    };
    let in_scope: bool = if scope_all {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM computers WHERE id = ?1 AND enrollment_state = 'enrolled')",
            params![computer_id],
            |row| row.get(0),
        )?
    } else {
        conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM access_computer_scope s
                JOIN computers c ON c.id = s.computer_id
                WHERE s.assignment_id = ?1 AND s.computer_id = ?2
                  AND c.enrollment_state = 'enrolled'
             )",
            params![assignment_id, computer_id],
            |row| row.get(0),
        )?
    };
    if !in_scope {
        let message = match capability {
            "observe" => "computer is outside the observe assignment or is not enrolled",
            "operate" => "computer is outside the operate assignment or is not enrolled",
            _ => return Err(AppError::internal("unsupported interaction capability")),
        };
        return Err(AppError::forbidden(message));
    }
    Ok(())
}

fn load_interaction_claims(
    conn: &Connection,
    computer_id: &str,
    requested_id: &str,
) -> AppResult<Vec<InteractionClaim>> {
    let mut statement = conn.prepare(
        "SELECT id, operation_fingerprint, kind, owner_account_id, owner_manager_id,
                affected_computer_ids_json, state, computer_id
         FROM interaction_claims
         WHERE computer_id = ?1 AND (state NOT IN ('ended', 'failed') OR id = ?2)
         ORDER BY created_at ASC, id ASC LIMIT ?3",
    )?;
    let stored: Vec<StoredClaim> = statement
        .query_map(
            params![
                computer_id,
                requested_id,
                (hs_core::bounds::MAX_INTERACTION_CLAIMS_PER_COMPUTER + 1) as i64
            ],
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
        )?
        .collect::<Result<_, _>>()?;

    stored
        .into_iter()
        .map(
            |(
                id,
                fingerprint,
                kind,
                owner_account_id,
                owner_manager_id,
                affected_json,
                state,
                computer_id,
            )| {
                let fingerprint: [u8; 32] = fingerprint.try_into().map_err(|_| {
                    AppError::unprocessable("stored interaction fingerprint is invalid")
                })?;
                let affected_ids: Vec<String> =
                    serde_json::from_str(&affected_json).map_err(|_| {
                        AppError::unprocessable("stored interaction recipients are invalid")
                    })?;
                Ok(InteractionClaim {
                    id: InteractionId::new(id).map_err(|_| {
                        AppError::unprocessable("stored interaction identity is invalid")
                    })?,
                    operation_fingerprint: OperationFingerprint(fingerprint),
                    kind: interaction_kind_from_db(&kind)?,
                    owner_account_id: AccountId::new(owner_account_id).map_err(|_| {
                        AppError::unprocessable("stored account identity is invalid")
                    })?,
                    owner_manager_id: ManagerId::new(owner_manager_id).map_err(|_| {
                        AppError::unprocessable("stored manager identity is invalid")
                    })?,
                    computer_id: ComputerId::new(computer_id).map_err(|_| {
                        AppError::unprocessable("stored computer identity is invalid")
                    })?,
                    affected_computer_ids: affected_ids
                        .into_iter()
                        .map(|id| {
                            ComputerId::new(id).map_err(|_| {
                                AppError::unprocessable("stored recipient identity is invalid")
                            })
                        })
                        .collect::<AppResult<Vec<_>>>()?,
                    state: interaction_state_from_db(&state)?,
                })
            },
        )
        .collect()
}

fn interaction_kind_to_db(kind: InteractionKind) -> AppResult<&'static str> {
    match kind {
        InteractionKind::Observation => Ok("observation"),
        InteractionKind::Control => Ok("control"),
        InteractionKind::ShareSource => Ok("share_source"),
        InteractionKind::ShareReceiver => Ok("share_receiver"),
        InteractionKind::Attention => Ok("attention"),
        _ => Err(AppError::not_implemented(
            "this interaction kind is not supported by the durable server schema",
        )),
    }
}

fn interaction_kind_from_db(value: &str) -> AppResult<InteractionKind> {
    match value {
        "observation" => Ok(InteractionKind::Observation),
        "control" => Ok(InteractionKind::Control),
        "share_source" => Ok(InteractionKind::ShareSource),
        "share_receiver" => Ok(InteractionKind::ShareReceiver),
        "attention" => Ok(InteractionKind::Attention),
        _ => Err(AppError::unprocessable(
            "stored interaction kind is invalid",
        )),
    }
}

fn interaction_state_from_db(value: &str) -> AppResult<InteractionState> {
    match value {
        "requested" => Ok(InteractionState::Requested),
        "connecting" => Ok(InteractionState::Connecting),
        "live" => Ok(InteractionState::Live),
        "controlling" => Ok(InteractionState::Controlling),
        "stalled" => Ok(InteractionState::Stalled),
        "ending" => Ok(InteractionState::Ending),
        "pending_release" => Ok(InteractionState::PendingRelease),
        "ended" => Ok(InteractionState::Ended),
        "failed" => Ok(InteractionState::Failed),
        _ => Err(AppError::unprocessable(
            "stored interaction state is invalid",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::SecurityState;

    fn fixture() -> (Service, AuthContext) {
        let db = crate::db::open_in_memory().expect("open in-memory store");
        let now = now_unix();
        {
            let conn = db.lock().expect("lock in-memory store");
            conn.execute(
                "INSERT INTO accounts (
                    id, username, password_hash, state, can_operate, created_at, updated_at
                 ) VALUES ('account-1', 'operator', 'unused-test-hash', 'active', 1, ?1, ?1)",
                params![now],
            )
            .expect("insert account");
            conn.execute(
                "INSERT INTO managers (
                    id, public_identity, friendly_name, lifecycle_state,
                    approved_by_account_id, approved_at, created_at, updated_at, public_key
                 ) VALUES (
                    'manager-1', 'manager-key-id', 'Test Manager', 'approved',
                    'account-1', ?1, ?1, ?1, 'test-public-key'
                 )",
                params![now],
            )
            .expect("insert approved manager");
            conn.execute(
                "INSERT INTO sessions (
                    id, account_id, manager_id, token_hash, created_at, expires_at,
                    assurance, mfa_assured_at
                 ) VALUES ('session-1', 'account-1', 'manager-1', 'session-token-hash',
                           ?1, ?2, 'password', NULL)",
                params![now, now + 3600],
            )
            .expect("insert active session");
            conn.execute(
                "INSERT INTO computers (
                    id, public_identity, friendly_name, platform, enrollment_state,
                    enrollment_epoch, created_at, updated_at
                 ) VALUES ('computer-1', 'endpoint-key-id', 'Test Computer',
                           'windows', 'enrolled', 1, ?1, ?1)",
                params![now],
            )
            .expect("insert enrolled computer");
            conn.execute(
                "INSERT INTO access_assignments (
                    id, account_id, capability, computer_scope_all, revision,
                    created_at, updated_at
                 ) VALUES ('operate-1', 'account-1', 'operate', 1, 1, ?1, ?1)",
                params![now],
            )
            .expect("insert operate assignment");
            conn.execute(
                "INSERT INTO access_assignments (
                    id, account_id, capability, computer_scope_all, revision,
                    created_at, updated_at
                 ) VALUES ('observe-1', 'account-1', 'observe', 1, 1, ?1, ?1)",
                params![now],
            )
            .expect("insert observe assignment");
        }

        let service = Service::new(db);
        let auth = AuthContext {
            account_id: "account-1".to_owned(),
            username: "operator".to_owned(),
            session_id: "session-1".to_owned(),
            manager_id: Some("manager-1".to_owned()),
            can_operate: true,
            can_manage_enrollment: false,
            can_manage_access: false,
            can_manage_accounts: false,
            can_manage_security: false,
            revision: 1,
        };
        assert_eq!(service.security_state(), SecurityState::Ok);
        (service, auth)
    }

    fn input(operation: TransitionOperation, revision: u64) -> InteractionTransitionInput {
        InteractionTransitionInput {
            operation,
            computer_id: "computer-1".to_owned(),
            expected_revision: revision,
        }
    }

    #[test]
    fn v2_inventory_reports_only_current_epoch_endpoint_session_facts() {
        let (service, auth) = fixture();
        let now = now_unix();
        service
            .db_handle()
            .lock()
            .expect("lock store")
            .execute(
                "INSERT INTO endpoint_sessions (
                    id, token_hash, computer_id, enrollment_epoch, local_user_id,
                    local_user_display_name, created_at, expires_at, revoked_at
                 ) VALUES ('endpoint-session-1', 'endpoint-token-hash-1', 'computer-1',
                           1, 'windows:sid:S-1-5-21-1000', 'Operator', ?1, ?2, NULL)",
                params![now - 10, now + 890],
            )
            .expect("insert active endpoint session");

        let response = service
            .list_computers_with_endpoint_sessions(&auth)
            .expect("read observe-scoped endpoint session summary");
        assert_eq!(response.computers.len(), 1);
        let summary = response.computers[0]
            .endpoint_session
            .as_ref()
            .expect("observe-scoped inventory includes endpoint session summary");
        assert_eq!(summary.last_authenticated_at_unix, Some(now - 10));
        assert_eq!(summary.current_session_expires_at_unix, Some(now + 890));
        assert_eq!(
            summary.current_session_id.as_deref(),
            Some("endpoint-session-1")
        );
        assert_eq!(summary.console_user_reported, Some(true));
    }

    #[test]
    fn v2_inventory_hides_endpoint_session_facts_without_observe_scope() {
        let (service, auth) = fixture();
        let now = now_unix();
        let db = service.db_handle();
        let conn = db.lock().expect("lock store");
        conn.execute("DELETE FROM access_assignments WHERE id = 'observe-1'", [])
            .expect("remove observe assignment");
        conn.execute(
            "INSERT INTO endpoint_sessions (
                id, token_hash, computer_id, enrollment_epoch, local_user_id,
                local_user_display_name, created_at, expires_at, revoked_at
             ) VALUES ('endpoint-session-2', 'endpoint-token-hash-2', 'computer-1',
                       1, 'windows:sid:S-1-5-21-1000', 'Operator', ?1, ?2, NULL)",
            params![now - 10, now + 890],
        )
        .expect("insert active endpoint session");
        drop(conn);

        let response = service
            .list_computers_with_endpoint_sessions(&auth)
            .expect("read operate-scoped inventory");
        assert_eq!(response.computers.len(), 1);
        assert!(
            response.computers[0].endpoint_session.is_none(),
            "operate-only inventory must not disclose endpoint session facts"
        );
    }

    #[test]
    fn v2_inventory_does_not_reuse_endpoint_sessions_from_an_old_enrollment_epoch() {
        let (service, auth) = fixture();
        let now = now_unix();
        let db = service.db_handle();
        let conn = db.lock().expect("lock store");
        conn.execute(
            "UPDATE computers SET enrollment_epoch = 2 WHERE id = 'computer-1'",
            [],
        )
        .expect("advance computer enrollment epoch");
        conn.execute(
            "INSERT INTO endpoint_sessions (
                id, token_hash, computer_id, enrollment_epoch, local_user_id,
                local_user_display_name, created_at, expires_at, revoked_at
             ) VALUES ('endpoint-session-old', 'endpoint-token-hash-old', 'computer-1',
                       1, 'windows:sid:S-1-5-21-1000', 'Operator', ?1, ?2, NULL)",
            params![now - 10, now + 890],
        )
        .expect("insert prior-epoch endpoint session");
        drop(conn);

        let response = service
            .list_computers_with_endpoint_sessions(&auth)
            .expect("read current enrollment endpoint summary");
        let summary = response.computers[0]
            .endpoint_session
            .as_ref()
            .expect("observe scope still includes endpoint summary");
        assert_eq!(summary.last_authenticated_at_unix, None);
        assert_eq!(summary.current_session_expires_at_unix, None);
        assert_eq!(summary.current_session_id, None);
        assert_eq!(summary.console_user_reported, None);
    }

    #[test]
    fn authorized_transition_reserves_once_and_exact_retry_reuses_claim() {
        let (service, auth) = fixture();
        service
            .db_handle()
            .lock()
            .expect("lock store")
            .execute("DELETE FROM access_assignments WHERE id = 'operate-1'", [])
            .expect("remove operate assignment");
        let operation = TransitionOperation::Observe(
            InteractionId::new("observe-1").expect("valid interaction id"),
        );

        let first = service
            .reserve_interaction_transition(&auth, input(operation.clone(), 0))
            .expect("reserve authorized observation");
        assert_eq!(first.plan.disposition, TransitionDisposition::Proceed);
        assert!(first.reservation_created);
        assert_eq!(first.current_revision, 1);

        // Simulate a lost response: the retry keeps the original revision and
        // stable ID. It must return the existing reservation without advancing.
        let retry = service
            .reserve_interaction_transition(&auth, input(operation, 0))
            .expect("reuse exact active reservation");
        assert_eq!(retry.plan.disposition, TransitionDisposition::ReuseExisting);
        assert!(!retry.reservation_created);
        assert_eq!(retry.current_revision, 1);

        let conn = service.db_handle().lock().expect("lock store");
        let claims: i64 = conn
            .query_row("SELECT COUNT(*) FROM interaction_claims", [], |row| {
                row.get(0)
            })
            .expect("count claims");
        let revision: i64 = conn
            .query_row(
                "SELECT revision FROM computer_interaction_revisions WHERE computer_id = 'computer-1'",
                [],
                |row| row.get(0),
            )
            .expect("read revision");
        assert_eq!(claims, 1);
        assert_eq!(revision, 1);
    }

    #[test]
    fn missing_observe_scope_cannot_reserve_or_advance_revision() {
        let (service, auth) = fixture();
        service
            .db_handle()
            .lock()
            .expect("lock store")
            .execute("DELETE FROM access_assignments WHERE id = 'observe-1'", [])
            .expect("remove observe assignment");

        let result = service.reserve_interaction_transition(
            &auth,
            input(
                TransitionOperation::Observe(
                    InteractionId::new("observe-denied").expect("valid interaction id"),
                ),
                0,
            ),
        );
        assert!(result.is_err(), "missing scoped permission must be denied");

        let conn = service.db_handle().lock().expect("lock store");
        let claims: i64 = conn
            .query_row("SELECT COUNT(*) FROM interaction_claims", [], |row| {
                row.get(0)
            })
            .expect("count claims");
        let revisions: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM computer_interaction_revisions",
                [],
                |row| row.get(0),
            )
            .expect("count revisions");
        assert_eq!(claims, 0);
        assert_eq!(revisions, 0);
    }

    #[test]
    fn observe_scope_does_not_authorize_control() {
        let (service, auth) = fixture();
        service
            .db_handle()
            .lock()
            .expect("lock store")
            .execute("DELETE FROM access_assignments WHERE id = 'operate-1'", [])
            .expect("remove operate assignment");

        let result = service.reserve_interaction_transition(
            &auth,
            input(
                TransitionOperation::TakeControl(
                    InteractionId::new("control-with-observe-only").expect("valid interaction id"),
                ),
                0,
            ),
        );
        assert!(result.is_err(), "observe scope must not authorize control");

        let conn = service.db_handle().lock().expect("lock store");
        let claims: i64 = conn
            .query_row("SELECT COUNT(*) FROM interaction_claims", [], |row| {
                row.get(0)
            })
            .expect("count claims");
        assert_eq!(claims, 0);
    }

    #[test]
    fn replacement_review_returns_impacts_without_mutating_claims() {
        let (service, auth) = fixture();
        let control = TransitionOperation::TakeControl(
            InteractionId::new("control-1").expect("valid interaction id"),
        );
        service
            .reserve_interaction_transition(&auth, input(control, 0))
            .expect("reserve control request");

        let review = service
            .reserve_interaction_transition(
                &auth,
                input(
                    TransitionOperation::Attention(
                        InteractionId::new("attention-1").expect("valid interaction id"),
                    ),
                    1,
                ),
            )
            .expect("plan replacement review");
        assert_eq!(
            review.plan.disposition,
            TransitionDisposition::ReviewRequired
        );
        assert!(!review.reservation_created);
        assert_eq!(review.current_revision, 1);
        assert_eq!(review.plan.impacts.len(), 1);

        let conn = service.db_handle().lock().expect("lock store");
        let claims: i64 = conn
            .query_row("SELECT COUNT(*) FROM interaction_claims", [], |row| {
                row.get(0)
            })
            .expect("count claims");
        assert_eq!(claims, 1, "review must not create the replacement claim");
    }

    #[test]
    fn expired_or_revoked_session_cannot_reserve() {
        let (service, auth) = fixture();
        service
            .db_handle()
            .lock()
            .expect("lock store")
            .execute(
                "UPDATE sessions SET revoked_at = ?1 WHERE id = 'session-1'",
                params![now_unix()],
            )
            .expect("revoke session");

        let result = service.reserve_interaction_transition(
            &auth,
            input(
                TransitionOperation::Observe(
                    InteractionId::new("observe-revoked").expect("valid interaction id"),
                ),
                0,
            ),
        );
        assert!(result.is_err(), "revoked session must not reserve");
        let conn = service.db_handle().lock().expect("lock store");
        let claims: i64 = conn
            .query_row("SELECT COUNT(*) FROM interaction_claims", [], |row| {
                row.get(0)
            })
            .expect("count claims");
        assert_eq!(claims, 0);
    }
}
