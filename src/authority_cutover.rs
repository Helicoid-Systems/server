//! Durable single-active authority drain and restore cutover review.
//!
//! The server can record a two-person review and keep a restored authority
//! quarantined until the predecessor host is attested as fenced. This does
//! not remotely prove that an unreachable or cloned old host is stopped, and
//! it does not update Manager or endpoint trust; peers remain a separate
//! reconciliation requirement.

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::audit::record_successful_event;
use crate::db::now_unix;
use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::service::{
    require_current_recovery_admin_session, AdminCapability, AuthContext, Service,
};

fn load_status(conn: &Connection) -> AppResult<AuthorityCutoverResponse> {
    let (authority_id, authority_state, authority_generation, predecessor_authority_id): (
        String,
        String,
        i64,
        Option<String>,
    ) = conn.query_row(
        "SELECT deployment_key, authority_state, authority_generation,
                predecessor_deployment_key
         FROM deployment WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let cutover = conn
        .query_row(
            "SELECT id, predecessor_authority_id, replacement_authority_id,
                    generation, state, initiated_by_account_id,
                    approved_by_account_id, fencing_method,
                    fencing_evidence_reference, created_at, approved_at
             FROM authority_cutovers
             WHERE predecessor_authority_id = ?1 OR replacement_authority_id = ?1
             ORDER BY created_at DESC, id DESC LIMIT 1",
            params![authority_id],
            |row| {
                Ok(AuthorityCutoverView {
                    id: row.get(0)?,
                    predecessor_authority_id: row.get(1)?,
                    replacement_authority_id: row.get(2)?,
                    generation: row.get(3)?,
                    state: row.get(4)?,
                    initiated_by_account_id: row.get(5)?,
                    approved_by_account_id: row.get(6)?,
                    fencing_method: row.get(7)?,
                    fencing_evidence_reference: row.get(8)?,
                    created_at: row.get(9)?,
                    approved_at: row.get(10)?,
                })
            },
        )
        .optional()?;
    Ok(AuthorityCutoverResponse {
        authority_id,
        authority_state,
        authority_generation,
        predecessor_authority_id,
        cutover,
    })
}

fn require_security_admin(conn: &Connection, auth: &AuthContext) -> AppResult<()> {
    let can_manage_security: bool = conn.query_row(
        "SELECT can_manage_security FROM accounts WHERE id = ?1 AND state = 'active'",
        params![auth.account_id],
        |row| row.get(0),
    )?;
    if !can_manage_security {
        return Err(AppError::forbidden(
            "a security administrator must review authority cutover",
        ));
    }
    Ok(())
}

impl Service {
    pub fn authority_cutover_status_v2(
        &self,
        auth: &AuthContext,
    ) -> AppResult<AuthorityCutoverResponse> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        if !auth.can_manage_accounts {
            return Err(AppError::forbidden(
                "account management permission is required to review authority cutover",
            ));
        }
        self.with_conn(|conn| {
            require_current_recovery_admin_session(
                conn,
                auth,
                AdminCapability::Accounts,
                now_unix(),
                false,
                true,
            )?;
            load_status(conn)
        })
    }

    /// Stop the predecessor from accepting ordinary manager, operator, and
    /// endpoint authority. Existing cutover/recovery review remains available.
    pub fn begin_authority_cutover_v2(
        &self,
        auth: &AuthContext,
        req: BeginAuthorityCutoverRequest,
    ) -> AppResult<AuthorityCutoverResponse> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        if !auth.can_manage_accounts || !auth.can_manage_security {
            return Err(AppError::forbidden(
                "a security administrator must drain the current authority",
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
            require_security_admin(conn, auth)?;
            let (authority_id, authority_state, authority_generation, quarantined): (
                String,
                String,
                i64,
                bool,
            ) = conn.query_row(
                "SELECT deployment_key, authority_state, authority_generation,
                        recovery_quarantined
                 FROM deployment WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
            if authority_state != "active" || quarantined {
                return Err(AppError::conflict(
                    "only an active, non-quarantined authority can begin a drain",
                    Some("authority_not_active".to_string()),
                ));
            }
            if req.confirmation_phrase != format!("drain authority {authority_id}") {
                return Err(AppError::bad_request(
                    "confirmation_phrase must exactly identify the active authority",
                ));
            }
            let live_interactions: i64 = conn.query_row(
                "SELECT COUNT(*) FROM interaction_claims
                 WHERE state NOT IN ('ended', 'failed')",
                [],
                |row| row.get(0),
            )?;
            let live_admissions: i64 = conn.query_row(
                "SELECT COUNT(*) FROM observation_admission_grants
                 WHERE expires_at > ?1 AND consumed_at IS NULL",
                params![now],
                |row| row.get(0),
            )?;
            let live_file_work: i64 = conn.query_row(
                "SELECT COUNT(*) FROM file_jobs
                 WHERE state IN ('uploading', 'queued', 'in_progress')",
                [],
                |row| row.get(0),
            )?;
            if live_interactions != 0 || live_admissions != 0 || live_file_work != 0 {
                return Err(AppError::conflict(
                    "end active interactions and settle or cancel pending observation grants and file jobs before draining",
                    Some("authority_has_live_work".to_string()),
                ));
            }
            let generation = authority_generation
                .checked_add(1)
                .filter(|generation| *generation > 0)
                .ok_or_else(|| AppError::unprocessable("authority generation is exhausted"))?;
            let cutover_id = Uuid::new_v4().to_string();
            conn.execute(
                "INSERT INTO authority_cutovers (
                    id, predecessor_authority_id, generation, state,
                    initiated_by_account_id, created_at
                 ) VALUES (?1, ?2, ?3, 'draining', ?4, ?5)",
                params![cutover_id, authority_id, generation, auth.account_id, now],
            )?;
            let changed = conn.execute(
                "UPDATE deployment SET authority_state = 'draining'
                 WHERE id = 1 AND authority_state = 'active' AND deployment_key = ?1",
                params![authority_id],
            )?;
            if changed != 1 {
                return Err(AppError::conflict(
                    "authority changed while the drain was being recorded",
                    Some("authority_changed".to_string()),
                ));
            }
            conn.execute(
                "UPDATE endpoint_sessions SET revoked_at = ?1 WHERE revoked_at IS NULL",
                params![now],
            )?;
            conn.execute(
                "UPDATE auth_challenges SET consumed_at = ?1 WHERE consumed_at IS NULL",
                params![now],
            )?;
            conn.execute(
                "UPDATE endpoint_auth_challenges SET consumed_at = ?1 WHERE consumed_at IS NULL",
                params![now],
            )?;
            conn.execute(
                "UPDATE computer_enrollment_invitations SET revoked_at = ?1
                 WHERE redeemed_at IS NULL AND revoked_at IS NULL",
                params![now],
            )?;
            conn.execute("DELETE FROM observation_admission_grants", [])?;
            record_successful_event(
                conn,
                auth,
                "authority.cutover_draining",
                &[cutover_id.clone(), authority_id.clone()],
                "predecessor_drained",
                now,
            )?;
            load_status(conn)
        })
    }

    /// Record an independent security-admin attestation for the exact
    /// predecessor/replacement pair. Evidence is an operator-supplied
    /// reference and must be reviewed outside this service.
    pub fn approve_authority_cutover_v2(
        &self,
        auth: &AuthContext,
        req: ApproveAuthorityCutoverRequest,
    ) -> AppResult<AuthorityCutoverResponse> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
        if !auth.can_manage_accounts || !auth.can_manage_security {
            return Err(AppError::forbidden(
                "a security administrator must approve authority cutover",
            ));
        }
        if req.cutover_id.is_empty()
            || req.cutover_id.len() > 128
            || req.expected_predecessor_authority_id.is_empty()
            || req.expected_predecessor_authority_id.len() > 128
            || req.expected_replacement_authority_id.is_empty()
            || req.expected_replacement_authority_id.len() > 128
            || req.fencing_evidence_reference.trim().is_empty()
            || req.fencing_evidence_reference.len() > 512
            || req.fencing_evidence_reference.chars().any(char::is_control)
        {
            return Err(AppError::bad_request(
                "cutover identity or fencing evidence reference is invalid",
            ));
        }
        if !matches!(
            req.fencing_method.as_str(),
            "host_powered_off"
                | "service_and_routes_isolated"
                | "network_isolated"
                | "locally_verified_profile"
        ) {
            return Err(AppError::bad_request(
                "fencing_method must name a supported host-fencing procedure",
            ));
        }
        let expected_phrase = format!(
            "approve authority cutover {} to {}",
            req.expected_predecessor_authority_id, req.expected_replacement_authority_id
        );
        if req.confirmation_phrase != expected_phrase {
            return Err(AppError::bad_request(
                "confirmation_phrase must identify both authority identities",
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
            require_security_admin(conn, auth)?;
            let (replacement_id, predecessor_id, generation, authority_state): (
                String,
                Option<String>,
                i64,
                String,
            ) = conn.query_row(
                "SELECT deployment_key, predecessor_deployment_key,
                        authority_generation, authority_state
                 FROM deployment WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
            if authority_state != "awaiting_cutover"
                || predecessor_id.as_deref() != Some(req.expected_predecessor_authority_id.as_str())
                || replacement_id != req.expected_replacement_authority_id
            {
                return Err(AppError::conflict(
                    "the restored authority does not match the reviewed cutover identities",
                    Some("cutover_identity_changed".to_string()),
                ));
            }
            let row: Option<(i64, Option<String>)> = conn
                .query_row(
                    "SELECT generation, initiated_by_account_id
                     FROM authority_cutovers
                     WHERE id = ?1 AND predecessor_authority_id = ?2
                       AND replacement_authority_id = ?3 AND state = 'awaiting_review'",
                    params![
                        req.cutover_id,
                        req.expected_predecessor_authority_id,
                        req.expected_replacement_authority_id
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let (review_generation, initiator_id) = row.ok_or_else(|| {
                AppError::conflict(
                    "the requested cutover is not awaiting independent review",
                    Some("cutover_not_reviewable".to_string()),
                )
            })?;
            if review_generation != generation {
                return Err(AppError::conflict(
                    "authority generation changed; cutover review must be restarted",
                    Some("cutover_generation_changed".to_string()),
                ));
            }
            if initiator_id.as_deref() == Some(auth.account_id.as_str()) {
                return Err(AppError::forbidden(
                    "the cutover initiator cannot approve their own host-fencing review",
                ));
            }
            let changed = conn.execute(
                "UPDATE authority_cutovers
                 SET state = 'approved', approved_by_account_id = ?1,
                     fencing_method = ?2, fencing_evidence_reference = ?3,
                     approved_at = ?4
                 WHERE id = ?5 AND state = 'awaiting_review' AND generation = ?6",
                params![
                    auth.account_id,
                    req.fencing_method,
                    req.fencing_evidence_reference.trim(),
                    now,
                    req.cutover_id,
                    generation
                ],
            )?;
            if changed != 1 {
                return Err(AppError::conflict(
                    "cutover review changed before approval committed",
                    Some("cutover_review_changed".to_string()),
                ));
            }
            let activated = conn.execute(
                "UPDATE deployment SET authority_state = 'active'
                 WHERE id = 1 AND deployment_key = ?1
                   AND authority_state = 'awaiting_cutover'
                   AND authority_generation = ?2",
                params![replacement_id, generation],
            )?;
            if activated != 1 {
                return Err(AppError::conflict(
                    "replacement authority changed before cutover approval committed",
                    Some("authority_changed".to_string()),
                ));
            }
            record_successful_event(
                conn,
                auth,
                "authority.cutover_approved",
                &[req.cutover_id.clone(), replacement_id.clone()],
                "replacement_activated",
                now,
            )?;
            load_status(conn)
        })
    }

    /// Cancellation is available only on the predecessor while it is still
    /// Draining. A restored replacement can never use cancellation to reactivate
    /// the predecessor after the transition began.
    pub fn cancel_authority_cutover_v2(
        &self,
        auth: &AuthContext,
        req: CancelAuthorityCutoverRequest,
    ) -> AppResult<AuthorityCutoverResponse> {
        self.require_persisted_v2_credentials()?;
        self.require_security_ok()?;
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
            require_security_admin(conn, auth)?;
            let (authority_id, authority_state): (String, String) = conn.query_row(
                "SELECT deployment_key, authority_state FROM deployment WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if authority_state != "draining"
                || req.confirmation_phrase != format!("cancel authority cutover {}", req.cutover_id)
            {
                return Err(AppError::conflict(
                    "only the still-running predecessor can cancel a draining cutover",
                    Some("cutover_cannot_be_cancelled".to_string()),
                ));
            }
            let changed = conn.execute(
                "UPDATE authority_cutovers SET state = 'cancelled'
                 WHERE id = ?1 AND predecessor_authority_id = ?2 AND state = 'draining'",
                params![req.cutover_id, authority_id],
            )?;
            if changed != 1 {
                return Err(AppError::conflict(
                    "the cutover is no longer cancellable",
                    Some("cutover_cannot_be_cancelled".to_string()),
                ));
            }
            conn.execute(
                "UPDATE deployment SET authority_state = 'active'
                 WHERE id = 1 AND deployment_key = ?1 AND authority_state = 'draining'",
                params![authority_id],
            )?;
            record_successful_event(
                conn,
                auth,
                "authority.cutover_cancelled",
                &[req.cutover_id.clone(), authority_id.clone()],
                "predecessor_reactivated",
                now,
            )?;
            load_status(conn)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{
        require_current_admin_session, require_current_manager_session, AdminCapability, Service,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn seeded_security_admin(service: &Service, account_id: &str) -> AuthContext {
        let now = now_unix();
        let manager_id = format!("manager-{account_id}");
        let session_id = format!("session-{account_id}");
        let conn = service.db_handle().lock().expect("lock test database");
        conn.execute(
            "INSERT INTO accounts (
                id, username, password_hash, state, can_manage_accounts,
                can_manage_security, created_at, updated_at
             ) VALUES (?1, ?2, 'test-hash', 'active', 1, 1, ?3, ?3)",
            params![account_id, format!("user-{account_id}"), now],
        )
        .expect("insert security admin");
        conn.execute(
            "INSERT INTO account_mfa (
                account_id, totp_secret, totp_confirmed_at, recovery_stored_at,
                status, created_at, updated_at
             ) VALUES (?1, 'test-secret', ?2, ?2, 'active', ?2, ?2)",
            params![account_id, now],
        )
        .expect("insert mfa factor");
        conn.execute(
            "INSERT INTO managers (
                id, public_identity, friendly_name, lifecycle_state,
                approved_by_account_id, approved_at, created_at, updated_at, public_key
             ) VALUES (?1, ?2, 'test device', 'approved', ?3, ?4, ?4, ?4, ?5)",
            params![
                manager_id,
                format!("identity-{account_id}"),
                account_id,
                now,
                format!("public-key-{account_id}")
            ],
        )
        .expect("insert manager");
        conn.execute(
            "INSERT INTO sessions (
                id, account_id, manager_id, token_hash, created_at, expires_at,
                assurance, mfa_assured_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'mfa', ?5)",
            params![
                session_id,
                account_id,
                manager_id,
                format!("token-hash-{account_id}"),
                now,
                now + 3600
            ],
        )
        .expect("insert mfa session");
        AuthContext {
            account_id: account_id.to_string(),
            username: format!("user-{account_id}"),
            session_id,
            manager_id: Some(manager_id),
            can_operate: false,
            can_manage_enrollment: true,
            can_manage_access: false,
            can_manage_accounts: true,
            can_manage_security: true,
            revision: 1,
        }
    }

    #[test]
    fn drain_pauses_normal_authority_and_restore_needs_cutover_review_before_release() {
        let service = Service::new(crate::db::open_in_memory().expect("open store"));
        let initiator = seeded_security_admin(&service, "initiator");
        let predecessor = service
            .with_conn(|conn| crate::db::deployment_key(conn))
            .expect("read predecessor");
        let phrase = format!("drain authority {predecessor}");
        let draining = service
            .begin_authority_cutover_v2(
                &initiator,
                BeginAuthorityCutoverRequest {
                    confirmation_phrase: phrase,
                },
            )
            .expect("begin drain");
        assert_eq!(draining.authority_state, "draining");
        let error = service
            .with_conn(|conn| {
                require_current_admin_session(
                    conn,
                    &initiator,
                    AdminCapability::Accounts,
                    now_unix(),
                    false,
                    true,
                )
            })
            .expect_err("normal administrative authority must stop while draining");
        assert!(error.to_string().contains("not Active"));

        let replacement = "dep_replacement".to_string();
        let cutover_id = draining
            .cutover
            .as_ref()
            .expect("cutover record")
            .id
            .clone();
        service
            .with_tx(|conn| {
                conn.execute(
                    "UPDATE deployment SET deployment_key = ?1,
                        predecessor_deployment_key = ?2, authority_state = 'awaiting_cutover',
                        authority_generation = 2, recovery_quarantined = 1,
                        bootstrap_completed = 1
                     WHERE id = 1",
                    params![replacement, predecessor],
                )?;
                conn.execute(
                    "UPDATE authority_cutovers
                     SET replacement_authority_id = ?1, state = 'awaiting_review', generation = 2
                     WHERE id = ?2",
                    params![replacement, cutover_id],
                )?;
                Ok(())
            })
            .expect("model restored database state");
        let reviewer = seeded_security_admin(&service, "reviewer");

        let quarantine = service
            .recovery_quarantine_status_v2(&reviewer)
            .expect("read recovery status");
        let release = ReleaseRecoveryQuarantineRequest {
            expected_deployment_id: replacement.clone(),
            expected_quarantined_account_count: quarantine.quarantined_account_count,
            expected_revoked_manager_count: quarantine.revoked_manager_count,
            expected_quarantined_endpoint_count: quarantine.quarantined_endpoint_count,
            acknowledge_missing_post_backup_history: true,
            acknowledge_restored_authorities_remain_quarantined: true,
            confirmation_phrase: format!("release restored deployment {replacement}"),
        };
        let blocked_release = service
            .release_recovery_quarantine_v2(&reviewer, release)
            .expect_err("recovery release must wait for host-fencing review");
        assert!(blocked_release.to_string().contains("cutover review"));

        let same_admin = service
            .approve_authority_cutover_v2(
                &initiator,
                ApproveAuthorityCutoverRequest {
                    cutover_id: cutover_id.clone(),
                    expected_predecessor_authority_id: predecessor.clone(),
                    expected_replacement_authority_id: replacement.clone(),
                    fencing_method: "host_powered_off".into(),
                    fencing_evidence_reference: "change-42".into(),
                    confirmation_phrase: format!(
                        "approve authority cutover {predecessor} to {replacement}"
                    ),
                },
            )
            .expect_err("the old initiator cannot approve the same review");
        assert!(same_admin.to_string().contains("cannot approve"));

        let approved = service
            .approve_authority_cutover_v2(
                &reviewer,
                ApproveAuthorityCutoverRequest {
                    cutover_id,
                    expected_predecessor_authority_id: predecessor,
                    expected_replacement_authority_id: replacement.clone(),
                    fencing_method: "host_powered_off".into(),
                    fencing_evidence_reference: "change-42".into(),
                    confirmation_phrase: format!(
                        "approve authority cutover {} to {replacement}",
                        draining.authority_id
                    ),
                },
            )
            .expect("independent reviewer approves exact replacement");
        assert_eq!(approved.authority_state, "active");
        assert_eq!(approved.authority_generation, 2);
        let current_quarantine = service
            .recovery_quarantine_status_v2(&reviewer)
            .expect("read quarantine after approval");
        let released = service
            .release_recovery_quarantine_v2(
                &reviewer,
                ReleaseRecoveryQuarantineRequest {
                    expected_deployment_id: replacement.clone(),
                    expected_quarantined_account_count: current_quarantine
                        .quarantined_account_count,
                    expected_revoked_manager_count: current_quarantine.revoked_manager_count,
                    expected_quarantined_endpoint_count: current_quarantine
                        .quarantined_endpoint_count,
                    acknowledge_missing_post_backup_history: true,
                    acknowledge_restored_authorities_remain_quarantined: true,
                    confirmation_phrase: format!("release restored deployment {replacement}"),
                },
            )
            .expect("release after cutover approval");
        assert!(!released.recovery_quarantined);
    }

    #[test]
    fn only_the_draining_predecessor_can_cancel_before_restore() {
        let service = Service::new(crate::db::open_in_memory().expect("open store"));
        let admin = seeded_security_admin(&service, "cancel-admin");
        let now = now_unix();
        service
            .with_tx(|conn| {
                conn.execute(
                    "INSERT INTO file_jobs (
                        id, owner_account_id, direction, file_name, file_size_bytes,
                        sha256, chunk_size_bytes, chunk_count, state, created_at,
                        updated_at, upload_expires_at, delivery_expires_at
                     ) VALUES (
                        'job-1', ?1, 'push', 'active.txt', 1, ?2, 262144, 1,
                        'queued', ?3, ?3, ?4, ?4
                     )",
                    params![admin.account_id, "a".repeat(64), now, now + 600],
                )?;
                Ok(())
            })
            .expect("insert pending file job");
        let blocked = service
            .begin_authority_cutover_v2(
                &admin,
                BeginAuthorityCutoverRequest {
                    confirmation_phrase: format!(
                        "drain authority {}",
                        service.deployment_id().expect("deployment id")
                    ),
                },
            )
            .expect_err("pending file work blocks drain");
        assert!(blocked.to_string().contains("settle or cancel"));
        service
            .with_tx(|conn| {
                conn.execute("DELETE FROM file_jobs WHERE id = 'job-1'", [])?;
                Ok(())
            })
            .expect("clear pending file job");
        let draining = service
            .begin_authority_cutover_v2(
                &admin,
                BeginAuthorityCutoverRequest {
                    confirmation_phrase: format!(
                        "drain authority {}",
                        service.deployment_id().expect("deployment id")
                    ),
                },
            )
            .expect("begin drain");
        let cutover_id = draining.cutover.expect("cutover").id;
        let cancelled = service
            .cancel_authority_cutover_v2(
                &admin,
                CancelAuthorityCutoverRequest {
                    cutover_id: cutover_id.clone(),
                    confirmation_phrase: format!("cancel authority cutover {cutover_id}"),
                },
            )
            .expect("cancel before restore");
        assert_eq!(cancelled.authority_state, "active");
        assert_eq!(cancelled.cutover.expect("review").state, "cancelled");
        service
            .with_conn(|conn| require_current_manager_session(conn, &admin, now_unix()))
            .expect("normal authority resumes after pre-cutover cancellation");
    }

    #[test]
    fn draining_authority_refuses_new_endpoint_sessions() {
        let service = Service::new(crate::db::open_in_memory().expect("open store"));
        let signer = SigningKey::from_bytes(&[31_u8; 32]);
        let public_key = hex::encode(signer.verifying_key().to_bytes());
        let identity = format!("key:{public_key}");
        let computer_id = Uuid::new_v4().to_string();
        let now = now_unix();
        let deployment_id = service.deployment_id().expect("deployment id");
        service
            .with_tx(|conn| {
                conn.execute(
                    "INSERT INTO computers (
                        id, public_identity, friendly_name, platform, enrollment_state,
                        enrollment_epoch, approved_incarnation_identity, created_at, updated_at
                     ) VALUES (?1, ?2, 'Test computer', 'windows', 'enrolled', 1, ?2, ?3, ?3)",
                    params![computer_id, identity, now],
                )?;
                conn.execute(
                    "UPDATE deployment SET authority_state = 'draining' WHERE id = 1",
                    [],
                )?;
                Ok(())
            })
            .expect("seed endpoint and drain authority");
        let nonce = "ab".repeat(32);
        let proof_message = crate::crypto::endpoint_session_begin_proof_message(
            &deployment_id,
            &computer_id,
            now,
            &nonce,
        );
        let proof = hex::encode(signer.sign(&proof_message).to_bytes());
        let result = service.endpoint_session_challenge(EndpointSessionChallengeRequest {
            computer_id,
            local_user_id: None,
            local_user_display_name: None,
            client_nonce: nonce,
            issued_at_unix: now,
            proof,
        });
        let error = match result {
            Ok(_) => panic!("draining authority must not issue endpoint challenges"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("new endpoint sessions"));
    }
}
