//! Durable metadata-only audit events for security-sensitive operations.
//!
//! Event writes run in the same database transaction as the protected change.
//! If the audit insert or its bounded-retention check fails, that change rolls
//! back. This store never accepts request bodies, free-form messages, file
//! data, credentials, or screen content.

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::db::now_unix;
use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::service::{require_current_admin_session, AdminCapability, AuthContext, Service};

pub const DEFAULT_AUDIT_RETENTION_DAYS: i64 = 30;
pub const MIN_AUDIT_RETENTION_DAYS: i64 = 1;
pub const MAX_AUDIT_RETENTION_DAYS: i64 = 3650;
pub const MAX_AUDIT_EVENTS: i64 = 100_000;
const MAX_AUDIT_PAGE_SIZE: usize = 100;
const MAX_AUDIT_TARGETS: usize = 102;

fn audit_retention_days(conn: &Connection) -> AppResult<(i64, i64)> {
    let row: Option<(i64, i64)> = conn
        .query_row(
            "SELECT audit_retention_days, updated_at FROM security_policy WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (days, updated_at) = row.ok_or_else(|| {
        AppError::unprocessable("audit retention policy is missing; refusing audit operation")
    })?;
    if !(MIN_AUDIT_RETENTION_DAYS..=MAX_AUDIT_RETENTION_DAYS).contains(&days) {
        return Err(AppError::unprocessable(
            "audit retention policy is corrupt; refusing audit operation",
        ));
    }
    Ok((days, updated_at))
}

impl Service {
    /// Remove expired audit metadata on the normal service maintenance cycle.
    /// This operation is idempotent and does not create another audit event.
    pub fn maintain_audit_events(&self) -> AppResult<()> {
        let now = now_unix();
        self.with_tx(|conn| {
            let (retention_days, _) = audit_retention_days(conn)?;
            let retention_seconds = retention_days
                .checked_mul(24 * 60 * 60)
                .ok_or_else(|| AppError::unprocessable("audit retention policy is out of range"))?;
            let cutoff = now.saturating_sub(retention_seconds);
            conn.execute(
                "DELETE FROM audit_events WHERE occurred_at < ?1",
                params![cutoff],
            )?;
            Ok(())
        })
    }
}

/// Append a successful allowlisted action inside the caller's protected
/// transaction. Expired rows are pruned first; unexpired rows are never
/// silently discarded to make room.
pub(crate) fn record_successful_event(
    conn: &Connection,
    auth: &AuthContext,
    action: &str,
    target_ids: &[String],
    reason_code: &str,
    now: i64,
) -> AppResult<()> {
    record_successful_event_as(
        conn,
        &auth.account_id,
        auth.manager_id.as_deref(),
        action,
        target_ids,
        reason_code,
        now,
    )
}

pub(crate) fn record_successful_event_as(
    conn: &Connection,
    actor_account_id: &str,
    actor_manager_id: Option<&str>,
    action: &str,
    target_ids: &[String],
    reason_code: &str,
    now: i64,
) -> AppResult<()> {
    if !valid_code(action)
        || !valid_code(reason_code)
        || !valid_target_id(actor_account_id)
        || actor_manager_id.is_some_and(|manager_id| !valid_target_id(manager_id))
        || target_ids.is_empty()
        || target_ids.len() > MAX_AUDIT_TARGETS
        || target_ids.iter().any(|target| !valid_target_id(target))
    {
        return Err(AppError::internal(
            "server generated invalid audit metadata; protected action was not saved",
        ));
    }
    let (retention_days, _) = audit_retention_days(conn)?;
    let retention_seconds = retention_days
        .checked_mul(24 * 60 * 60)
        .ok_or_else(|| AppError::unprocessable("audit retention policy is out of range"))?;
    let cutoff = now
        .checked_sub(retention_seconds)
        .ok_or_else(|| AppError::unprocessable("audit retention cutoff is out of range"))?;
    conn.execute(
        "DELETE FROM audit_events WHERE occurred_at < ?1",
        params![cutoff],
    )?;
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))?;
    if count >= MAX_AUDIT_EVENTS {
        return Err(AppError::conflict(
            "audit event capacity is full; the protected change was not saved",
            Some("audit_capacity_full".to_string()),
        ));
    }
    let targets_json = serde_json::to_string(target_ids)
        .map_err(|_| AppError::internal("could not encode audit target metadata"))?;
    if targets_json.len() > 16_384 {
        return Err(AppError::internal(
            "audit target metadata exceeds the storage bound; protected action was not saved",
        ));
    }
    conn.execute(
        "INSERT INTO audit_events (
            id, actor_account_id, actor_manager_id, action, target_ids_json,
            occurred_at, result, reason_code
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'succeeded', ?7)",
        params![
            Uuid::new_v4().to_string(),
            actor_account_id,
            actor_manager_id,
            action,
            targets_json,
            now,
            reason_code
        ],
    )?;
    Ok(())
}

fn valid_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_target_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

impl Service {
    /// Read recent security audit metadata. Requires an active, approved
    /// Manager session with fresh MFA and current security-administrator role.
    pub fn list_audit_events(
        &self,
        auth: &AuthContext,
        query: AuditEventListQuery,
    ) -> AppResult<AuditEventListResponse> {
        self.require_security_ok()?;
        if !auth.can_manage_security {
            return Err(AppError::forbidden(
                "security administrator credentials are required to read audit events",
            ));
        }
        if query.before_unix.is_some() != query.before_id.is_some()
            || query
                .before_id
                .as_deref()
                .is_some_and(|id| !valid_target_id(id))
            || query.before_unix.is_some_and(|time| time < 0)
            || query
                .actor_account_id
                .as_deref()
                .is_some_and(|id| !valid_target_id(id))
            || query
                .action
                .as_deref()
                .is_some_and(|action| !valid_code(action))
            || query
                .target_id
                .as_deref()
                .is_some_and(|id| !valid_target_id(id))
            || query.from_unix.is_some_and(|time| time < 0)
            || query.to_unix.is_some_and(|time| time < 0)
            || matches!((query.from_unix, query.to_unix), (Some(from), Some(to)) if from > to)
        {
            return Err(AppError::bad_request("audit filters or cursor are invalid"));
        }
        let limit = query.limit.unwrap_or(50);
        if !(1..=MAX_AUDIT_PAGE_SIZE).contains(&limit) {
            return Err(AppError::bad_request(format!(
                "limit must be between 1 and {MAX_AUDIT_PAGE_SIZE}"
            )));
        }

        let now = now_unix();
        self.with_tx(|conn| {
            require_current_admin_session(conn, auth, AdminCapability::Security, now, true, true)?;
            let (retention_days, _) = audit_retention_days(conn)?;
            let cutoff = now.saturating_sub(retention_days * 24 * 60 * 60);
            let mut stmt = conn.prepare(
                r#"SELECT id, actor_account_id, actor_manager_id, action,
                        target_ids_json, occurred_at, result, reason_code
                 FROM audit_events
                 WHERE occurred_at >= ?1
                   AND (?2 IS NULL OR actor_account_id = ?2)
                   AND (?3 IS NULL OR action = ?3)
                   AND (?4 IS NULL OR instr(target_ids_json, '"' || ?4 || '"') > 0)
                   AND (?5 IS NULL OR occurred_at >= ?5)
                   AND (?6 IS NULL OR occurred_at <= ?6)
                   AND (?7 IS NULL OR occurred_at < ?7 OR (occurred_at = ?7 AND id < ?8))
                 ORDER BY occurred_at DESC, id DESC
                 LIMIT ?9"#,
            )?;
            let rows = stmt.query_map(
                params![
                    cutoff,
                    query.actor_account_id,
                    query.action,
                    query.target_id,
                    query.from_unix,
                    query.to_unix,
                    query.before_unix,
                    query.before_id,
                    (limit + 1) as i64
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )?;
            let mut events = Vec::with_capacity(limit + 1);
            for row in rows {
                let (id, account_id, manager_id, action, targets, time, result, reason_code) = row?;
                let target_ids: Vec<String> = serde_json::from_str(&targets).map_err(|_| {
                    AppError::unprocessable(
                        "stored audit target metadata is corrupt; refusing to return partial data",
                    )
                })?;
                if target_ids.is_empty()
                    || target_ids.len() > MAX_AUDIT_TARGETS
                    || target_ids.iter().any(|target| !valid_target_id(target))
                    || !valid_code(&action)
                    || !valid_code(&reason_code)
                    || !matches!(result.as_str(), "succeeded" | "denied" | "failed")
                {
                    return Err(AppError::unprocessable(
                        "stored audit event is malformed; refusing to return partial data",
                    ));
                }
                events.push(AuditEventView {
                    id,
                    actor: AuditEventActor {
                        account_id,
                        manager_id,
                    },
                    action,
                    target_ids,
                    time_unix: time,
                    result,
                    reason_code,
                });
            }
            let has_more = events.len() > limit;
            events.truncate(limit);
            let next_cursor = if has_more {
                events.last().map(|event| AuditEventCursor {
                    before_unix: event.time_unix,
                    before_id: event.id.clone(),
                })
            } else {
                None
            };
            Ok(AuditEventListResponse {
                events,
                next_cursor,
            })
        })
    }

    pub fn get_audit_retention(&self, auth: &AuthContext) -> AppResult<AuditRetentionResponse> {
        self.require_security_ok()?;
        if !auth.can_manage_security {
            return Err(AppError::forbidden(
                "security administrator credentials are required to read audit retention",
            ));
        }
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_admin_session(conn, auth, AdminCapability::Security, now, true, true)?;
            let (retention_days, updated_at) = audit_retention_days(conn)?;
            Ok(AuditRetentionResponse {
                retention_days,
                updated_at_unix: updated_at,
            })
        })
    }

    pub fn set_audit_retention(
        &self,
        auth: &AuthContext,
        request: AuditRetentionUpdateRequest,
    ) -> AppResult<AuditRetentionResponse> {
        self.require_security_ok()?;
        self.require_persisted_v2_credentials()?;
        if !auth.can_manage_security {
            return Err(AppError::forbidden(
                "security administrator credentials are required to change audit retention",
            ));
        }
        if !(MIN_AUDIT_RETENTION_DAYS..=MAX_AUDIT_RETENTION_DAYS).contains(&request.retention_days)
        {
            return Err(AppError::bad_request(format!(
                "retention_days must be between {MIN_AUDIT_RETENTION_DAYS} and {MAX_AUDIT_RETENTION_DAYS}"
            )));
        }

        let now = now_unix();
        self.with_tx(|conn| {
            require_current_admin_session(conn, auth, AdminCapability::Security, now, true, true)?;
            let changed = conn.execute(
                "UPDATE security_policy SET audit_retention_days = ?1, updated_at = ?2
                 WHERE id = 1",
                params![request.retention_days, now],
            )?;
            if changed != 1 {
                return Err(AppError::unprocessable(
                    "security policy is missing; refusing to change audit retention",
                ));
            }
            record_successful_event(
                conn,
                auth,
                "security.audit_retention_updated",
                &["deployment".to_string()],
                "retention_policy_changed",
                now,
            )?;
            Ok(AuditRetentionResponse {
                retention_days: request.retention_days,
                updated_at_unix: now,
            })
        })
    }
}
