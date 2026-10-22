//! Durable manager-to-endpoint file delivery jobs.
//!
//! Uploads are stored as fixed-size chunks in the private database. A job is
//! queued only after the complete object hash matches the manager's declared
//! digest. Each enrolled target fetches only its own work and reports an
//! independently verified result. Reverse file requests and received-file
//! workflows remain separate capabilities.

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::now_unix;
use crate::endpoint_auth::require_current_endpoint_session;
use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::service::{
    require_current_manager_session, require_current_operator_session, AuthContext,
    EndpointAuthContext, Service,
};

pub const FILE_JOB_CHUNK_SIZE_BYTES: usize = 256 * 1024;
const FILE_JOB_MAX_SIZE_BYTES: u64 = 128 * 1024 * 1024;
const FILE_JOB_MAX_TARGETS: usize = 50;
const FILE_JOB_MAX_PAGE_SIZE: usize = 100;
const ENDPOINT_FILE_JOB_MAX_PAGE_SIZE: usize = 50;
const FILE_JOB_UPLOAD_TTL_SECS: i64 = 24 * 60 * 60;
// Development candidate only: E06 must freeze delivery and retention budgets
// before the production file-job feature can be enabled.
const FILE_JOB_DELIVERY_TTL_SECS: i64 = 24 * 60 * 60;
const FILE_RECIPIENT_SESSION_FRESHNESS_SECS: i64 = 3 * 60;
pub(crate) const FILE_STORAGE_MAX_BYTES: i64 = 2 * 1024 * 1024 * 1024;
const FILE_JOB_MAX_ACTIVE_COUNT: i64 = 500;
const FILE_JOB_MAX_ACTIVE_COUNT_PER_ACCOUNT: i64 = 100;

type FileJobRow = (
    String,
    String,
    String,
    String,
    i64,
    String,
    i64,
    i64,
    String,
    i64,
    i64,
    i64,
    i64,
);
type FileJobTargetRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<i64>,
);
type CurrentFileJobTargetResultRow = (String, Option<String>, Option<i64>, Option<String>);

fn canonical_uuid(value: &str, field: &str) -> AppResult<String> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| AppError::bad_request(format!("{field} must be a UUID")))?
        .to_string();
    if parsed != value {
        return Err(AppError::bad_request(format!(
            "{field} must use its canonical lowercase form"
        )));
    }
    Ok(parsed)
}

pub(crate) fn validate_file_name(value: &str) -> AppResult<String> {
    let name = value.trim();
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '/' | '\\' | ':'))
    {
        return Err(AppError::bad_request(
            "file_name must be a safe single file name of at most 255 bytes",
        ));
    }
    let device_stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    let reserved_device = matches!(device_stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (device_stem.len() == 4
            && (device_stem.starts_with("COM") || device_stem.starts_with("LPT"))
            && matches!(device_stem.as_bytes()[3], b'1'..=b'9'));
    if reserved_device {
        return Err(AppError::bad_request("file_name is reserved by Windows"));
    }
    Ok(name.to_string())
}

pub(crate) fn validate_sha256(value: &str, field: &str) -> AppResult<String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppError::bad_request(format!(
            "{field} must be 32 bytes of lowercase SHA-256 hex"
        )));
    }
    Ok(value.to_string())
}

fn to_u64(value: i64, field: &str) -> AppResult<u64> {
    u64::try_from(value).map_err(|_| AppError::unprocessable(format!("stored {field} is invalid")))
}

fn read_job_row(conn: &Connection, job_id: &str) -> AppResult<FileJobRow> {
    conn.query_row(
        "SELECT id, owner_account_id, direction, file_name, file_size_bytes,
                sha256, chunk_size_bytes, chunk_count, state, created_at,
                updated_at, upload_expires_at, delivery_expires_at
         FROM file_jobs WHERE id = ?1",
        params![job_id],
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
                row.get(11)?,
                row.get(12)?,
            ))
        },
    )
    .optional()?
    .ok_or_else(|| AppError::not_found("file job not found"))
}

fn map_target_row(row: &FileJobTargetRow) -> AppResult<FileJobTargetView> {
    Ok(FileJobTargetView {
        computer_id: row.0.clone(),
        friendly_name: row.1.clone(),
        state: row.2.clone(),
        recipient_display_name: row.3.clone(),
        result_detail: row.4.clone(),
        received_size_bytes: row
            .5
            .map(|size| to_u64(size, "received file size"))
            .transpose()?,
        received_sha256: row.6.clone(),
        started_at_unix: row.7,
        finished_at_unix: row.8,
    })
}

fn read_target_view(
    conn: &Connection,
    job_id: &str,
    computer_id: &str,
) -> AppResult<FileJobTargetView> {
    let now = now_unix();
    let row: Option<FileJobTargetRow> = conn
        .query_row(
            "SELECT t.computer_id, c.friendly_name,
                    CASE
                      WHEN t.state NOT IN ('queued', 'in_progress') THEN t.state
                      WHEN t.recipient_local_user_id IS NULL
                        OR t.recipient_local_user_display_name IS NULL THEN 'recipient_unavailable'
                      WHEN current_session.id IS NULL THEN 'waiting_computer'
                      WHEN current_session.local_user_id IS NULL
                        OR current_session.local_user_display_name IS NULL THEN 'recipient_unavailable'
                      WHEN current_session.local_user_id <> t.recipient_local_user_id THEN 'waiting_recipient'
                      ELSE t.state
                    END,
                    t.recipient_local_user_display_name, t.result_detail,
                    t.received_size_bytes, t.received_sha256, t.started_at, t.finished_at
             FROM file_job_targets t
             JOIN computers c ON c.id = t.computer_id
             LEFT JOIN endpoint_sessions current_session ON current_session.id = (
                 SELECT s.id FROM endpoint_sessions s
                 WHERE s.computer_id = t.computer_id AND s.revoked_at IS NULL
                   AND s.expires_at > ?3 AND s.created_at > ?4
                   AND s.enrollment_epoch = c.enrollment_epoch
                   AND c.enrollment_state = 'enrolled'
                   AND c.approved_incarnation_identity = c.public_identity
                 ORDER BY s.created_at DESC, s.id DESC LIMIT 1
             )
             WHERE t.job_id = ?1 AND t.computer_id = ?2",
            params![job_id, computer_id, now, now - FILE_RECIPIENT_SESSION_FRESHNESS_SECS],
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
                ))
            },
        )
        .optional()?;
    let row = row.ok_or_else(|| AppError::not_found("file job target not found"))?;
    map_target_row(&row)
}

fn load_file_job_view(conn: &Connection, job_id: &str) -> AppResult<FileJobView> {
    let row = read_job_row(conn, job_id)?;
    let now = now_unix();
    let mut stmt = conn.prepare(
        "SELECT t.computer_id, c.friendly_name,
                CASE
                  WHEN t.state NOT IN ('queued', 'in_progress') THEN t.state
                  WHEN t.recipient_local_user_id IS NULL
                    OR t.recipient_local_user_display_name IS NULL THEN 'recipient_unavailable'
                  WHEN current_session.id IS NULL THEN 'waiting_computer'
                  WHEN current_session.local_user_id IS NULL
                    OR current_session.local_user_display_name IS NULL THEN 'recipient_unavailable'
                  WHEN current_session.local_user_id <> t.recipient_local_user_id THEN 'waiting_recipient'
                  ELSE t.state
                END,
                t.recipient_local_user_display_name, t.result_detail,
                t.received_size_bytes, t.received_sha256, t.started_at, t.finished_at
         FROM file_job_targets t
         JOIN computers c ON c.id = t.computer_id
         LEFT JOIN endpoint_sessions current_session ON current_session.id = (
             SELECT s.id FROM endpoint_sessions s
             WHERE s.computer_id = t.computer_id AND s.revoked_at IS NULL
               AND s.expires_at > ?2 AND s.created_at > ?4
               AND s.enrollment_epoch = c.enrollment_epoch
               AND c.enrollment_state = 'enrolled'
               AND c.approved_incarnation_identity = c.public_identity
             ORDER BY s.created_at DESC, s.id DESC LIMIT 1
         )
         WHERE t.job_id = ?1
         ORDER BY c.friendly_name COLLATE NOCASE, t.computer_id
         LIMIT ?3",
    )?;
    let targets = stmt
        .query_map(
            params![
                job_id,
                now,
                FILE_JOB_MAX_TARGETS as i64,
                now - FILE_RECIPIENT_SESSION_FRESHNESS_SECS
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
                    row.get(8)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .map(map_target_row)
        .collect::<AppResult<Vec<_>>>()?;
    Ok(FileJobView {
        id: row.0,
        direction: row.2,
        file_name: row.3,
        file_size_bytes: to_u64(row.4, "file size")?,
        sha256: row.5,
        chunk_size_bytes: u32::try_from(row.6)
            .map_err(|_| AppError::unprocessable("stored chunk size is invalid"))?,
        chunk_count: u32::try_from(row.7)
            .map_err(|_| AppError::unprocessable("stored chunk count is invalid"))?,
        state: row.8,
        created_at_unix: row.9,
        updated_at_unix: row.10,
        delivery_expires_at_unix: row.12,
        targets,
    })
}

pub(crate) fn require_operate_scope(
    conn: &Connection,
    account_id: &str,
    computer_id: &str,
) -> AppResult<()> {
    let assignment: Option<(String, bool)> = conn
        .query_row(
            "SELECT id, computer_scope_all FROM access_assignments
             WHERE account_id = ?1 AND capability = 'operate'",
            params![account_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((assignment_id, scope_all)) = assignment else {
        return Err(AppError::forbidden(
            "operate access to every target computer is required",
        ));
    };
    let in_scope: bool = if scope_all {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM computers WHERE id = ?1)",
            params![computer_id],
            |row| row.get(0),
        )?
    } else {
        conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM access_computer_scope
                WHERE assignment_id = ?1 AND computer_id = ?2
             )",
            params![assignment_id, computer_id],
            |row| row.get(0),
        )?
    };
    if !in_scope {
        return Err(AppError::forbidden(
            "computer is outside the account operate access scope",
        ));
    }
    let state: String = conn.query_row(
        "SELECT enrollment_state FROM computers WHERE id = ?1",
        params![computer_id],
        |row| row.get(0),
    )?;
    if state != "enrolled" {
        return Err(AppError::forbidden(
            "file delivery requires an enrolled endpoint",
        ));
    }
    Ok(())
}

fn require_job_operator(
    conn: &Connection,
    auth: &AuthContext,
    job_id: &str,
    now: i64,
) -> AppResult<FileJobRow> {
    require_current_operator_session(conn, auth, now)?;
    let row = read_job_row(conn, job_id)?;
    if row.1 != auth.account_id {
        return Err(AppError::not_found("file job not found"));
    }
    let mut stmt = conn.prepare(
        "SELECT computer_id FROM file_job_targets
         WHERE job_id = ?1 AND state IN ('awaiting_upload', 'queued', 'in_progress')
         ORDER BY computer_id LIMIT ?2",
    )?;
    let computer_ids = stmt
        .query_map(params![job_id, FILE_JOB_MAX_TARGETS as i64], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if computer_ids.len() > FILE_JOB_MAX_TARGETS
        || (computer_ids.is_empty()
            && !matches!(
                row.8.as_str(),
                "completed" | "partial" | "failed" | "cancelled" | "expired"
            ))
    {
        return Err(AppError::unprocessable(
            "stored file job targets are invalid",
        ));
    }
    for computer_id in computer_ids {
        require_operate_scope(conn, &auth.account_id, &computer_id)?;
    }
    Ok(row)
}

pub(crate) fn expire_file_jobs(conn: &Connection, now: i64) -> AppResult<()> {
    conn.execute(
        "UPDATE file_job_targets SET state = 'cancelled',
                result_detail = 'upload_expired', finished_at = ?1
         WHERE state = 'awaiting_upload' AND job_id IN (
             SELECT id FROM file_jobs
             WHERE state = 'uploading' AND delivery_expires_at <= ?1
         )",
        params![now],
    )?;
    conn.execute(
        "UPDATE file_job_targets SET state = 'failed',
                result_detail = 'delivery_expired', finished_at = ?1
         WHERE state IN ('queued', 'in_progress') AND job_id IN (
             SELECT id FROM file_jobs
             WHERE state IN ('queued', 'in_progress') AND delivery_expires_at <= ?1
         )",
        params![now],
    )?;
    conn.execute(
        "DELETE FROM file_job_chunks WHERE job_id IN (
             SELECT id FROM file_jobs
             WHERE state IN ('uploading', 'queued', 'in_progress')
               AND delivery_expires_at <= ?1
         )",
        params![now],
    )?;
    conn.execute(
        "UPDATE file_jobs SET state = 'expired', updated_at = ?1
         WHERE state IN ('uploading', 'queued', 'in_progress')
           AND delivery_expires_at <= ?1",
        params![now],
    )?;
    Ok(())
}

fn recalculate_file_job_if_terminal(conn: &Connection, job_id: &str, now: i64) -> AppResult<()> {
    let (total, terminal, completed, failed): (i64, i64, i64, i64) = conn.query_row(
        "SELECT COUNT(*),
                SUM(CASE WHEN state IN ('completed', 'failed', 'cancelled') THEN 1 ELSE 0 END),
                SUM(CASE WHEN state = 'completed' THEN 1 ELSE 0 END),
                SUM(CASE WHEN state = 'failed' THEN 1 ELSE 0 END)
         FROM file_job_targets WHERE job_id = ?1",
        params![job_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if total <= 0 {
        return Err(AppError::unprocessable("file job has no targets"));
    }
    if terminal == total {
        let final_state = if completed == total {
            "completed"
        } else if failed == total {
            "failed"
        } else {
            "partial"
        };
        conn.execute(
            "UPDATE file_jobs SET state = ?1, updated_at = ?2
             WHERE id = ?3 AND state IN ('uploading', 'queued', 'in_progress')",
            params![final_state, now, job_id],
        )?;
        conn.execute(
            "DELETE FROM file_job_chunks WHERE job_id = ?1",
            params![job_id],
        )?;
    }
    Ok(())
}

/// Failing an endpoint's waiting/in-progress targets is part of the same
/// transaction as revoking its enrollment epoch, so revoked devices cannot
/// strand payload reservations or retain queued work.
pub(crate) fn fail_file_jobs_for_revoked_endpoint(
    conn: &Connection,
    computer_id: &str,
    now: i64,
) -> AppResult<()> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT job_id FROM file_job_targets
         WHERE computer_id = ?1 AND state IN ('awaiting_upload', 'queued', 'in_progress')
         ORDER BY job_id LIMIT 1000",
    )?;
    let job_ids = stmt
        .query_map(params![computer_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    conn.execute(
        "UPDATE file_job_targets SET state = 'failed',
                result_detail = 'endpoint_revoked', finished_at = ?1
         WHERE computer_id = ?2 AND state IN ('awaiting_upload', 'queued', 'in_progress')",
        params![now, computer_id],
    )?;
    for job_id in job_ids {
        recalculate_file_job_if_terminal(conn, &job_id, now)?;
    }
    Ok(())
}

impl Service {
    /// Return aggregate logical payload usage for the authenticated operator.
    /// This reports quota reservations, not filesystem free space.
    pub fn file_storage_summary(&self, auth: &AuthContext) -> AppResult<FileStorageSummary> {
        self.require_security_ok()?;
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            expire_file_jobs(conn, now)?;
            crate::file_requests::close_expired_requests(conn, now)?;

            let active_file_jobs: i64 = conn.query_row(
                "SELECT COUNT(*) FROM file_jobs
                 WHERE state IN ('uploading', 'queued', 'in_progress')",
                [],
                |row| row.get(0),
            )?;
            let delivery_payload_bytes: i64 = conn.query_row(
                "SELECT COALESCE(SUM(file_size_bytes), 0) FROM file_jobs
                 WHERE state IN ('uploading', 'queued', 'in_progress')",
                [],
                |row| row.get(0),
            )?;
            let active_request_uploads: i64 = conn.query_row(
                "SELECT COUNT(*) FROM file_request_submissions WHERE state = 'uploading'",
                [],
                |row| row.get(0),
            )?;
            let request_payload_bytes: i64 = conn.query_row(
                "SELECT COALESCE(SUM(f.file_size_bytes), 0)
                 FROM file_request_submission_files f
                 JOIN file_request_submissions s ON s.id = f.submission_id
                 WHERE s.state IN ('uploading', 'received') AND f.content_available = 1",
                [],
                |row| row.get(0),
            )?;
            let (retained_received_files, retained_received_bytes): (i64, i64) = conn.query_row(
                "SELECT COUNT(*), COALESCE(SUM(f.file_size_bytes), 0)
                 FROM file_request_submission_files f
                 JOIN file_request_submissions s ON s.id = f.submission_id
                 WHERE s.state = 'received' AND f.content_available = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;

            let delivery_payload_bytes = to_u64(delivery_payload_bytes, "delivery payload usage")?;
            let request_payload_bytes = to_u64(request_payload_bytes, "request payload usage")?;
            let reserved_payload_bytes =
                delivery_payload_bytes.saturating_add(request_payload_bytes);
            let payload_limit_bytes = to_u64(FILE_STORAGE_MAX_BYTES, "file storage quota")?;
            Ok(FileStorageSummary {
                payload_limit_bytes,
                delivery_payload_bytes,
                request_payload_bytes,
                reserved_payload_bytes,
                available_payload_bytes: payload_limit_bytes.saturating_sub(reserved_payload_bytes),
                active_file_jobs: to_u64(active_file_jobs, "active file job count")?,
                active_file_job_limit: to_u64(FILE_JOB_MAX_ACTIVE_COUNT, "active file job limit")?,
                active_request_uploads: to_u64(
                    active_request_uploads,
                    "active request upload count",
                )?,
                active_request_upload_limit: to_u64(
                    crate::file_requests::FILE_REQUEST_MAX_ACTIVE_UPLOADS,
                    "active request upload limit",
                )?,
                retained_received_files: to_u64(
                    retained_received_files,
                    "retained received file count",
                )?,
                retained_received_bytes: to_u64(
                    retained_received_bytes,
                    "retained received payload usage",
                )?,
            })
        })
    }

    /// Return the newest fresh, signed local recipient for an explicitly
    /// operated computer so the Manager can label its confirmation dialog.
    pub fn file_job_recipient(
        &self,
        auth: &AuthContext,
        computer_id: &str,
    ) -> AppResult<FileJobRecipientView> {
        self.require_security_ok()?;
        if !auth.can_operate {
            return Err(AppError::forbidden(
                "computer operation permission is required",
            ));
        }
        let computer_id = canonical_uuid(computer_id, "computer_id")?;
        let now = now_unix();
        self.with_conn(|conn| {
            require_current_operator_session(conn, auth, now)?;
            require_operate_scope(conn, &auth.account_id, &computer_id)?;
            let recipient: Option<(String, Option<String>, Option<String>, i64)> = conn
                .query_row(
                    "SELECT s.id, s.local_user_id, s.local_user_display_name, s.created_at
                     FROM endpoint_sessions s
                     JOIN computers c ON c.id = s.computer_id
                     WHERE s.computer_id = ?1 AND s.revoked_at IS NULL
                       AND s.expires_at > ?2 AND s.created_at > ?3
                       AND s.enrollment_epoch = c.enrollment_epoch
                       AND c.enrollment_state = 'enrolled'
                       AND c.approved_incarnation_identity = c.public_identity
                     ORDER BY s.created_at DESC, s.id DESC LIMIT 1",
                    params![
                        computer_id,
                        now,
                        now - FILE_RECIPIENT_SESSION_FRESHNESS_SECS
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let Some((session_id, Some(_local_user_id), Some(display_name), verified_at)) =
                recipient
            else {
                return Err(AppError::conflict(
                    "the target has no fresh, verifiable signed-in recipient",
                    Some("file_recipient_unavailable".into()),
                ));
            };
            Ok(FileJobRecipientView {
                computer_id,
                session_id,
                display_name,
                verified_at_unix: verified_at,
            })
        })
    }

    /// Create a durable push job after checking the current manager session,
    /// operator role, and a capability-specific `operate` assignment for each
    /// enrolled target. Cross-server targets cannot occur in this server-local
    /// API; the Qt client partitions them before dispatch.
    pub fn create_file_job(
        &self,
        auth: &AuthContext,
        req: CreateFileJobRequest,
    ) -> AppResult<FileJobView> {
        self.require_security_ok()?;
        if !auth.can_operate {
            return Err(AppError::forbidden(
                "computer operation permission is required",
            ));
        }
        let file_name = validate_file_name(&req.file_name)?;
        if req.file_size_bytes > FILE_JOB_MAX_SIZE_BYTES {
            return Err(AppError::bad_request(
                "file exceeds the 128 MiB v1 job limit",
            ));
        }
        let size = i64::try_from(req.file_size_bytes)
            .map_err(|_| AppError::bad_request("file_size_bytes is too large"))?;
        let sha256 = validate_sha256(&req.sha256, "sha256")?;
        let mut computer_ids = Vec::with_capacity(req.computer_ids.len());
        if req.computer_ids.is_empty() || req.computer_ids.len() > FILE_JOB_MAX_TARGETS {
            return Err(AppError::bad_request(
                "computer_ids must contain between 1 and 50 targets",
            ));
        }
        for value in &req.computer_ids {
            let id = canonical_uuid(value, "computer_id")?;
            if computer_ids.contains(&id) {
                return Err(AppError::bad_request("computer_ids must be unique"));
            }
            computer_ids.push(id);
        }
        if req.expected_recipients.len() != computer_ids.len() {
            return Err(AppError::bad_request(
                "expected_recipients must match each target computer",
            ));
        }
        let mut expected_recipient_sessions = Vec::with_capacity(req.expected_recipients.len());
        for (expected, computer_id) in req.expected_recipients.iter().zip(&computer_ids) {
            if canonical_uuid(&expected.computer_id, "expected_recipients.computer_id")?
                != *computer_id
            {
                return Err(AppError::bad_request(
                    "expected_recipients must use the same target order as computer_ids",
                ));
            }
            expected_recipient_sessions.push(canonical_uuid(
                &expected.session_id,
                "expected_recipients.session_id",
            )?);
        }
        let chunk_count = if size == 0 {
            0_i64
        } else {
            (size + FILE_JOB_CHUNK_SIZE_BYTES as i64 - 1) / FILE_JOB_CHUNK_SIZE_BYTES as i64
        };
        let initial_state = if size == 0 { "queued" } else { "uploading" };
        let target_state = if size == 0 {
            "queued"
        } else {
            "awaiting_upload"
        };
        if size == 0 && sha256 != hex::encode(Sha256::digest([])) {
            return Err(AppError::bad_request(
                "zero-byte file sha256 must match the empty file",
            ));
        }

        let job_id = Uuid::new_v4().to_string();
        let now = now_unix();
        let upload_expires_at = now + FILE_JOB_UPLOAD_TTL_SECS;
        let delivery_expires_at = now + FILE_JOB_DELIVERY_TTL_SECS;
        self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            expire_file_jobs(conn, now)?;
            let mut target_recipients = Vec::with_capacity(computer_ids.len());
            for (computer_id, expected_session_id) in
                computer_ids.iter().zip(&expected_recipient_sessions)
            {
                require_operate_scope(conn, &auth.account_id, computer_id)?;
                let recipient: Option<(String, Option<String>, Option<String>)> = conn
                    .query_row(
                        "SELECT s.id, s.local_user_id, s.local_user_display_name
                         FROM endpoint_sessions s
                         JOIN computers c ON c.id = s.computer_id
                         WHERE s.computer_id = ?1 AND s.revoked_at IS NULL
                           AND s.expires_at > ?2 AND s.created_at > ?3
                           AND s.enrollment_epoch = c.enrollment_epoch
                           AND c.enrollment_state = 'enrolled'
                           AND c.approved_incarnation_identity = c.public_identity
                         ORDER BY s.created_at DESC, s.id DESC LIMIT 1",
                        params![
                            computer_id,
                            now,
                            now - FILE_RECIPIENT_SESSION_FRESHNESS_SECS
                        ],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                let Some((session_id, Some(local_user_id), Some(display_name))) = recipient else {
                    return Err(AppError::conflict(
                        "the target has no fresh, verifiable signed-in recipient",
                        Some("file_recipient_unavailable".into()),
                    ));
                };
                if session_id != *expected_session_id {
                    return Err(AppError::conflict(
                        "the signed-in recipient changed before confirmation",
                        Some("file_recipient_changed".into()),
                    ));
                }
                target_recipients.push((local_user_id, display_name));
            }
            let active_jobs: i64 = conn.query_row(
                "SELECT COUNT(*) FROM file_jobs
                 WHERE state IN ('uploading', 'queued', 'in_progress')",
                [],
                |row| row.get(0),
            )?;
            let account_active_jobs: i64 = conn.query_row(
                "SELECT COUNT(*) FROM file_jobs WHERE owner_account_id = ?1
                 AND state IN ('uploading', 'queued', 'in_progress')",
                params![auth.account_id],
                |row| row.get(0),
            )?;
            if active_jobs >= FILE_JOB_MAX_ACTIVE_COUNT
                || account_active_jobs >= FILE_JOB_MAX_ACTIVE_COUNT_PER_ACCOUNT
            {
                return Err(AppError::rate_limited(
                    "active file job count limit is full",
                ));
            }
            let reserved_bytes: i64 = conn.query_row(
                "SELECT COALESCE(SUM(file_size_bytes), 0) FROM file_jobs
                 WHERE state IN ('uploading', 'queued', 'in_progress')",
                [],
                |row| row.get(0),
            )?;
            let request_storage_bytes: i64 = conn.query_row(
                "SELECT COALESCE(SUM(f.file_size_bytes), 0)
                 FROM file_request_submission_files f
                 JOIN file_request_submissions s ON s.id = f.submission_id
                 WHERE s.state IN ('uploading', 'received') AND f.content_available = 1",
                [],
                |row| row.get(0),
            )?;
            if reserved_bytes
                .saturating_add(request_storage_bytes)
                .saturating_add(size)
                > FILE_STORAGE_MAX_BYTES
            {
                return Err(AppError::rate_limited(
                    "active file job storage quota is full",
                ));
            }
            conn.execute(
                "INSERT INTO file_jobs (
                    id, owner_account_id, direction, file_name, file_size_bytes,
                    sha256, chunk_size_bytes, chunk_count, state, created_at,
                    updated_at, upload_expires_at, delivery_expires_at
                 ) VALUES (?1, ?2, 'push', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?10, ?11)",
                params![
                    job_id,
                    auth.account_id,
                    file_name,
                    size,
                    sha256,
                    FILE_JOB_CHUNK_SIZE_BYTES as i64,
                    chunk_count,
                    initial_state,
                    now,
                    upload_expires_at,
                    delivery_expires_at
                ],
            )?;
            for (computer_id, (recipient_local_user_id, recipient_display_name)) in
                computer_ids.iter().zip(target_recipients.iter())
            {
                conn.execute(
                    "INSERT INTO file_job_targets (
                        job_id, computer_id, recipient_local_user_id,
                        recipient_local_user_display_name, state
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        job_id,
                        computer_id,
                        recipient_local_user_id,
                        recipient_display_name,
                        target_state
                    ],
                )?;
            }
            let mut audit_targets = Vec::with_capacity(computer_ids.len() + 1);
            audit_targets.push(job_id.clone());
            audit_targets.extend(computer_ids.iter().cloned());
            crate::audit::record_successful_event(
                conn,
                auth,
                "file.delivery_created",
                &audit_targets,
                "recipient_confirmed",
                now,
            )?;
            load_file_job_view(conn, &job_id)
        })
    }

    /// Bounded owner-only list of durable jobs and per-target outcomes.
    pub fn list_file_jobs(&self, auth: &AuthContext) -> AppResult<FileJobListResponse> {
        self.require_security_ok()?;
        let now = now_unix();
        let jobs = self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            expire_file_jobs(conn, now)?;
            let mut stmt = conn.prepare(
                "SELECT id FROM file_jobs WHERE owner_account_id = ?1
                 ORDER BY created_at DESC, id LIMIT ?2",
            )?;
            let ids = stmt
                .query_map(
                    params![auth.account_id, FILE_JOB_MAX_PAGE_SIZE as i64],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?;
            ids.iter()
                .map(|id| load_file_job_view(conn, id))
                .collect::<AppResult<Vec<_>>>()
        })?;
        Ok(FileJobListResponse {
            jobs,
            max_page_size: FILE_JOB_MAX_PAGE_SIZE,
        })
    }

    /// Owner-only job details. Target results remain separate and never imply
    /// that a multi-target delivery was atomic.
    pub fn get_file_job(&self, auth: &AuthContext, job_id: &str) -> AppResult<FileJobView> {
        self.require_security_ok()?;
        let job_id = canonical_uuid(job_id, "job_id")?;
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            expire_file_jobs(conn, now)?;
            let row = read_job_row(conn, &job_id)?;
            if row.1 != auth.account_id {
                return Err(AppError::not_found("file job not found"));
            }
            load_file_job_view(conn, &job_id)
        })
    }

    /// Cancel an owned upload or queued delivery after the manager confirms
    /// the displayed job ID. Work already leased to an endpoint is committed
    /// and cannot be cancelled through this surface.
    pub fn cancel_file_job(
        &self,
        auth: &AuthContext,
        job_id: &str,
        req: CancelFileJobRequest,
    ) -> AppResult<FileJobView> {
        self.require_security_ok()?;
        let job_id = canonical_uuid(job_id, "job_id")?;
        if req.confirm_job_id != job_id {
            return Err(AppError::bad_request(
                "the displayed file job ID must be confirmed",
            ));
        }
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_manager_session(conn, auth, now)?;
            expire_file_jobs(conn, now)?;
            let job = read_job_row(conn, &job_id)?;
            if job.1 != auth.account_id {
                return Err(AppError::not_found("file job not found"));
            }
            if job.8 == "cancelled" {
                return load_file_job_view(conn, &job_id);
            }
            if !matches!(job.8.as_str(), "uploading" | "queued") {
                return Err(AppError::conflict(
                    "only uploads and unleased queued jobs can be cancelled",
                    Some("file_job_already_committed".into()),
                ));
            }
            conn.execute(
                "UPDATE file_job_targets SET state = 'cancelled',
                        result_detail = 'cancelled_by_owner', finished_at = ?1
                 WHERE job_id = ?2 AND state IN ('awaiting_upload', 'queued')",
                params![now, job_id],
            )?;
            let changed = conn.execute(
                "UPDATE file_jobs SET state = 'cancelled', updated_at = ?1
                 WHERE id = ?2 AND owner_account_id = ?3 AND state IN ('uploading', 'queued')",
                params![now, job_id, auth.account_id],
            )?;
            if changed != 1 {
                return Err(AppError::conflict(
                    "file job changed before cancellation",
                    Some("file_job_changed".into()),
                ));
            }
            conn.execute(
                "DELETE FROM file_job_chunks WHERE job_id = ?1",
                params![job_id],
            )?;
            crate::audit::record_successful_event(
                conn,
                auth,
                "file.delivery_cancelled",
                std::slice::from_ref(&job_id),
                "cancelled_before_lease",
                now,
            )?;
            load_file_job_view(conn, &job_id)
        })
    }

    /// Persist or replace one bounded upload chunk. Repeated identical chunks
    /// are idempotent. The job moves to `queued` only after its assembled
    /// SHA-256 matches the declaration.
    pub fn put_file_job_chunk(
        &self,
        auth: &AuthContext,
        job_id: &str,
        chunk_index: u32,
        bytes: &[u8],
    ) -> AppResult<FileJobChunkReceipt> {
        self.require_security_ok()?;
        if !auth.can_operate {
            return Err(AppError::forbidden(
                "computer operation permission is required",
            ));
        }
        let job_id = canonical_uuid(job_id, "job_id")?;
        let chunk_hash = hex::encode(Sha256::digest(bytes));
        let now = now_unix();
        self.with_tx(|conn| {
            expire_file_jobs(conn, now)?;
            let job = require_job_operator(conn, auth, &job_id, now)?;
            let declared_size = to_u64(job.4, "file size")?;
            let declared_count = u32::try_from(job.7)
                .map_err(|_| AppError::unprocessable("stored chunk count is invalid"))?;
            if chunk_index >= declared_count {
                return Err(AppError::bad_request("chunk_index is outside this file job"));
            }
            let start = u64::from(chunk_index) * FILE_JOB_CHUNK_SIZE_BYTES as u64;
            let expected_size = (declared_size - start).min(FILE_JOB_CHUNK_SIZE_BYTES as u64);
            if bytes.len() as u64 != expected_size {
                return Err(AppError::bad_request(
                    "chunk byte length does not match its declared position",
                ));
            }
            if job.8 == "uploading" && job.11 <= now {
                return Err(AppError::conflict(
                    "file job upload window expired",
                    Some("upload_expired".into()),
                ));
            }
            if !matches!(job.8.as_str(), "uploading" | "queued" | "in_progress") {
                return Err(AppError::conflict(
                    "file job is no longer accepting chunks",
                    Some("file_job_not_uploading".into()),
                ));
            }

            let existing: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT data FROM file_job_chunks WHERE job_id = ?1 AND chunk_index = ?2",
                    params![job_id, chunk_index],
                    |row| row.get(0),
                )
                .optional()?;
            if existing.as_deref() != Some(bytes) {
                if job.8 != "uploading" {
                    return Err(AppError::conflict(
                        "an accepted file job chunk cannot be changed after queueing",
                        Some("file_job_chunk_immutable".into()),
                    ));
                }
                conn.execute(
                    "INSERT INTO file_job_chunks (job_id, chunk_index, sha256, data, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT (job_id, chunk_index) DO UPDATE SET
                        sha256 = excluded.sha256, data = excluded.data, created_at = excluded.created_at",
                    params![job_id, chunk_index, chunk_hash, bytes, now],
                )?;
            }

            let received_chunks: i64 = conn.query_row(
                "SELECT COUNT(*) FROM file_job_chunks WHERE job_id = ?1",
                params![job_id],
                |row| row.get(0),
            )?;
            let mut finalized = job.8 != "uploading";
            let mut state = job.8.clone();
            if job.8 == "uploading" && received_chunks == i64::from(declared_count) {
                let mut hasher = Sha256::new();
                let mut stmt = conn.prepare(
                    "SELECT chunk_index, data FROM file_job_chunks
                     WHERE job_id = ?1 ORDER BY chunk_index LIMIT ?2",
                )?;
                let mut rows = stmt.query(params![job_id, declared_count])?;
                let mut expected_index = 0_u32;
                while let Some(row) = rows.next()? {
                    let stored_index: u32 = row.get(0)?;
                    if stored_index != expected_index {
                        return Err(AppError::unprocessable(
                            "stored file job chunks are not contiguous",
                        ));
                    }
                    let chunk: Vec<u8> = row.get(1)?;
                    hasher.update(&chunk);
                    expected_index += 1;
                }
                let actual_hash = hex::encode(hasher.finalize());
                if actual_hash == job.5 {
                    conn.execute(
                        "UPDATE file_jobs SET state = 'queued', updated_at = ?1,
                                delivery_expires_at = ?2
                         WHERE id = ?3 AND state = 'uploading'",
                        params![now, now + FILE_JOB_DELIVERY_TTL_SECS, job_id],
                    )?;
                    conn.execute(
                        "UPDATE file_job_targets SET state = 'queued'
                         WHERE job_id = ?1 AND state = 'awaiting_upload'",
                        params![job_id],
                    )?;
                    crate::audit::record_successful_event(
                        conn,
                        auth,
                        "file.delivery_upload_verified",
                        std::slice::from_ref(&job_id),
                        "declared_digest_verified",
                        now,
                    )?;
                    state = "queued".into();
                    finalized = true;
                }
            }
            Ok(FileJobChunkReceipt {
                job_id: job_id.clone(),
                chunk_index,
                received_chunks: u32::try_from(received_chunks)
                    .map_err(|_| AppError::unprocessable("stored chunk count is invalid"))?,
                chunk_count: declared_count,
                state,
                finalized,
            })
        })
    }

    /// Atomically lease queued work to this authenticated endpoint session.
    /// Repeated polls return its current in-progress jobs for restart recovery.
    pub fn endpoint_file_jobs(
        &self,
        auth: &EndpointAuthContext,
    ) -> AppResult<EndpointFileJobListResponse> {
        self.require_security_ok()?;
        let local_user_id = auth.local_user_id.as_deref().ok_or_else(|| {
            AppError::forbidden("a verified local user session is required for file delivery")
        })?;
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_endpoint_session(conn, auth, now)?;
            expire_file_jobs(conn, now)?;
            conn.execute(
                "UPDATE file_job_targets SET state = 'queued'
                 WHERE computer_id = ?1 AND state = 'in_progress'
                   AND recipient_local_user_id IS NOT ?2",
                params![auth.computer_id, local_user_id],
            )?;
            let in_progress_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM file_job_targets
                 WHERE computer_id = ?1 AND recipient_local_user_id = ?2
                   AND state = 'in_progress'",
                params![auth.computer_id, local_user_id],
                |row| row.get(0),
            )?;
            let available_slots = (ENDPOINT_FILE_JOB_MAX_PAGE_SIZE as i64 - in_progress_count)
                .max(0);
            conn.execute(
                "UPDATE file_job_targets SET state = 'in_progress', started_at = COALESCE(started_at, ?1)
                 WHERE computer_id = ?2 AND state = 'queued'
                   AND recipient_local_user_id = ?4
                   AND job_id IN (
                       SELECT t.job_id FROM file_job_targets t
                       JOIN file_jobs j ON j.id = t.job_id
                       WHERE t.computer_id = ?2 AND t.state = 'queued'
                         AND t.recipient_local_user_id = ?4
                         AND j.state IN ('queued', 'in_progress')
                       ORDER BY j.created_at, j.id LIMIT ?3
                   )",
                params![now, auth.computer_id, available_slots, local_user_id],
            )?;
            conn.execute(
                "UPDATE file_jobs SET state = 'in_progress', updated_at = ?1
                 WHERE state = 'queued' AND id IN (
                     SELECT job_id FROM file_job_targets
                     WHERE computer_id = ?2 AND state = 'in_progress'
                       AND recipient_local_user_id = ?3
                 )",
                params![now, auth.computer_id, local_user_id],
            )?;
            let mut stmt = conn.prepare(
                "SELECT j.id, j.file_name, j.file_size_bytes, j.sha256,
                        j.chunk_size_bytes, j.chunk_count, j.state, j.created_at,
                        j.delivery_expires_at
                 FROM file_jobs j
                 JOIN file_job_targets t ON t.job_id = j.id
                 WHERE t.computer_id = ?1 AND t.state = 'in_progress'
                   AND t.recipient_local_user_id = ?3
                   AND j.state = 'in_progress'
                 ORDER BY j.created_at, j.id LIMIT ?2",
            )?;
            let jobs = stmt
                .query_map(
                    params![auth.computer_id, ENDPOINT_FILE_JOB_MAX_PAGE_SIZE as i64, local_user_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, i64>(7)?,
                            row.get::<_, i64>(8)?,
                        ))
                    },
                )?
                .map(|row| {
                    let row = row?;
                    Ok(EndpointFileJobView {
                        id: row.0,
                        file_name: row.1,
                        file_size_bytes: to_u64(row.2, "file size")?,
                        sha256: row.3,
                        chunk_size_bytes: u32::try_from(row.4).map_err(|_| {
                            AppError::unprocessable("stored chunk size is invalid")
                        })?,
                        chunk_count: u32::try_from(row.5).map_err(|_| {
                            AppError::unprocessable("stored chunk count is invalid")
                        })?,
                        state: row.6,
                        created_at_unix: row.7,
                        delivery_expires_at_unix: row.8,
                    })
                })
                .collect::<AppResult<Vec<_>>>()?;
            Ok(EndpointFileJobListResponse {
                jobs,
                max_page_size: ENDPOINT_FILE_JOB_MAX_PAGE_SIZE,
            })
        })
    }

    /// Read exactly one job chunk assigned to this endpoint. Both job state
    /// and target ownership are checked alongside the current endpoint session.
    pub fn endpoint_file_job_chunk(
        &self,
        auth: &EndpointAuthContext,
        job_id: &str,
        chunk_index: u32,
    ) -> AppResult<FileJobChunkContent> {
        self.require_security_ok()?;
        let local_user_id = auth.local_user_id.as_deref().ok_or_else(|| {
            AppError::forbidden("a verified local user session is required for file delivery")
        })?;
        let job_id = canonical_uuid(job_id, "job_id")?;
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_endpoint_session(conn, auth, now)?;
            expire_file_jobs(conn, now)?;
            let row: Option<(String, i64, String, Vec<u8>)> = conn
                .query_row(
                    "SELECT j.state, j.chunk_count, c.sha256, c.data
                     FROM file_jobs j
                     JOIN file_job_targets t ON t.job_id = j.id
                     JOIN file_job_chunks c ON c.job_id = j.id
                     WHERE j.id = ?1 AND t.computer_id = ?2
                       AND t.recipient_local_user_id = ?3
                       AND t.state = 'in_progress' AND j.state = 'in_progress'
                       AND c.chunk_index = ?4",
                    params![job_id, auth.computer_id, local_user_id, chunk_index],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let Some((state, count, sha256, bytes)) = row else {
                return Err(AppError::not_found("file job chunk not found"));
            };
            let count = u32::try_from(count)
                .map_err(|_| AppError::unprocessable("stored chunk count is invalid"))?;
            if state != "in_progress" || chunk_index >= count {
                return Err(AppError::not_found("file job chunk not found"));
            }
            if hex::encode(Sha256::digest(&bytes)) != sha256 {
                return Err(AppError::unprocessable(
                    "stored file job chunk failed its integrity check",
                ));
            }
            Ok(FileJobChunkContent { bytes, sha256 })
        })
    }

    /// Record a target's independently verified delivery result. A success is
    /// accepted only when the endpoint reports the exact declared size and
    /// SHA-256. Once all targets are terminal, payload chunks are removed and
    /// the durable result rows remain.
    pub fn complete_endpoint_file_job(
        &self,
        auth: &EndpointAuthContext,
        job_id: &str,
        req: EndpointFileJobResultRequest,
    ) -> AppResult<EndpointFileJobResultResponse> {
        self.require_security_ok()?;
        let local_user_id = auth.local_user_id.as_deref().ok_or_else(|| {
            AppError::forbidden("a verified local user session is required for file delivery")
        })?;
        let job_id = canonical_uuid(job_id, "job_id")?;
        let detail = match req.detail {
            Some(value) => {
                let trimmed = value.trim();
                if trimmed.len() > 512 || trimmed.chars().any(char::is_control) {
                    return Err(AppError::bad_request(
                        "detail must be at most 512 non-control characters",
                    ));
                }
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            None => None,
        };
        let (received_size, received_sha) = if req.succeeded {
            let size = req.received_size_bytes.ok_or_else(|| {
                AppError::bad_request("successful results require received_size_bytes")
            })?;
            let sha = req.received_sha256.as_deref().ok_or_else(|| {
                AppError::bad_request("successful results require received_sha256")
            })?;
            (Some(size), Some(validate_sha256(sha, "received_sha256")?))
        } else {
            if req.received_size_bytes.is_some() || req.received_sha256.is_some() {
                return Err(AppError::bad_request(
                    "failed results must omit received size and digest",
                ));
            }
            (None, None)
        };
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_endpoint_session(conn, auth, now)?;
            expire_file_jobs(conn, now)?;
            let job = read_job_row(conn, &job_id)?;
            let target: Option<CurrentFileJobTargetResultRow> = conn
                .query_row(
                    "SELECT state, result_detail, received_size_bytes, received_sha256
                     FROM file_job_targets WHERE job_id = ?1 AND computer_id = ?2
                       AND recipient_local_user_id = ?3",
                    params![job_id, auth.computer_id, local_user_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let Some((target_state, current_detail, current_size, current_sha)) = target else {
                return Err(AppError::not_found("file job target not found"));
            };
            let desired_state = if req.succeeded { "completed" } else { "failed" };
            let received_size_i64 = received_size
                .map(i64::try_from)
                .transpose()
                .map_err(|_| AppError::bad_request("received_size_bytes is too large"))?;
            if matches!(target_state.as_str(), "completed" | "failed" | "cancelled") {
                if target_state == desired_state
                    && current_detail == detail
                    && current_size == received_size_i64
                    && current_sha == received_sha
                {
                    return Ok(EndpointFileJobResultResponse {
                        job_id: job_id.clone(),
                        target: read_target_view(conn, &job_id, &auth.computer_id)?,
                    });
                }
                return Err(AppError::conflict(
                    "file job target already has a different terminal result",
                    Some("file_job_target_terminal".into()),
                ));
            }
            if target_state != "in_progress" || job.8 != "in_progress" {
                return Err(AppError::conflict(
                    "file job target is not in progress",
                    Some("file_job_target_not_in_progress".into()),
                ));
            }
            if req.succeeded
                && (received_size != Some(to_u64(job.4, "file size")?)
                    || received_sha.as_deref() != Some(job.5.as_str()))
            {
                return Err(AppError::bad_request(
                    "successful result size and digest must match the file job",
                ));
            }
            let changed = conn.execute(
                "UPDATE file_job_targets
                 SET state = ?1, result_detail = ?2, received_size_bytes = ?3,
                     received_sha256 = ?4, started_at = COALESCE(started_at, ?5), finished_at = ?5
                 WHERE job_id = ?6 AND computer_id = ?7 AND state = 'in_progress'
                   AND recipient_local_user_id = ?8",
                params![
                    desired_state,
                    detail,
                    received_size_i64,
                    received_sha,
                    now,
                    job_id,
                    auth.computer_id,
                    local_user_id
                ],
            )?;
            if changed != 1 {
                return Err(AppError::conflict(
                    "file job target changed before result commit",
                    Some("file_job_target_changed".into()),
                ));
            }
            let (total, terminal, completed, failed): (i64, i64, i64, i64) = conn.query_row(
                "SELECT COUNT(*),
                        SUM(CASE WHEN state IN ('completed', 'failed', 'cancelled') THEN 1 ELSE 0 END),
                        SUM(CASE WHEN state = 'completed' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN state = 'failed' THEN 1 ELSE 0 END)
                 FROM file_job_targets WHERE job_id = ?1",
                params![job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
            if total <= 0 {
                return Err(AppError::unprocessable("file job has no targets"));
            }
            if terminal == total {
                let final_state = if completed == total {
                    "completed"
                } else if failed == total {
                    "failed"
                } else {
                    "partial"
                };
                conn.execute(
                    "UPDATE file_jobs SET state = ?1, updated_at = ?2
                     WHERE id = ?3 AND state = 'in_progress'",
                    params![final_state, now, job_id],
                )?;
                conn.execute("DELETE FROM file_job_chunks WHERE job_id = ?1", params![job_id])?;
            }
            Ok(EndpointFileJobResultResponse {
                job_id: job_id.clone(),
                target: read_target_view(conn, &job_id, &auth.computer_id)?,
            })
        })
    }

    /// Reclaim expired upload and recipient-wait reservations even when the
    /// Manager or endpoint has not made another request.
    pub fn maintain_file_jobs(&self) -> AppResult<()> {
        let now = now_unix();
        self.with_tx(|conn| expire_file_jobs(conn, now))
    }
}
