//! Bounded server-owned file request lifecycle.
//!
//! This module owns request drafts, explicit publication/closure, endpoint
//! user-bound submissions, private content chunks, and scoped manager review.

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::now_unix;
use crate::endpoint_auth::require_current_endpoint_session;
use crate::error::{AppError, AppResult};
use crate::file_jobs::{
    require_operate_scope, validate_file_name, validate_sha256, FILE_JOB_CHUNK_SIZE_BYTES,
    FILE_STORAGE_MAX_BYTES,
};
use crate::models::*;
use crate::service::{require_current_operator_session, AuthContext, EndpointAuthContext, Service};

const FILE_REQUEST_MAX_PAGE_SIZE: usize = 100;
const FILE_REQUEST_MAX_TARGETS: usize = 50;
const FILE_REQUEST_MAX_EXTENSIONS: usize = 64;
const FILE_REQUEST_MAX_ACTIVE_REQUESTS: i64 = 500;
const FILE_REQUEST_MAX_ACTIVE_REQUESTS_PER_OWNER: i64 = 100;
const FILE_REQUEST_MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
const FILE_REQUEST_UPLOAD_TTL_SECS: i64 = 24 * 60 * 60;
pub(crate) const FILE_REQUEST_MAX_ACTIVE_UPLOADS: i64 = 100;
const FILE_REQUEST_MIN_LIFETIME_SECS: i64 = 60;
// Development bound pending the E06 storage and retention budget decision.
const FILE_REQUEST_MAX_LIFETIME_SECS: i64 = 30 * 24 * 60 * 60;

type RequestRow = (
    String,
    String,
    i64,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
);

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

fn validate_title(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 120 || value.chars().any(char::is_control) {
        return Err(AppError::bad_request(
            "title must contain 1 to 120 printable characters",
        ));
    }
    Ok(value.to_string())
}

fn validate_instructions(value: &str) -> AppResult<String> {
    if value.chars().count() > 2000
        || value
            .chars()
            .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        return Err(AppError::bad_request(
            "instructions must be at most 2000 characters and contain no unsupported controls",
        ));
    }
    Ok(value.to_string())
}

fn validate_extensions(values: &[String]) -> AppResult<Vec<String>> {
    if values.is_empty() || values.len() > FILE_REQUEST_MAX_EXTENSIONS {
        return Err(AppError::bad_request(
            "allowed_extensions must contain between 1 and 64 entries",
        ));
    }
    let mut extensions = Vec::with_capacity(values.len());
    for value in values {
        let extension = value.trim().to_ascii_lowercase();
        let valid = extension == "*"
            || (!extension.is_empty()
                && extension.len() <= 32
                && extension.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'_' | b'-')
                })
                && !extension.starts_with('.')
                && !extension.ends_with('.')
                && !extension.contains(".."));
        if !valid {
            return Err(AppError::bad_request(
                "allowed_extensions entries must be safe extensions or a single wildcard",
            ));
        }
        if extensions.contains(&extension) {
            return Err(AppError::bad_request("allowed_extensions must be unique"));
        }
        extensions.push(extension);
    }
    if extensions.contains(&"*".to_string()) && extensions.len() != 1 {
        return Err(AppError::bad_request(
            "the wildcard extension cannot be combined with specific extensions",
        ));
    }
    extensions.sort();
    Ok(extensions)
}

fn validate_computer_ids(values: &[String]) -> AppResult<Vec<String>> {
    if values.is_empty() || values.len() > FILE_REQUEST_MAX_TARGETS {
        return Err(AppError::bad_request(
            "computer_ids must contain between 1 and 50 computers",
        ));
    }
    let mut ids = Vec::with_capacity(values.len());
    for value in values {
        let id = canonical_uuid(value, "computer_id")?;
        if ids.contains(&id) {
            return Err(AppError::bad_request("computer_ids must be unique"));
        }
        ids.push(id);
    }
    Ok(ids)
}

fn validate_deadline(closes_at: i64, now: i64) -> AppResult<()> {
    if closes_at < now + FILE_REQUEST_MIN_LIFETIME_SECS
        || closes_at > now + FILE_REQUEST_MAX_LIFETIME_SECS
    {
        return Err(AppError::bad_request(
            "closes_at_unix must be between one minute and 30 days from now",
        ));
    }
    Ok(())
}

fn valid_account_label(value: &str) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= 128
        && value.chars().all(|ch| !ch.is_control())
}

fn extension_is_allowed(file_name: &str, allowed_extensions: &[String]) -> bool {
    if allowed_extensions.iter().any(|extension| extension == "*") {
        return true;
    }
    let lower_name = file_name.to_ascii_lowercase();
    allowed_extensions.iter().any(|extension| {
        lower_name.ends_with(&format!(".{extension}")) && lower_name.len() > extension.len() + 1
    })
}

pub(crate) fn close_expired_requests(conn: &Connection, now: i64) -> AppResult<()> {
    conn.execute(
        "UPDATE file_requests SET state = 'closed', revision = revision + 1,
             closed_at = closes_at, updated_at = ?1
         WHERE state IN ('draft', 'open') AND closes_at <= ?1",
        params![now],
    )?;
    expire_pending_request_submissions(conn, now)?;
    Ok(())
}

fn expire_pending_request_submissions(conn: &Connection, now: i64) -> AppResult<()> {
    conn.execute(
        "UPDATE file_request_submissions
         SET state = 'expired', updated_at = ?1
         WHERE state = 'uploading' AND (
             upload_expires_at <= ?1 OR request_id IN (
                 SELECT id FROM file_requests WHERE state != 'open' OR closes_at <= ?1
             )
         )",
        params![now],
    )?;
    conn.execute(
        "UPDATE file_request_submission_files SET content_available = 0
         WHERE submission_id IN (
             SELECT id FROM file_request_submissions WHERE state = 'expired'
         )",
        [],
    )?;
    conn.execute(
        "DELETE FROM file_request_submission_chunks
         WHERE file_id IN (
             SELECT f.id FROM file_request_submission_files f
             JOIN file_request_submissions s ON s.id = f.submission_id
             WHERE s.state = 'expired'
         )",
        [],
    )?;
    Ok(())
}

fn load_file_request_view(conn: &Connection, id: &str) -> AppResult<FileRequestView> {
    let row: RequestRow = conn.query_row(
        "SELECT id, title, revision, state, allowed_extensions_json,
                max_file_count, max_total_size_bytes, closes_at,
                replacement_allowed, created_at, published_at, closed_at
         FROM file_requests WHERE id = ?1",
        params![id],
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
            ))
        },
    )?;
    let instructions: String = conn.query_row(
        "SELECT instructions FROM file_requests WHERE id = ?1",
        params![id],
        |row| row.get(0),
    )?;
    let updated_at_unix: i64 = conn.query_row(
        "SELECT updated_at FROM file_requests WHERE id = ?1",
        params![id],
        |row| row.get(0),
    )?;
    let extensions: Vec<String> = serde_json::from_str(&row.4)
        .map_err(|_| AppError::unprocessable("stored file request extensions are invalid"))?;
    let mut statement = conn.prepare(
        "SELECT computer_id FROM file_request_computers
         WHERE request_id = ?1 ORDER BY computer_id",
    )?;
    let computer_ids = statement
        .query_map(params![id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FileRequestView {
        id: row.0,
        title: row.1,
        instructions,
        revision: row.2,
        state: row.3,
        computer_ids,
        allowed_extensions: extensions,
        max_file_count: u32::try_from(row.5)
            .map_err(|_| AppError::unprocessable("stored file request count is invalid"))?,
        max_total_size_bytes: u64::try_from(row.6)
            .map_err(|_| AppError::unprocessable("stored file request size is invalid"))?,
        closes_at_unix: row.7,
        replacement_allowed: row.8 != 0,
        created_at_unix: row.9,
        updated_at_unix,
        published_at_unix: row.10,
        closed_at_unix: row.11,
    })
}

type SubmissionRow = (
    String,
    String,
    i64,
    String,
    String,
    String,
    i64,
    i64,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<String>,
);

fn load_file_request_submission_view(
    conn: &Connection,
    submission_id: &str,
) -> AppResult<FileRequestSubmissionView> {
    let row: SubmissionRow = conn.query_row(
        "SELECT id, request_id, request_revision, computer_id,
                local_user_display_name, state, created_at, upload_expires_at,
                received_at, replaces_submission_id, content_deleted_at,
                content_deleted_by_account_id
         FROM file_request_submissions WHERE id = ?1",
        params![submission_id],
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
            ))
        },
    )?;
    let mut statement = conn.prepare(
        "SELECT id, file_name, file_size_bytes, sha256, chunk_size_bytes,
                chunk_count, state, content_available
         FROM file_request_submission_files WHERE submission_id = ?1
         ORDER BY id",
    )?;
    let files = statement
        .query_map(params![submission_id], |file| {
            Ok((
                file.get::<_, String>(0)?,
                file.get::<_, String>(1)?,
                file.get::<_, i64>(2)?,
                file.get::<_, String>(3)?,
                file.get::<_, i64>(4)?,
                file.get::<_, i64>(5)?,
                file.get::<_, String>(6)?,
                file.get::<_, bool>(7)?,
            ))
        })?
        .map(|file| {
            let file = file?;
            Ok(FileRequestSubmissionFileView {
                id: file.0,
                file_name: file.1,
                file_size_bytes: u64::try_from(file.2)
                    .map_err(|_| AppError::unprocessable("stored file size is invalid"))?,
                sha256: file.3,
                chunk_size_bytes: u32::try_from(file.4)
                    .map_err(|_| AppError::unprocessable("stored chunk size is invalid"))?,
                chunk_count: u32::try_from(file.5)
                    .map_err(|_| AppError::unprocessable("stored chunk count is invalid"))?,
                state: if file.7 {
                    file.6
                } else {
                    "deleted".to_string()
                },
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok(FileRequestSubmissionView {
        id: row.0,
        request_id: row.1,
        request_revision: row.2,
        computer_id: row.3,
        local_user_display_name: row.4,
        state: row.5,
        created_at_unix: row.6,
        upload_expires_at_unix: row.7,
        received_at_unix: row.8,
        replaces_submission_id: row.9,
        content_deleted_at_unix: row.10,
        content_deleted_by_account_id: row.11,
        files,
    })
}

fn load_endpoint_file_request_submission_view(
    conn: &Connection,
    submission_id: &str,
) -> AppResult<FileRequestSubmissionView> {
    let mut view = load_file_request_submission_view(conn, submission_id)?;
    view.content_deleted_by_account_id = None;
    Ok(view)
}

impl Service {
    /// Save a draft. It sends no endpoint work until a separately confirmed
    /// publish call rechecks every target's current operate assignment.
    pub fn create_file_request(
        &self,
        auth: &AuthContext,
        req: CreateFileRequestRequest,
    ) -> AppResult<FileRequestView> {
        self.require_security_ok()?;
        if !auth.can_operate {
            return Err(AppError::forbidden(
                "computer operation permission is required for file requests",
            ));
        }
        let title = validate_title(&req.title)?;
        let instructions = validate_instructions(&req.instructions)?;
        let computer_ids = validate_computer_ids(&req.computer_ids)?;
        let extensions = validate_extensions(&req.allowed_extensions)?;
        let max_file_count = i64::from(req.max_file_count);
        let max_total_size = i64::try_from(req.max_total_size_bytes)
            .map_err(|_| AppError::bad_request("max_total_size_bytes is too large"))?;
        if !(1..=50).contains(&max_file_count)
            || !(1..=FILE_REQUEST_MAX_FILE_BYTES as i64).contains(&max_total_size)
        {
            return Err(AppError::bad_request(
                "file count must be 1 to 50 and total size must be 1 byte to 128 MiB",
            ));
        }
        let now = now_unix();
        validate_deadline(req.closes_at_unix, now)?;
        let request_id = Uuid::new_v4().to_string();
        let extension_json = serde_json::to_string(&extensions)
            .map_err(|_| AppError::unprocessable("file extension rules could not be encoded"))?;
        self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            close_expired_requests(conn, now)?;
            let active_requests: i64 = conn.query_row(
                "SELECT COUNT(*) FROM file_requests WHERE state IN ('draft', 'open')",
                [],
                |row| row.get(0),
            )?;
            let owner_requests: i64 = conn.query_row(
                "SELECT COUNT(*) FROM file_requests
                 WHERE owner_account_id = ?1 AND state IN ('draft', 'open')",
                params![auth.account_id],
                |row| row.get(0),
            )?;
            if active_requests >= FILE_REQUEST_MAX_ACTIVE_REQUESTS
                || owner_requests >= FILE_REQUEST_MAX_ACTIVE_REQUESTS_PER_OWNER
            {
                return Err(AppError::rate_limited("active file request limit is full"));
            }
            for computer_id in &computer_ids {
                require_operate_scope(conn, &auth.account_id, computer_id)?;
                let enrolled: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM computers WHERE id = ?1
                     AND enrollment_state = 'enrolled'
                     AND approved_incarnation_identity = public_identity)",
                    params![computer_id],
                    |row| row.get(0),
                )?;
                if !enrolled {
                    return Err(AppError::conflict(
                        "every file request target must be an enrolled computer",
                        Some("file_request_target_unavailable".into()),
                    ));
                }
            }
            conn.execute(
                "INSERT INTO file_requests (
                    id, owner_account_id, title, instructions, revision, state,
                    allowed_extensions_json, max_file_count, max_total_size_bytes,
                    closes_at, replacement_allowed, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, 1, 'draft', ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
                params![
                    request_id,
                    auth.account_id,
                    title,
                    instructions,
                    extension_json,
                    max_file_count,
                    max_total_size,
                    req.closes_at_unix,
                    req.replacement_allowed,
                    now
                ],
            )?;
            for computer_id in &computer_ids {
                conn.execute(
                    "INSERT INTO file_request_computers (request_id, computer_id)
                     VALUES (?1, ?2)",
                    params![request_id, computer_id],
                )?;
            }
            let mut audit_targets = Vec::with_capacity(computer_ids.len() + 1);
            audit_targets.push(request_id.clone());
            audit_targets.extend(computer_ids.iter().cloned());
            crate::audit::record_successful_event(
                conn,
                auth,
                "file_request.created",
                &audit_targets,
                "request_drafted",
                now,
            )?;
            load_file_request_view(conn, &request_id)
        })
    }

    pub fn list_file_requests(&self, auth: &AuthContext) -> AppResult<FileRequestListResponse> {
        self.require_security_ok()?;
        let now = now_unix();
        let requests = self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            close_expired_requests(conn, now)?;
            let mut statement = conn.prepare(
                "SELECT id FROM file_requests WHERE owner_account_id = ?1
                 ORDER BY created_at DESC, id LIMIT ?2",
            )?;
            let ids = statement
                .query_map(
                    params![auth.account_id, FILE_REQUEST_MAX_PAGE_SIZE as i64],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?;
            ids.iter()
                .map(|id| load_file_request_view(conn, id))
                .collect::<AppResult<Vec<_>>>()
        })?;
        Ok(FileRequestListResponse {
            requests,
            max_page_size: FILE_REQUEST_MAX_PAGE_SIZE,
        })
    }

    pub fn get_file_request(&self, auth: &AuthContext, id: &str) -> AppResult<FileRequestView> {
        self.require_security_ok()?;
        let id = canonical_uuid(id, "request_id")?;
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            close_expired_requests(conn, now)?;
            let owner: Option<String> = conn
                .query_row(
                    "SELECT owner_account_id FROM file_requests WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .optional()?;
            if owner.as_deref() != Some(&auth.account_id) {
                return Err(AppError::not_found("file request not found"));
            }
            load_file_request_view(conn, &id)
        })
    }

    pub fn publish_file_request(
        &self,
        auth: &AuthContext,
        id: &str,
        req: FileRequestRevisionRequest,
    ) -> AppResult<FileRequestView> {
        self.require_security_ok()?;
        if !auth.can_operate {
            return Err(AppError::forbidden(
                "computer operation permission is required for file requests",
            ));
        }
        let id = canonical_uuid(id, "request_id")?;
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            close_expired_requests(conn, now)?;
            let row: Option<(String, String, i64, i64)> = conn
                .query_row(
                    "SELECT owner_account_id, state, revision, closes_at
                     FROM file_requests WHERE id = ?1",
                    params![id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let Some((owner, state, revision, closes_at)) = row else {
                return Err(AppError::not_found("file request not found"));
            };
            if owner != auth.account_id {
                return Err(AppError::not_found("file request not found"));
            }
            if state != "draft" || revision != req.expected_revision {
                return Err(AppError::conflict(
                    "file request changed; refresh before publishing",
                    Some("file_request_revision_changed".into()),
                ));
            }
            validate_deadline(closes_at, now)?;
            let mut statement = conn
                .prepare("SELECT computer_id FROM file_request_computers WHERE request_id = ?1")?;
            let computers = statement
                .query_map(params![id], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            if computers.is_empty() {
                return Err(AppError::conflict(
                    "file request has no eligible computers",
                    Some("file_request_empty_scope".into()),
                ));
            }
            for computer_id in &computers {
                require_operate_scope(conn, &auth.account_id, &computer_id)?;
                let enrolled: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM computers WHERE id = ?1
                     AND enrollment_state = 'enrolled'
                     AND approved_incarnation_identity = public_identity)",
                    params![computer_id],
                    |row| row.get(0),
                )?;
                if !enrolled {
                    return Err(AppError::conflict(
                        "a file request target is no longer enrolled",
                        Some("file_request_target_unavailable".into()),
                    ));
                }
            }
            conn.execute(
                "UPDATE file_requests SET state = 'open', revision = revision + 1,
                    published_at = ?1, updated_at = ?1
                 WHERE id = ?2 AND owner_account_id = ?3 AND state = 'draft' AND revision = ?4",
                params![now, id, auth.account_id, req.expected_revision],
            )?;
            let mut audit_targets = Vec::with_capacity(computers.len() + 1);
            audit_targets.push(id.clone());
            audit_targets.extend(computers);
            crate::audit::record_successful_event(
                conn,
                auth,
                "file_request.published",
                &audit_targets,
                "request_opened",
                now,
            )?;
            load_file_request_view(conn, &id)
        })
    }

    /// Closing is an explicit one-way transition. Completed submissions stay
    /// stored and remain available for authorized manager review.
    pub fn close_file_request(
        &self,
        auth: &AuthContext,
        id: &str,
        req: CloseFileRequestRequest,
    ) -> AppResult<FileRequestView> {
        self.require_security_ok()?;
        let id = canonical_uuid(id, "request_id")?;
        if canonical_uuid(&req.confirm_request_id, "confirm_request_id")? != id {
            return Err(AppError::bad_request(
                "confirm_request_id must exactly match the request ID",
            ));
        }
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            close_expired_requests(conn, now)?;
            let updated = conn.execute(
                "UPDATE file_requests SET state = 'closed', revision = revision + 1,
                    closed_at = ?1, updated_at = ?1
                 WHERE id = ?2 AND owner_account_id = ?3 AND state = 'open' AND revision = ?4",
                params![now, id, auth.account_id, req.expected_revision],
            )?;
            if updated == 0 {
                let exists: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM file_requests WHERE id = ?1
                     AND owner_account_id = ?2)",
                    params![id, auth.account_id],
                    |row| row.get(0),
                )?;
                if !exists {
                    return Err(AppError::not_found("file request not found"));
                }
                return Err(AppError::conflict(
                    "file request is already closed or changed; refresh before closing",
                    Some("file_request_revision_changed".into()),
                ));
            }
            expire_pending_request_submissions(conn, now)?;
            crate::audit::record_successful_event(
                conn,
                auth,
                "file_request.closed",
                std::slice::from_ref(&id),
                "request_closed",
                now,
            )?;
            load_file_request_view(conn, &id)
        })
    }

    /// Reserve a complete manifest for one signed-in local OS user. The
    /// submission remains temporary until every file has been uploaded and its
    /// digest has been verified by `complete_file_request_submission`.
    pub fn create_endpoint_file_request_submission(
        &self,
        auth: &EndpointAuthContext,
        request_id: &str,
        req: CreateFileRequestSubmissionRequest,
    ) -> AppResult<FileRequestSubmissionView> {
        self.require_security_ok()?;
        let request_id = canonical_uuid(request_id, "request_id")?;
        let local_user_id = auth
            .local_user_id
            .clone()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::forbidden("a signed-in local user identity is required"))?;
        let local_user_display_name = auth
            .local_user_display_name
            .clone()
            .filter(|value| valid_account_label(value))
            .ok_or_else(|| {
                AppError::forbidden("a signed-in local user label is required for attribution")
            })?;
        if req.files.is_empty() || req.files.len() > 50 {
            return Err(AppError::bad_request(
                "files must contain between 1 and 50 entries",
            ));
        }
        if req.request_revision <= 0 {
            return Err(AppError::bad_request("request_revision must be positive"));
        }
        let replace_submission_id = match req.replace_submission_id.as_deref() {
            Some(value) => {
                if !req.confirm_replacement {
                    return Err(AppError::bad_request(
                        "confirm_replacement must be true when replacing a submission",
                    ));
                }
                Some(canonical_uuid(value, "replace_submission_id")?)
            }
            None if req.confirm_replacement => {
                return Err(AppError::bad_request(
                    "replace_submission_id is required when confirm_replacement is true",
                ));
            }
            None => None,
        };
        let mut manifest = Vec::with_capacity(req.files.len());
        let mut names = Vec::with_capacity(req.files.len());
        let mut total_size = 0_u64;
        for file in &req.files {
            let file_name = validate_file_name(&file.file_name)?;
            let normalized_name = file_name.to_lowercase();
            if names.contains(&normalized_name) {
                return Err(AppError::bad_request(
                    "manifest file names must be unique without case sensitivity",
                ));
            }
            names.push(normalized_name);
            if file.file_size_bytes > FILE_REQUEST_MAX_FILE_BYTES {
                return Err(AppError::bad_request("a file exceeds the 128 MiB v1 limit"));
            }
            validate_sha256(&file.sha256, "files.sha256")?;
            total_size = total_size
                .checked_add(file.file_size_bytes)
                .ok_or_else(|| AppError::bad_request("manifest size is too large"))?;
            let chunk_count = if file.file_size_bytes == 0 {
                0
            } else {
                file.file_size_bytes
                    .div_ceil(FILE_JOB_CHUNK_SIZE_BYTES as u64)
            };
            manifest.push((
                Uuid::new_v4().to_string(),
                file_name,
                i64::try_from(file.file_size_bytes)
                    .map_err(|_| AppError::bad_request("file size is too large"))?,
                file.sha256.clone(),
                i64::try_from(chunk_count)
                    .map_err(|_| AppError::bad_request("chunk count is too large"))?,
            ));
        }
        if total_size > FILE_REQUEST_MAX_FILE_BYTES {
            return Err(AppError::bad_request(
                "the manifest exceeds the 128 MiB v1 total size limit",
            ));
        }
        let total_size_i64 = i64::try_from(total_size)
            .map_err(|_| AppError::bad_request("manifest size is too large"))?;
        let submission_id = Uuid::new_v4().to_string();
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_endpoint_session(conn, auth, now)?;
            close_expired_requests(conn, now)?;
            let request: Option<(i64, String, i64, i64, i64, String)> = conn
                .query_row(
                    "SELECT r.revision, r.state, r.closes_at, r.max_file_count,
                            r.max_total_size_bytes, r.allowed_extensions_json
                     FROM file_requests r
                     JOIN file_request_computers c ON c.request_id = r.id
                     WHERE r.id = ?1 AND c.computer_id = ?2",
                    params![request_id, auth.computer_id],
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
            let Some((revision, state, closes_at, max_file_count, max_total_size, extension_json)) =
                request
            else {
                return Err(AppError::not_found("open file request not found"));
            };
            if state != "open" || closes_at <= now || revision != req.request_revision {
                return Err(AppError::conflict(
                    "file request is closed, expired, or changed; refresh before submitting",
                    Some("file_request_revision_changed".into()),
                ));
            }
            let allowed_extensions: Vec<String> =
                serde_json::from_str(&extension_json).map_err(|_| {
                    AppError::unprocessable("stored file request extensions are invalid")
                })?;
            if manifest
                .iter()
                .any(|file| !extension_is_allowed(&file.1, &allowed_extensions))
            {
                return Err(AppError::bad_request(
                    "a manifest file does not match the request's allowed extensions",
                ));
            }

            let mut replaced_size = 0_i64;
            let mut replaced_count = 0_i64;
            if let Some(old_id) = &replace_submission_id {
                if !conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM file_request_submissions
                     WHERE id = ?1 AND request_id = ?2 AND computer_id = ?3
                       AND local_user_id = ?4 AND state = 'received')",
                    params![old_id, request_id, auth.computer_id, local_user_id],
                    |row| row.get::<_, bool>(0),
                )? {
                    return Err(AppError::not_found(
                        "replaceable submission not found for this local user",
                    ));
                }
                let replacement_allowed: bool = conn.query_row(
                    "SELECT replacement_allowed FROM file_requests WHERE id = ?1",
                    params![request_id],
                    |row| row.get::<_, bool>(0),
                )?;
                if !replacement_allowed {
                    return Err(AppError::forbidden(
                        "this request does not allow replacing a submission",
                    ));
                }
                let already_replacing: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM file_request_submissions
                     WHERE replaces_submission_id = ?1 AND state = 'uploading')",
                    params![old_id],
                    |row| row.get(0),
                )?;
                if already_replacing {
                    return Err(AppError::conflict(
                        "a replacement upload is already in progress",
                        Some("file_replacement_in_progress".into()),
                    ));
                }
                let replacement_usage: (i64, i64) = conn.query_row(
                    "SELECT COUNT(*), COALESCE(SUM(file_size_bytes), 0)
                     FROM file_request_submission_files
                     WHERE submission_id = ?1 AND content_available = 1",
                    params![old_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                replaced_count = replacement_usage.0;
                replaced_size = replacement_usage.1;
            }
            let current_usage: (i64, i64) = conn.query_row(
                "SELECT COUNT(*), COALESCE(SUM(f.file_size_bytes), 0)
                 FROM file_request_submission_files f
                 JOIN file_request_submissions s ON s.id = f.submission_id
                 WHERE s.request_id = ?1 AND s.computer_id = ?2 AND s.local_user_id = ?3
                   AND s.state IN ('uploading', 'received') AND f.content_available = 1",
                params![request_id, auth.computer_id, local_user_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if current_usage.0 - replaced_count + manifest.len() as i64 > max_file_count
                || current_usage
                    .1
                    .saturating_sub(replaced_size)
                    .saturating_add(total_size_i64)
                    > max_total_size
            {
                return Err(AppError::rate_limited(
                    "the request file count or aggregate size limit is full",
                ));
            }
            let active_uploads: i64 = conn.query_row(
                "SELECT COUNT(*) FROM file_request_submissions WHERE state = 'uploading'",
                [],
                |row| row.get(0),
            )?;
            let stored_bytes: i64 = conn.query_row(
                "SELECT COALESCE(SUM(f.file_size_bytes), 0)
                 FROM file_request_submission_files f
                 JOIN file_request_submissions s ON s.id = f.submission_id
                 WHERE s.state IN ('uploading', 'received') AND f.content_available = 1",
                [],
                |row| row.get(0),
            )?;
            let file_job_reserved_bytes: i64 = conn.query_row(
                "SELECT COALESCE(SUM(file_size_bytes), 0) FROM file_jobs
                 WHERE state IN ('uploading', 'queued', 'in_progress')",
                [],
                |row| row.get(0),
            )?;
            if active_uploads >= FILE_REQUEST_MAX_ACTIVE_UPLOADS
                || stored_bytes
                    .saturating_add(file_job_reserved_bytes)
                    .saturating_add(total_size_i64)
                    > FILE_STORAGE_MAX_BYTES
            {
                return Err(AppError::rate_limited(
                    "file request storage or active upload quota is full",
                ));
            }
            let upload_expires_at = (now + FILE_REQUEST_UPLOAD_TTL_SECS).min(closes_at);
            conn.execute(
                "INSERT INTO file_request_submissions (
                    id, request_id, request_revision, computer_id, local_user_id,
                    local_user_display_name, state, replaces_submission_id,
                    created_at, updated_at, upload_expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'uploading', ?7, ?8, ?8, ?9)",
                params![
                    submission_id,
                    request_id,
                    revision,
                    auth.computer_id,
                    local_user_id,
                    local_user_display_name,
                    replace_submission_id,
                    now,
                    upload_expires_at
                ],
            )?;
            for (file_id, file_name, size, digest, chunk_count) in &manifest {
                conn.execute(
                    "INSERT INTO file_request_submission_files (
                        id, submission_id, file_name, file_size_bytes, sha256,
                        chunk_size_bytes, chunk_count, state, created_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'uploading', ?8)",
                    params![
                        file_id,
                        submission_id,
                        file_name,
                        size,
                        digest,
                        FILE_JOB_CHUNK_SIZE_BYTES as i64,
                        chunk_count,
                        now
                    ],
                )?;
            }
            load_endpoint_file_request_submission_view(conn, &submission_id)
        })
    }

    /// Resume/status view is restricted to the current endpoint and the exact
    /// signed local OS user bound when each submission was created.
    pub fn endpoint_file_request_submissions(
        &self,
        auth: &EndpointAuthContext,
        request_id: &str,
    ) -> AppResult<Vec<FileRequestSubmissionView>> {
        self.require_security_ok()?;
        let request_id = canonical_uuid(request_id, "request_id")?;
        let local_user_id = auth
            .local_user_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::forbidden("a signed-in local user identity is required"))?;
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_endpoint_session(conn, auth, now)?;
            close_expired_requests(conn, now)?;
            let is_targeted: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM file_request_computers
                 WHERE request_id = ?1 AND computer_id = ?2)",
                params![request_id, auth.computer_id],
                |row| row.get(0),
            )?;
            if !is_targeted {
                return Err(AppError::not_found("file request not found"));
            }
            let mut statement = conn.prepare(
                "SELECT id FROM file_request_submissions
                 WHERE request_id = ?1 AND computer_id = ?2 AND local_user_id = ?3
                 ORDER BY created_at DESC, id LIMIT ?4",
            )?;
            let ids = statement
                .query_map(
                    params![
                        request_id,
                        auth.computer_id,
                        local_user_id,
                        FILE_REQUEST_MAX_PAGE_SIZE as i64
                    ],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?;
            ids.iter()
                .map(|id| load_endpoint_file_request_submission_view(conn, id))
                .collect::<AppResult<Vec<_>>>()
        })
    }

    pub fn put_endpoint_file_request_chunk(
        &self,
        auth: &EndpointAuthContext,
        request_id: &str,
        submission_id: &str,
        file_id: &str,
        chunk_index: u32,
        data: &[u8],
    ) -> AppResult<FileRequestSubmissionChunkReceipt> {
        self.require_security_ok()?;
        let request_id = canonical_uuid(request_id, "request_id")?;
        let submission_id = canonical_uuid(submission_id, "submission_id")?;
        let file_id = canonical_uuid(file_id, "file_id")?;
        let local_user_id = auth
            .local_user_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::forbidden("a signed-in local user identity is required"))?;
        let now = now_unix();
        let digest = hex::encode(Sha256::digest(data));
        self.with_tx(|conn| {
            require_current_endpoint_session(conn, auth, now)?;
            close_expired_requests(conn, now)?;
            let file: Option<(i64, i64, String, i64)> = conn
                .query_row(
                    "SELECT f.file_size_bytes, f.chunk_count, f.state, s.request_revision
                     FROM file_request_submission_files f
                     JOIN file_request_submissions s ON s.id = f.submission_id
                     JOIN file_requests r ON r.id = s.request_id
                     WHERE f.id = ?1 AND s.id = ?2 AND r.id = ?3
                       AND s.computer_id = ?4 AND s.local_user_id = ?5
                       AND s.state = 'uploading' AND s.upload_expires_at > ?6
                       AND r.state = 'open' AND r.closes_at > ?6
                       AND s.request_revision = r.revision",
                    params![
                        file_id,
                        submission_id,
                        request_id,
                        auth.computer_id,
                        local_user_id,
                        now
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let Some((file_size, chunk_count, file_state, _request_revision)) = file else {
                return Err(AppError::not_found("active file request upload not found"));
            };
            if file_state != "uploading" {
                return Err(AppError::conflict(
                    "file request upload is no longer writable",
                    Some("file_request_submission_closed".into()),
                ));
            }
            if chunk_count <= 0 || i64::from(chunk_index) >= chunk_count {
                return Err(AppError::bad_request("chunk_index is outside the manifest"));
            }
            let chunk_start = i64::from(chunk_index) * FILE_JOB_CHUNK_SIZE_BYTES as i64;
            let expected_len = (file_size - chunk_start).min(FILE_JOB_CHUNK_SIZE_BYTES as i64);
            if expected_len <= 0 || data.len() as i64 != expected_len {
                return Err(AppError::bad_request(
                    "chunk has an invalid size for its manifest position",
                ));
            }
            let existing: Option<(String, Vec<u8>)> = conn
                .query_row(
                    "SELECT sha256, data FROM file_request_submission_chunks
                     WHERE file_id = ?1 AND chunk_index = ?2",
                    params![file_id, i64::from(chunk_index)],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let already_present = existing
                .as_ref()
                .map(|(existing_digest, existing_data)| {
                    existing_digest == &digest && existing_data.as_slice() == data
                })
                .unwrap_or(false);
            if !already_present {
                conn.execute(
                    "INSERT INTO file_request_submission_chunks (
                        file_id, chunk_index, sha256, data, created_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(file_id, chunk_index) DO UPDATE SET
                        sha256 = excluded.sha256, data = excluded.data,
                        created_at = excluded.created_at",
                    params![file_id, i64::from(chunk_index), digest, data, now],
                )?;
            }
            Ok(FileRequestSubmissionChunkReceipt {
                submission_id,
                file_id,
                chunk_index,
                sha256: digest,
                already_present,
            })
        })
    }

    pub fn complete_endpoint_file_request_submission(
        &self,
        auth: &EndpointAuthContext,
        request_id: &str,
        submission_id: &str,
        req: CompleteFileRequestSubmissionRequest,
    ) -> AppResult<FileRequestSubmissionView> {
        self.require_security_ok()?;
        let request_id = canonical_uuid(request_id, "request_id")?;
        let submission_id = canonical_uuid(submission_id, "submission_id")?;
        if canonical_uuid(&req.confirm_submission_id, "confirm_submission_id")? != submission_id {
            return Err(AppError::bad_request(
                "confirm_submission_id must exactly match the submission ID",
            ));
        }
        let local_user_id = auth
            .local_user_id
            .clone()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::forbidden("a signed-in local user identity is required"))?;
        let now = now_unix();
        let result = self.with_tx(|conn| {
            require_current_endpoint_session(conn, auth, now)?;
            close_expired_requests(conn, now)?;
            let submission: Option<(String, String, i64, i64, String, Option<String>)> = conn
                .query_row(
                    "SELECT s.state, r.state, s.request_revision, r.revision,
                            r.state, s.replaces_submission_id
                     FROM file_request_submissions s
                     JOIN file_requests r ON r.id = s.request_id
                     WHERE s.id = ?1 AND s.request_id = ?2
                       AND s.computer_id = ?3 AND s.local_user_id = ?4",
                    params![submission_id, request_id, auth.computer_id, local_user_id],
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
            let Some((
                submission_state,
                request_state,
                bound_revision,
                current_revision,
                _state_again,
                replaces_id,
            )) = submission
            else {
                return Err(AppError::not_found("file request submission not found"));
            };
            if submission_state == "received" {
                return Ok(Some(load_endpoint_file_request_submission_view(
                    conn,
                    &submission_id,
                )?));
            }
            if submission_state != "uploading" {
                return Err(AppError::conflict(
                    "file request submission is no longer active",
                    Some("file_request_submission_closed".into()),
                ));
            }
            if request_state != "open"
                || bound_revision != req.request_revision
                || current_revision != req.request_revision
            {
                return Err(AppError::conflict(
                    "file request was closed or changed during upload",
                    Some("file_request_revision_changed".into()),
                ));
            }
            let mut files_stmt = conn.prepare(
                "SELECT id, file_size_bytes, sha256, chunk_count
                 FROM file_request_submission_files WHERE submission_id = ?1 ORDER BY id",
            )?;
            let files = files_stmt
                .query_map(params![submission_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            if files.is_empty() {
                return Err(AppError::unprocessable("submission manifest is empty"));
            }
            for (file_id, file_size, expected_digest, expected_chunks) in &files {
                let mut chunk_stmt = conn.prepare(
                    "SELECT chunk_index, data FROM file_request_submission_chunks
                     WHERE file_id = ?1 ORDER BY chunk_index",
                )?;
                let chunk_rows = chunk_stmt.query_map(params![file_id], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
                })?;
                let mut hasher = Sha256::new();
                let mut bytes_seen = 0_i64;
                let mut chunks_seen = 0_i64;
                let mut missing_chunk = false;
                let mut invalid_chunk = false;
                for (expected_index, chunk_result) in chunk_rows.enumerate() {
                    let (chunk_index, chunk) = chunk_result?;
                    if chunk_index != expected_index as i64 {
                        missing_chunk = true;
                        break;
                    }
                    let expected_len =
                        (*file_size - bytes_seen).min(FILE_JOB_CHUNK_SIZE_BYTES as i64);
                    if expected_len <= 0 || chunk.len() as i64 != expected_len {
                        invalid_chunk = true;
                        break;
                    }
                    bytes_seen += chunk.len() as i64;
                    chunks_seen += 1;
                    hasher.update(&chunk);
                }
                if missing_chunk || chunks_seen < *expected_chunks {
                    return Err(AppError::conflict(
                        "file request submission still has missing chunks",
                        Some("file_request_upload_incomplete".into()),
                    ));
                }
                let actual_digest = hex::encode(hasher.finalize());
                if invalid_chunk
                    || chunks_seen != *expected_chunks
                    || bytes_seen != *file_size
                    || actual_digest != *expected_digest
                {
                    conn.execute(
                        "UPDATE file_request_submissions SET state = 'failed', updated_at = ?1
                         WHERE id = ?2 AND state = 'uploading'",
                        params![now, submission_id],
                    )?;
                    conn.execute(
                        "UPDATE file_request_submission_files SET content_available = 0
                         WHERE submission_id = ?1",
                        params![submission_id],
                    )?;
                    conn.execute(
                        "DELETE FROM file_request_submission_chunks
                         WHERE file_id IN (SELECT id FROM file_request_submission_files
                                           WHERE submission_id = ?1)",
                        params![submission_id],
                    )?;
                    return Ok(None);
                }
            }
            conn.execute(
                "UPDATE file_request_submission_files SET state = 'received'
                 WHERE submission_id = ?1",
                params![submission_id],
            )?;
            conn.execute(
                "UPDATE file_request_submissions SET state = 'received',
                    received_at = ?1, updated_at = ?1
                 WHERE id = ?2 AND state = 'uploading'",
                params![now, submission_id],
            )?;
            if let Some(old_id) = replaces_id {
                conn.execute(
                    "UPDATE file_request_submissions SET state = 'superseded', updated_at = ?1
                     WHERE id = ?2 AND request_id = ?3 AND computer_id = ?4
                       AND local_user_id = ?5 AND state = 'received'",
                    params![now, old_id, request_id, auth.computer_id, local_user_id],
                )?;
                conn.execute(
                    "DELETE FROM file_request_submission_chunks
                     WHERE file_id IN (SELECT id FROM file_request_submission_files
                                       WHERE submission_id = ?1)",
                    params![old_id],
                )?;
                conn.execute(
                    "UPDATE file_request_submission_files SET content_available = 0
                     WHERE submission_id = ?1",
                    params![old_id],
                )?;
            }
            Ok(Some(load_endpoint_file_request_submission_view(
                conn,
                &submission_id,
            )?))
        })?;
        result.ok_or_else(|| {
            AppError::conflict(
                "uploaded manifest did not match its declared size or SHA-256",
                Some("file_request_integrity_failed".into()),
            )
        })
    }

    /// Endpoint view is limited to currently open requests addressed to this
    /// enrolled computer and requires the signed local OS-user identity used
    /// to bind submissions and resume them safely.
    pub fn endpoint_file_requests(
        &self,
        auth: &EndpointAuthContext,
    ) -> AppResult<EndpointFileRequestListResponse> {
        self.require_security_ok()?;
        let now = now_unix();
        let requests = self.with_tx(|conn| {
            require_current_endpoint_session(conn, auth, now)?;
            if auth.local_user_id.as_deref().is_none_or(str::is_empty) {
                return Err(AppError::forbidden(
                    "a signed-in local user identity is required for file requests",
                ));
            }
            close_expired_requests(conn, now)?;
            let mut statement = conn.prepare(
                "SELECT r.id, r.revision, r.title, r.instructions,
                        r.allowed_extensions_json, r.max_file_count,
                        r.max_total_size_bytes, r.closes_at, r.replacement_allowed
                 FROM file_requests r
                 JOIN file_request_computers rc ON rc.request_id = r.id
                 WHERE rc.computer_id = ?1 AND r.state = 'open' AND r.closes_at > ?2
                 ORDER BY r.closes_at, r.id LIMIT ?3",
            )?;
            let rows = statement.query_map(
                params![auth.computer_id, now, FILE_REQUEST_MAX_PAGE_SIZE as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )?;
            rows.map(|row| {
                let row = row?;
                let allowed_extensions = serde_json::from_str(&row.4).map_err(|_| {
                    AppError::unprocessable("stored file request extensions are invalid")
                })?;
                Ok(EndpointFileRequestView {
                    id: row.0,
                    revision: row.1,
                    title: row.2,
                    instructions: row.3,
                    allowed_extensions,
                    max_file_count: u32::try_from(row.5).map_err(|_| {
                        AppError::unprocessable("stored file request count is invalid")
                    })?,
                    max_total_size_bytes: u64::try_from(row.6).map_err(|_| {
                        AppError::unprocessable("stored file request size is invalid")
                    })?,
                    closes_at_unix: row.7,
                    replacement_allowed: row.8 != 0,
                })
            })
            .collect::<AppResult<Vec<_>>>()
        })?;
        Ok(EndpointFileRequestListResponse {
            requests,
            max_page_size: FILE_REQUEST_MAX_PAGE_SIZE,
        })
    }

    pub fn list_file_request_submissions(
        &self,
        auth: &AuthContext,
        request_id: &str,
    ) -> AppResult<Vec<FileRequestSubmissionView>> {
        self.require_security_ok()?;
        let request_id = canonical_uuid(request_id, "request_id")?;
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            close_expired_requests(conn, now)?;
            let owner: Option<String> = conn
                .query_row(
                    "SELECT owner_account_id FROM file_requests WHERE id = ?1",
                    params![request_id],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(owner) = owner else {
                return Err(AppError::not_found("file request not found"));
            };
            if owner != auth.account_id {
                return Err(AppError::not_found("file request not found"));
            }
            let mut scope_statement = conn
                .prepare("SELECT computer_id FROM file_request_computers WHERE request_id = ?1")?;
            let computers = scope_statement
                .query_map(params![request_id], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            for computer_id in computers {
                require_operate_scope(conn, &auth.account_id, &computer_id)?;
            }
            let mut statement = conn.prepare(
                "SELECT id FROM file_request_submissions WHERE request_id = ?1
                 ORDER BY created_at DESC, id LIMIT ?2",
            )?;
            let ids = statement
                .query_map(
                    params![request_id, FILE_REQUEST_MAX_PAGE_SIZE as i64],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?;
            ids.iter()
                .map(|id| load_file_request_submission_view(conn, id))
                .collect::<AppResult<Vec<_>>>()
        })
    }

    /// Explicitly remove retained bytes while preserving the submission's
    /// audit metadata. The request owner must still hold operate scope for
    /// the enrolled computer that submitted the files.
    pub fn delete_file_request_submission_content(
        &self,
        auth: &AuthContext,
        request_id: &str,
        submission_id: &str,
        req: DeleteFileRequestSubmissionRequest,
    ) -> AppResult<FileRequestSubmissionView> {
        self.require_security_ok()?;
        let request_id = canonical_uuid(request_id, "request_id")?;
        let submission_id = canonical_uuid(submission_id, "submission_id")?;
        if canonical_uuid(&req.confirm_submission_id, "confirm_submission_id")? != submission_id {
            return Err(AppError::bad_request(
                "confirm_submission_id must exactly match the submission ID",
            ));
        }
        if !auth.can_operate {
            return Err(AppError::forbidden(
                "computer operation permission is required to delete submission content",
            ));
        }

        let now = now_unix();
        self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            close_expired_requests(conn, now)?;
            let submission: Option<(String, String, bool)> = conn
                .query_row(
                    "SELECT s.computer_id, s.state,
                            EXISTS(SELECT 1 FROM file_request_submission_files f
                                   WHERE f.submission_id = s.id AND f.content_available = 1)
                     FROM file_request_submissions s
                     JOIN file_requests r ON r.id = s.request_id
                     WHERE r.id = ?1 AND s.id = ?2 AND r.owner_account_id = ?3",
                    params![request_id, submission_id, auth.account_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((computer_id, state, content_available)) = submission else {
                return Err(AppError::not_found("file request submission not found"));
            };
            require_operate_scope(conn, &auth.account_id, &computer_id)?;
            if state != "received" {
                return Err(AppError::conflict(
                    "only a received submission can have its retained content deleted",
                    Some("file_request_submission_not_received".into()),
                ));
            }
            if content_available {
                conn.execute(
                    "UPDATE file_request_submission_files SET content_available = 0
                     WHERE submission_id = ?1 AND state = 'received' AND content_available = 1",
                    params![submission_id],
                )?;
                conn.execute(
                    "DELETE FROM file_request_submission_chunks
                     WHERE file_id IN (
                         SELECT id FROM file_request_submission_files
                         WHERE submission_id = ?1 AND content_available = 0
                     )",
                    params![submission_id],
                )?;
                conn.execute(
                    "UPDATE file_request_submissions
                     SET updated_at = ?1, content_deleted_at = ?1,
                         content_deleted_by_account_id = ?2
                     WHERE id = ?3 AND state = 'received'",
                    params![now, auth.account_id, submission_id],
                )?;
                crate::audit::record_successful_event(
                    conn,
                    auth,
                    "file_request.content_deleted",
                    &[request_id.to_string(), submission_id.to_string()],
                    "content_deleted_by_owner",
                    now,
                )?;
            }
            load_file_request_submission_view(conn, &submission_id)
        })
    }

    pub fn get_file_request_submission_chunk(
        &self,
        auth: &AuthContext,
        request_id: &str,
        submission_id: &str,
        file_id: &str,
        chunk_index: u32,
    ) -> AppResult<Vec<u8>> {
        self.require_security_ok()?;
        let request_id = canonical_uuid(request_id, "request_id")?;
        let submission_id = canonical_uuid(submission_id, "submission_id")?;
        let file_id = canonical_uuid(file_id, "file_id")?;
        let now = now_unix();
        self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            close_expired_requests(conn, now)?;
            let target: Option<(String, String, String, i64)> = conn
                .query_row(
                    "SELECT r.owner_account_id, s.computer_id, s.state, f.chunk_count
                     FROM file_request_submission_files f
                     JOIN file_request_submissions s ON s.id = f.submission_id
                     JOIN file_requests r ON r.id = s.request_id
                     WHERE r.id = ?1 AND s.id = ?2 AND f.id = ?3
                       AND r.owner_account_id = ?4 AND s.state = 'received'
                       AND f.state = 'received' AND f.content_available = 1",
                    params![request_id, submission_id, file_id, auth.account_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let Some((_owner, computer_id, _state, chunk_count)) = target else {
                return Err(AppError::not_found("received file not found"));
            };
            require_operate_scope(conn, &auth.account_id, &computer_id)?;
            if i64::from(chunk_index) >= chunk_count {
                return Err(AppError::not_found("file chunk not found"));
            }
            conn.query_row(
                "SELECT data FROM file_request_submission_chunks
                 WHERE file_id = ?1 AND chunk_index = ?2",
                params![file_id, i64::from(chunk_index)],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| AppError::not_found("file chunk not found"))
        })
    }

    pub fn maintain_file_requests(&self) -> AppResult<()> {
        self.require_security_ok()?;
        let now = now_unix();
        self.with_tx(|conn| close_expired_requests(conn, now))
    }
}
