//! Endpoint admission: short-lived, key-proven sessions fenced by enrollment.
//!
//! Session tokens are opaque, stored only as hashes, and bound to a single
//! computer and enrollment epoch. Every endpoint-authorized operation must
//! recheck the session and current enrolled incarnation inside its own final
//! transaction; a bearer token alone is not a long-lived admission decision.

use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

use crate::crypto::{
    endpoint_session_begin_proof_message, endpoint_session_begin_proof_message_for_user,
    endpoint_session_begin_proof_message_for_user_label, endpoint_session_proof_message,
    endpoint_session_proof_message_for_user, endpoint_session_proof_message_for_user_label,
    generate_token, hash_token, token_hash_eq, verify_ed25519_strict,
};
use crate::db::{deployment_key, now_unix};
use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::service::{EndpointAuthContext, Service};

const ENDPOINT_CHALLENGE_TTL_SECS: i64 = 120;
const ENDPOINT_CHALLENGE_RETENTION_SECS: i64 = 15 * 60;
const ENDPOINT_SESSION_TTL_SECS: i64 = 15 * 60;
const ENDPOINT_CHALLENGE_CLOCK_SKEW_SECS: i64 = 120;
const MAX_ENDPOINT_CHALLENGES_PER_RETENTION: i64 = 20_000;
const MAX_ENDPOINT_CHALLENGES_PER_COMPUTER: i64 = 20;

type EndpointIdentityRow = (String, String, i64, String, Option<String>, String);
type EndpointChallengeRow = (
    String,
    String,
    String,
    String,
    i64,
    String,
    i64,
    String,
    i64,
    i64,
    Option<i64>,
    Option<String>,
    Option<String>,
);
type EndpointSessionRow = (
    String,
    String,
    i64,
    i64,
    Option<i64>,
    String,
    i64,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);
type CurrentEndpointSessionRow = (
    String,
    i64,
    i64,
    Option<i64>,
    String,
    i64,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);
fn canonical_computer_id(value: &str) -> AppResult<String> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| AppError::bad_request("computer_id must be a UUID"))?
        .to_string();
    if parsed != value {
        return Err(AppError::bad_request(
            "computer_id must use its canonical lowercase form",
        ));
    }
    Ok(parsed)
}

fn validate_nonce(value: &str) -> AppResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppError::bad_request(
            "client_nonce must be 32 bytes of lowercase hex",
        ));
    }
    Ok(())
}

fn validate_local_user_id(value: &str, platform: &str) -> AppResult<()> {
    if value.len() > 256
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(AppError::bad_request("local_user_id is invalid"));
    }
    let uid = match platform {
        "macos" => value.strip_prefix("macos:uid:"),
        "linux" => value.strip_prefix("linux:uid:"),
        _ => None,
    };
    if let Some(uid) = uid {
        let parsed = uid
            .parse::<u32>()
            .map_err(|_| AppError::bad_request("local_user_id is invalid"))?;
        if parsed == 0 || parsed.to_string() != uid {
            return Err(AppError::bad_request("local_user_id is invalid"));
        }
        return Ok(());
    }
    if let Some(sid) = value
        .strip_prefix("windows:sid:")
        .filter(|_| platform == "windows")
    {
        let parts = sid.split('-').collect::<Vec<_>>();
        if parts.len() < 4
            || parts[0] != "S"
            || parts[1] != "1"
            || parts.iter().skip(2).any(|part| {
                part.is_empty()
                    || !part.bytes().all(|byte| byte.is_ascii_digit())
                    || part
                        .parse::<u64>()
                        .map_or(true, |parsed| parsed.to_string() != *part)
            })
        {
            return Err(AppError::bad_request("local_user_id is invalid"));
        }
        return Ok(());
    }
    Err(AppError::bad_request("local_user_id is invalid"))
}

fn validate_local_user_display_name(value: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(AppError::bad_request(
            "local_user_display_name must be a trimmed, bounded OS account label",
        ));
    }
    Ok(())
}

fn approved_endpoint_identity(
    row: Option<EndpointIdentityRow>,
) -> AppResult<(String, i64, String)> {
    let Some((identity, state, epoch, _friendly_name, approved_identity, platform)) = row else {
        return Err(AppError::unauthorized("endpoint is not admitted"));
    };
    if state != "enrolled" || epoch <= 0 || approved_identity.as_deref() != Some(&identity) {
        return Err(AppError::forbidden(
            "endpoint is not approved for this deployment",
        ));
    }
    let public_key = identity
        .strip_prefix("key:")
        .filter(|key| key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| AppError::forbidden("endpoint identity is not approved"))?
        .to_ascii_lowercase();
    Ok((public_key, epoch, platform))
}

/// Fresh endpoint authority check for endpoint APIs that mutate state. Call
/// from the same connection transaction as the requested operation.
pub(crate) fn require_current_endpoint_session(
    conn: &rusqlite::Connection,
    auth: &EndpointAuthContext,
    now: i64,
) -> AppResult<()> {
    let recovery_quarantined: bool = conn.query_row(
        "SELECT recovery_quarantined FROM deployment WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    if recovery_quarantined {
        return Err(AppError::forbidden(
            "restored deployment is quarantined; endpoint operations are unavailable until recovery review completes",
        ));
    }

    let row: Option<CurrentEndpointSessionRow> = conn
        .query_row(
            "SELECT s.computer_id, s.enrollment_epoch, s.expires_at, s.revoked_at,
                    c.public_identity, c.enrollment_epoch, c.enrollment_state,
                    c.approved_incarnation_identity, s.local_user_id,
                    s.local_user_display_name
             FROM endpoint_sessions s
             JOIN computers c ON c.id = s.computer_id
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
        computer_id,
        session_epoch,
        expires_at,
        revoked_at,
        identity,
        current_epoch,
        state,
        approved_identity,
        local_user_id,
        local_user_display_name,
    )) = row
    else {
        return Err(AppError::unauthorized("invalid endpoint session"));
    };
    if computer_id != auth.computer_id
        || session_epoch != auth.enrollment_epoch
        || expires_at <= now
        || revoked_at.is_some()
        || current_epoch != auth.enrollment_epoch
        || state != "enrolled"
        || approved_identity.as_deref() != Some(identity.as_str())
        || local_user_id != auth.local_user_id
        || local_user_display_name != auth.local_user_display_name
    {
        return Err(AppError::unauthorized("invalid endpoint session"));
    }
    Ok(())
}

impl Service {
    /// Allocate a bounded, one-use challenge after the enrolled endpoint signs
    /// a fresh client nonce. The final insert rechecks identity, epoch, and
    /// deployment under the write transaction.
    pub fn endpoint_session_challenge(
        &self,
        req: EndpointSessionChallengeRequest,
    ) -> AppResult<EndpointSessionChallengeResponse> {
        self.require_security_ok()?;
        let computer_id = canonical_computer_id(&req.computer_id)?;
        validate_nonce(&req.client_nonce)?;
        let now = now_unix();
        if req.issued_at_unix < now - ENDPOINT_CHALLENGE_CLOCK_SKEW_SECS
            || req.issued_at_unix > now + ENDPOINT_CHALLENGE_CLOCK_SKEW_SECS
        {
            return Err(AppError::unauthorized(
                "endpoint challenge proof is outside the allowed time window",
            ));
        }

        let (deployment_id, public_key, enrollment_epoch, platform) = self.with_conn(|conn| {
            let deployment_id = deployment_key(conn)?;
            let row = conn
                .query_row(
                    "SELECT public_identity, enrollment_state, enrollment_epoch,
                            friendly_name, approved_incarnation_identity
                            , platform
                     FROM computers WHERE id = ?1",
                    params![computer_id],
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
            let (public_key, epoch, platform) = approved_endpoint_identity(row)?;
            Ok((deployment_id, public_key, epoch, platform))
        })?;
        if let Some(local_user_id) = &req.local_user_id {
            validate_local_user_id(local_user_id, &platform)?;
        }
        match (&req.local_user_id, &req.local_user_display_name) {
            (Some(_), Some(display_name)) => validate_local_user_display_name(display_name)?,
            (None, Some(_)) => {
                return Err(AppError::bad_request(
                    "local_user_display_name requires local_user_id",
                ));
            }
            _ => {}
        }

        let begin_message = match (&req.local_user_id, &req.local_user_display_name) {
            (Some(local_user_id), Some(display_name)) => {
                endpoint_session_begin_proof_message_for_user_label(
                    &deployment_id,
                    &computer_id,
                    local_user_id,
                    display_name,
                    req.issued_at_unix,
                    &req.client_nonce,
                )
            }
            (Some(local_user_id), None) => endpoint_session_begin_proof_message_for_user(
                &deployment_id,
                &computer_id,
                local_user_id,
                req.issued_at_unix,
                &req.client_nonce,
            ),
            (None, None) => endpoint_session_begin_proof_message(
                &deployment_id,
                &computer_id,
                req.issued_at_unix,
                &req.client_nonce,
            ),
            (None, Some(_)) => {
                return Err(AppError::bad_request(
                    "local_user_display_name requires local_user_id",
                ));
            }
        };
        if !verify_ed25519_strict(&public_key, &begin_message, &req.proof)? {
            return Err(AppError::unauthorized(
                "endpoint challenge proof is invalid",
            ));
        }

        let (challenge_token, challenge_token_hash) = generate_token()?;
        let challenge_id = Uuid::new_v4().to_string();
        let expires_at = now + ENDPOINT_CHALLENGE_TTL_SECS;
        let client_nonce = req.client_nonce.clone();
        let issued_at = req.issued_at_unix;
        let local_user_id = req.local_user_id.clone();
        let local_user_display_name = req.local_user_display_name.clone();

        self.with_tx(|conn| {
            let authority_state: String = conn.query_row(
                "SELECT authority_state FROM deployment WHERE id = 1",
                [],
                |row| row.get(0),
            )?;
            if authority_state != "active" {
                return Err(AppError::forbidden(
                    "authority is not Active; new endpoint sessions are paused during cutover",
                ));
            }
            if deployment_key(conn)? != deployment_id {
                return Err(AppError::unauthorized("endpoint deployment changed"));
            }
            let current: Option<EndpointIdentityRow> = conn
                .query_row(
                    "SELECT public_identity, enrollment_state, enrollment_epoch,
                            friendly_name, approved_incarnation_identity
                            , platform
                     FROM computers WHERE id = ?1",
                    params![computer_id],
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
            let (current_key, current_epoch, current_platform) =
                approved_endpoint_identity(current)?;
            if current_key != public_key
                || current_epoch != enrollment_epoch
                || current_platform != platform
            {
                return Err(AppError::unauthorized("endpoint enrollment changed"));
            }

            conn.execute(
                "DELETE FROM endpoint_auth_challenges
                 WHERE created_at <= ?1",
                params![now - ENDPOINT_CHALLENGE_RETENTION_SECS],
            )?;
            let duplicate_nonce: bool = conn.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM endpoint_auth_challenges
                    WHERE computer_id = ?1 AND client_nonce = ?2
                )",
                params![computer_id, client_nonce],
                |row| row.get(0),
            )?;
            if duplicate_nonce {
                return Err(AppError::unauthorized(
                    "endpoint challenge request was already used",
                ));
            }
            let recent_endpoint_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM endpoint_auth_challenges
                 WHERE computer_id = ?1 AND created_at > ?2",
                params![computer_id, now - ENDPOINT_CHALLENGE_RETENTION_SECS],
                |row| row.get(0),
            )?;
            if recent_endpoint_count >= MAX_ENDPOINT_CHALLENGES_PER_COMPUTER {
                return Err(AppError::rate_limited(
                    "endpoint session challenge rate limit reached",
                ));
            }
            let recent_total_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM endpoint_auth_challenges WHERE created_at > ?1",
                params![now - ENDPOINT_CHALLENGE_RETENTION_SECS],
                |row| row.get(0),
            )?;
            if recent_total_count >= MAX_ENDPOINT_CHALLENGES_PER_RETENTION {
                return Err(AppError::rate_limited(
                    "endpoint session challenge capacity is temporarily full",
                ));
            }

            // A fresh proof invalidates older challenges for this same
            // endpoint, keeping durable active state bounded to one per key.
            conn.execute(
                "UPDATE endpoint_auth_challenges SET consumed_at = ?1
                 WHERE computer_id = ?2 AND consumed_at IS NULL",
                params![now, computer_id],
            )?;
            conn.execute(
                "INSERT INTO endpoint_auth_challenges (
                    id, token_hash, computer_id, client_nonce, issued_at,
                    public_key, enrollment_epoch, deployment_key, created_at,
                    expires_at, consumed_at, local_user_id, local_user_display_name
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11, ?12)",
                params![
                    challenge_id,
                    challenge_token_hash,
                    computer_id,
                    client_nonce,
                    issued_at,
                    public_key,
                    enrollment_epoch,
                    deployment_id,
                    now,
                    expires_at,
                    local_user_id,
                    local_user_display_name
                ],
            )?;
            Ok(())
        })?;

        Ok(EndpointSessionChallengeResponse {
            challenge_id,
            challenge_token,
            deployment_id,
            computer_id,
            enrollment_epoch,
            expires_at_unix: expires_at,
        })
    }

    /// Verify the endpoint's response and atomically consume the challenge,
    /// fence older endpoint sessions, and issue one short-lived bearer token.
    pub fn complete_endpoint_session(
        &self,
        req: EndpointSessionCompleteRequest,
    ) -> AppResult<EndpointSessionIssuedResponse> {
        self.require_security_ok()?;
        let challenge_id = Uuid::parse_str(&req.challenge_id)
            .map_err(|_| AppError::bad_request("challenge_id must be a UUID"))?
            .to_string();
        if challenge_id != req.challenge_id {
            return Err(AppError::bad_request(
                "challenge_id must use its canonical lowercase form",
            ));
        }
        if req.challenge_token.len() != 43
            || !req
                .challenge_token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(AppError::unauthorized("invalid endpoint challenge"));
        }
        if req.signature.trim().is_empty() {
            return Err(AppError::bad_request("signature is required"));
        }

        let now = now_unix();
        let challenge_token_hash = hash_token(&req.challenge_token);
        let pre = self.with_conn(|conn| {
            let authority_state: String = conn.query_row(
                "SELECT authority_state FROM deployment WHERE id = 1",
                [],
                |row| row.get(0),
            )?;
            if authority_state != "active" {
                return Err(AppError::forbidden(
                    "authority is not Active; endpoint session renewal is paused during cutover",
                ));
            }
            let row: Option<EndpointChallengeRow> = conn
                .query_row(
                    "SELECT id, token_hash, computer_id, public_key, enrollment_epoch,
                            deployment_key, expires_at, client_nonce, issued_at,
                            created_at, consumed_at, local_user_id, local_user_display_name
                     FROM endpoint_auth_challenges WHERE id = ?1",
                    params![challenge_id],
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
                .optional()?;
            Ok(row)
        })?;
        let Some((
            stored_id,
            stored_token_hash,
            computer_id,
            public_key,
            enrollment_epoch,
            deployment_id,
            expires_at,
            _client_nonce,
            _issued_at,
            _created_at,
            consumed_at,
            local_user_id,
            local_user_display_name,
        )) = pre
        else {
            return Err(AppError::unauthorized("invalid endpoint challenge"));
        };
        if !token_hash_eq(&challenge_token_hash, &stored_token_hash)
            || consumed_at.is_some()
            || expires_at <= now
        {
            return Err(AppError::unauthorized("invalid endpoint challenge"));
        }
        let proof = match (&local_user_id, &local_user_display_name) {
            (Some(local_user_id), Some(display_name)) => {
                endpoint_session_proof_message_for_user_label(
                    &deployment_id,
                    &stored_id,
                    &stored_token_hash,
                    &computer_id,
                    enrollment_epoch,
                    &public_key,
                    local_user_id,
                    display_name,
                )
            }
            (Some(local_user_id), None) => endpoint_session_proof_message_for_user(
                &deployment_id,
                &stored_id,
                &stored_token_hash,
                &computer_id,
                enrollment_epoch,
                &public_key,
                local_user_id,
            ),
            (None, None) => endpoint_session_proof_message(
                &deployment_id,
                &stored_id,
                &stored_token_hash,
                &computer_id,
                enrollment_epoch,
                &public_key,
            ),
            (None, Some(_)) => {
                return Err(AppError::unauthorized("invalid endpoint challenge"));
            }
        };
        if !verify_ed25519_strict(&public_key, &proof, &req.signature)? {
            return Err(AppError::unauthorized("endpoint session proof is invalid"));
        }

        let (session_token, session_token_hash) = generate_token()?;
        let session_id = Uuid::new_v4().to_string();
        let session_expires_at = now + ENDPOINT_SESSION_TTL_SECS;
        self.with_tx(|conn| {
            let authority_state: String = conn.query_row(
                "SELECT authority_state FROM deployment WHERE id = 1",
                [],
                |row| row.get(0),
            )?;
            if authority_state != "active" {
                return Err(AppError::forbidden(
                    "authority is not Active; endpoint session renewal is paused during cutover",
                ));
            }
            let current: Option<EndpointChallengeRow> = conn
                .query_row(
                    "SELECT id, token_hash, computer_id, public_key, enrollment_epoch,
                            deployment_key, expires_at, client_nonce, issued_at,
                            created_at, consumed_at, local_user_id, local_user_display_name
                     FROM endpoint_auth_challenges WHERE id = ?1",
                    params![stored_id],
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
                .optional()?;
            let Some((
                current_id,
                current_hash,
                current_computer_id,
                current_key,
                current_epoch,
                current_deployment,
                current_expiry,
                _,
                _,
                _,
                current_consumed,
                current_local_user_id,
                current_local_user_display_name,
            )) = current
            else {
                return Err(AppError::unauthorized("invalid endpoint challenge"));
            };
            if current_id != stored_id
                || !token_hash_eq(&challenge_token_hash, &current_hash)
                || current_computer_id != computer_id
                || current_key != public_key
                || current_epoch != enrollment_epoch
                || current_deployment != deployment_id
                || current_expiry <= now
                || current_consumed.is_some()
                || current_local_user_id != local_user_id
                || current_local_user_display_name != local_user_display_name
            {
                return Err(AppError::unauthorized("invalid endpoint challenge"));
            }
            if deployment_key(conn)? != deployment_id {
                return Err(AppError::unauthorized("endpoint deployment changed"));
            }
            let endpoint: Option<EndpointIdentityRow> = conn
                .query_row(
                    "SELECT public_identity, enrollment_state, enrollment_epoch,
                            friendly_name, approved_incarnation_identity
                            , platform
                     FROM computers WHERE id = ?1",
                    params![computer_id],
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
            let (current_public_key, current_endpoint_epoch, current_platform) =
                approved_endpoint_identity(endpoint)?;
            if current_public_key != public_key || current_endpoint_epoch != enrollment_epoch {
                return Err(AppError::unauthorized("endpoint enrollment changed"));
            }
            if let Some(local_user_id) = &local_user_id {
                validate_local_user_id(local_user_id, &current_platform)?;
            }
            if let Some(display_name) = &local_user_display_name {
                validate_local_user_display_name(display_name)?;
            }

            let consumed = conn.execute(
                "UPDATE endpoint_auth_challenges SET consumed_at = ?1
                 WHERE id = ?2 AND token_hash = ?3 AND consumed_at IS NULL AND expires_at > ?1",
                params![now, stored_id, stored_token_hash],
            )?;
            if consumed != 1 {
                return Err(AppError::unauthorized("invalid endpoint challenge"));
            }
            conn.execute(
                "DELETE FROM endpoint_sessions
                 WHERE expires_at <= ?1 OR revoked_at <= ?2",
                params![now, now - ENDPOINT_CHALLENGE_RETENTION_SECS],
            )?;
            conn.execute(
                "UPDATE endpoint_sessions SET revoked_at = ?1
                 WHERE computer_id = ?2 AND revoked_at IS NULL",
                params![now, computer_id],
            )?;
            conn.execute(
                "INSERT INTO endpoint_sessions (
                    id, token_hash, computer_id, enrollment_epoch,
                    local_user_id, local_user_display_name, created_at, expires_at, revoked_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
                params![
                    session_id,
                    session_token_hash,
                    computer_id,
                    enrollment_epoch,
                    local_user_id,
                    local_user_display_name,
                    now,
                    session_expires_at
                ],
            )?;
            Ok(())
        })?;

        Ok(EndpointSessionIssuedResponse {
            token: session_token,
            session_id,
            deployment_id,
            computer_id,
            enrollment_epoch,
            expires_at_unix: session_expires_at,
        })
    }

    /// Authenticate an endpoint bearer token. Current enrollment and epoch
    /// checks make approval changes, revocation, and replacement identities
    /// immediately fence every prior session.
    pub fn authenticate_endpoint_token(&self, token: &str) -> AppResult<EndpointAuthContext> {
        self.require_security_ok()?;
        if token.len() != 43
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(AppError::unauthorized("invalid endpoint bearer token"));
        }
        let token_hash = hash_token(token);
        let now = now_unix();
        self.with_conn(|conn| {
            let (recovery_quarantined, authority_state): (bool, String) = conn.query_row(
                "SELECT recovery_quarantined, authority_state FROM deployment WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if recovery_quarantined {
                return Err(AppError::forbidden(
                    "restored deployment is quarantined; endpoint operations are unavailable until recovery review completes",
                ));
            }
            if authority_state != "active" {
                return Err(AppError::forbidden(
                    "authority is not Active; endpoint authority is paused during cutover",
                ));
            }
            let row: Option<EndpointSessionRow> = conn
                .query_row(
                    "SELECT s.id, s.computer_id, s.enrollment_epoch, s.expires_at,
                            s.revoked_at, c.public_identity, c.enrollment_epoch,
                            c.enrollment_state, c.approved_incarnation_identity,
                            s.local_user_id, s.local_user_display_name
                     FROM endpoint_sessions s
                     JOIN computers c ON c.id = s.computer_id
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
                            row.get(8)?,
                            row.get(9)?,
                            row.get(10)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                session_id,
                computer_id,
                session_epoch,
                expires_at,
                revoked_at,
                identity,
                current_epoch,
                state,
                approved_identity,
                local_user_id,
                local_user_display_name,
            )) = row
            else {
                return Err(AppError::unauthorized("invalid endpoint session"));
            };
            if expires_at <= now
                || revoked_at.is_some()
                || state != "enrolled"
                || session_epoch != current_epoch
                || approved_identity.as_deref() != Some(identity.as_str())
            {
                return Err(AppError::unauthorized("invalid endpoint session"));
            }
            Ok(EndpointAuthContext {
                session_id,
                computer_id,
                enrollment_epoch: session_epoch,
                local_user_id,
                local_user_display_name,
            })
        })
    }

    /// Resolve the endpoint's own current metadata with a fresh in-query
    /// session and enrollment recheck.
    pub fn endpoint_self(&self, auth: &EndpointAuthContext) -> AppResult<EndpointSelfResponse> {
        self.with_conn(|conn| {
            let now = now_unix();
            require_current_endpoint_session(conn, auth, now)?;
            let row: Option<(String, String, i64)> = conn
                .query_row(
                    "SELECT friendly_name, platform, enrollment_epoch
                     FROM computers WHERE id = ?1",
                    params![auth.computer_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((friendly_name, platform, enrollment_epoch)) = row else {
                return Err(AppError::unauthorized("invalid endpoint session"));
            };
            Ok(EndpointSelfResponse {
                computer_id: auth.computer_id.clone(),
                friendly_name,
                platform,
                enrollment_epoch,
            })
        })
    }
}
