//! Short-lived, single-use endpoint observation admission.
//!
//! This control-plane exchange requires current Manager and endpoint sessions,
//! the current per-computer `observe` assignment, and an endpoint-generated
//! nonce signed by the approved Manager device. It does not start capture or
//! establish a media channel; the endpoint must verify the signed lease and
//! consume it before exposing pixels.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use hs_core::{WebRtcChannelBinding, WEBRTC_CHANNEL_BINDING_LEN};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::{hash_token, verify_ed25519_strict};
use crate::db::{deployment_key, grant_signing_secret, now_unix};
use crate::endpoint_auth::require_current_endpoint_session;
use crate::error::{AppError, AppResult};
use crate::interactions::require_current_interaction_scope;
use crate::models::{
    EndpointPendingObservationGrant, EndpointPendingObservationGrantsResponse,
    IssueObservationGrantRequest, ObservationAdmissionAcceptedResponse, ObservationSignalBatch,
    ObservationSignalMessage, ObservationSignalRequest, SignedObservationGrantResponse,
};
use crate::service::{
    lock_observation_grants, require_current_operator_session, AuthContext,
    DispatchedObservationGrant, EndpointAuthContext, ObservationSignalMailbox, Service,
};

const GRANT_TTL_SECS: i64 = 10;
const GRANT_RETENTION_SECS: i64 = 24 * 60 * 60;
const MAX_GRANT_ROWS: i64 = 100_000;
const MAX_GRANTS_PER_MANAGER_PER_MINUTE: i64 = 2_000;
const MAX_GRANTS_PER_COMPUTER_PER_MINUTE: i64 = 60;
const MAX_GRANT_TOKEN_BYTES: usize = 8 * 1024;
const MAX_SIGNALING_MAILBOXES: usize = 128;
const MAX_SIGNALS_PER_GRANT: usize = 128;
const MAX_SIGNAL_BYTES_PER_GRANT: usize = 256 * 1024;
const MAX_SIGNAL_BATCH: usize = 64;
const MAX_PENDING_OBSERVATION_GRANTS_PER_ENDPOINT: usize = 8;
const MAX_PENDING_OBSERVATION_GRANTS_TOTAL: usize = 512;

const GRANT_DOMAIN: &[u8] = b"hs-observation-grant-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationGrantClaimsV1 {
    version: u8,
    grant_id: String,
    deployment_id: String,
    account_id: String,
    manager_id: String,
    manager_public_key: String,
    computer_id: String,
    endpoint_public_key: String,
    endpoint_session_id: String,
    enrollment_epoch: i64,
    issued_at_unix: i64,
    expires_at_unix: i64,
    capability: String,
}

#[derive(Debug)]
struct DecodedGrant {
    claims: ObservationGrantClaimsV1,
    token_hash: String,
    signature: String,
    payload: Vec<u8>,
}

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

fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn deployment_id_is_canonical(value: &str) -> bool {
    value.len() == 36
        && value.starts_with("dep_")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_claims(claims: &ObservationGrantClaimsV1, now: i64) -> AppResult<()> {
    if claims.version != 1
        || claims.capability != "observe"
        || !deployment_id_is_canonical(&claims.deployment_id)
        || !valid_hex(&claims.manager_public_key, 32)
        || !valid_hex(&claims.endpoint_public_key, 32)
        || claims.enrollment_epoch <= 0
        || claims.issued_at_unix > now + 5
        || claims.expires_at_unix <= now
        || claims.expires_at_unix <= claims.issued_at_unix
        || claims.expires_at_unix - claims.issued_at_unix > GRANT_TTL_SECS
    {
        return Err(AppError::unauthorized(
            "invalid or expired observation grant",
        ));
    }
    canonical_uuid(&claims.grant_id, "grant_id")
        .and_then(|_| canonical_uuid(&claims.account_id, "account_id"))
        .and_then(|_| canonical_uuid(&claims.manager_id, "manager_id"))
        .and_then(|_| canonical_uuid(&claims.computer_id, "computer_id"))
        .and_then(|_| canonical_uuid(&claims.endpoint_session_id, "endpoint_session_id"))
        .map(|_| ())
        .map_err(|_| AppError::unauthorized("invalid or expired observation grant"))
}

fn signed_payload(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(GRANT_DOMAIN.len() + payload.len());
    message.extend_from_slice(GRANT_DOMAIN);
    message.extend_from_slice(payload);
    message
}

fn encode_token(claims: &ObservationGrantClaimsV1, secret: &[u8; 32]) -> AppResult<String> {
    let payload = serde_json::to_vec(claims)
        .map_err(|_| AppError::internal("could not encode observation grant"))?;
    if payload.len() > 4096 {
        return Err(AppError::internal(
            "observation grant exceeded its size bound",
        ));
    }
    let signing_key = SigningKey::from_bytes(secret);
    let signature = signing_key.sign(&signed_payload(&payload));
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        hex::encode(signature.to_bytes())
    ))
}

fn decode_token(token: &str, now: i64) -> AppResult<DecodedGrant> {
    if token.is_empty() || token.len() > MAX_GRANT_TOKEN_BYTES || !token.is_ascii() {
        return Err(AppError::unauthorized("invalid observation grant"));
    }
    let (encoded_payload, signature) = token
        .split_once('.')
        .ok_or_else(|| AppError::unauthorized("invalid observation grant"))?;
    if encoded_payload.is_empty() || signature.len() != 128 || !valid_hex(signature, 64) {
        return Err(AppError::unauthorized("invalid observation grant"));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .map_err(|_| AppError::unauthorized("invalid observation grant"))?;
    if URL_SAFE_NO_PAD.encode(&payload) != encoded_payload || payload.len() > 4096 {
        return Err(AppError::unauthorized("invalid observation grant"));
    }
    let claims: ObservationGrantClaimsV1 = serde_json::from_slice(&payload)
        .map_err(|_| AppError::unauthorized("invalid observation grant"))?;
    let canonical_payload = serde_json::to_vec(&claims)
        .map_err(|_| AppError::unauthorized("invalid observation grant"))?;
    if canonical_payload != payload {
        return Err(AppError::unauthorized("invalid observation grant"));
    }
    validate_claims(&claims, now)?;
    Ok(DecodedGrant {
        claims,
        token_hash: hash_token(token),
        signature: signature.to_string(),
        payload,
    })
}

/// Message the Manager device signs after receiving a fresh endpoint nonce
/// over the already verified peer data channel. The endpoint checks this proof
/// locally; the server checks the same bytes before its one-use consume commit.
fn observation_peer_proof_message(
    claims: &ObservationGrantClaimsV1,
    endpoint_nonce: &str,
    channel_binding: &str,
) -> AppResult<Vec<u8>> {
    if !valid_hex(endpoint_nonce, 32) {
        return Err(AppError::bad_request(
            "endpoint_nonce must be 32 bytes of lowercase hex",
        ));
    }
    if !valid_hex(channel_binding, WEBRTC_CHANNEL_BINDING_LEN) {
        return Err(AppError::unauthorized("invalid observation peer proof"));
    }
    let binding_bytes = hex::decode(channel_binding)
        .map_err(|_| AppError::unauthorized("invalid observation peer proof"))?;
    WebRtcChannelBinding::decode(&binding_bytes)
        .map_err(|_| AppError::unauthorized("invalid observation peer proof"))?;
    Ok(format!(
        "hs-observation-peer-proof-v2|deployment:{}|grant:{}|computer:{}|endpoint_session:{}|epoch:{}|nonce:{}|channel_binding:{}",
        claims.deployment_id,
        claims.grant_id,
        claims.computer_id,
        claims.endpoint_session_id,
        claims.enrollment_epoch,
        endpoint_nonce,
        channel_binding
    )
    .into_bytes())
}

fn parse_endpoint_public_key(identity: &str) -> AppResult<String> {
    let key = identity
        .strip_prefix("key:")
        .filter(|key| valid_hex(key, 32))
        .ok_or_else(|| AppError::forbidden("endpoint identity is not approved"))?;
    Ok(key.to_string())
}

impl Service {
    /// Issue a deployment-signed, short-lived observation lease after current
    /// Manager authority, observe scope, endpoint incarnation, and console
    /// session are checked in the same write transaction as persistence.
    pub fn issue_observation_grant(
        &self,
        auth: &AuthContext,
        req: IssueObservationGrantRequest,
    ) -> AppResult<SignedObservationGrantResponse> {
        self.require_security_ok()?;
        self.require_persisted_v2_credentials()?;
        let computer_id = canonical_uuid(&req.computer_id, "computer_id")?;
        let manager_id = auth
            .manager_id
            .as_deref()
            .ok_or_else(|| AppError::forbidden("an approved Manager device session is required"))?
            .to_string();
        canonical_uuid(&manager_id, "manager_id")?;
        let now = now_unix();

        let (response, endpoint_session_id) = self.with_tx(|conn| {
            require_current_operator_session(conn, auth, now)?;
            require_current_interaction_scope(conn, &auth.account_id, &computer_id, "observe")?;
            let current_manager: Option<(Option<String>, Option<String>)> = conn
                .query_row(
                    "SELECT s.manager_id, m.public_key
                     FROM sessions s JOIN managers m ON m.id = s.manager_id
                     WHERE s.id = ?1 AND s.account_id = ?2 AND m.lifecycle_state = 'approved'",
                    params![auth.session_id, auth.account_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((Some(current_manager_id), Some(manager_public_key))) = current_manager else {
                return Err(AppError::forbidden(
                    "an approved key-bearing Manager session is required",
                ));
            };
            if current_manager_id != manager_id
                || !valid_hex(&manager_public_key, 32)
                || auth.manager_id.as_deref() != Some(current_manager_id.as_str())
            {
                return Err(AppError::unauthorized("Manager device identity changed"));
            }

            let endpoint: Option<(String, String, i64, String, String, i64)> = conn
                .query_row(
                    "SELECT c.public_identity, c.enrollment_state, c.enrollment_epoch,
                            c.approved_incarnation_identity, s.id, s.expires_at
                     FROM computers c
                     JOIN endpoint_sessions s ON s.computer_id = c.id
                        AND s.enrollment_epoch = c.enrollment_epoch
                     WHERE c.id = ?1 AND c.enrollment_state = 'enrolled'
                       AND c.approved_incarnation_identity = c.public_identity
                       AND s.revoked_at IS NULL AND s.expires_at > ?2
                       AND s.local_user_id IS NOT NULL
                     ORDER BY s.created_at DESC, s.id DESC LIMIT 1",
                    params![computer_id, now],
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
                endpoint_identity,
                state,
                enrollment_epoch,
                approved_identity,
                endpoint_session_id,
                endpoint_expires_at,
            )) = endpoint
            else {
                return Err(AppError::forbidden(
                    "computer has no current signed-in endpoint session",
                ));
            };
            if state != "enrolled" || approved_identity != endpoint_identity {
                return Err(AppError::forbidden("endpoint incarnation is not approved"));
            }
            let endpoint_public_key = parse_endpoint_public_key(&endpoint_identity)?;
            let platform: String = conn.query_row(
                "SELECT platform FROM computers WHERE id = ?1",
                params![computer_id],
                |row| row.get(0),
            )?;
            if platform != "windows" && platform != "macos" {
                return Err(AppError::not_implemented(
                    "observation admission is limited to Windows and macOS endpoints",
                ));
            }

            conn.execute(
                "DELETE FROM observation_admission_grants
                 WHERE issued_at < ?1 AND (consumed_at IS NOT NULL OR expires_at <= ?2)",
                params![now - GRANT_RETENTION_SECS, now - 60],
            )?;
            let retained: i64 = conn.query_row(
                "SELECT COUNT(*) FROM observation_admission_grants",
                [],
                |row| row.get(0),
            )?;
            if retained >= MAX_GRANT_ROWS {
                return Err(AppError::rate_limited(
                    "observation admission capacity is temporarily full",
                ));
            }
            let recent_manager: i64 = conn.query_row(
                "SELECT COUNT(*) FROM observation_admission_grants
                 WHERE manager_id = ?1 AND issued_at > ?2",
                params![manager_id, now - 60],
                |row| row.get(0),
            )?;
            let recent_computer: i64 = conn.query_row(
                "SELECT COUNT(*) FROM observation_admission_grants
                 WHERE computer_id = ?1 AND issued_at > ?2",
                params![computer_id, now - 60],
                |row| row.get(0),
            )?;
            if recent_manager >= MAX_GRANTS_PER_MANAGER_PER_MINUTE
                || recent_computer >= MAX_GRANTS_PER_COMPUTER_PER_MINUTE
            {
                return Err(AppError::rate_limited(
                    "observation admission renewal rate limit reached",
                ));
            }

            let deployment_id = deployment_key(conn)?;
            let expires_at = (now + GRANT_TTL_SECS).min(endpoint_expires_at);
            if expires_at <= now {
                return Err(AppError::unauthorized("endpoint session is expired"));
            }
            let claims = ObservationGrantClaimsV1 {
                version: 1,
                grant_id: Uuid::new_v4().to_string(),
                deployment_id: deployment_id.clone(),
                account_id: auth.account_id.clone(),
                manager_id: manager_id.clone(),
                manager_public_key,
                computer_id: computer_id.clone(),
                endpoint_public_key: endpoint_public_key.clone(),
                endpoint_session_id: endpoint_session_id.clone(),
                enrollment_epoch,
                issued_at_unix: now,
                expires_at_unix: expires_at,
                capability: "observe".into(),
            };
            let mut secret = grant_signing_secret(conn)?;
            let token = encode_token(&claims, &secret)?;
            secret.zeroize();
            let token_hash = hash_token(&token);
            conn.execute(
                "INSERT INTO observation_admission_grants (
                    id, token_hash, deployment_key, account_id, manager_id,
                    manager_session_id, computer_id, endpoint_session_id,
                    endpoint_public_key, enrollment_epoch, manager_public_key,
                    issued_at, expires_at, consumed_at, endpoint_nonce_hash
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL, NULL)",
                params![
                    claims.grant_id,
                    token_hash,
                    deployment_id,
                    auth.account_id,
                    manager_id,
                    auth.session_id,
                    computer_id,
                    endpoint_session_id,
                    endpoint_public_key,
                    enrollment_epoch,
                    claims.manager_public_key,
                    now,
                    expires_at,
                ],
            )?;
            crate::audit::record_successful_event(
                conn,
                auth,
                "observation.grant_created",
                &[claims.grant_id.clone(), computer_id.clone()],
                "short_lived_observation",
                now,
            )?;
            Ok((
                SignedObservationGrantResponse {
                    grant_id: claims.grant_id,
                    computer_id: claims.computer_id,
                    expires_at_unix: claims.expires_at_unix,
                    grant_token: token,
                },
                endpoint_session_id,
            ))
        })?;

        let now = now_unix();
        let queued = {
            let mut grants = lock_observation_grants(self)
                .map_err(|_| AppError::internal("observation grant delivery is unavailable"))?;
            grants.retain(|_, queue| {
                queue.retain(|grant| grant.expires_at_unix > now);
                !queue.is_empty()
            });
            let pending_total: usize = grants.values().map(|queue| queue.len()).sum();
            if grants
                .get(&endpoint_session_id)
                .map(|queue| queue.len())
                .unwrap_or_default()
                >= MAX_PENDING_OBSERVATION_GRANTS_PER_ENDPOINT
                || pending_total >= MAX_PENDING_OBSERVATION_GRANTS_TOTAL
            {
                false
            } else {
                let queue = grants.entry(endpoint_session_id.clone()).or_default();
                queue.push_back(DispatchedObservationGrant {
                    grant_id: response.grant_id.clone(),
                    computer_id: response.computer_id.clone(),
                    expires_at_unix: response.expires_at_unix,
                    grant_token: response.grant_token.clone(),
                });
                true
            }
        };
        if !queued {
            let token_hash = hash_token(&response.grant_token);
            let grant_id = response.grant_id.clone();
            self.with_tx(|conn| {
                conn.execute(
                    "DELETE FROM observation_admission_grants
                     WHERE id = ?1 AND token_hash = ?2 AND consumed_at IS NULL",
                    params![grant_id, token_hash],
                )?;
                Ok(())
            })?;
            return Err(AppError::rate_limited(
                "observation grant delivery capacity is temporarily full",
            ));
        }
        let _ = self.observation_grant_notifier.send(endpoint_session_id);
        Ok(response)
    }

    /// Return and consume the short-lived grants queued for this exact current
    /// endpoint session. Session authority is rechecked immediately before
    /// exposing the tokens.
    pub fn take_pending_observation_grants(
        &self,
        endpoint_auth: &EndpointAuthContext,
    ) -> AppResult<EndpointPendingObservationGrantsResponse> {
        self.require_security_ok()?;
        let now = now_unix();
        self.with_conn(|conn| require_current_endpoint_session(conn, endpoint_auth, now))?;

        let mut grants = lock_observation_grants(self)
            .map_err(|_| AppError::internal("observation grant delivery is unavailable"))?;
        grants.retain(|_, queue| {
            queue.retain(|grant| grant.expires_at_unix > now);
            !queue.is_empty()
        });
        let queued = grants.remove(&endpoint_auth.session_id).unwrap_or_default();
        Ok(EndpointPendingObservationGrantsResponse {
            grants: queued
                .into_iter()
                .map(|grant| EndpointPendingObservationGrant {
                    grant_id: grant.grant_id.clone(),
                    computer_id: grant.computer_id.clone(),
                    expires_at_unix: grant.expires_at_unix,
                    grant_token: grant.grant_token.clone(),
                })
                .collect(),
        })
    }

    /// Consume one exact observation grant from its target endpoint session.
    /// The manager proof binds a fresh endpoint nonce to the approved device;
    /// current account, Manager, endpoint, and observe access are rechecked
    /// atomically before the grant becomes unusable.
    pub fn redeem_observation_grant(
        &self,
        endpoint_auth: &EndpointAuthContext,
        req: crate::models::RedeemObservationGrantRequest,
    ) -> AppResult<ObservationAdmissionAcceptedResponse> {
        self.require_security_ok()?;
        let now = now_unix();
        let decoded = decode_token(&req.grant_token, now)?;
        if !valid_hex(&req.endpoint_nonce, 32)
            || !valid_hex(&req.channel_binding, WEBRTC_CHANNEL_BINDING_LEN)
            || req.manager_proof.len() != 128
            || !valid_hex(&req.manager_proof, 64)
        {
            return Err(AppError::unauthorized("invalid observation peer proof"));
        }
        let proof_message = observation_peer_proof_message(
            &decoded.claims,
            &req.endpoint_nonce,
            &req.channel_binding,
        )?;
        if !verify_ed25519_strict(
            &decoded.claims.manager_public_key,
            &proof_message,
            &req.manager_proof,
        )? {
            return Err(AppError::unauthorized("observation peer proof is invalid"));
        }
        if endpoint_auth.computer_id != decoded.claims.computer_id
            || endpoint_auth.session_id != decoded.claims.endpoint_session_id
            || endpoint_auth.enrollment_epoch != decoded.claims.enrollment_epoch
        {
            return Err(AppError::unauthorized(
                "observation grant is bound to another endpoint session",
            ));
        }

        self.with_tx(|conn| {
            require_current_endpoint_session(conn, endpoint_auth, now)?;
            let mut secret = grant_signing_secret(conn)?;
            let signing_key = SigningKey::from_bytes(&secret);
            secret.zeroize();
            let verifying_key = signing_key.verifying_key();
            let signature_bytes = hex::decode(&decoded.signature)
                .map_err(|_| AppError::unauthorized("invalid observation grant"))?;
            let signature_array: [u8; 64] = signature_bytes
                .try_into()
                .map_err(|_| AppError::unauthorized("invalid observation grant"))?;
            if verifying_key
                .verify_strict(
                    &signed_payload(&decoded.payload),
                    &ed25519_dalek::Signature::from_bytes(&signature_array),
                )
                .is_err()
            {
                return Err(AppError::unauthorized(
                    "observation grant signature is invalid",
                ));
            }

            let deployment_id = deployment_key(conn)?;
            if deployment_id != decoded.claims.deployment_id {
                return Err(AppError::unauthorized(
                    "observation grant deployment changed",
                ));
            }
            require_current_interaction_scope(
                conn,
                &decoded.claims.account_id,
                &decoded.claims.computer_id,
                "observe",
            )?;
            let manager_auth = AuthContext {
                account_id: decoded.claims.account_id.clone(),
                username: String::new(),
                session_id: grant_manager_session_id(conn, &decoded)?,
                manager_id: Some(decoded.claims.manager_id.clone()),
                can_operate: true,
                can_manage_enrollment: false,
                can_manage_access: false,
                can_manage_accounts: false,
                can_manage_security: false,
                revision: 0,
            };
            require_current_operator_session(conn, &manager_auth, now)?;

            let current_manager_key: Option<String> = conn
                .query_row(
                    "SELECT m.public_key FROM managers m
                     JOIN sessions s ON s.manager_id = m.id
                     WHERE m.id = ?1 AND s.id = ?2 AND s.account_id = ?3
                       AND m.lifecycle_state = 'approved'",
                    params![
                        decoded.claims.manager_id,
                        manager_auth.session_id,
                        decoded.claims.account_id
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            if current_manager_key.as_deref() != Some(decoded.claims.manager_public_key.as_str()) {
                return Err(AppError::unauthorized("Manager device identity changed"));
            }
            let current_endpoint_key: Option<String> = conn
                .query_row(
                    "SELECT c.public_identity FROM computers c
                     JOIN endpoint_sessions s ON s.computer_id = c.id
                       AND s.enrollment_epoch = c.enrollment_epoch
                     WHERE c.id = ?1 AND s.id = ?2 AND c.enrollment_state = 'enrolled'
                       AND c.approved_incarnation_identity = c.public_identity
                       AND s.revoked_at IS NULL AND s.expires_at > ?3
                       AND s.local_user_id IS NOT NULL",
                    params![
                        decoded.claims.computer_id,
                        decoded.claims.endpoint_session_id,
                        now
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            if current_endpoint_key
                .as_deref()
                .and_then(|identity| identity.strip_prefix("key:"))
                != Some(decoded.claims.endpoint_public_key.as_str())
            {
                return Err(AppError::unauthorized("endpoint incarnation changed"));
            }

            let stored: Option<(String, i64, Option<i64>, Option<String>)> = conn
                .query_row(
                    "SELECT deployment_key, expires_at, consumed_at, endpoint_nonce_hash
                     FROM observation_admission_grants
                     WHERE id = ?1 AND token_hash = ?2 AND account_id = ?3
                       AND manager_id = ?4 AND manager_session_id = ?5
                       AND computer_id = ?6 AND endpoint_session_id = ?7
                       AND endpoint_public_key = ?8 AND enrollment_epoch = ?9
                       AND manager_public_key = ?10 AND issued_at = ?11",
                    params![
                        decoded.claims.grant_id,
                        decoded.token_hash,
                        decoded.claims.account_id,
                        decoded.claims.manager_id,
                        manager_auth.session_id,
                        decoded.claims.computer_id,
                        decoded.claims.endpoint_session_id,
                        decoded.claims.endpoint_public_key,
                        decoded.claims.enrollment_epoch,
                        decoded.claims.manager_public_key,
                        decoded.claims.issued_at_unix,
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let Some((stored_deployment, expires_at, consumed_at, nonce_hash)) = stored else {
                return Err(AppError::unauthorized("observation grant is not current"));
            };
            if stored_deployment != deployment_id
                || expires_at != decoded.claims.expires_at_unix
                || expires_at <= now
                || consumed_at.is_some()
                || nonce_hash.is_some()
            {
                return Err(AppError::unauthorized(
                    "observation grant is expired or consumed",
                ));
            }
            let endpoint_nonce_hash = hash_token(&req.endpoint_nonce);
            let consumed = conn
                .execute(
                    "UPDATE observation_admission_grants
                     SET consumed_at = ?1, endpoint_nonce_hash = ?2
                     WHERE id = ?3 AND token_hash = ?4 AND consumed_at IS NULL
                       AND expires_at > ?1",
                    params![
                        now,
                        endpoint_nonce_hash,
                        decoded.claims.grant_id,
                        decoded.token_hash
                    ],
                )
                .map_err(|err| {
                    crate::service::map_unique(err, "endpoint nonce was already used")
                })?;
            if consumed != 1 {
                return Err(AppError::unauthorized(
                    "observation grant is expired or consumed",
                ));
            }
            Ok(ObservationAdmissionAcceptedResponse {
                grant_id: decoded.claims.grant_id.clone(),
                computer_id: decoded.claims.computer_id.clone(),
                endpoint_session_id: decoded.claims.endpoint_session_id.clone(),
                expires_at_unix: decoded.claims.expires_at_unix,
            })
        })
    }

    /// Relay one SDP/ICE value under the exact observation grant. Signaling
    /// remains process-local and expires with the grant, so candidate data is
    /// never written to the authority database.
    pub fn publish_observation_signal(
        &self,
        auth: &AuthContext,
        grant_id: &str,
        req: ObservationSignalRequest,
    ) -> AppResult<()> {
        self.require_security_ok()?;
        let grant_id = canonical_uuid(grant_id, "grant_id")?;
        let kind = validate_observation_signal(&req.kind, &req.payload, "manager")?;
        let now = now_unix();
        self.with_tx(|conn| {
            let grant = load_signal_grant(conn, &grant_id, now)?;
            if auth.account_id != grant.account_id
                || auth.session_id != grant.manager_session_id
                || auth.manager_id.as_deref() != Some(grant.manager_id.as_str())
            {
                return Err(AppError::unauthorized(
                    "observation signaling grant belongs to another Manager session",
                ));
            }
            require_live_signal_grant(conn, &grant, now)?;
            require_current_operator_session(conn, auth, now)?;
            self.queue_observation_signal(&grant, kind, req.payload, "manager", now)
        })
    }

    /// Relay one endpoint SDP/ICE value after rechecking the authenticated
    /// endpoint incarnation, the grant's Manager session and observe scope.
    pub fn publish_endpoint_observation_signal(
        &self,
        auth: &EndpointAuthContext,
        grant_id: &str,
        req: ObservationSignalRequest,
    ) -> AppResult<()> {
        self.require_security_ok()?;
        let grant_id = canonical_uuid(grant_id, "grant_id")?;
        let kind = validate_observation_signal(&req.kind, &req.payload, "endpoint")?;
        let now = now_unix();
        self.with_tx(|conn| {
            let grant = load_signal_grant(conn, &grant_id, now)?;
            if auth.computer_id != grant.computer_id
                || auth.session_id != grant.endpoint_session_id
                || auth.enrollment_epoch != grant.enrollment_epoch
            {
                return Err(AppError::unauthorized(
                    "observation signaling grant belongs to another endpoint session",
                ));
            }
            require_current_endpoint_session(conn, auth, now)?;
            require_live_signal_grant(conn, &grant, now)?;
            self.queue_observation_signal(&grant, kind, req.payload, "endpoint", now)
        })
    }

    /// Read a bounded batch sent by the endpoint. Every poll rechecks the
    /// exact Manager session and current observe assignment.
    pub fn poll_observation_signals(
        &self,
        auth: &AuthContext,
        grant_id: &str,
        after: u64,
    ) -> AppResult<ObservationSignalBatch> {
        self.require_security_ok()?;
        let grant_id = canonical_uuid(grant_id, "grant_id")?;
        let now = now_unix();
        self.with_tx(|conn| {
            let grant = load_signal_grant(conn, &grant_id, now)?;
            if auth.account_id != grant.account_id
                || auth.session_id != grant.manager_session_id
                || auth.manager_id.as_deref() != Some(grant.manager_id.as_str())
            {
                return Err(AppError::unauthorized(
                    "observation signaling grant belongs to another Manager session",
                ));
            }
            require_live_signal_grant(conn, &grant, now)?;
            require_current_operator_session(conn, auth, now)?;
            self.read_observation_signals(&grant, "manager", after, now)
        })
    }

    /// Read a bounded batch sent by the Manager. Endpoint authentication is
    /// rechecked against the exact computer/session/epoch on every poll.
    pub fn poll_endpoint_observation_signals(
        &self,
        auth: &EndpointAuthContext,
        grant_id: &str,
        after: u64,
    ) -> AppResult<ObservationSignalBatch> {
        self.require_security_ok()?;
        let grant_id = canonical_uuid(grant_id, "grant_id")?;
        let now = now_unix();
        self.with_tx(|conn| {
            let grant = load_signal_grant(conn, &grant_id, now)?;
            if auth.computer_id != grant.computer_id
                || auth.session_id != grant.endpoint_session_id
                || auth.enrollment_epoch != grant.enrollment_epoch
            {
                return Err(AppError::unauthorized(
                    "observation signaling grant belongs to another endpoint session",
                ));
            }
            require_current_endpoint_session(conn, auth, now)?;
            require_live_signal_grant(conn, &grant, now)?;
            self.read_observation_signals(&grant, "endpoint", after, now)
        })
    }

    fn queue_observation_signal(
        &self,
        grant: &ObservationSignalGrantRow,
        kind: ObservationSignalKind,
        payload: String,
        sender: &'static str,
        now: i64,
    ) -> AppResult<()> {
        let mut mailboxes = self
            .observation_signals
            .lock()
            .map_err(|_| AppError::internal("observation signaling is unavailable"))?;
        mailboxes.retain(|_, mailbox| mailbox.expires_at > now);
        if !mailboxes.contains_key(&grant.id) && mailboxes.len() >= MAX_SIGNALING_MAILBOXES {
            return Err(AppError::rate_limited(
                "observation signaling capacity is temporarily full",
            ));
        }
        let mailbox =
            mailboxes
                .entry(grant.id.clone())
                .or_insert_with(|| ObservationSignalMailbox {
                    expires_at: grant.expires_at,
                    ..ObservationSignalMailbox::default()
                });
        if mailbox.expires_at != grant.expires_at || mailbox.closed {
            return Err(AppError::conflict(
                "observation signaling session is closed",
                Some("observation_signaling_closed".into()),
            ));
        }
        if mailbox.messages.len() >= MAX_SIGNALS_PER_GRANT
            || mailbox.bytes.saturating_add(payload.len()) > MAX_SIGNAL_BYTES_PER_GRANT
        {
            return Err(AppError::rate_limited(
                "observation signaling message budget is exhausted",
            ));
        }
        if matches!(kind, ObservationSignalKind::Challenge) {
            validate_endpoint_observation_challenge(&payload, grant, now)?;
        }
        match kind {
            ObservationSignalKind::Challenge => {
                if mailbox.challenge_sent || sender != "endpoint" {
                    return Err(AppError::conflict(
                        "only one endpoint challenge is allowed for an observation grant",
                        Some("observation_challenge_exists".into()),
                    ));
                }
                mailbox.challenge_sent = true;
            }
            ObservationSignalKind::Offer => {
                if mailbox.offer_sent || sender != "manager" || !mailbox.challenge_sent {
                    return Err(AppError::conflict(
                        "one endpoint challenge is required before the Manager offer",
                        Some("observation_offer_exists".into()),
                    ));
                }
                mailbox.offer_sent = true;
            }
            ObservationSignalKind::Answer => {
                if mailbox.answer_sent || sender != "endpoint" || !mailbox.offer_sent {
                    return Err(AppError::conflict(
                        "an endpoint answer requires one Manager offer",
                        Some("observation_answer_invalid".into()),
                    ));
                }
                mailbox.answer_sent = true;
            }
            ObservationSignalKind::Ice => {
                if !mailbox.offer_sent {
                    return Err(AppError::conflict(
                        "ICE candidates require a Manager offer",
                        Some("observation_offer_missing".into()),
                    ));
                }
            }
            ObservationSignalKind::Close => mailbox.closed = true,
        }
        let sequence = mailbox
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| AppError::rate_limited("observation signaling sequence exhausted"))?;
        mailbox.next_sequence = sequence;
        mailbox.bytes += payload.len();
        mailbox.messages.push(ObservationSignalMessage {
            sequence,
            sender,
            kind: kind.as_str().to_string(),
            payload,
        });
        Ok(())
    }

    fn read_observation_signals(
        &self,
        grant: &ObservationSignalGrantRow,
        recipient: &'static str,
        after: u64,
        now: i64,
    ) -> AppResult<ObservationSignalBatch> {
        let mut mailboxes = self
            .observation_signals
            .lock()
            .map_err(|_| AppError::internal("observation signaling is unavailable"))?;
        mailboxes.retain(|_, mailbox| mailbox.expires_at > now);
        let Some(mailbox) = mailboxes.get(&grant.id) else {
            return Ok(ObservationSignalBatch {
                cursor: after,
                messages: Vec::new(),
            });
        };
        if after > mailbox.next_sequence {
            return Err(AppError::bad_request(
                "observation signaling cursor is ahead of the session",
            ));
        }
        let mut messages = Vec::new();
        for message in mailbox
            .messages
            .iter()
            .filter(|message| message.sequence > after && message.sender != recipient)
        {
            if messages.len() == MAX_SIGNAL_BATCH {
                break;
            }
            messages.push(message.clone());
        }
        let cursor = if messages.len() == MAX_SIGNAL_BATCH {
            messages
                .last()
                .map(|message| message.sequence)
                .unwrap_or(after)
        } else {
            mailbox.next_sequence
        };
        Ok(ObservationSignalBatch { cursor, messages })
    }
}

#[derive(Debug)]
struct ObservationSignalGrantRow {
    id: String,
    deployment_id: String,
    account_id: String,
    manager_id: String,
    manager_session_id: String,
    manager_public_key: String,
    computer_id: String,
    endpoint_session_id: String,
    endpoint_public_key: String,
    enrollment_epoch: i64,
    expires_at: i64,
}

#[derive(Debug, Clone, Copy)]
enum ObservationSignalKind {
    Challenge,
    Offer,
    Answer,
    Ice,
    Close,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointObservationChallengeSignal {
    computer_id: String,
    endpoint_session_id: String,
    endpoint_nonce: String,
    expires_at_unix: i64,
    #[serde(default)]
    endpoint_certificate_pem: Option<String>,
    #[serde(default)]
    endpoint_certificate_signature: Option<String>,
}

fn validate_endpoint_observation_challenge(
    payload: &str,
    grant: &ObservationSignalGrantRow,
    now: i64,
) -> AppResult<()> {
    let challenge: EndpointObservationChallengeSignal = serde_json::from_str(payload)
        .map_err(|_| AppError::bad_request("invalid observation endpoint challenge"))?;
    let computer_id = canonical_uuid(&challenge.computer_id, "computer_id")?;
    let endpoint_session_id =
        canonical_uuid(&challenge.endpoint_session_id, "endpoint_session_id")?;
    if computer_id != grant.computer_id
        || endpoint_session_id != grant.endpoint_session_id
        || !valid_hex(&challenge.endpoint_nonce, 32)
        || challenge.expires_at_unix != grant.expires_at
        || challenge.expires_at_unix <= now
    {
        return Err(AppError::unauthorized(
            "observation endpoint challenge does not match the current grant",
        ));
    }
    match (
        challenge.endpoint_certificate_pem.as_deref(),
        challenge.endpoint_certificate_signature.as_deref(),
    ) {
        (None, None) => {}
        (Some(certificate_pem), Some(signature_hex)) => {
            if !is_canonical_observation_certificate_pem(certificate_pem)
                || !valid_hex(signature_hex, 64)
            {
                return Err(AppError::bad_request(
                    "observation endpoint certificate attestation is malformed",
                ));
            }
            let certificate_sha256 = hex::encode(Sha256::digest(certificate_pem.as_bytes()));
            let message = format!(
                "hs-observation-peer-certificate-v1|deployment:{}|grant:{}|computer:{}|endpoint_session:{}|epoch:{}|nonce:{}|role:endpoint|certificate_sha256:{}",
                grant.deployment_id,
                grant.id,
                grant.computer_id,
                grant.endpoint_session_id,
                grant.enrollment_epoch,
                challenge.endpoint_nonce,
                certificate_sha256,
            );
            if !verify_ed25519_strict(
                &grant.endpoint_public_key,
                message.as_bytes(),
                signature_hex,
            )? {
                return Err(AppError::unauthorized(
                    "observation endpoint certificate attestation is invalid",
                ));
            }
        }
        _ => {
            return Err(AppError::bad_request(
                "observation endpoint certificate attestation is incomplete",
            ));
        }
    }
    Ok(())
}

fn is_canonical_observation_certificate_pem(value: &str) -> bool {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----\n";
    const END: &str = "-----END CERTIFICATE-----\n";
    if value.len() > 4096 || !value.is_ascii() {
        return false;
    }
    let Some(body) = value
        .strip_prefix(BEGIN)
        .and_then(|value| value.strip_suffix(END))
    else {
        return false;
    };
    !body.is_empty()
        && body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'\n'))
}

impl ObservationSignalKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::Offer => "offer",
            Self::Answer => "answer",
            Self::Ice => "ice",
            Self::Close => "close",
        }
    }
}

fn validate_observation_signal(
    kind: &str,
    payload: &str,
    sender: &'static str,
) -> AppResult<ObservationSignalKind> {
    let parsed = match kind {
        "challenge" if sender == "endpoint" => ObservationSignalKind::Challenge,
        "offer" if sender == "manager" => ObservationSignalKind::Offer,
        "answer" if sender == "endpoint" => ObservationSignalKind::Answer,
        "ice" => ObservationSignalKind::Ice,
        "close" => ObservationSignalKind::Close,
        _ => return Err(AppError::bad_request("invalid observation signal kind")),
    };
    let max_bytes = match parsed {
        ObservationSignalKind::Challenge => 4096,
        ObservationSignalKind::Offer | ObservationSignalKind::Answer => 65_536,
        ObservationSignalKind::Ice => 4_096,
        ObservationSignalKind::Close => 0,
    };
    if payload.len() > max_bytes
        || (matches!(
            parsed,
            ObservationSignalKind::Offer | ObservationSignalKind::Answer
        ) && payload.is_empty())
        || (matches!(
            parsed,
            ObservationSignalKind::Offer | ObservationSignalKind::Answer
        ) && !payload.starts_with("v=0"))
        || (matches!(parsed, ObservationSignalKind::Challenge) && payload.is_empty())
        || payload.bytes().any(|byte| {
            byte == 0 || (byte.is_ascii_control() && !matches!(byte, b'\r' | b'\n' | b'\t'))
        })
    {
        return Err(AppError::bad_request(
            "observation signal payload is invalid or oversized",
        ));
    }
    Ok(parsed)
}

fn load_signal_grant(
    conn: &rusqlite::Connection,
    grant_id: &str,
    now: i64,
) -> AppResult<ObservationSignalGrantRow> {
    let row = conn
        .query_row(
            "SELECT deployment_key, account_id, manager_id, manager_session_id,
                    manager_public_key, computer_id, endpoint_session_id,
                    endpoint_public_key, enrollment_epoch, expires_at
             FROM observation_admission_grants WHERE id = ?1 AND expires_at > ?2",
            params![grant_id, now],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| AppError::unauthorized("observation signaling grant is not current"))?;
    Ok(ObservationSignalGrantRow {
        id: grant_id.to_string(),
        deployment_id: row.0,
        account_id: row.1,
        manager_id: row.2,
        manager_session_id: row.3,
        manager_public_key: row.4,
        computer_id: row.5,
        endpoint_session_id: row.6,
        endpoint_public_key: row.7,
        enrollment_epoch: row.8,
        expires_at: row.9,
    })
}

fn require_live_signal_grant(
    conn: &rusqlite::Connection,
    grant: &ObservationSignalGrantRow,
    now: i64,
) -> AppResult<()> {
    if deployment_key(conn)? != grant.deployment_id || grant.expires_at <= now {
        return Err(AppError::unauthorized(
            "observation signaling grant is not current",
        ));
    }
    require_current_interaction_scope(conn, &grant.account_id, &grant.computer_id, "observe")?;
    let endpoint_current: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM computers c JOIN endpoint_sessions s ON s.computer_id = c.id
             AND s.enrollment_epoch = c.enrollment_epoch
            WHERE c.id = ?1 AND c.enrollment_state = 'enrolled'
              AND c.approved_incarnation_identity = c.public_identity
              AND c.public_identity = 'key:' || ?5
              AND s.id = ?2 AND s.enrollment_epoch = ?3
              AND s.revoked_at IS NULL AND s.expires_at > ?4
              AND s.local_user_id IS NOT NULL
        )",
        params![
            grant.computer_id,
            grant.endpoint_session_id,
            grant.enrollment_epoch,
            now,
            grant.endpoint_public_key
        ],
        |row| row.get(0),
    )?;
    if !endpoint_current {
        return Err(AppError::unauthorized(
            "endpoint session is no longer current",
        ));
    }
    let manager_auth = AuthContext {
        account_id: grant.account_id.clone(),
        username: String::new(),
        session_id: grant.manager_session_id.clone(),
        manager_id: Some(grant.manager_id.clone()),
        can_operate: true,
        can_manage_enrollment: false,
        can_manage_access: false,
        can_manage_accounts: false,
        can_manage_security: false,
        revision: 0,
    };
    require_current_operator_session(conn, &manager_auth, now).and_then(|()| {
        let current_key: Option<String> = conn
            .query_row(
                "SELECT m.public_key FROM managers m
                     JOIN sessions s ON s.manager_id = m.id
                     WHERE m.id = ?1 AND s.id = ?2 AND s.account_id = ?3
                       AND m.lifecycle_state = 'approved'",
                params![grant.manager_id, grant.manager_session_id, grant.account_id],
                |row| row.get(0),
            )
            .optional()?;
        if current_key.as_deref() != Some(grant.manager_public_key.as_str()) {
            return Err(AppError::unauthorized("Manager device identity changed"));
        }
        Ok(())
    })
}

fn grant_manager_session_id(
    conn: &rusqlite::Connection,
    decoded: &DecodedGrant,
) -> AppResult<String> {
    let session_id: Option<String> = conn
        .query_row(
            "SELECT manager_session_id FROM observation_admission_grants
             WHERE id = ?1 AND token_hash = ?2",
            params![decoded.claims.grant_id, decoded.token_hash],
            |row| row.get(0),
        )
        .optional()?;
    session_id.ok_or_else(|| AppError::unauthorized("observation grant is not current"))
}

impl Drop for crate::models::RedeemObservationGrantRequest {
    fn drop(&mut self) {
        self.grant_token.zeroize();
        self.manager_proof.zeroize();
        self.endpoint_nonce.zeroize();
        self.channel_binding.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::RedeemObservationGrantRequest;
    use ed25519_dalek::SigningKey;
    use rusqlite::params;

    const ACCOUNT_ID: &str = "00000000-0000-4000-8000-000000000001";
    const MANAGER_ID: &str = "00000000-0000-4000-8000-000000000002";
    const COMPUTER_ID: &str = "00000000-0000-4000-8000-000000000003";
    const MANAGER_SESSION_ID: &str = "00000000-0000-4000-8000-000000000004";
    const ENDPOINT_SESSION_ID: &str = "00000000-0000-4000-8000-000000000005";
    const OBSERVE_ASSIGNMENT_ID: &str = "00000000-0000-4000-8000-000000000006";
    const MANAGER_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const ENDPOINT_TOKEN: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    struct AdmissionFixture {
        service: Service,
        manager_signer: SigningKey,
        endpoint_signer: SigningKey,
        manager_public_key: String,
    }

    fn admission_fixture() -> AdmissionFixture {
        let db = crate::db::open_in_memory().expect("in-memory database");
        let service = Service::new(db);
        let manager_signer = SigningKey::from_bytes(&[0x11; 32]);
        let endpoint_signer = SigningKey::from_bytes(&[0x22; 32]);
        let manager_public_key = hex::encode(manager_signer.verifying_key().to_bytes());
        let endpoint_public_key = hex::encode(endpoint_signer.verifying_key().to_bytes());
        let now = now_unix();
        let db = service.db_handle();
        let conn = db.lock().expect("lock database");
        conn.execute(
            "INSERT INTO accounts (
                id, username, password_hash, state, can_operate, created_at, updated_at
             ) VALUES (?1, 'operator', 'test-hash', 'active', 1, ?2, ?2)",
            params![ACCOUNT_ID, now],
        )
        .expect("insert account");
        conn.execute(
            "INSERT INTO managers (
                id, public_identity, friendly_name, lifecycle_state,
                approved_by_account_id, approved_at, created_at, updated_at, public_key
             ) VALUES (?1, ?2, 'Manager', 'approved', ?3, ?4, ?4, ?4, ?5)",
            params![
                MANAGER_ID,
                format!("key:{manager_public_key}"),
                ACCOUNT_ID,
                now,
                manager_public_key
            ],
        )
        .expect("insert Manager");
        conn.execute(
            "INSERT INTO sessions (
                id, account_id, manager_id, token_hash, created_at, expires_at,
                assurance, mfa_assured_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'password', NULL)",
            params![
                MANAGER_SESSION_ID,
                ACCOUNT_ID,
                MANAGER_ID,
                hash_token(MANAGER_TOKEN),
                now,
                now + 3600
            ],
        )
        .expect("insert Manager session");
        conn.execute(
            "INSERT INTO computers (
                id, public_identity, friendly_name, platform, enrollment_state,
                enrollment_epoch, approved_incarnation_identity, created_at, updated_at
             ) VALUES (?1, ?2, 'Endpoint', 'windows', 'enrolled', 2, ?2, ?3, ?3)",
            params![COMPUTER_ID, format!("key:{endpoint_public_key}"), now],
        )
        .expect("insert computer");
        conn.execute(
            "INSERT INTO endpoint_sessions (
                id, token_hash, computer_id, enrollment_epoch, local_user_id,
                local_user_display_name, created_at, expires_at, revoked_at
             ) VALUES (?1, ?2, ?3, 2, 'windows:sid:S-1-5-21-1', 'Operator', ?4, ?5, NULL)",
            params![
                ENDPOINT_SESSION_ID,
                hash_token(ENDPOINT_TOKEN),
                COMPUTER_ID,
                now,
                now + 900
            ],
        )
        .expect("insert endpoint session");
        conn.execute(
            "INSERT INTO access_assignments (
                id, account_id, capability, computer_scope_all, revision,
                created_at, updated_at
             ) VALUES (?1, ?2, 'observe', 0, 1, ?3, ?3)",
            params![OBSERVE_ASSIGNMENT_ID, ACCOUNT_ID, now],
        )
        .expect("insert observe assignment");
        conn.execute(
            "INSERT INTO access_computer_scope (assignment_id, computer_id)
             VALUES (?1, ?2)",
            params![OBSERVE_ASSIGNMENT_ID, COMPUTER_ID],
        )
        .expect("scope observe assignment");
        drop(conn);
        AdmissionFixture {
            service,
            manager_signer,
            endpoint_signer,
            manager_public_key,
        }
    }

    fn issued_grant(fixture: &AdmissionFixture) -> SignedObservationGrantResponse {
        let auth = fixture
            .service
            .authenticate_token(MANAGER_TOKEN)
            .expect("authenticate Manager");
        fixture
            .service
            .issue_observation_grant(
                &auth,
                IssueObservationGrantRequest {
                    computer_id: COMPUTER_ID.into(),
                },
            )
            .expect("issue observation grant")
    }

    fn redeem_request(
        fixture: &AdmissionFixture,
        grant_token: String,
    ) -> RedeemObservationGrantRequest {
        let now = now_unix();
        let decoded = decode_token(&grant_token, now).expect("decode issued grant");
        assert_eq!(
            decoded.claims.manager_public_key,
            fixture.manager_public_key
        );
        let endpoint_nonce = "33".repeat(32);
        let channel_binding = hex::encode(
            WebRtcChannelBinding::new(7, [0x11; 32], [0x22; 32])
                .expect("valid WebRTC test binding")
                .encode(),
        );
        let proof =
            observation_peer_proof_message(&decoded.claims, &endpoint_nonce, &channel_binding)
                .expect("proof message");
        RedeemObservationGrantRequest {
            grant_token,
            endpoint_nonce,
            channel_binding,
            manager_proof: hex::encode(fixture.manager_signer.sign(&proof).to_bytes()),
        }
    }

    #[test]
    fn observation_grant_token_is_canonical_and_domain_separated() {
        let claims = ObservationGrantClaimsV1 {
            version: 1,
            grant_id: "00000000-0000-4000-8000-000000000001".into(),
            deployment_id: "dep_00000000000040008000000000000002".into(),
            account_id: "00000000-0000-4000-8000-000000000003".into(),
            manager_id: "00000000-0000-4000-8000-000000000004".into(),
            manager_public_key: "11".repeat(32),
            computer_id: "00000000-0000-4000-8000-000000000005".into(),
            endpoint_public_key: "22".repeat(32),
            endpoint_session_id: "00000000-0000-4000-8000-000000000006".into(),
            enrollment_epoch: 2,
            issued_at_unix: 100,
            expires_at_unix: 110,
            capability: "observe".into(),
        };
        let secret = [7_u8; 32];
        let token = encode_token(&claims, &secret).expect("encode token");
        let decoded = decode_token(&token, 105).expect("decode token");
        assert_eq!(decoded.claims, claims);
        let nonce = "33".repeat(32);
        let channel_binding = hex::encode(
            WebRtcChannelBinding::new(7, [0x11; 32], [0x22; 32])
                .expect("valid WebRTC test binding")
                .encode(),
        );
        let proof = observation_peer_proof_message(&decoded.claims, &nonce, &channel_binding)
            .expect("proof bytes");
        assert!(String::from_utf8(proof)
            .expect("UTF-8 proof")
            .starts_with("hs-observation-peer-proof-v2|deployment:dep_"));
        assert!(decode_token(&token, 110).is_err(), "expiry is exclusive");
    }

    #[test]
    fn endpoint_challenge_verifies_certificate_against_its_device_key_and_nonce() {
        let fixture = admission_fixture();
        let grant = issued_grant(&fixture);
        let now = now_unix();
        let db = fixture.service.db_handle();
        let conn = db.lock().expect("lock database");
        let grant_row = load_signal_grant(&conn, &grant.grant_id, now).expect("load grant");
        drop(conn);

        let certificate_pem = "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n";
        let endpoint_nonce = "44".repeat(32);
        let certificate_sha256 = hex::encode(Sha256::digest(certificate_pem.as_bytes()));
        let message = format!(
            "hs-observation-peer-certificate-v1|deployment:{}|grant:{}|computer:{}|endpoint_session:{}|epoch:{}|nonce:{}|role:endpoint|certificate_sha256:{}",
            grant_row.deployment_id,
            grant_row.id,
            grant_row.computer_id,
            grant_row.endpoint_session_id,
            grant_row.enrollment_epoch,
            endpoint_nonce,
            certificate_sha256,
        );
        let signature = hex::encode(fixture.endpoint_signer.sign(message.as_bytes()).to_bytes());
        let payload = serde_json::json!({
            "computer_id": grant_row.computer_id,
            "endpoint_session_id": grant_row.endpoint_session_id,
            "endpoint_nonce": endpoint_nonce,
            "expires_at_unix": grant_row.expires_at,
            "endpoint_certificate_pem": certificate_pem,
            "endpoint_certificate_signature": signature,
        })
        .to_string();

        validate_endpoint_observation_challenge(&payload, &grant_row, now)
            .expect("valid device-attested certificate challenge");

        let replayed_nonce = serde_json::json!({
            "computer_id": grant_row.computer_id,
            "endpoint_session_id": grant_row.endpoint_session_id,
            "endpoint_nonce": "55".repeat(32),
            "expires_at_unix": grant_row.expires_at,
            "endpoint_certificate_pem": certificate_pem,
            "endpoint_certificate_signature": signature,
        })
        .to_string();
        assert!(validate_endpoint_observation_challenge(&replayed_nonce, &grant_row, now).is_err());
    }

    #[test]
    fn observation_grant_binds_both_sessions_and_is_consumed_once() {
        let fixture = admission_fixture();
        let grant = issued_grant(&fixture);
        let grant_token = grant.grant_token.clone();
        assert!(grant.expires_at_unix <= now_unix() + GRANT_TTL_SECS);
        let endpoint = fixture
            .service
            .authenticate_endpoint_token(ENDPOINT_TOKEN)
            .expect("authenticate endpoint");
        let accepted = fixture
            .service
            .redeem_observation_grant(&endpoint, redeem_request(&fixture, grant_token.clone()))
            .expect("redeem grant");
        assert_eq!(accepted.grant_id, grant.grant_id);
        assert_eq!(accepted.computer_id, COMPUTER_ID);
        assert_eq!(accepted.endpoint_session_id, ENDPOINT_SESSION_ID);

        let replay = fixture
            .service
            .redeem_observation_grant(&endpoint, redeem_request(&fixture, grant_token))
            .expect_err("grant replay must fail");
        assert!(matches!(
            replay,
            AppError::Api {
                code: crate::error::ErrorCode::Unauthorized,
                ..
            }
        ));
    }

    #[test]
    fn observation_grant_rechecks_observe_scope_at_redemption() {
        let fixture = admission_fixture();
        let grant = issued_grant(&fixture);
        let grant_token = grant.grant_token.clone();
        let db = fixture.service.db_handle();
        db.lock()
            .expect("lock database")
            .execute(
                "DELETE FROM access_assignments WHERE id = ?1",
                params![OBSERVE_ASSIGNMENT_ID],
            )
            .expect("revoke observe assignment");
        let endpoint = fixture
            .service
            .authenticate_endpoint_token(ENDPOINT_TOKEN)
            .expect("authenticate endpoint");
        assert!(fixture
            .service
            .redeem_observation_grant(&endpoint, redeem_request(&fixture, grant_token))
            .is_err());
        let conn = db.lock().expect("lock database");
        let consumed: Option<i64> = conn
            .query_row(
                "SELECT consumed_at FROM observation_admission_grants WHERE id = ?1",
                params![grant.grant_id],
                |row| row.get(0),
            )
            .expect("read grant state");
        assert!(consumed.is_none(), "denied grant must remain unconsumed");
    }
}
