//! HTTP surface for contract version 1. Loopback-only by default in `main`.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::service::{AuthContext, Service};

pub type SharedService = Arc<Service>;

pub fn router(service: SharedService) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/bootstrap", post(bootstrap))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/session", get(session))
        .route("/v1/managers", get(list_managers).post(register_manager))
        .route("/v1/managers/{id}/approve", post(approve_manager))
        .route("/v1/managers/{id}/revoke", post(revoke_manager))
        .route("/v1/computers", get(list_computers).post(create_computer))
        .route("/v1/computers/{id}", get(get_computer))
        .route("/v1/access", get(list_access).post(grant_access))
        .route("/v1/mfa/status", get(mfa_status))
        .route("/v1/files/jobs", post(file_jobs_unavailable))
        .route("/v1/security/recovery", post(security_recovery_unavailable))
        // Auth v2: MFA enrollment, device-key challenge, recovery-only.
        .route("/v2/bootstrap", post(bootstrap_v2))
        .route("/v2/mfa/enroll/confirm", post(mfa_enroll_confirm))
        .route("/v2/mfa/enroll/cancel", post(mfa_enroll_cancel))
        .route("/v2/auth/challenge", post(auth_challenge_begin))
        .route("/v2/auth/challenge/complete", post(auth_challenge_complete))
        .route("/v2/auth/recovery/begin", post(factor_recovery_begin))
        .route("/v2/auth/recovery/complete", post(factor_recovery_complete))
        .with_state(service)
}

async fn health(State(service): State<SharedService>) -> AppResult<Json<HealthResponse>> {
    Ok(Json(service.health()?))
}

async fn bootstrap(
    State(service): State<SharedService>,
    Json(req): Json<BootstrapRequest>,
) -> AppResult<(StatusCode, Json<BootstrapResponse>)> {
    let response = service.bootstrap(req)?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn login(
    State(service): State<SharedService>,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    Ok(Json(service.login(req)?))
}

async fn logout(State(service): State<SharedService>, headers: HeaderMap) -> AppResult<StatusCode> {
    let auth = authenticate(&service, &headers)?;
    service.logout(&auth)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn session(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<SessionResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.session_info(&auth)?))
}

async fn list_managers(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let auth = authenticate(&service, &headers)?;
    let managers = service.list_managers(&auth)?;
    Ok(Json(serde_json::json!({
        "managers": managers,
        "max_page_size": crate::service::MAX_PAGE_SIZE,
    })))
}

async fn register_manager(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<RegisterManagerRequest>,
) -> AppResult<(StatusCode, Json<ManagerView>)> {
    let auth = authenticate(&service, &headers)?;
    let manager = service.register_manager(&auth, req)?;
    Ok((StatusCode::CREATED, Json(manager)))
}

async fn approve_manager(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ApproveManagerRequest>,
) -> AppResult<Json<ManagerView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.approve_manager(&auth, &id, req)?))
}

async fn revoke_manager(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<ManagerView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.revoke_manager(&auth, &id)?))
}

async fn list_computers(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<ComputerListResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.list_computers(&auth)?))
}

async fn create_computer(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<CreateComputerRequest>,
) -> AppResult<(StatusCode, Json<ComputerView>)> {
    let auth = authenticate(&service, &headers)?;
    let computer = service.create_computer(&auth, req)?;
    Ok((StatusCode::CREATED, Json(computer)))
}

async fn get_computer(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<ComputerView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.get_computer(&auth, &id)?))
}

async fn list_access(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let auth = authenticate(&service, &headers)?;
    let assignments = service.list_access(&auth)?;
    Ok(Json(
        serde_json::json!({ "access_assignments": assignments }),
    ))
}

async fn grant_access(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<GrantAccessRequest>,
) -> AppResult<(StatusCode, Json<AccessAssignmentView>)> {
    let auth = authenticate(&service, &headers)?;
    let assignment = service.grant_access(&auth, req)?;
    Ok((StatusCode::CREATED, Json(assignment)))
}

async fn mfa_status() -> Json<MfaStatus> {
    Json(MfaStatus {
        required: true,
        available: true,
        reason: "totp_recovery_device_key_v2",
    })
}

// ----- auth v2 -----

async fn bootstrap_v2(
    State(service): State<SharedService>,
    Json(req): Json<BootstrapV2Request>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let response = service.bootstrap_v2(req)?;
    // Secrets are returned once in the response body and never logged.
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "account_id": response.account_id,
            "username": response.username,
            "mfa_enrollment_id": response.mfa_enrollment_id,
            "totp_secret_base32": response.totp_secret_base32,
            "recovery_codes": response.recovery_codes,
            "manager_public_key": response.manager_public_key,
            "account_state": response.account_state,
            "server_state": response.server_state,
        })),
    ))
}

async fn mfa_enroll_confirm(
    State(service): State<SharedService>,
    Json(req): Json<MfaConfirmRequest>,
) -> AppResult<Json<MfaConfirmResponse>> {
    Ok(Json(service.confirm_mfa_enrollment(req)?))
}

async fn mfa_enroll_cancel(
    State(service): State<SharedService>,
    Json(req): Json<MfaEnrollCancelRequest>,
) -> AppResult<StatusCode> {
    service.cancel_mfa_enrollment(&req.mfa_enrollment_id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn auth_challenge_begin(
    State(service): State<SharedService>,
    Json(req): Json<AuthChallengeBeginRequest>,
) -> AppResult<(StatusCode, Json<AuthChallengeBeginResponse>)> {
    let response = service.begin_auth_challenge(req)?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn auth_challenge_complete(
    State(service): State<SharedService>,
    Json(req): Json<AuthChallengeCompleteRequest>,
) -> AppResult<Json<LoginResponse>> {
    Ok(Json(service.complete_auth_challenge(req)?))
}

async fn factor_recovery_begin(
    State(service): State<SharedService>,
    Json(req): Json<FactorRecoveryBeginRequest>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let response = service.begin_factor_recovery(req)?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "mfa_enrollment_id": response.mfa_enrollment_id,
            "totp_secret_base32": response.totp_secret_base32,
            "account_id": response.account_id,
            "purpose": response.purpose,
        })),
    ))
}

async fn factor_recovery_complete(
    State(service): State<SharedService>,
    Json(req): Json<MfaConfirmRequest>,
) -> AppResult<Json<MfaConfirmResponse>> {
    Ok(Json(service.complete_factor_recovery(req)?))
}

#[derive(Serialize)]
struct UnavailableBody {
    available: bool,
    reason: &'static str,
}

async fn file_jobs_unavailable() -> (StatusCode, Json<UnavailableBody>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(UnavailableBody {
            available: false,
            reason: "file_jobs_not_implemented_in_this_foundation",
        }),
    )
}

async fn security_recovery_unavailable() -> (StatusCode, Json<UnavailableBody>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(UnavailableBody {
            available: false,
            reason: "security_recovery_not_implemented_in_this_foundation",
        }),
    )
}

/// Extract and verify the bearer token. Owner fields always come from the session.
fn authenticate(service: &Service, headers: &HeaderMap) -> AppResult<AuthContext> {
    let token = bearer_token(headers)?;
    service.authenticate_token(&token)
}

fn bearer_token(headers: &HeaderMap) -> AppResult<String> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;
    let token = value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| AppError::unauthorized("Authorization must use Bearer token"))?;
    Ok(token.to_string())
}
