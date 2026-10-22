//! Versioned HTTP surface. Plain HTTP uses the full development router on
//! loopback; explicitly enabled TLS network listeners use the v2-only router.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::{timeout, Instant};

use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::service::{AuthContext, Service};

pub type SharedService = Arc<Service>;

pub fn router(service: SharedService) -> Router {
    router_with_modes(service, true, true)
}

/// Network-facing TLS router. Legacy v1 development routes and local-only v2
/// bootstrap/recovery routes are absent; remote Manager traffic uses v2 APIs.
pub fn network_router(service: SharedService) -> Router {
    router_with_modes(service, false, true)
}

fn router_with_modes(
    service: SharedService,
    enable_v1_development_routes: bool,
    enable_file_job_routes: bool,
) -> Router {
    // Manager-owned file requests and recipient-bound endpoint file jobs are
    // authenticated v2 capabilities on both routers. Legacy v1 file routes
    // remain unavailable.
    let mut routes = Router::new().route("/health", get(health));
    if enable_v1_development_routes {
        routes = routes
            .route("/v1/bootstrap", post(bootstrap))
            .route("/v1/auth/login", post(login))
            .route("/v1/auth/logout", post(logout))
            .route("/v1/auth/session", get(session))
            .route("/v1/managers", get(list_managers).post(register_manager))
            .route("/v1/managers/{id}/approve", post(approve_manager))
            .route("/v1/managers/{id}/revoke", post(revoke_manager))
            .route("/v1/accounts", get(list_accounts))
            .route("/v1/computers", get(list_computers).post(create_computer))
            .route("/v1/computers/{id}", get(get_computer))
            .route("/v1/access", get(list_access).post(grant_access))
            .route("/v1/mfa/status", get(mfa_status))
            .route("/v1/files/jobs", post(file_jobs_unavailable))
            .route("/v1/security/recovery", post(security_recovery_unavailable));
    }

    routes = routes
        // Auth v2: MFA enrollment and device-key challenge.
        .route("/v2/deployment", get(deployment_info))
        .route("/v2/deployment/authority", get(deployment_authority))
        .route("/v2/authority/cutover", get(authority_cutover_status_v2))
        .route(
            "/v2/authority/cutover/drain",
            post(begin_authority_cutover_v2),
        )
        .route(
            "/v2/authority/cutover/approve",
            post(approve_authority_cutover_v2),
        )
        .route(
            "/v2/authority/cutover/cancel",
            post(cancel_authority_cutover_v2),
        )
        .route("/v2/mfa/enroll/confirm", post(mfa_enroll_confirm))
        .route("/v2/mfa/enroll/begin", post(mfa_enroll_begin))
        .route("/v2/mfa/enroll/cancel", post(mfa_enroll_cancel))
        .route("/v2/auth/challenge", post(auth_challenge_begin))
        .route("/v2/auth/challenge/complete", post(auth_challenge_complete))
        .route("/v2/auth/logout", post(logout))
        .route("/v2/accounts", get(list_accounts).post(create_account_v2))
        .route("/v2/computers", get(list_computers_v2))
        .route("/v2/access/observe-scope", get(observation_scope))
        .route("/v2/enrollment/computers", get(list_enrollment_computers))
        .route(
            "/v2/enrollment/invitations",
            get(list_endpoint_invitations).post(create_endpoint_invitation),
        )
        .route(
            "/v2/enrollment/invitations/{id}/revoke",
            post(revoke_endpoint_invitation),
        )
        .route("/v2/endpoints/enroll", post(enroll_endpoint))
        .route(
            "/v2/endpoints/session/challenge",
            post(endpoint_session_challenge),
        )
        .route(
            "/v2/endpoints/session/complete",
            post(endpoint_session_complete),
        )
        .route("/v2/endpoints/self", get(endpoint_self))
        .route("/v2/admissions/observation", post(issue_observation_grant))
        .route(
            "/v2/admissions/observation/{grant_id}/signals",
            get(poll_observation_signals).post(publish_observation_signal),
        )
        .route(
            "/v2/endpoints/admissions/observation/redeem",
            post(redeem_observation_grant),
        )
        .route(
            "/v2/endpoints/admissions/observation/pending",
            get(poll_pending_observation_grants),
        )
        .route(
            "/v2/endpoints/admissions/observation/{grant_id}/signals",
            get(poll_endpoint_observation_signals).post(publish_endpoint_observation_signal),
        )
        .route(
            "/v2/enrollment/computers/{id}/approve",
            post(approve_computer_enrollment),
        )
        .route(
            "/v2/enrollment/computers/{id}/revoke",
            post(revoke_computer_enrollment),
        )
        .route(
            "/v2/groups",
            get(list_computer_groups).post(create_computer_group),
        )
        .route(
            "/v2/groups/{id}",
            axum::routing::put(rename_computer_group).delete(delete_computer_group),
        )
        .route(
            "/v2/groups/{id}/computers/{computer_id}",
            axum::routing::put(set_computer_group_membership),
        )
        .route(
            "/v2/accounts/{id}/capabilities",
            axum::routing::put(update_account_capabilities_v2),
        )
        .route(
            "/v2/accounts/{id}/state",
            axum::routing::put(update_account_state_v2),
        )
        .route("/v2/access", get(list_access).post(grant_access_v2))
        .route("/v2/access/{id}", axum::routing::delete(revoke_access_v2))
        .route("/v2/managers", get(list_managers).post(enroll_manager_key))
        .route("/v2/managers/{id}/approve", post(approve_manager_v2))
        .route("/v2/managers/{id}/revoke", post(revoke_manager_v2))
        .route(
            "/v2/security/operator-mfa-policy",
            get(get_operator_mfa_policy).put(put_operator_mfa_policy),
        )
        .route(
            "/v2/security/audit-retention",
            get(get_audit_retention).put(put_audit_retention),
        )
        .route("/v2/audit/events", get(list_audit_events));

    if enable_v1_development_routes {
        routes = routes
            .route("/v2/bootstrap", post(bootstrap_v2))
            .route(
                "/v2/recovery/quarantine",
                get(recovery_quarantine_status_v2),
            )
            .route(
                "/v2/recovery/quarantine/release",
                post(release_recovery_quarantine_v2),
            )
            .route("/v2/auth/recovery/begin", post(factor_recovery_begin))
            .route("/v2/auth/recovery/complete", post(factor_recovery_complete));
    }

    routes = routes
        .route("/v2/files/storage", get(file_storage_summary))
        .route(
            "/v2/files/requests",
            get(list_file_requests).post(create_file_request),
        )
        .route("/v2/files/requests/{id}", get(get_file_request))
        .route(
            "/v2/files/requests/{id}/publish",
            post(publish_file_request),
        )
        .route("/v2/files/requests/{id}/close", post(close_file_request))
        .route(
            "/v2/files/requests/{id}/submissions",
            get(list_file_request_submissions),
        )
        .route(
            "/v2/files/requests/{request_id}/submissions/{submission_id}",
            delete(delete_file_request_submission_content),
        )
        .route(
            "/v2/files/requests/{id}/submissions/{submission_id}/files/{file_id}/chunks/{index}",
            get(get_file_request_submission_chunk),
        )
        .route("/v2/endpoints/file-requests", get(endpoint_file_requests))
        .route(
            "/v2/endpoints/file-requests/{request_id}/submissions",
            get(endpoint_file_request_submissions).post(create_endpoint_file_request_submission),
        )
        .route(
            "/v2/endpoints/file-requests/{request_id}/submissions/{submission_id}/files/{file_id}/chunks/{index}",
            put(put_endpoint_file_request_chunk),
        )
        .route(
            "/v2/endpoints/file-requests/{request_id}/submissions/{submission_id}/complete",
            post(complete_endpoint_file_request_submission),
        );

    routes = if enable_file_job_routes {
        routes
            .route("/v2/files/jobs", get(list_file_jobs).post(create_file_job))
            .route(
                "/v2/files/recipients/{computer_id}",
                get(file_job_recipient),
            )
            .route(
                "/v2/files/jobs/{id}",
                get(get_file_job).post(cancel_file_job),
            )
            .route(
                "/v2/files/jobs/{id}/chunks/{index}",
                put(put_file_job_chunk),
            )
            .route("/v2/endpoints/jobs", get(endpoint_file_jobs))
            .route(
                "/v2/endpoints/jobs/{id}/chunks/{index}",
                get(endpoint_file_job_chunk),
            )
            .route(
                "/v2/endpoints/jobs/{id}/result",
                post(complete_endpoint_file_job),
            )
    } else {
        routes
            .route(
                "/v2/files/jobs",
                get(file_jobs_unavailable).post(file_jobs_unavailable),
            )
            .route(
                "/v2/files/jobs/{id}",
                get(file_jobs_unavailable).post(file_jobs_unavailable),
            )
            .route(
                "/v2/files/jobs/{id}/chunks/{index}",
                put(file_jobs_unavailable),
            )
            .route("/v2/endpoints/jobs", get(file_jobs_unavailable))
            .route(
                "/v2/endpoints/jobs/{id}/chunks/{index}",
                get(file_jobs_unavailable),
            )
            .route(
                "/v2/endpoints/jobs/{id}/result",
                post(file_jobs_unavailable),
            )
    };

    routes.with_state(service)
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
    // Cleanup-only: revoke this bearer's session without minting authority.
    // Weaker historical sessions must still be dismissable when mandatory
    // MFA refuses authenticate_token.
    let token = bearer_token(&headers)?;
    service.logout_token(&token)?;
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

async fn approve_manager_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ApproveManagerRequest>,
) -> AppResult<Json<ManagerView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.approve_manager_v2(&auth, &id, req)?))
}

async fn revoke_manager_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<RevokeManagerRequest>,
) -> AppResult<Json<ManagerView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.revoke_manager_v2(&auth, &id, req)?))
}

async fn list_accounts(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<AccountListResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.list_accounts(&auth)?))
}

async fn list_computers(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<ComputerListResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.list_computers(&auth)?))
}

async fn list_computers_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<ComputerListResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.list_computers_with_endpoint_sessions(&auth)?))
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

async fn observation_scope(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<ObservationScopeResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.observation_scope(&auth)?))
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

async fn deployment_info(
    State(service): State<SharedService>,
) -> AppResult<Json<DeploymentInfoResponse>> {
    Ok(Json(DeploymentInfoResponse {
        deployment_id: service.deployment_id()?,
    }))
}

async fn deployment_authority(
    State(service): State<SharedService>,
) -> AppResult<Json<DeploymentAuthorityResponse>> {
    Ok(Json(DeploymentAuthorityResponse {
        deployment_id: service.deployment_id()?,
        grant_signing_public_key: service.grant_signing_public_key()?,
        authority_generation: service.authority_generation()?,
    }))
}

async fn mfa_enroll_confirm(
    State(service): State<SharedService>,
    Json(req): Json<MfaConfirmRequest>,
) -> AppResult<Json<MfaConfirmResponse>> {
    Ok(Json(service.confirm_mfa_enrollment(req)?))
}

async fn mfa_enroll_begin(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<(StatusCode, Json<MfaEnrollmentBeginResponse>)> {
    let auth = authenticate(&service, &headers)?;
    Ok((
        StatusCode::CREATED,
        Json(service.begin_self_mfa_enrollment(&auth)?),
    ))
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

async fn enroll_manager_key(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<ManagerKeyEnrollmentRequest>,
) -> AppResult<(StatusCode, Json<ManagerView>)> {
    let auth = authenticate(&service, &headers)?;
    let manager = service.enroll_manager_key(&auth, req)?;
    Ok((StatusCode::CREATED, Json(manager)))
}

async fn create_account_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<CreateAccountV2Request>,
) -> AppResult<(StatusCode, Json<AccountProvisioningResponse>)> {
    let auth = authenticate(&service, &headers)?;
    let account = service.create_account_v2(&auth, req)?;
    Ok((StatusCode::CREATED, Json(account)))
}

async fn update_account_capabilities_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpdateAccountCapabilitiesRequest>,
) -> AppResult<Json<AccountView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(
        service.update_account_capabilities_v2(&auth, &id, req)?,
    ))
}

async fn update_account_state_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpdateAccountStateRequest>,
) -> AppResult<Json<AccountView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.update_account_state_v2(&auth, &id, req)?))
}

async fn recovery_quarantine_status_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<RecoveryQuarantineStatusResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.recovery_quarantine_status_v2(&auth)?))
}

async fn release_recovery_quarantine_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<ReleaseRecoveryQuarantineRequest>,
) -> AppResult<Json<RecoveryQuarantineStatusResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.release_recovery_quarantine_v2(&auth, req)?))
}

async fn authority_cutover_status_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<AuthorityCutoverResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.authority_cutover_status_v2(&auth)?))
}

async fn begin_authority_cutover_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<BeginAuthorityCutoverRequest>,
) -> AppResult<Json<AuthorityCutoverResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.begin_authority_cutover_v2(&auth, req)?))
}

async fn approve_authority_cutover_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<ApproveAuthorityCutoverRequest>,
) -> AppResult<Json<AuthorityCutoverResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.approve_authority_cutover_v2(&auth, req)?))
}

async fn cancel_authority_cutover_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<CancelAuthorityCutoverRequest>,
) -> AppResult<Json<AuthorityCutoverResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.cancel_authority_cutover_v2(&auth, req)?))
}

async fn grant_access_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<GrantAccessRequest>,
) -> AppResult<(StatusCode, Json<AccessAssignmentView>)> {
    let auth = authenticate(&service, &headers)?;
    let assignment = service.grant_access_v2(&auth, req)?;
    Ok((StatusCode::CREATED, Json(assignment)))
}

async fn revoke_access_v2(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<RevokeAccessRequest>,
) -> AppResult<Json<AccessRevocationResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.revoke_access_v2(&auth, &id, req)?))
}

async fn list_computer_groups(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<ComputerGroupListResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.list_computer_groups(&auth)?))
}

async fn list_enrollment_computers(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<EnrollmentComputerListResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.list_enrollment_computers(&auth)?))
}

async fn create_endpoint_invitation(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<CreateEndpointInvitationRequest>,
) -> AppResult<(StatusCode, Json<EndpointInvitationIssuedResponse>)> {
    let auth = authenticate(&service, &headers)?;
    Ok((
        StatusCode::CREATED,
        Json(service.create_endpoint_invitation(&auth, req)?),
    ))
}

async fn list_endpoint_invitations(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<EndpointInvitationListResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.list_endpoint_invitations(&auth)?))
}

async fn revoke_endpoint_invitation(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<RevokeEndpointInvitationRequest>,
) -> AppResult<Json<EndpointInvitationView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.revoke_endpoint_invitation(&auth, &id, req)?))
}

async fn enroll_endpoint(
    State(service): State<SharedService>,
    Json(req): Json<EndpointEnrollRequest>,
) -> AppResult<(StatusCode, Json<EndpointEnrollResponse>)> {
    Ok((StatusCode::CREATED, Json(service.enroll_endpoint(req)?)))
}

async fn endpoint_session_challenge(
    State(service): State<SharedService>,
    Json(req): Json<EndpointSessionChallengeRequest>,
) -> AppResult<(StatusCode, Json<EndpointSessionChallengeResponse>)> {
    Ok((
        StatusCode::CREATED,
        Json(service.endpoint_session_challenge(req)?),
    ))
}

async fn endpoint_session_complete(
    State(service): State<SharedService>,
    Json(req): Json<EndpointSessionCompleteRequest>,
) -> AppResult<Json<EndpointSessionIssuedResponse>> {
    Ok(Json(service.complete_endpoint_session(req)?))
}

async fn endpoint_self(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<EndpointSelfResponse>> {
    let token = bearer_token(&headers)?;
    let auth = service.authenticate_endpoint_token(&token)?;
    Ok(Json(service.endpoint_self(&auth)?))
}

async fn issue_observation_grant(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<IssueObservationGrantRequest>,
) -> AppResult<(StatusCode, Json<SignedObservationGrantResponse>)> {
    let auth = authenticate(&service, &headers)?;
    Ok((
        StatusCode::CREATED,
        Json(service.issue_observation_grant(&auth, req)?),
    ))
}

async fn redeem_observation_grant(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<RedeemObservationGrantRequest>,
) -> AppResult<Json<ObservationAdmissionAcceptedResponse>> {
    let token = bearer_token(&headers)?;
    let endpoint_auth = service.authenticate_endpoint_token(&token)?;
    Ok(Json(service.redeem_observation_grant(&endpoint_auth, req)?))
}

/// Long-poll for a grant delivered to this exact authenticated endpoint
/// session. The broadcast is only a wake hint; Service rechecks the current
/// endpoint session before releasing each token.
async fn poll_pending_observation_grants(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<EndpointPendingObservationGrantsResponse>> {
    let token = bearer_token(&headers)?;
    let endpoint_auth = service.authenticate_endpoint_token(&token)?;
    let mut notifications = service.observation_grant_notifier.subscribe();
    // Stay below native endpoint clients' 15-second request deadline.
    let wait = Duration::from_secs(10);
    let deadline = Instant::now() + wait;

    loop {
        let pending = service.take_pending_observation_grants(&endpoint_auth)?;
        if !pending.grants.is_empty() {
            return Ok(Json(pending));
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(Json(
                service.take_pending_observation_grants(&endpoint_auth)?,
            ));
        }

        match timeout(remaining, notifications.recv()).await {
            Ok(Ok(session_id)) if session_id == endpoint_auth.session_id => {}
            Ok(Ok(_)) | Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) | Err(_) => {
                return Ok(Json(
                    service.take_pending_observation_grants(&endpoint_auth)?,
                ));
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct ObservationSignalCursor {
    #[serde(default)]
    after: u64,
}

async fn publish_observation_signal(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
    Json(req): Json<ObservationSignalRequest>,
) -> AppResult<StatusCode> {
    let auth = authenticate(&service, &headers)?;
    service.publish_observation_signal(&auth, &grant_id, req)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn poll_observation_signals(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
    Query(cursor): Query<ObservationSignalCursor>,
) -> AppResult<Json<ObservationSignalBatch>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.poll_observation_signals(
        &auth,
        &grant_id,
        cursor.after,
    )?))
}

async fn publish_endpoint_observation_signal(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
    Json(req): Json<ObservationSignalRequest>,
) -> AppResult<StatusCode> {
    let token = bearer_token(&headers)?;
    let auth = service.authenticate_endpoint_token(&token)?;
    service.publish_endpoint_observation_signal(&auth, &grant_id, req)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn poll_endpoint_observation_signals(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
    Query(cursor): Query<ObservationSignalCursor>,
) -> AppResult<Json<ObservationSignalBatch>> {
    let token = bearer_token(&headers)?;
    let auth = service.authenticate_endpoint_token(&token)?;
    Ok(Json(service.poll_endpoint_observation_signals(
        &auth,
        &grant_id,
        cursor.after,
    )?))
}

async fn create_file_job(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<CreateFileJobRequest>,
) -> AppResult<(StatusCode, Json<FileJobView>)> {
    let auth = authenticate(&service, &headers)?;
    Ok((
        StatusCode::CREATED,
        Json(service.create_file_job(&auth, req)?),
    ))
}

async fn file_job_recipient(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(computer_id): Path<String>,
) -> AppResult<Json<FileJobRecipientView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.file_job_recipient(&auth, &computer_id)?))
}

async fn list_file_jobs(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<FileJobListResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.list_file_jobs(&auth)?))
}

async fn file_storage_summary(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<FileStorageSummary>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.file_storage_summary(&auth)?))
}

async fn create_file_request(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<CreateFileRequestRequest>,
) -> AppResult<(StatusCode, Json<FileRequestView>)> {
    let auth = authenticate(&service, &headers)?;
    Ok((
        StatusCode::CREATED,
        Json(service.create_file_request(&auth, req)?),
    ))
}

async fn list_file_requests(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<FileRequestListResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.list_file_requests(&auth)?))
}

async fn get_file_request(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<FileRequestView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.get_file_request(&auth, &id)?))
}

async fn publish_file_request(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<FileRequestRevisionRequest>,
) -> AppResult<Json<FileRequestView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.publish_file_request(&auth, &id, req)?))
}

async fn close_file_request(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<CloseFileRequestRequest>,
) -> AppResult<Json<FileRequestView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.close_file_request(&auth, &id, req)?))
}

async fn endpoint_file_requests(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<EndpointFileRequestListResponse>> {
    let token = bearer_token(&headers)?;
    let auth = service.authenticate_endpoint_token(&token)?;
    Ok(Json(service.endpoint_file_requests(&auth)?))
}

async fn create_endpoint_file_request_submission(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(req): Json<CreateFileRequestSubmissionRequest>,
) -> AppResult<(StatusCode, Json<FileRequestSubmissionView>)> {
    let token = bearer_token(&headers)?;
    let auth = service.authenticate_endpoint_token(&token)?;
    Ok((
        StatusCode::CREATED,
        Json(service.create_endpoint_file_request_submission(&auth, &request_id, req)?),
    ))
}

async fn endpoint_file_request_submissions(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> AppResult<Json<Vec<FileRequestSubmissionView>>> {
    let token = bearer_token(&headers)?;
    let auth = service.authenticate_endpoint_token(&token)?;
    Ok(Json(
        service.endpoint_file_request_submissions(&auth, &request_id)?,
    ))
}

async fn put_endpoint_file_request_chunk(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path((request_id, submission_id, file_id, index)): Path<(String, String, String, u32)>,
    bytes: Bytes,
) -> AppResult<Json<FileRequestSubmissionChunkReceipt>> {
    let token = bearer_token(&headers)?;
    let auth = service.authenticate_endpoint_token(&token)?;
    Ok(Json(service.put_endpoint_file_request_chunk(
        &auth,
        &request_id,
        &submission_id,
        &file_id,
        index,
        &bytes,
    )?))
}

async fn complete_endpoint_file_request_submission(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path((request_id, submission_id)): Path<(String, String)>,
    Json(req): Json<CompleteFileRequestSubmissionRequest>,
) -> AppResult<Json<FileRequestSubmissionView>> {
    let token = bearer_token(&headers)?;
    let auth = service.authenticate_endpoint_token(&token)?;
    Ok(Json(service.complete_endpoint_file_request_submission(
        &auth,
        &request_id,
        &submission_id,
        req,
    )?))
}

async fn list_file_request_submissions(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> AppResult<Json<Vec<FileRequestSubmissionView>>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(
        service.list_file_request_submissions(&auth, &request_id)?,
    ))
}

async fn delete_file_request_submission_content(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path((request_id, submission_id)): Path<(String, String)>,
    Json(req): Json<DeleteFileRequestSubmissionRequest>,
) -> AppResult<Json<FileRequestSubmissionView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.delete_file_request_submission_content(
        &auth,
        &request_id,
        &submission_id,
        req,
    )?))
}

async fn get_file_request_submission_chunk(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path((request_id, submission_id, file_id, index)): Path<(String, String, String, u32)>,
) -> AppResult<Response> {
    let auth = authenticate(&service, &headers)?;
    let chunk = service.get_file_request_submission_chunk(
        &auth,
        &request_id,
        &submission_id,
        &file_id,
        index,
    )?;
    let mut response = Response::new(Body::from(chunk));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(response)
}

async fn get_file_job(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<FileJobView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.get_file_job(&auth, &id)?))
}

async fn cancel_file_job(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<CancelFileJobRequest>,
) -> AppResult<Json<FileJobView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.cancel_file_job(&auth, &id, req)?))
}

async fn put_file_job_chunk(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path((id, index)): Path<(String, u32)>,
    bytes: Bytes,
) -> AppResult<Json<FileJobChunkReceipt>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.put_file_job_chunk(&auth, &id, index, &bytes)?))
}

async fn endpoint_file_jobs(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<EndpointFileJobListResponse>> {
    let token = bearer_token(&headers)?;
    let auth = service.authenticate_endpoint_token(&token)?;
    Ok(Json(service.endpoint_file_jobs(&auth)?))
}

async fn endpoint_file_job_chunk(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path((id, index)): Path<(String, u32)>,
) -> AppResult<Response> {
    let token = bearer_token(&headers)?;
    let auth = service.authenticate_endpoint_token(&token)?;
    let chunk = service.endpoint_file_job_chunk(&auth, &id, index)?;
    let mut response = Response::new(Body::from(chunk.bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        "x-helicoid-chunk-sha256",
        HeaderValue::from_str(&chunk.sha256)
            .map_err(|_| AppError::unprocessable("stored file chunk digest is invalid"))?,
    );
    Ok(response)
}

async fn complete_endpoint_file_job(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<EndpointFileJobResultRequest>,
) -> AppResult<Json<EndpointFileJobResultResponse>> {
    let token = bearer_token(&headers)?;
    let auth = service.authenticate_endpoint_token(&token)?;
    Ok(Json(service.complete_endpoint_file_job(&auth, &id, req)?))
}

async fn approve_computer_enrollment(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ComputerEnrollmentDecisionRequest>,
) -> AppResult<Json<EnrollmentComputerView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.approve_computer_enrollment(&auth, &id, req)?))
}

async fn revoke_computer_enrollment(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ComputerEnrollmentDecisionRequest>,
) -> AppResult<Json<EnrollmentComputerView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.revoke_computer_enrollment(&auth, &id, req)?))
}

async fn create_computer_group(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<CreateComputerGroupRequest>,
) -> AppResult<(StatusCode, Json<ComputerGroupView>)> {
    let auth = authenticate(&service, &headers)?;
    Ok((
        StatusCode::CREATED,
        Json(service.create_computer_group(&auth, req)?),
    ))
}

async fn rename_computer_group(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<RenameComputerGroupRequest>,
) -> AppResult<Json<ComputerGroupView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.rename_computer_group(&auth, &id, req)?))
}

async fn set_computer_group_membership(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path((id, computer_id)): Path<(String, String)>,
    Json(req): Json<SetComputerGroupMembershipRequest>,
) -> AppResult<Json<ComputerGroupView>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.set_computer_group_membership(
        &auth,
        &id,
        &computer_id,
        req,
    )?))
}

async fn delete_computer_group(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<DeleteComputerGroupRequest>,
) -> AppResult<StatusCode> {
    let auth = authenticate(&service, &headers)?;
    service.delete_computer_group(&auth, &id, req)?;
    Ok(StatusCode::NO_CONTENT)
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

async fn get_operator_mfa_policy(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<OperatorMfaPolicyResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.get_operator_mfa_policy(&auth)?))
}

async fn put_operator_mfa_policy(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(req): Json<OperatorMfaPolicyUpdateRequest>,
) -> AppResult<Json<OperatorMfaPolicyResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.set_operator_mfa_policy(&auth, req)?))
}

async fn list_audit_events(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Query(query): Query<AuditEventListQuery>,
) -> AppResult<Json<AuditEventListResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.list_audit_events(&auth, query)?))
}

async fn get_audit_retention(
    State(service): State<SharedService>,
    headers: HeaderMap,
) -> AppResult<Json<AuditRetentionResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.get_audit_retention(&auth)?))
}

async fn put_audit_retention(
    State(service): State<SharedService>,
    headers: HeaderMap,
    Json(request): Json<AuditRetentionUpdateRequest>,
) -> AppResult<Json<AuditRetentionResponse>> {
    let auth = authenticate(&service, &headers)?;
    Ok(Json(service.set_audit_retention(&auth, request)?))
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
