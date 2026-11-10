//! Real, fail-closed macOS launchd apply lifecycle.
//!
//! This module installs only the fixed reviewed macOS product layout after:
//!
//! - re-running the read-only macOS preflight and binding the reviewed digest;
//! - independently re-verifying the target-bound signed package;
//! - requiring a fresh `_helicoid` account and group (no adoption or
//!   overwrite of a preexisting identity);
//! - validating operator TLS material at the fixed source path before any
//!   identity or filesystem mutation; and
//! - writing a durable operation record and per-resource journal before effects.
//!
//! A successful apply creates the service account/group, product directories,
//! the verified `hs-server` executable, the reviewed `service.json`, the fixed
//! TLS files, a durable install receipt, and the launchd plist, then bootstraps
//! the daemon. Success also requires a pinned-certificate TLS `/health` request
//! with an `ok` or `degraded` status and a schema version; `launchctl print`
//! alone is not readiness. Mutations are serialized with a persistent nonblocking
//! `flock`, so a SIGKILL cannot leave a stale create-new marker. A failed phase
//! rolls back only resources recorded as completed by this operation; unproven
//! intent/failed resources are preserved and make rollback incomplete. The
//! service is stopped before file removal, and a nonempty Data directory keeps
//! the owning account/group. Readiness, enrollment, updates, backups, restore,
//! and removal remain unavailable.
//!
//! The install receipt is root-owned evidence that this installer created the
//! exact service identity. It binds the account/group IDs, package evidence,
//! TLS certificate digest, reviewed plan digest, operation ID, and launchd
//! label. The service runtime accepts an existing `_helicoid` account only when
//! that receipt verifies and the account shape is otherwise valid.

#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use std::path::Component;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

use super::lifecycle_v2 as v2;
#[cfg(target_os = "macos")]
use super::macos_identity::{observe_service_identity, MacosIdentityObserver};
#[cfg(target_os = "macos")]
use super::macos_identity::{parse_group_record, parse_user_record};
#[cfg(unix)]
use super::macos_identity::{
    parse_identity_search, IdentityRefusal, NON_LOGIN_SHELLS, PRODUCT_SERVICE_ACCOUNT,
    PRODUCT_SERVICE_GROUP,
};
use super::macos_identity::{
    GroupRecordFacts, IdentityObservation, IdentityQuery, ServiceIdentityDecision, UserRecordFacts,
};
#[cfg(unix)]
use super::macos_package::{VerifiedMacosPackage, MACOS_ARTIFACT_PATH};
#[cfg(unix)]
use super::models::{DirectorySpec, InstallPlan, PhaseStatus};

/// Fixed receipt path. Root-owned, not secret, and read by the service runtime.
pub const INSTALL_RECEIPT_PATH: &str =
    "/Library/Application Support/Helicoid/Configuration/install-receipt.json";
/// Version understood by this receipt verifier.
pub const RECEIPT_VERSION: u32 = 1;
/// Fixed macOS installer state directory. Caller-selected state paths are
/// refused so root writes cannot be redirected by case aliases or arbitrary
/// directories.
pub const INSTALL_STATE_DIRECTORY: &str = "/Library/Application Support/Helicoid-Installer";
/// Fixed product-wide installer lock. A persistent flock serializes every
/// state directory, so separate --state-dir values cannot race.
pub const INSTALL_LOCK_PATH: &str = "/Library/Application Support/Helicoid-Installer.lock";
/// Operator-provided TLS source directory.
pub const TLS_SOURCE_DIRECTORY: &str = super::macos_launchd::TLS_SOURCE_DIRECTORY;
/// Operator-provided certificate-chain source.
pub const TLS_SOURCE_CERTIFICATE_PATH: &str = super::macos_launchd::TLS_SOURCE_CERTIFICATE_PATH;
/// Operator-provided private-key source.
pub const TLS_SOURCE_PRIVATE_KEY_PATH: &str = super::macos_launchd::TLS_SOURCE_PRIVATE_KEY_PATH;
/// Hard bound for the receipt document.
pub const MAX_RECEIPT_BYTES: usize = 16 * 1024;
/// Hard bound for operation records and journals.
pub const MAX_STATE_BYTES: usize = 1024 * 1024;
/// First UID/GID considered for the dedicated service identity.
pub const SERVICE_ID_RANGE_START: u32 = 400;
/// Last UID/GID considered for the dedicated service identity.
pub const SERVICE_ID_RANGE_END: u32 = 499;
/// Independently trusted Ed25519 release roots. Empty in this source tree:
/// the real install capability is gated off until a trusted release root and
/// installed acceptance exist.
pub const TRUSTED_RELEASE_KEYS: &[[u8; 32]] = &[];

#[cfg(unix)]
const OPERATION_RECORD: &str = "operation-v2.json";
#[cfg(unix)]
const JOURNAL_RECORD: &str = "journal.json";
#[cfg(unix)]
const PHASES: [&str; 8] = [
    "service_user",
    "directories",
    "files",
    "configuration",
    "tls",
    "receipt",
    "launchd",
    "completed",
];

/// Path facts used by the apply policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacosApplyPathMetadata {
    pub is_symlink: bool,
    pub is_directory: bool,
    pub is_regular_file: bool,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub len: u64,
}

/// Validated TLS source evidence. The key bytes are never retained here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSourceEvidence {
    pub certificate_sha256: String,
    pub private_key_sha256: String,
}

/// Durable root-owned evidence for the identity and package created by apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosInstallReceipt {
    pub receipt_version: u32,
    pub product: String,
    pub version: String,
    pub service_account: String,
    pub service_group: String,
    pub unique_id: u32,
    pub primary_group_id: u32,
    pub package_manifest_sha256: String,
    pub verifying_key_sha256: String,
    pub artifact_sha256: String,
    pub artifact_size_bytes: u64,
    pub tls_certificate_sha256: String,
    pub tls_private_key_sha256: String,
    pub reviewed_plan_digest: String,
    pub operation_id: String,
    pub launchd_label: String,
    pub installed_at: String,
}

/// Injectable apply and host-mutation boundary.
pub trait MacosApplyAdapter: Send + Sync {
    fn now_iso8601(&self) -> String;
    fn effective_uid(&self) -> Result<u32, String>;
    fn preflight(
        &self,
        configuration: &v2::DeploymentConfiguration,
    ) -> AppResult<v2::PreflightResult>;
    fn identity_decision(&self) -> ServiceIdentityDecision;
    fn observe_user(&self) -> Result<Option<UserRecordFacts>, String>;
    fn observe_group(&self) -> Result<Option<GroupRecordFacts>, String>;
    fn identity_search(&self, query: IdentityQuery) -> Result<IdentityObservation, String>;
    fn resolver_identity_absent(&self) -> Result<bool, String>;
    fn resolver_id_in_use(&self, id: u32) -> Result<bool, String>;
    fn resolver_user_by_uid(&self, uid: u32) -> Result<Option<String>, String>;
    fn resolver_group_by_gid(&self, gid: u32) -> Result<Option<String>, String>;
    fn resolver_identity_matches(&self, uid: u32, gid: u32) -> Result<bool, String>;
    fn create_service_group(&self, name: &str, gid: u32) -> Result<(), String>;
    fn create_service_user(&self, name: &str, uid: u32, gid: u32) -> Result<(), String>;
    fn remove_service_user(&self, name: &str) -> Result<(), String>;
    fn remove_service_group(&self, name: &str) -> Result<(), String>;
    fn path_metadata(&self, path: &Path) -> Result<Option<MacosApplyPathMetadata>, String>;
    fn create_directory(&self, path: &Path, mode: u32, uid: u32, gid: u32) -> Result<(), String>;
    fn remove_directory(&self, path: &Path) -> Result<(), String>;
    fn write_new_file(
        &self,
        path: &Path,
        contents: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(), String>;
    fn write_state_file(&self, path: &Path, contents: &[u8]) -> Result<(), String>;
    fn remove_file(&self, path: &Path) -> Result<(), String>;
    fn read_bounded_file(&self, path: &Path, max_bytes: usize) -> Result<Vec<u8>, String>;
    fn extended_acl_is_safe(&self, path: &Path) -> Result<bool, String>;
    fn validate_tls_sources(&self, port: u16) -> Result<TlsSourceEvidence, String>;
    fn authorize_package_key(&self, verify_key_hex: &str) -> Result<(), String>;
    fn copy_tls_file(
        &self,
        source: &Path,
        destination: &Path,
        uid: u32,
        gid: u32,
        expected_sha256: &str,
    ) -> Result<(), String>;
    fn launchd_bootstrap(&self, plist: &Path, label: &str) -> Result<(), String>;
    fn launchd_bootout(&self, label: &str) -> Result<(), String>;
    fn launchd_is_loaded(&self, label: &str) -> Result<bool, String>;
    fn service_health(
        &self,
        port: u16,
        expected_certificate_sha256: &str,
        service_uid: u32,
    ) -> Result<bool, String>;
    fn acquire_lock(&self, path: &Path) -> Result<MacosApplyLock, String>;
}

/// Held operation lock. Releasing the flock never removes the lock file, so a
/// SIGKILL cannot leave a stale create-new marker that wedges recovery.
pub struct MacosApplyLock {
    release: Option<Box<dyn FnOnce() + Send>>,
}

impl MacosApplyLock {
    /// Build a guard from a release callback. The caller owns the underlying
    /// resource (for example an flocked file) inside the callback.
    pub fn new(release: impl FnOnce() + Send + 'static) -> Self {
        Self {
            release: Some(Box::new(release)),
        }
    }
}

impl Drop for MacosApplyLock {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

#[cfg(unix)]
struct ValidatedApply {
    plan: InstallPlan,
    verified: VerifiedMacosPackage,
    package_evidence: v2::PackageEvidence,
    tls: TlsSourceEvidence,
    reviewed_plan_digest: String,
}

#[cfg(unix)]
struct ApplyContext {
    uid: u32,
    gid: u32,
}

/// Apply one freshly reviewed macOS install. This function performs host
/// effects only after every review, package, identity, and TLS gate passes.
#[cfg(unix)]
pub fn apply_v2_with_adapter(
    adapter: &dyn MacosApplyAdapter,
    input: &v2::ApplyInput,
    state_dir: &Path,
) -> AppResult<v2::OperationStatus> {
    let validated = validate_apply(adapter, input)?;
    prepare_state_dir(adapter, state_dir)?;
    let _lock = acquire_lock(adapter, state_dir)?;

    let journal_path = state_dir.join(JOURNAL_RECORD);
    if adapter
        .path_metadata(&journal_path)
        .map_err(|error| unavailable(error.to_string()))?
        .is_some()
    {
        return Err(AppError::conflict(
            "a macOS installer journal already exists; run cancel-v2 to roll back the interrupted operation before applying again",
            None,
        ));
    }

    let record_path = state_dir.join(OPERATION_RECORD);
    let existing = read_operation_record(adapter, &record_path)?;
    if let Some(record) = existing.as_ref() {
        if record.action != v2::LifecycleAction::Install {
            return Err(AppError::conflict(
                "the recorded macOS operation is not an install; removal/update is not implemented",
                None,
            ));
        }
        match record.outcome.as_ref().map(|outcome| outcome.state) {
            Some(v2::OperationState::Completed) => {
                return Err(AppError::conflict(
                    "a completed macOS installation is already recorded; removal/update is not implemented",
                    None,
                ));
            }
            Some(v2::OperationState::Cancelled) => {}
            Some(v2::OperationState::AttentionRequired)
                if record
                    .outcome
                    .as_ref()
                    .is_some_and(|outcome| outcome.result.code == "rolled_back") => {}
            // The record is written before the journal and before any host
            // effect. A missing journal with no outcome is therefore a stale
            // pre-effect record and may be replaced.
            None => {}
            _ => {
                return Err(AppError::conflict(
                    "an unfinished macOS install operation is recorded; run cancel-v2 before starting another apply",
                    None,
                ));
            }
        }
    }

    let operation_id = uuid::Uuid::new_v4().to_string();
    let mut record = v2::OperationRecord {
        contract_version: v2::CONTRACT_VERSION,
        operation_id: operation_id.clone(),
        action: v2::LifecycleAction::Install,
        resource_operation_id: None,
        reviewed_plan_digest: validated.reviewed_plan_digest.clone(),
        configuration: input.configuration.clone(),
        created_at: adapter.now_iso8601(),
        outcome: None,
    };
    adapter
        .write_state_file(
            &record_path,
            &serde_json::to_vec_pretty(&record).map_err(|error| {
                AppError::internal(format!("serialize operation record: {error}"))
            })?,
        )
        .map_err(|error| AppError::internal(format!("save operation record: {error}")))?;

    let mut journal = create_journal(adapter, &validated.plan.review_digest);
    save_journal(adapter, &journal_path, &journal)?;

    let mut context = ApplyContext { uid: 0, gid: 0 };
    for phase in PHASES {
        let phase_key = phase.to_string();
        {
            let entry = journal
                .phases
                .entry(phase_key.clone())
                .or_insert_with(pending_phase);
            if entry.status == PhaseStatus::Completed {
                continue;
            }
            entry.status = PhaseStatus::InProgress;
            entry.started_at = Some(adapter.now_iso8601());
            entry.error = None;
        }
        journal.current_phase = phase_key.clone();
        journal.updated_at = adapter.now_iso8601();
        save_journal(adapter, &journal_path, &journal)?;

        if phase == "completed" {
            if let Some(entry) = journal.phases.get_mut("completed") {
                entry.status = PhaseStatus::Completed;
                entry.completed_at = Some(adapter.now_iso8601());
            }
            journal.updated_at = adapter.now_iso8601();
            save_journal(adapter, &journal_path, &journal)?;
            break;
        }

        let result = execute_phase(
            adapter,
            phase,
            &validated,
            &operation_id,
            &mut context,
            &mut journal,
            &journal_path,
        );
        match result {
            Ok(()) => {
                if let Some(entry) = journal.phases.get_mut(&phase_key) {
                    entry.status = PhaseStatus::Completed;
                    entry.completed_at = Some(adapter.now_iso8601());
                }
                journal.updated_at = adapter.now_iso8601();
                save_journal(adapter, &journal_path, &journal)?;
            }
            Err(error) => {
                if let Some(entry) = journal.phases.get_mut(&phase_key) {
                    entry.status = PhaseStatus::Failed;
                    entry.error = Some(error.to_string());
                }
                journal.current_phase = phase_key;
                journal.updated_at = adapter.now_iso8601();
                save_journal(adapter, &journal_path, &journal)?;
                return finish_failed_apply(
                    adapter,
                    state_dir,
                    &journal_path,
                    &record_path,
                    &mut record,
                    &mut journal,
                );
            }
        }
    }

    let completed = journal
        .phases
        .get("completed")
        .is_some_and(|phase| phase.status == PhaseStatus::Completed);
    if !completed {
        return finish_failed_apply(
            adapter,
            state_dir,
            &journal_path,
            &record_path,
            &mut record,
            &mut journal,
        );
    }

    if !matches!(verify_runtime_receipt_with_adapter(adapter), Ok(true)) {
        journal.current_phase = "receipt_verification".to_string();
        journal.updated_at = adapter.now_iso8601();
        save_journal(adapter, &journal_path, &journal)?;
        return finish_failed_apply(
            adapter,
            state_dir,
            &journal_path,
            &record_path,
            &mut record,
            &mut journal,
        );
    }

    record.outcome = Some(v2::OperationOutcome {
        state: v2::OperationState::Completed,
        result: v2::OperationResult {
            code: "installed".to_string(),
            summary: "The reviewed macOS package, fixed service identity, TLS material, and launchd daemon were installed. Service readiness and enrollment are not claimed.".to_string(),
            errors: Vec::new(),
            warnings: vec![
                "launchd was bootstrapped, but server readiness/enrollment is not verified by apply"
                    .to_string(),
            ],
        },
    });
    write_record(adapter, &record_path, &record)?;
    Ok(status_from_state(
        adapter,
        state_dir,
        &input.configuration,
        Some(record),
        Some(journal),
    )?)
}

#[cfg(not(unix))]
pub fn apply_v2_with_adapter(
    _adapter: &dyn MacosApplyAdapter,
    _input: &v2::ApplyInput,
    _state_dir: &Path,
) -> AppResult<v2::OperationStatus> {
    Err(AppError::not_implemented(
        "macOS apply is available only on Unix hosts",
    ))
}

/// Read-only operation status for the macOS lifecycle.
#[cfg(unix)]
pub fn status_v2_with_adapter(
    adapter: &dyn MacosApplyAdapter,
    input: &v2::StatusInput,
    state_dir: &Path,
) -> AppResult<v2::OperationStatus> {
    if input.contract_version != v2::CONTRACT_VERSION {
        return Err(AppError::bad_request(format!(
            "unsupported lifecycle contract_version: {} (expected {})",
            input.contract_version,
            v2::CONTRACT_VERSION
        )));
    }
    super::macos_launchd::validate_macos_configuration(&input.configuration)?;
    let record = read_operation_record(adapter, &state_dir.join(OPERATION_RECORD))?;
    if let Some(record) = record.as_ref() {
        if record.contract_version != v2::CONTRACT_VERSION
            || record.configuration != input.configuration
            || uuid::Uuid::parse_str(&record.operation_id).is_err()
        {
            return Err(AppError::unprocessable(
                "operation record does not match the requested macOS deployment configuration",
            ));
        }
    }
    let journal = read_journal(adapter, &state_dir.join(JOURNAL_RECORD))?;
    status_from_state(adapter, state_dir, &input.configuration, record, journal)
}

#[cfg(not(unix))]
pub fn status_v2_with_adapter(
    _adapter: &dyn MacosApplyAdapter,
    _input: &v2::StatusInput,
    _state_dir: &Path,
) -> AppResult<v2::OperationStatus> {
    Err(AppError::not_implemented(
        "macOS status is available only on Unix hosts",
    ))
}

/// Cancel an incomplete macOS install by rolling back only journaled resources.
#[cfg(unix)]
pub fn cancel_v2_with_adapter(
    adapter: &dyn MacosApplyAdapter,
    input: &v2::CancelInput,
    state_dir: &Path,
) -> AppResult<v2::OperationStatus> {
    if input.contract_version != v2::CONTRACT_VERSION {
        return Err(AppError::bad_request(format!(
            "unsupported lifecycle contract_version: {} (expected {})",
            input.contract_version,
            v2::CONTRACT_VERSION
        )));
    }
    super::macos_launchd::validate_macos_configuration(&input.configuration)?;
    if !input.confirm {
        return Err(AppError::bad_request("cancel requires confirm: true"));
    }
    prepare_state_dir(adapter, state_dir)?;
    let _lock = acquire_lock(adapter, state_dir)?;
    let record_path = state_dir.join(OPERATION_RECORD);
    let journal_path = state_dir.join(JOURNAL_RECORD);
    let mut record = read_operation_record(adapter, &record_path)?.ok_or_else(|| {
        AppError::conflict("no macOS install operation is recorded to cancel", None)
    })?;
    if record.operation_id != input.operation_id {
        return Err(AppError::conflict(
            "cancel operation identity does not match the recorded operation",
            None,
        ));
    }
    if record.configuration != input.configuration {
        return Err(AppError::conflict(
            "cancel configuration does not match the recorded operation",
            None,
        ));
    }
    if record
        .outcome
        .as_ref()
        .is_some_and(|outcome| outcome.state == v2::OperationState::Completed)
    {
        return Err(AppError::conflict(
            "a completed macOS install cannot be cancelled; removal is not implemented",
            None,
        ));
    }
    let mut journal = read_journal(adapter, &journal_path)?.ok_or_else(|| {
        AppError::conflict(
            "the macOS ownership journal is missing; refusing to infer rollback targets",
            None,
        )
    })?;
    let journal_completed = journal
        .phases
        .get("completed")
        .is_some_and(|phase| phase.status == super::models::PhaseStatus::Completed);
    if journal_completed
        && !record
            .outcome
            .as_ref()
            .is_some_and(|outcome| outcome.state == v2::OperationState::Completed)
        && !input.confirm_unverified_completion
    {
        return Err(AppError::conflict(
            "the journal records a completed install but the final operation record is missing; cancel would delete a potentially healthy service. Verify the service first, then set confirm_unverified_completion only for an explicit recovery decision",
            None,
        ));
    }
    let errors = rollback(adapter, &mut journal, &journal_path)?;
    if errors.is_empty() {
        record.outcome = Some(v2::OperationOutcome {
            state: v2::OperationState::Cancelled,
            result: v2::OperationResult {
                code: "cancelled".to_string(),
                summary: "The incomplete macOS install was rolled back. No service is installed."
                    .to_string(),
                errors: Vec::new(),
                warnings: Vec::new(),
            },
        });
        // Persist the terminal record before unlinking the journal. A crash
        // between these steps leaves recovery evidence rather than an
        // unexplained missing record.
        write_record(adapter, &record_path, &record)?;
        adapter
            .remove_file(&journal_path)
            .map_err(|error| AppError::internal(format!("remove installer journal: {error}")))?;
        Ok(status_from_state(
            adapter,
            state_dir,
            &input.configuration,
            Some(record),
            None,
        )?)
    } else {
        record.outcome = Some(v2::OperationOutcome {
            state: v2::OperationState::AttentionRequired,
            result: v2::OperationResult {
                code: "rollback_incomplete".to_string(),
                summary: "The macOS install cancellation could not remove every journaled resource; inspect the host before retrying.".to_string(),
                errors,
                warnings: Vec::new(),
            },
        });
        write_record(adapter, &record_path, &record)?;
        Ok(status_from_state(
            adapter,
            state_dir,
            &input.configuration,
            Some(record),
            Some(journal),
        )?)
    }
}

#[cfg(not(unix))]
pub fn cancel_v2_with_adapter(
    _adapter: &dyn MacosApplyAdapter,
    _input: &v2::CancelInput,
    _state_dir: &Path,
) -> AppResult<v2::OperationStatus> {
    Err(AppError::not_implemented(
        "macOS cancellation is available only on Unix hosts",
    ))
}

#[cfg(unix)]
fn validate_apply(
    adapter: &dyn MacosApplyAdapter,
    input: &v2::ApplyInput,
) -> AppResult<ValidatedApply> {
    if input.contract_version != v2::CONTRACT_VERSION {
        return Err(AppError::bad_request(format!(
            "unsupported lifecycle contract_version: {} (expected {})",
            input.contract_version,
            v2::CONTRACT_VERSION
        )));
    }
    super::macos_launchd::validate_macos_configuration(&input.configuration)?;
    if !input.confirm {
        return Err(AppError::bad_request("install requires confirm: true"));
    }
    if input.preflight.contract_version != v2::CONTRACT_VERSION
        || input.preflight.host_checks.contract_version != super::models::CONTRACT_VERSION
        || input.preflight.configuration != input.configuration
        || !input.preflight.ok
        || !input.preflight.host_checks.ok
    {
        return Err(AppError::bad_request(
            "preflight must pass and match the reviewed macOS configuration",
        ));
    }
    if adapter.effective_uid().map_err(unavailable)? != 0 {
        return Err(AppError::forbidden(
            "macOS apply requires root; no identity or filesystem mutation was performed",
        ));
    }

    let fresh_preflight = adapter.preflight(&input.configuration)?;
    if !fresh_preflight.ok {
        return Err(AppError::conflict(
            "host preflight no longer passes; generate a fresh macOS plan",
            None,
        ));
    }
    let supplied = super::machine::macos_preflight_review_value(&input.preflight)?;
    let current = super::machine::macos_preflight_review_value(&fresh_preflight)?;
    if supplied != current {
        return Err(AppError::conflict(
            "macOS host preflight changed after review; generate a new plan",
            None,
        ));
    }

    match adapter.identity_decision() {
        ServiceIdentityDecision::AccountAbsentObservation => {
            let absent = adapter.resolver_identity_absent().map_err(unavailable)?;
            if !absent {
                return Err(AppError::conflict(
                    "the fixed macOS service identity resolves through the full name-service stack; fresh apply will not overwrite it",
                    None,
                ));
            }
        }
        ServiceIdentityDecision::ExistingAccountRefused { .. } => {
            return Err(AppError::conflict(
                "the fixed macOS service identity already exists; fresh apply will not overwrite it",
                None,
            ));
        }
        ServiceIdentityDecision::AccountAbsentGroupPresentObservation => {
            return Err(AppError::conflict(
                "the fixed macOS service group already exists without its account; this is not a fresh identity",
                None,
            ));
        }
        ServiceIdentityDecision::Unavailable { reason } => {
            return Err(AppError::security_state_unavailable(format!(
                "cannot verify the macOS service identity: {reason}"
            )));
        }
    }

    adapter
        .authorize_package_key(&input.verify_key)
        .map_err(AppError::forbidden)?;
    let target = super::machine::macos_package_target_for_architecture(
        &fresh_preflight.host_checks.checks.arch.value,
    )?;
    let key_bytes = decode_key_hex(&input.verify_key)?;
    let verified = super::macos_package::verify_macos_package_for_target_real(
        Path::new(&input.package_dir),
        &key_bytes,
        target,
    )?;
    if verified.target() != target {
        return Err(AppError::forbidden(
            "verified macOS package target does not match the observed host architecture",
        ));
    }

    let mut canonical = super::machine::generate_canonical_macos_plan(
        &verified.manifest().product,
        &verified.manifest().version,
        &input.configuration,
    );
    canonical.review_digest = super::machine::compute_plan_digest(&canonical);
    if serde_json::to_vec(&canonical)
        .map_err(|error| AppError::internal(format!("serialize canonical macOS plan: {error}")))?
        != serde_json::to_vec(&input.plan).map_err(|error| {
            AppError::internal(format!("serialize submitted macOS plan: {error}"))
        })?
    {
        return Err(AppError::forbidden(
            "macOS plan does not match the canonical plan derived from the verified package and fixed policy",
        ));
    }

    let artifact = verified.artifact();
    let package_evidence = v2::PackageEvidence {
        manifest_sha256: verified.verified_manifest().manifest_sha256().to_string(),
        verifying_key_sha256: verified
            .verified_manifest()
            .verifying_key_sha256()
            .to_string(),
        target: target.platform_str().to_string(),
        artifact_path: artifact.path.clone(),
        artifact_sha256: artifact.sha256.clone(),
        artifact_size_bytes: artifact.size_bytes,
    };
    let identity_evidence = v2::IdentityEvidence {
        service_account: PRODUCT_SERVICE_ACCOUNT.to_string(),
        service_group: PRODUCT_SERVICE_GROUP.to_string(),
        decision: "account_absent_group_absent".to_string(),
    };
    let tls = adapter
        .validate_tls_sources(input.configuration.network.authority_port)
        .map_err(|error| {
            AppError::forbidden(format!(
                "operator TLS material is unavailable or invalid at the fixed source paths: {error}"
            ))
        })?;
    let tls_evidence = v2::TlsEvidence {
        certificate_sha256: tls.certificate_sha256.clone(),
        private_key_sha256: tls.private_key_sha256.clone(),
    };
    let reviewed_plan_digest = super::machine::compute_macos_reviewed_plan_digest(
        &input.configuration,
        &current,
        &canonical,
        &package_evidence,
        &tls_evidence,
        &identity_evidence,
    )?;
    if reviewed_plan_digest != input.reviewed_plan_digest {
        return Err(AppError::forbidden(
            "reviewed_plan_digest does not match the canonical macOS plan, fresh host evidence, package, TLS sources, and identity",
        ));
    }

    Ok(ValidatedApply {
        plan: canonical,
        verified,
        package_evidence,
        tls,
        reviewed_plan_digest,
    })
}

#[cfg(unix)]
fn execute_phase(
    adapter: &dyn MacosApplyAdapter,
    phase: &str,
    validated: &ValidatedApply,
    operation_id: &str,
    context: &mut ApplyContext,
    journal: &mut super::models::Journal,
    journal_path: &Path,
) -> AppResult<()> {
    match phase {
        "service_user" => {
            create_service_identity(adapter, validated, context, journal, journal_path)
        }
        "directories" => create_directories(adapter, validated, context, journal, journal_path),
        "files" => install_executable(adapter, validated, journal, journal_path),
        "configuration" => write_service_configuration(adapter, validated, journal, journal_path),
        "tls" => install_tls_material(adapter, context, validated, journal, journal_path),
        "receipt" => write_install_receipt(
            adapter,
            validated,
            operation_id,
            context,
            journal,
            journal_path,
        ),
        "launchd" => install_launchd(adapter, validated, context, journal, journal_path),
        other => Err(AppError::internal(format!(
            "unknown macOS install phase '{other}'"
        ))),
    }
}

#[cfg(unix)]
fn create_service_identity(
    adapter: &dyn MacosApplyAdapter,
    validated: &ValidatedApply,
    context: &mut ApplyContext,
    journal: &mut super::models::Journal,
    journal_path: &Path,
) -> AppResult<()> {
    let (uid, gid) = select_service_ids(adapter)?;
    context.uid = uid;
    context.gid = gid;

    if !resource_completed(journal, "service_group", PRODUCT_SERVICE_GROUP) {
        record_intent(
            adapter,
            journal,
            journal_path,
            "service_group",
            PRODUCT_SERVICE_GROUP,
        )?;
        if let Err(error) = adapter.create_service_group(PRODUCT_SERVICE_GROUP, gid) {
            let detail = format!("create macOS service group: {error}");
            // Never adopt a record after a failed create. The record may be
            // foreign or partially ours; rollback will preserve it and report
            // an incomplete recovery.
            record_failed(
                adapter,
                journal,
                journal_path,
                "service_group",
                PRODUCT_SERVICE_GROUP,
                &detail,
            )?;
            return Err(AppError::internal(detail));
        }
    }
    if !resource_completed(journal, "service_user", PRODUCT_SERVICE_ACCOUNT) {
        record_intent(
            adapter,
            journal,
            journal_path,
            "service_user",
            PRODUCT_SERVICE_ACCOUNT,
        )?;
        if let Err(error) = adapter.create_service_user(PRODUCT_SERVICE_ACCOUNT, uid, gid) {
            let detail = format!("create macOS service account: {error}");
            record_failed(
                adapter,
                journal,
                journal_path,
                "service_user",
                PRODUCT_SERVICE_ACCOUNT,
                &detail,
            )?;
            return Err(AppError::internal(detail));
        }
    }

    // Only a fully re-observed, full-resolver-unique identity becomes
    // "completed" and therefore eligible for rollback deletion.
    verify_created_identity(adapter, uid, gid, &validated.plan.service_user.name)?;
    record_completed(
        adapter,
        journal,
        journal_path,
        "service_group",
        PRODUCT_SERVICE_GROUP,
    )?;
    record_completed(
        adapter,
        journal,
        journal_path,
        "service_user",
        PRODUCT_SERVICE_ACCOUNT,
    )?;
    Ok(())
}

#[cfg(unix)]
fn select_service_ids(adapter: &dyn MacosApplyAdapter) -> AppResult<(u32, u32)> {
    for id in SERVICE_ID_RANGE_START..=SERVICE_ID_RANGE_END {
        let resolver_in_use = adapter.resolver_id_in_use(id).map_err(unavailable)?;
        if !resolver_in_use && !identity_id_in_use(adapter, id)? {
            return Ok((id, id));
        }
    }
    Err(AppError::conflict(
        "no free UID/GID is available in the reviewed macOS service range",
        None,
    ))
}

#[cfg(unix)]
fn identity_id_in_use(adapter: &dyn MacosApplyAdapter, id: u32) -> AppResult<bool> {
    let users = adapter
        .identity_search(IdentityQuery::UsersWithUniqueId { unique_id: id })
        .map_err(unavailable)?;
    let users = parse_identity_search(&users, "UniqueID", id).map_err(|error| {
        AppError::security_state_unavailable(format!("verify free UID {id}: {error}"))
    })?;
    let primary_users = adapter
        .identity_search(IdentityQuery::UsersWithPrimaryGroupId {
            primary_group_id: id,
        })
        .map_err(unavailable)?;
    let primary_users =
        parse_identity_search(&primary_users, "PrimaryGroupID", id).map_err(|error| {
            AppError::security_state_unavailable(format!("verify free primary GID {id}: {error}"))
        })?;
    let groups = adapter
        .identity_search(IdentityQuery::GroupsWithPrimaryGroupId {
            primary_group_id: id,
        })
        .map_err(unavailable)?;
    let groups = parse_identity_search(&groups, "PrimaryGroupID", id).map_err(|error| {
        AppError::security_state_unavailable(format!("verify free group GID {id}: {error}"))
    })?;
    Ok(!users.is_empty() || !primary_users.is_empty() || !groups.is_empty())
}

#[cfg(unix)]
fn verify_created_identity(
    adapter: &dyn MacosApplyAdapter,
    uid: u32,
    gid: u32,
    expected_name: &str,
) -> AppResult<()> {
    match adapter.identity_decision() {
        ServiceIdentityDecision::ExistingAccountRefused { reasons }
            if reasons.len() == 1 && reasons[0] == IdentityRefusal::OwnershipNotVerified => {}
        other => {
            return Err(AppError::security_state_unavailable(format!(
                "new macOS service identity did not validate after creation: {other}"
            )))
        }
    }
    let user = adapter
        .observe_user()
        .map_err(unavailable)?
        .ok_or_else(|| {
            AppError::security_state_unavailable("new macOS service account is absent")
        })?;
    let group = adapter.observe_group().map_err(unavailable)?.ok_or(
        AppError::security_state_unavailable("new macOS service group is absent"),
    )?;
    if !exact_record_name(&user.record_names, expected_name)
        || user.unique_id != i64::from(uid)
        || user.primary_group_id != i64::from(gid)
        || !NON_LOGIN_SHELLS.contains(&user.user_shell.as_str())
        || user.password != "*"
        || !acceptable_auth_authority(&user.authentication_authority)
    {
        return Err(AppError::security_state_unavailable(
            "new macOS service account fields do not match the reviewed identity",
        ));
    }
    if !exact_record_name(&group.record_names, PRODUCT_SERVICE_GROUP)
        || group.primary_group_id != i64::from(gid)
        || !group
            .group_membership
            .iter()
            .all(|member| member.as_str() == PRODUCT_SERVICE_ACCOUNT)
    {
        return Err(AppError::security_state_unavailable(
            "new macOS service group fields do not match the reviewed identity",
        ));
    }
    if !adapter
        .resolver_identity_matches(uid, gid)
        .map_err(unavailable)?
    {
        return Err(AppError::security_state_unavailable(
            "new macOS service identity is not unique or does not resolve to the fixed names through the full name-service stack",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn create_directories(
    adapter: &dyn MacosApplyAdapter,
    validated: &ValidatedApply,
    context: &ApplyContext,
    journal: &mut super::models::Journal,
    journal_path: &Path,
) -> AppResult<()> {
    for directory in &validated.plan.directories {
        if !directory.create || resource_completed(journal, "directory", &directory.path) {
            continue;
        }
        let (uid, gid) = directory_ids(directory, context)?;
        let mode = parse_mode(&directory.mode)?;
        ensure_absent(adapter, Path::new(&directory.path), "directory")?;
        record_intent(adapter, journal, journal_path, "directory", &directory.path)?;
        if let Err(error) = adapter.create_directory(Path::new(&directory.path), mode, uid, gid) {
            let detail = format!("create directory '{}': {error}", directory.path);
            record_failed(
                adapter,
                journal,
                journal_path,
                "directory",
                &directory.path,
                &detail,
            )?;
            return Err(AppError::internal(detail));
        }
        record_completed(adapter, journal, journal_path, "directory", &directory.path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn directory_ids(directory: &DirectorySpec, context: &ApplyContext) -> AppResult<(u32, u32)> {
    match directory.owner.as_str() {
        "root" => Ok((0, 0)),
        owner if owner == PRODUCT_SERVICE_ACCOUNT => Ok((context.uid, context.gid)),
        other => Err(AppError::forbidden(format!(
            "refusing unsupported macOS directory owner '{other}' for '{}'",
            directory.path
        ))),
    }
}

#[cfg(unix)]
fn install_executable(
    adapter: &dyn MacosApplyAdapter,
    validated: &ValidatedApply,
    journal: &mut super::models::Journal,
    journal_path: &Path,
) -> AppResult<()> {
    let file = validated
        .plan
        .files
        .iter()
        .find(|file| file.source == MACOS_ARTIFACT_PATH)
        .ok_or(AppError::forbidden(
            "macOS plan has no verified server artifact",
        ))?;
    if resource_completed(journal, "file", &file.destination) {
        return Ok(());
    }
    let bytes = validated.verified.read_artifact()?;
    let artifact = validated.verified.artifact();
    if bytes.len() as u64 != artifact.size_bytes
        || super::manifest::sha256_hex(&bytes) != artifact.sha256
    {
        return Err(AppError::forbidden(
            "verified macOS artifact changed before installation",
        ));
    }
    ensure_absent(adapter, Path::new(&file.destination), "file")?;
    record_intent(adapter, journal, journal_path, "file", &file.destination)?;
    if let Err(error) = adapter.write_new_file(
        Path::new(&file.destination),
        &bytes,
        parse_mode(&file.mode)?,
        0,
        0,
    ) {
        let detail = format!(
            "install verified macOS executable '{}': {error}",
            file.destination
        );
        record_failed(
            adapter,
            journal,
            journal_path,
            "file",
            &file.destination,
            &detail,
        )?;
        return Err(AppError::internal(detail));
    }
    record_completed(adapter, journal, journal_path, "file", &file.destination)?;
    Ok(())
}

#[cfg(unix)]
fn write_service_configuration(
    adapter: &dyn MacosApplyAdapter,
    validated: &ValidatedApply,
    journal: &mut super::models::Journal,
    journal_path: &Path,
) -> AppResult<()> {
    let path = Path::new(super::macos_launchd::CONFIGURATION_PATH);
    if resource_completed(journal, "configuration", &path.to_string_lossy()) {
        return Ok(());
    }
    let authority_port = validated
        .plan
        .listeners
        .first()
        .map(|listener| listener.port)
        .ok_or(AppError::forbidden(
            "macOS plan has no reviewed loopback listener",
        ))?;
    let configuration = crate::macos_service::ServiceConfiguration {
        config_version: crate::macos_service::SERVICE_CONFIG_VERSION,
        deployment_kind: v2::DeploymentKind::MacosLaunchd,
        network: crate::macos_service::ServiceNetworkConfiguration {
            scope: v2::NetworkScope::LoopbackDevelopment,
            authority_port,
        },
        storage: crate::macos_service::ServiceStorageConfiguration {
            data_directory: super::macos_launchd::DATA_PATH.to_string(),
        },
        tls: crate::macos_service::ServiceTlsConfiguration {
            certificate_path: super::macos_launchd::TLS_CERTIFICATE_PATH.to_string(),
            private_key_path: super::macos_launchd::TLS_PRIVATE_KEY_PATH.to_string(),
        },
    };
    let bytes = serde_json::to_vec_pretty(&configuration)
        .map_err(|error| AppError::internal(format!("serialize macOS service config: {error}")))?;
    let identity = path.to_string_lossy().into_owned();
    ensure_absent(adapter, path, "configuration")?;
    record_intent(adapter, journal, journal_path, "configuration", &identity)?;
    if let Err(error) = adapter.write_new_file(path, &bytes, 0o644, 0, 0) {
        let detail = format!("write macOS service config: {error}");
        record_failed(
            adapter,
            journal,
            journal_path,
            "configuration",
            &identity,
            &detail,
        )?;
        return Err(AppError::internal(detail));
    }
    record_completed(adapter, journal, journal_path, "configuration", &identity)?;
    Ok(())
}

#[cfg(unix)]
fn install_tls_material(
    adapter: &dyn MacosApplyAdapter,
    context: &ApplyContext,
    validated: &ValidatedApply,
    journal: &mut super::models::Journal,
    journal_path: &Path,
) -> AppResult<()> {
    for (source, destination, expected_sha256) in [
        (
            TLS_SOURCE_CERTIFICATE_PATH,
            super::macos_launchd::TLS_CERTIFICATE_PATH,
            validated.tls.certificate_sha256.as_str(),
        ),
        (
            TLS_SOURCE_PRIVATE_KEY_PATH,
            super::macos_launchd::TLS_PRIVATE_KEY_PATH,
            validated.tls.private_key_sha256.as_str(),
        ),
    ] {
        if resource_completed(journal, "tls_file", destination) {
            continue;
        }
        ensure_absent(adapter, Path::new(destination), "TLS file")?;
        record_intent(adapter, journal, journal_path, "tls_file", destination)?;
        if let Err(error) = adapter.copy_tls_file(
            Path::new(source),
            Path::new(destination),
            context.uid,
            context.gid,
            expected_sha256,
        ) {
            let detail = format!("install TLS material '{destination}': {error}");
            record_failed(
                adapter,
                journal,
                journal_path,
                "tls_file",
                destination,
                &detail,
            )?;
            return Err(AppError::internal(detail));
        }
        record_completed(adapter, journal, journal_path, "tls_file", destination)?;
    }
    Ok(())
}

#[cfg(unix)]
fn write_install_receipt(
    adapter: &dyn MacosApplyAdapter,
    validated: &ValidatedApply,
    operation_id: &str,
    context: &ApplyContext,
    journal: &mut super::models::Journal,
    journal_path: &Path,
) -> AppResult<()> {
    let path = Path::new(INSTALL_RECEIPT_PATH);
    if resource_completed(journal, "receipt", &path.to_string_lossy()) {
        return Ok(());
    }
    let receipt = MacosInstallReceipt {
        receipt_version: RECEIPT_VERSION,
        product: validated.plan.product.clone(),
        version: validated.plan.version.clone(),
        service_account: PRODUCT_SERVICE_ACCOUNT.to_string(),
        service_group: PRODUCT_SERVICE_GROUP.to_string(),
        unique_id: context.uid,
        primary_group_id: context.gid,
        package_manifest_sha256: validated.package_evidence.manifest_sha256.clone(),
        verifying_key_sha256: validated.package_evidence.verifying_key_sha256.clone(),
        artifact_sha256: validated.package_evidence.artifact_sha256.clone(),
        artifact_size_bytes: validated.package_evidence.artifact_size_bytes,
        tls_certificate_sha256: validated.tls.certificate_sha256.clone(),
        tls_private_key_sha256: validated.tls.private_key_sha256.clone(),
        reviewed_plan_digest: validated.reviewed_plan_digest.clone(),
        operation_id: operation_id.to_string(),
        launchd_label: super::macos_launchd::LAUNCHD_LABEL.to_string(),
        installed_at: adapter.now_iso8601(),
    };
    let bytes = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| AppError::internal(format!("serialize macOS install receipt: {error}")))?;
    let identity = path.to_string_lossy().into_owned();
    ensure_absent(adapter, path, "install receipt")?;
    record_intent(adapter, journal, journal_path, "receipt", &identity)?;
    if let Err(error) = adapter.write_new_file(path, &bytes, 0o644, 0, 0) {
        let detail = format!("write macOS install receipt: {error}");
        record_failed(
            adapter,
            journal,
            journal_path,
            "receipt",
            &identity,
            &detail,
        )?;
        return Err(AppError::internal(detail));
    }
    record_completed(adapter, journal, journal_path, "receipt", &identity)?;
    Ok(())
}

#[cfg(unix)]
fn install_launchd(
    adapter: &dyn MacosApplyAdapter,
    validated: &ValidatedApply,
    context: &ApplyContext,
    journal: &mut super::models::Journal,
    journal_path: &Path,
) -> AppResult<()> {
    let plist = Path::new(super::macos_launchd::LAUNCHD_PLIST_PATH);
    let label = super::macos_launchd::LAUNCHD_LABEL;
    if !resource_completed(journal, "launchd_plist", &label) {
        let contents = launchd_plist();
        ensure_absent(adapter, plist, "launchd plist")?;
        record_intent(adapter, journal, journal_path, "launchd_plist", label)?;
        if let Err(error) = adapter.write_new_file(plist, contents.as_bytes(), 0o644, 0, 0) {
            let detail = format!("write launchd plist: {error}");
            record_failed(
                adapter,
                journal,
                journal_path,
                "launchd_plist",
                label,
                &detail,
            )?;
            return Err(AppError::internal(detail));
        }
        record_completed(adapter, journal, journal_path, "launchd_plist", label)?;
    }
    if !resource_completed(journal, "launchd_service", label) {
        record_intent(adapter, journal, journal_path, "launchd_service", label)?;
        adapter
            .launchd_bootstrap(plist, label)
            .map_err(|error| AppError::internal(format!("bootstrap launchd daemon: {error}")))?;
        let loaded = adapter
            .launchd_is_loaded(label)
            .map_err(|error| AppError::internal(format!("verify launchd daemon: {error}")))?;
        if !loaded {
            return Err(AppError::security_state_unavailable(
                "launchd did not report the macOS service as loaded",
            ));
        }
        let port = validated
            .plan
            .listeners
            .first()
            .map(|listener| listener.port)
            .ok_or(AppError::forbidden(
                "macOS plan has no reviewed loopback listener",
            ))?;
        let mut last_health_error = "no health attempt completed".to_string();
        let mut healthy = false;
        for _ in 0..10 {
            match adapter.service_health(port, &validated.tls.certificate_sha256, context.uid) {
                Ok(true) => {
                    healthy = true;
                    break;
                }
                Ok(false) => {
                    last_health_error =
                        "health endpoint returned an unsuccessful response".to_string();
                }
                Err(error) => last_health_error = error,
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        if !healthy {
            return Err(AppError::security_state_unavailable(format!(
                "macOS service did not return a healthy /health response after launchd bootstrap: {last_health_error}"
            )));
        }
        record_completed(adapter, journal, journal_path, "launchd_service", label)?;
    }
    Ok(())
}

#[cfg(unix)]
fn launchd_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{executable}</string>
    <string>macos-service</string>
  </array>
  <key>UserName</key><string>{account}</string>
  <key>GroupName</key><string>{group}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
</dict>
</plist>
"#,
        label = super::macos_launchd::LAUNCHD_LABEL,
        executable = super::macos_launchd::EXECUTABLE_PATH,
        account = PRODUCT_SERVICE_ACCOUNT,
        group = PRODUCT_SERVICE_GROUP,
    )
}

#[cfg(unix)]
fn finish_failed_apply(
    adapter: &dyn MacosApplyAdapter,
    state_dir: &Path,
    journal_path: &Path,
    record_path: &Path,
    record: &mut v2::OperationRecord,
    journal: &mut super::models::Journal,
) -> AppResult<v2::OperationStatus> {
    if let Err(error) = validate_journal_resources(journal) {
        record.outcome = Some(v2::OperationOutcome {
            state: v2::OperationState::AttentionRequired,
            result: v2::OperationResult {
                code: "rollback_journal_invalid".to_string(),
                summary: "The macOS install journal contains an unconstrained resource; rollback was refused.".to_string(),
                errors: vec![error.to_string()],
                warnings: Vec::new(),
            },
        });
        write_record(adapter, record_path, record)?;
        return status_from_state(
            adapter,
            state_dir,
            &record.configuration,
            Some((*record).clone()),
            Some((*journal).clone()),
        );
    }
    let errors = rollback(adapter, journal, journal_path)?;
    if errors.is_empty() {
        record.outcome = Some(v2::OperationOutcome {
            state: v2::OperationState::AttentionRequired,
            result: v2::OperationResult {
                code: "rolled_back".to_string(),
                summary: "The macOS install failed and every journaled resource was rolled back. No service is installed.".to_string(),
                errors: Vec::new(),
                warnings: Vec::new(),
            },
        });
        // Persist the terminal record before unlinking the journal.
        write_record(adapter, record_path, record)?;
        adapter
            .remove_file(journal_path)
            .map_err(|error| AppError::internal(format!("remove rolled-back journal: {error}")))?;
        Ok(status_from_state(
            adapter,
            state_dir,
            &record.configuration,
            Some((*record).clone()),
            None,
        )?)
    } else {
        record.outcome = Some(v2::OperationOutcome {
            state: v2::OperationState::AttentionRequired,
            result: v2::OperationResult {
                code: "rollback_incomplete".to_string(),
                summary: "The macOS install failed and rollback could not remove every journaled resource; inspect the host and run cancel-v2.".to_string(),
                errors,
                warnings: Vec::new(),
            },
        });
        write_record(adapter, record_path, record)?;
        Ok(status_from_state(
            adapter,
            state_dir,
            &record.configuration,
            Some((*record).clone()),
            Some((*journal).clone()),
        )?)
    }
}

#[cfg(unix)]
fn rollback(
    adapter: &dyn MacosApplyAdapter,
    journal: &mut super::models::Journal,
    journal_path: &Path,
) -> AppResult<Vec<String>> {
    use super::models::ResourceStatus;

    let resources = journal.resources.clone();
    let mut errors = Vec::new();

    // Stop launchd before touching any file. If the service may still be
    // running, every later deletion is unsafe, so abort immediately.
    for resource in resources
        .iter()
        .filter(|resource| resource.resource_type == "launchd_service")
    {
        match resource.status {
            ResourceStatus::Completed => {
                if let Err(error) = adapter.launchd_bootout(&resource.identity) {
                    errors.push(format!("rollback launchd service: {error}"));
                    return finish_rollback(adapter, journal, journal_path, errors);
                }
                match adapter.launchd_is_loaded(&resource.identity) {
                    Ok(false) => mark_rolled_back(journal, resource),
                    Ok(true) => {
                        errors.push(format!(
                            "rollback cannot prove launchd service '{}' is stopped",
                            resource.identity
                        ));
                        return finish_rollback(adapter, journal, journal_path, errors);
                    }
                    Err(error) => {
                        errors.push(format!(
                            "rollback cannot observe launchd service '{}': {error}",
                            resource.identity
                        ));
                        return finish_rollback(adapter, journal, journal_path, errors);
                    }
                }
            }
            ResourceStatus::RolledBack => {}
            ResourceStatus::Intent | ResourceStatus::Failed => {
                // The label is fixed and operation-owned. Attempt bootout first
                // so a partially loaded service cannot keep files alive.
                if let Err(error) = adapter.launchd_bootout(&resource.identity) {
                    errors.push(format!(
                        "rollback could not stop launchd service '{}': {error}",
                        resource.identity
                    ));
                    return finish_rollback(adapter, journal, journal_path, errors);
                }
                match adapter.launchd_is_loaded(&resource.identity) {
                    Ok(false) => {}
                    Ok(true) => {
                        errors.push(format!(
                            "rollback cannot prove launchd service '{}' is stopped",
                            resource.identity
                        ));
                        return finish_rollback(adapter, journal, journal_path, errors);
                    }
                    Err(error) => {
                        errors.push(format!(
                            "rollback cannot observe launchd service '{}': {error}",
                            resource.identity
                        ));
                        return finish_rollback(adapter, journal, journal_path, errors);
                    }
                }
            }
        }
    }

    // Remove only journaled-completed non-identity resources. Intent/failed
    // entries are never deleted; if the object exists, rollback is reported as
    // incomplete because ownership is not proven.
    for resource in resources.iter().rev() {
        if matches!(
            resource.resource_type.as_str(),
            "launchd_service" | "service_user" | "service_group"
        ) {
            continue;
        }
        let Some(path) = rollback_path(resource) else {
            errors.push(format!(
                "rollback journal contains unknown resource type '{}'",
                resource.resource_type
            ));
            continue;
        };
        match resource.status {
            ResourceStatus::Completed => {
                let result = if resource.resource_type == "directory" {
                    adapter.remove_directory(&path)
                } else {
                    adapter.remove_file(&path)
                };
                match result {
                    Ok(()) => mark_rolled_back(journal, resource),
                    Err(error) => errors.push(format!(
                        "rollback {} '{}': {error}",
                        resource.resource_type,
                        path.display()
                    )),
                }
            }
            ResourceStatus::RolledBack => {}
            ResourceStatus::Intent | ResourceStatus::Failed => match adapter.path_metadata(&path) {
                Ok(None) => {}
                Ok(Some(_)) => errors.push(format!(
                    "rollback refuses unproven {} '{}'; ownership is not established",
                    resource.resource_type,
                    path.display()
                )),
                Err(error) => errors.push(format!(
                    "rollback cannot inspect unproven {} '{}': {error}",
                    resource.resource_type,
                    path.display()
                )),
            },
        }
    }

    // Never delete the service identity while any non-identity resource or
    // earlier failure remains. A nonempty Data directory therefore preserves
    // the account/group that owns those files.
    if !errors.is_empty() {
        return finish_rollback(adapter, journal, journal_path, errors);
    }

    for resource in resources.iter().rev() {
        if !matches!(
            resource.resource_type.as_str(),
            "service_user" | "service_group"
        ) {
            continue;
        }
        match resource.status {
            ResourceStatus::Completed => {
                let result = if resource.resource_type == "service_user" {
                    adapter.remove_service_user(&resource.identity)
                } else {
                    adapter.remove_service_group(&resource.identity)
                };
                match result {
                    Ok(()) => mark_rolled_back(journal, resource),
                    Err(error) => errors.push(format!(
                        "rollback {} '{}': {error}",
                        resource.resource_type, resource.identity
                    )),
                }
            }
            ResourceStatus::RolledBack => {}
            ResourceStatus::Intent | ResourceStatus::Failed => {
                let exists = if resource.resource_type == "service_user" {
                    adapter.observe_user().map(|user| user.is_some())
                } else {
                    adapter.observe_group().map(|group| group.is_some())
                };
                match exists {
                    Ok(false) => {}
                    Ok(true) => errors.push(format!(
                        "rollback refuses unproven {} '{}'; identity ownership is not established",
                        resource.resource_type, resource.identity
                    )),
                    Err(error) => errors.push(format!(
                        "rollback cannot inspect unproven {} '{}': {error}",
                        resource.resource_type, resource.identity
                    )),
                }
            }
        }
    }

    finish_rollback(adapter, journal, journal_path, errors)
}

#[cfg(unix)]
fn finish_rollback(
    adapter: &dyn MacosApplyAdapter,
    journal: &mut super::models::Journal,
    journal_path: &Path,
    errors: Vec<String>,
) -> AppResult<Vec<String>> {
    journal.updated_at = adapter.now_iso8601();
    save_journal(adapter, journal_path, journal)?;
    Ok(errors)
}

#[cfg(unix)]
fn rollback_path(resource: &super::models::ResourceEntry) -> Option<PathBuf> {
    match resource.resource_type.as_str() {
        "launchd_plist" => Some(PathBuf::from(super::macos_launchd::LAUNCHD_PLIST_PATH)),
        "receipt" => Some(PathBuf::from(INSTALL_RECEIPT_PATH)),
        "tls_file" | "configuration" | "file" | "directory" => {
            Some(PathBuf::from(&resource.identity))
        }
        _ => None,
    }
}

#[cfg(unix)]
fn mark_rolled_back(journal: &mut super::models::Journal, resource: &super::models::ResourceEntry) {
    if let Some(entry) = journal.resources.iter_mut().rev().find(|entry| {
        entry.resource_type == resource.resource_type && entry.identity == resource.identity
    }) {
        entry.status = super::models::ResourceStatus::RolledBack;
    }
}

#[cfg(unix)]
fn status_from_state(
    adapter: &dyn MacosApplyAdapter,
    state_dir: &Path,
    configuration: &v2::DeploymentConfiguration,
    record: Option<v2::OperationRecord>,
    journal: Option<super::models::Journal>,
) -> AppResult<v2::OperationStatus> {
    use v2::{OperationResult, OperationState};

    let phases: BTreeMap<String, super::models::PhaseStatus> = journal
        .as_ref()
        .map(|journal| {
            journal
                .phases
                .iter()
                .map(|(name, entry)| (name.clone(), entry.status))
                .collect()
        })
        .unwrap_or_default();
    let completed = phases.get("completed") == Some(&super::models::PhaseStatus::Completed);
    let failed = phases
        .values()
        .any(|status| *status == super::models::PhaseStatus::Failed);
    let outcome = record.as_ref().and_then(|record| record.outcome.as_ref());
    let cancelled = outcome.is_some_and(|outcome| outcome.state == OperationState::Cancelled);
    let receipt_valid = verify_runtime_receipt_with_adapter(adapter).unwrap_or(false);
    let service_installed = completed
        && receipt_valid
        && !cancelled
        && record.as_ref().is_some_and(|record| {
            record
                .outcome
                .as_ref()
                .is_some_and(|outcome| outcome.state == OperationState::Completed)
        });
    let state = if let Some(outcome) = outcome {
        match outcome.state {
            OperationState::Cancelled => OperationState::Cancelled,
            OperationState::Completed if completed && receipt_valid => OperationState::Completed,
            OperationState::Completed => OperationState::AttentionRequired,
            OperationState::AttentionRequired => OperationState::AttentionRequired,
            OperationState::InProgress => OperationState::InProgress,
            OperationState::NotInstalled => OperationState::NotInstalled,
        }
    } else if completed {
        OperationState::AttentionRequired
    } else if failed {
        OperationState::AttentionRequired
    } else if record.is_some() {
        OperationState::InProgress
    } else {
        OperationState::NotInstalled
    };
    let (code, summary) = match state {
        OperationState::Completed => (
            "completed",
            "The macOS service is installed; readiness and enrollment remain unverified.",
        ),
        OperationState::Cancelled => (
            "cancelled",
            "The incomplete macOS install was cancelled and rolled back.",
        ),
        OperationState::AttentionRequired => (
            "attention_required",
            "The macOS install requires attention; inspect the journal before retrying.",
        ),
        OperationState::InProgress => (
            "in_progress",
            "A macOS install operation is in progress or was interrupted.",
        ),
        OperationState::NotInstalled => ("not_installed", "No macOS installer journal is present."),
    };
    let unverified_completion =
        completed && !outcome.is_some_and(|outcome| outcome.state == OperationState::Completed);
    let cancellation_available = record.as_ref().is_some_and(|record| {
        record.action == v2::LifecycleAction::Install
            && !service_installed
            && !cancelled
            && !unverified_completion
            && !record.outcome.as_ref().is_some_and(|outcome| {
                outcome.state == OperationState::Cancelled
                    || outcome.state == OperationState::Completed
                    || outcome.result.code == "rolled_back"
            })
    });
    let _ = state_dir;
    Ok(v2::OperationStatus {
        contract_version: v2::CONTRACT_VERSION,
        configuration: configuration.clone(),
        operation_id: record.as_ref().map(|record| record.operation_id.clone()),
        action: record.as_ref().map(|record| record.action),
        state,
        reviewed_plan_digest: record
            .as_ref()
            .map(|record| record.reviewed_plan_digest.clone()),
        current_phase: journal
            .as_ref()
            .map(|journal| journal.current_phase.clone()),
        phases,
        cancellation_available,
        resume_available: false,
        service_installed,
        bootstrap_ready: false,
        server_ready_for_enrollment: false,
        result: match outcome {
            Some(outcome)
                if state == OperationState::AttentionRequired
                    && outcome.state == OperationState::Completed =>
            {
                OperationResult {
                    code: "install_unverified".to_string(),
                    summary: "A completed install record exists, but the receipt, journal, or installed identity no longer verifies; service_installed is withheld.".to_string(),
                    errors: Vec::new(),
                    warnings: vec!["inspect status and the install receipt before trusting the service".to_string()],
                }
            }
            Some(outcome) => outcome.result.clone(),
            None => OperationResult {
                code: code.to_string(),
                summary: summary.to_string(),
                errors: Vec::new(),
                warnings: Vec::new(),
            },
        },
    })
}

#[cfg(unix)]
fn prepare_state_dir(adapter: &dyn MacosApplyAdapter, state_dir: &Path) -> AppResult<()> {
    if state_dir != Path::new(INSTALL_STATE_DIRECTORY) {
        return Err(AppError::bad_request(format!(
            "macOS installer state directory must be the fixed path {INSTALL_STATE_DIRECTORY}"
        )));
    }
    let mut current = PathBuf::new();
    for component in state_dir.components() {
        current.push(component);
        match adapter.path_metadata(&current).map_err(unavailable)? {
            Some(metadata) => {
                if metadata.is_symlink {
                    return Err(AppError::security_state_unavailable(format!(
                        "state path '{}' is a symlink",
                        current.display()
                    )));
                }
                if !metadata.is_directory {
                    return Err(AppError::conflict(
                        format!("state path '{}' is not a directory", current.display()),
                        None,
                    ));
                }
                if metadata.uid != 0 || metadata.mode & 0o022 != 0 {
                    return Err(AppError::security_state_unavailable(format!(
                        "state path '{}' is not root-owned or is group/world-writable",
                        current.display()
                    )));
                }
                if !adapter
                    .extended_acl_is_safe(&current)
                    .map_err(unavailable)?
                {
                    return Err(AppError::security_state_unavailable(format!(
                        "state path '{}' carries an extended ACL with an ALLOW entry",
                        current.display()
                    )));
                }
            }
            None if current.as_path() == state_dir => {
                adapter
                    .create_directory(&current, 0o700, 0, 0)
                    .map_err(|error| {
                        AppError::internal(format!(
                            "create macOS installer state directory: {error}"
                        ))
                    })?;
            }
            None => {
                return Err(AppError::security_state_unavailable(format!(
                    "state path parent '{}' is absent",
                    current.display()
                )))
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn acquire_lock(adapter: &dyn MacosApplyAdapter, _state_dir: &Path) -> AppResult<MacosApplyLock> {
    let path = Path::new(INSTALL_LOCK_PATH);
    adapter.acquire_lock(path).map_err(|error| {
        AppError::conflict(
            format!("cannot acquire macOS installer operation lock: {error}"),
            None,
        )
    })
}

#[cfg(unix)]
fn ensure_absent(adapter: &dyn MacosApplyAdapter, path: &Path, label: &str) -> AppResult<()> {
    if adapter.path_metadata(path).map_err(unavailable)?.is_some() {
        return Err(AppError::conflict(
            format!(
                "{label} '{}' already exists; refusing to overwrite",
                path.display()
            ),
            None,
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn parse_mode(mode: &str) -> AppResult<u32> {
    u32::from_str_radix(mode, 8).map_err(|_| {
        AppError::internal(format!(
            "canonical macOS plan contains an invalid octal mode '{mode}'"
        ))
    })
}

#[cfg(unix)]
fn decode_key_hex(value: &str) -> AppResult<[u8; 32]> {
    let bytes = hex::decode(value)
        .map_err(|error| AppError::bad_request(format!("invalid hex key: {error}")))?;
    if bytes.len() != 32 {
        return Err(AppError::bad_request(format!(
            "verifying key must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(unix)]
fn create_journal(adapter: &dyn MacosApplyAdapter, plan_digest: &str) -> super::models::Journal {
    let mut phases = BTreeMap::new();
    for phase in PHASES {
        phases.insert(phase.to_string(), pending_phase());
    }
    let now = adapter.now_iso8601();
    super::models::Journal {
        contract_version: super::models::CONTRACT_VERSION,
        plan_digest: plan_digest.to_string(),
        started_at: now.clone(),
        updated_at: now,
        current_phase: "pending".to_string(),
        phases,
        resources_created: super::models::ResourcesCreated::default(),
        resources: Vec::new(),
    }
}

#[cfg(unix)]
fn pending_phase() -> super::models::PhaseEntry {
    super::models::PhaseEntry {
        status: super::models::PhaseStatus::Pending,
        started_at: None,
        completed_at: None,
        error: None,
    }
}

#[cfg(unix)]
fn save_journal(
    adapter: &dyn MacosApplyAdapter,
    path: &Path,
    journal: &super::models::Journal,
) -> AppResult<()> {
    let bytes = serde_json::to_vec_pretty(journal)
        .map_err(|error| AppError::internal(format!("serialize macOS journal: {error}")))?;
    adapter
        .write_state_file(path, &bytes)
        .map_err(|error| AppError::internal(format!("save macOS journal: {error}")))
}

#[cfg(unix)]
fn write_record(
    adapter: &dyn MacosApplyAdapter,
    path: &Path,
    record: &v2::OperationRecord,
) -> AppResult<()> {
    let bytes = serde_json::to_vec_pretty(record).map_err(|error| {
        AppError::internal(format!("serialize macOS operation record: {error}"))
    })?;
    adapter
        .write_state_file(path, &bytes)
        .map_err(|error| AppError::internal(format!("save macOS operation record: {error}")))
}

#[cfg(unix)]
fn read_operation_record(
    adapter: &dyn MacosApplyAdapter,
    path: &Path,
) -> AppResult<Option<v2::OperationRecord>> {
    match adapter.path_metadata(path) {
        Ok(None) => Ok(None),
        Ok(Some(metadata)) => {
            validate_state_file(&metadata, path)?;
            let bytes = adapter
                .read_bounded_file(path, MAX_STATE_BYTES)
                .map_err(unavailable)?;
            let record: v2::OperationRecord = serde_json::from_slice(&bytes).map_err(|error| {
                AppError::security_state_unavailable(format!(
                    "corrupt macOS operation record: {error}"
                ))
            })?;
            if record.contract_version != v2::CONTRACT_VERSION
                || uuid::Uuid::parse_str(&record.operation_id).is_err()
            {
                return Err(AppError::security_state_unavailable(
                    "macOS operation record has an unsupported identity",
                ));
            }
            Ok(Some(record))
        }
        Err(error) => Err(AppError::security_state_unavailable(error)),
    }
}

#[cfg(unix)]
fn validate_journal_resources(journal: &super::models::Journal) -> AppResult<()> {
    for resource in &journal.resources {
        let identity = resource.identity.as_str();
        match resource.resource_type.as_str() {
            "service_user" | "service_group" => {
                if identity != PRODUCT_SERVICE_ACCOUNT && identity != PRODUCT_SERVICE_GROUP {
                    return Err(AppError::security_state_unavailable(
                        "macOS journal contains an unapproved service identity",
                    ));
                }
            }
            "launchd_service" | "launchd_plist" => {
                if identity != super::macos_launchd::LAUNCHD_LABEL {
                    return Err(AppError::security_state_unavailable(
                        "macOS journal contains an unapproved launchd identity",
                    ));
                }
            }
            "receipt" => {
                if identity != INSTALL_RECEIPT_PATH {
                    return Err(AppError::security_state_unavailable(
                        "macOS journal contains an unapproved receipt path",
                    ));
                }
            }
            "tls_file" => {
                if identity != super::macos_launchd::TLS_CERTIFICATE_PATH
                    && identity != super::macos_launchd::TLS_PRIVATE_KEY_PATH
                {
                    return Err(AppError::security_state_unavailable(
                        "macOS journal contains an unapproved TLS path",
                    ));
                }
            }
            "configuration" => {
                if identity != super::macos_launchd::CONFIGURATION_PATH {
                    return Err(AppError::security_state_unavailable(
                        "macOS journal contains an unapproved configuration path",
                    ));
                }
            }
            "file" => {
                if identity != super::macos_launchd::EXECUTABLE_PATH {
                    return Err(AppError::security_state_unavailable(
                        "macOS journal contains an unapproved product file path",
                    ));
                }
            }
            "directory" => {
                require_normalized_absolute(identity)?;
                let fixed = [
                    super::macos_launchd::PRODUCT_ROOT_PATH,
                    super::macos_launchd::EXECUTABLE_DIRECTORY,
                    super::macos_launchd::CONFIGURATION_DIRECTORY,
                    super::macos_launchd::DATA_PATH,
                    super::macos_launchd::TLS_DIRECTORY,
                ];
                if !fixed.contains(&identity) {
                    return Err(AppError::security_state_unavailable(
                        "macOS journal contains an unapproved directory path",
                    ));
                }
            }
            _ => {
                return Err(AppError::security_state_unavailable(
                    "macOS journal contains an unknown resource type",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_normalized_absolute(path: &str) -> AppResult<()> {
    let path = Path::new(path);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(AppError::security_state_unavailable(
            "macOS journal contains an unnormalized resource path",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn read_journal(
    adapter: &dyn MacosApplyAdapter,
    path: &Path,
) -> AppResult<Option<super::models::Journal>> {
    match adapter.path_metadata(path) {
        Ok(None) => Ok(None),
        Ok(Some(metadata)) => {
            validate_state_file(&metadata, path)?;
            let bytes = adapter
                .read_bounded_file(path, MAX_STATE_BYTES)
                .map_err(unavailable)?;
            let journal: super::models::Journal =
                serde_json::from_slice(&bytes).map_err(|error| {
                    AppError::security_state_unavailable(format!("corrupt macOS journal: {error}"))
                })?;
            if journal.contract_version != super::models::CONTRACT_VERSION {
                return Err(AppError::security_state_unavailable(
                    "macOS journal has an unsupported contract version",
                ));
            }
            validate_journal_resources(&journal)?;
            Ok(Some(journal))
        }
        Err(error) => Err(AppError::security_state_unavailable(error)),
    }
}

#[cfg(unix)]
fn validate_state_file(metadata: &MacosApplyPathMetadata, path: &Path) -> AppResult<()> {
    if metadata.is_symlink
        || !metadata.is_regular_file
        || metadata.uid != 0
        || metadata.nlink != 1
        || metadata.mode & 0o022 != 0
        || metadata.len == 0
        || metadata.len > MAX_STATE_BYTES as u64
    {
        return Err(AppError::security_state_unavailable(format!(
            "macOS installer state file '{}' has an unsafe shape",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn record_intent(
    adapter: &dyn MacosApplyAdapter,
    journal: &mut super::models::Journal,
    path: &Path,
    resource_type: &str,
    identity: &str,
) -> AppResult<()> {
    journal.resources.push(super::models::ResourceEntry {
        resource_type: resource_type.to_string(),
        identity: identity.to_string(),
        status: super::models::ResourceStatus::Intent,
        error: None,
    });
    journal.updated_at = adapter.now_iso8601();
    save_journal(adapter, path, journal)
}

#[cfg(unix)]
fn record_completed(
    adapter: &dyn MacosApplyAdapter,
    journal: &mut super::models::Journal,
    path: &Path,
    resource_type: &str,
    identity: &str,
) -> AppResult<()> {
    if let Some(entry) = journal.resources.iter_mut().rev().find(|entry| {
        entry.resource_type == resource_type
            && entry.identity == identity
            && entry.status == super::models::ResourceStatus::Intent
    }) {
        entry.status = super::models::ResourceStatus::Completed;
    }
    journal.updated_at = adapter.now_iso8601();
    save_journal(adapter, path, journal)
}

#[cfg(unix)]
fn record_failed(
    adapter: &dyn MacosApplyAdapter,
    journal: &mut super::models::Journal,
    path: &Path,
    resource_type: &str,
    identity: &str,
    error: &str,
) -> AppResult<()> {
    if let Some(entry) = journal.resources.iter_mut().rev().find(|entry| {
        entry.resource_type == resource_type
            && entry.identity == identity
            && entry.status == super::models::ResourceStatus::Intent
    }) {
        entry.status = super::models::ResourceStatus::Failed;
        entry.error = Some(error.to_string());
    }
    journal.updated_at = adapter.now_iso8601();
    save_journal(adapter, path, journal)
}

#[cfg(unix)]
fn resource_completed(
    journal: &super::models::Journal,
    resource_type: &str,
    identity: &str,
) -> bool {
    journal.resources.iter().any(|entry| {
        entry.resource_type == resource_type
            && entry.identity == identity
            && entry.status == super::models::ResourceStatus::Completed
    })
}

/// Verify the durable receipt against the currently observed identity.
///
/// Returns `Ok(false)` only when the receipt is absent. Any present receipt
/// with an unsafe shape, unsupported fields, changed UID/GID, missing account,
/// or mismatched evidence fails closed.
#[cfg(unix)]
pub fn verify_runtime_receipt_with_adapter(adapter: &dyn MacosApplyAdapter) -> AppResult<bool> {
    verify_runtime_receipt_with_adapter_for_euid(adapter, None)
}

/// Verify the receipt and, when supplied, bind it to the running effective UID.
#[cfg(unix)]
pub fn verify_runtime_receipt_with_adapter_for_euid(
    adapter: &dyn MacosApplyAdapter,
    expected_uid: Option<u32>,
) -> AppResult<bool> {
    let path = Path::new(INSTALL_RECEIPT_PATH);
    let metadata = adapter.path_metadata(path).map_err(unavailable)?;
    let Some(metadata) = metadata else {
        return Ok(false);
    };
    if metadata.is_symlink
        || !metadata.is_regular_file
        || metadata.uid != 0
        || metadata.nlink != 1
        || metadata.mode & 0o022 != 0
        || metadata.len == 0
        || metadata.len > MAX_RECEIPT_BYTES as u64
    {
        return Err(AppError::security_state_unavailable(
            "the macOS install receipt has an unsafe shape",
        ));
    }
    if !adapter.extended_acl_is_safe(path).map_err(unavailable)? {
        return Err(AppError::security_state_unavailable(
            "the macOS install receipt carries an extended ACL with an ALLOW entry",
        ));
    }
    let bytes = adapter
        .read_bounded_file(path, MAX_RECEIPT_BYTES)
        .map_err(unavailable)?;
    let receipt: MacosInstallReceipt = serde_json::from_slice(&bytes).map_err(|error| {
        AppError::security_state_unavailable(format!("invalid macOS receipt: {error}"))
    })?;
    verify_receipt(adapter, &receipt, expected_uid)?;
    Ok(true)
}

#[cfg(not(unix))]
pub fn verify_runtime_receipt_with_adapter(_adapter: &dyn MacosApplyAdapter) -> AppResult<bool> {
    Err(AppError::not_implemented(
        "macOS receipt verification is available only on Unix hosts",
    ))
}

#[cfg(not(unix))]
pub fn verify_runtime_receipt_with_adapter_for_euid(
    _adapter: &dyn MacosApplyAdapter,
    _expected_uid: Option<u32>,
) -> AppResult<bool> {
    Err(AppError::not_implemented(
        "macOS receipt verification is available only on Unix hosts",
    ))
}

#[cfg(unix)]
fn verify_receipt(
    adapter: &dyn MacosApplyAdapter,
    receipt: &MacosInstallReceipt,
    expected_uid: Option<u32>,
) -> AppResult<()> {
    if expected_uid.is_some_and(|uid| uid != receipt.unique_id) {
        return Err(AppError::security_state_unavailable(
            "the macOS install receipt does not match the running effective UID",
        ));
    }
    if receipt.receipt_version != RECEIPT_VERSION
        || receipt.product != "hs-server"
        || receipt.service_account != PRODUCT_SERVICE_ACCOUNT
        || receipt.service_group != PRODUCT_SERVICE_GROUP
        || receipt.launchd_label != super::macos_launchd::LAUNCHD_LABEL
        || receipt.unique_id == 0
        || receipt.primary_group_id == 0
        || uuid::Uuid::parse_str(&receipt.operation_id).is_err()
        || !is_sha256(&receipt.package_manifest_sha256)
        || !is_sha256(&receipt.verifying_key_sha256)
        || !is_sha256(&receipt.artifact_sha256)
        || !is_sha256(&receipt.tls_certificate_sha256)
        || !is_sha256(&receipt.tls_private_key_sha256)
        || !is_sha256(&receipt.reviewed_plan_digest)
        || receipt.version.is_empty()
        || receipt.installed_at.is_empty()
    {
        return Err(AppError::security_state_unavailable(
            "the macOS install receipt does not match the reviewed product evidence",
        ));
    }
    match adapter.identity_decision() {
        ServiceIdentityDecision::ExistingAccountRefused { reasons }
            if reasons.len() == 1 && reasons[0] == IdentityRefusal::OwnershipNotVerified => {}
        other => {
            return Err(AppError::security_state_unavailable(format!(
                "the macOS service identity is not a valid receipt-owned identity: {other}"
            )))
        }
    }
    let user = adapter
        .observe_user()
        .map_err(unavailable)?
        .ok_or_else(|| {
            AppError::security_state_unavailable("receipt exists but the service account is absent")
        })?;
    let group = adapter
        .observe_group()
        .map_err(unavailable)?
        .ok_or_else(|| {
            AppError::security_state_unavailable("receipt exists but the service group is absent")
        })?;
    if !exact_record_name(&user.record_names, PRODUCT_SERVICE_ACCOUNT)
        || user.unique_id != i64::from(receipt.unique_id)
        || user.primary_group_id != i64::from(receipt.primary_group_id)
        || !NON_LOGIN_SHELLS.contains(&user.user_shell.as_str())
        || user.password != "*"
        || !acceptable_auth_authority(&user.authentication_authority)
    {
        return Err(AppError::security_state_unavailable(
            "the macOS install receipt does not match the observed service account",
        ));
    }
    if !exact_record_name(&group.record_names, PRODUCT_SERVICE_GROUP)
        || group.primary_group_id != i64::from(receipt.primary_group_id)
        || !group
            .group_membership
            .iter()
            .all(|member| member.as_str() == PRODUCT_SERVICE_ACCOUNT)
    {
        return Err(AppError::security_state_unavailable(
            "the macOS install receipt does not match the observed service group",
        ));
    }
    if !adapter
        .resolver_identity_matches(receipt.unique_id, receipt.primary_group_id)
        .map_err(unavailable)?
    {
        return Err(AppError::security_state_unavailable(
            "the macOS install receipt identity is not unique or does not resolve through the full name-service stack",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn unavailable(error: String) -> AppError {
    AppError::security_state_unavailable(error)
}

#[cfg(unix)]
fn acceptable_auth_authority(values: &[String]) -> bool {
    values.is_empty() || values.iter().all(|value| value == ";DisabledUser;")
}

#[cfg(unix)]
fn exact_record_name(names: &[String], expected: &str) -> bool {
    names.len() == 1 && names[0] == expected
}

#[cfg(unix)]
fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Production macOS adapter
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub struct MacosSystemApplyAdapter {
    observer: MacosIdentityObserverImpl,
}

#[cfg(target_os = "macos")]
type MacosIdentityObserverImpl = super::macos_identity::MacosSystemIdentityObserver;

#[cfg(target_os = "macos")]
impl MacosSystemApplyAdapter {
    pub fn new() -> Self {
        Self {
            observer: super::macos_identity::MacosSystemIdentityObserver::new(),
        }
    }
}

#[cfg(target_os = "macos")]
impl Default for MacosSystemApplyAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
impl MacosIdentityObserver for MacosSystemApplyAdapter {
    fn observe(&self, query: IdentityQuery) -> Result<IdentityObservation, String> {
        self.observer.observe(query)
    }
}

#[cfg(target_os = "macos")]
impl MacosApplyAdapter for MacosSystemApplyAdapter {
    fn now_iso8601(&self) -> String {
        match run_fixed(&[
            "/bin/date".to_string(),
            "-u".to_string(),
            "+%Y-%m-%dT%H:%M:%SZ".to_string(),
        ]) {
            Ok((0, stdout, _)) if !stdout.trim().is_empty() => stdout.trim().to_string(),
            _ => "1970-01-01T00:00:00Z".to_string(),
        }
    }

    fn effective_uid(&self) -> Result<u32, String> {
        // SAFETY: geteuid has no preconditions and cannot fail.
        Ok(unsafe { libc::geteuid() })
    }

    fn preflight(
        &self,
        configuration: &v2::DeploymentConfiguration,
    ) -> AppResult<v2::PreflightResult> {
        super::macos_launchd::preflight_v2(
            &super::macos_launchd::MacosSystemObserver,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration.clone(),
            },
        )
    }

    fn identity_decision(&self) -> ServiceIdentityDecision {
        observe_service_identity(self)
    }

    fn observe_user(&self) -> Result<Option<UserRecordFacts>, String> {
        let observation = self.observe(IdentityQuery::AccountRecord)?;
        parse_user_record(&observation)
    }

    fn observe_group(&self) -> Result<Option<GroupRecordFacts>, String> {
        let observation = self.observe(IdentityQuery::GroupRecord)?;
        parse_group_record(&observation)
    }

    fn identity_search(&self, query: IdentityQuery) -> Result<IdentityObservation, String> {
        self.observe(query)
    }

    fn resolver_identity_absent(&self) -> Result<bool, String> {
        nss_identity_absent()
    }

    fn resolver_id_in_use(&self, id: u32) -> Result<bool, String> {
        nss_id_in_use(id)
    }

    fn resolver_user_by_uid(&self, uid: u32) -> Result<Option<String>, String> {
        lookup_user_name_by_uid(uid)
    }

    fn resolver_group_by_gid(&self, gid: u32) -> Result<Option<String>, String> {
        lookup_group_name_by_gid(gid)
    }

    fn resolver_identity_matches(&self, uid: u32, gid: u32) -> Result<bool, String> {
        nss_identity_matches(uid, gid)
    }

    fn create_service_group(&self, name: &str, gid: u32) -> Result<(), String> {
        if name != PRODUCT_SERVICE_GROUP {
            return Err("refusing non-product macOS service group".to_string());
        }
        for argv in [
            vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-create".to_string(),
                format!("/Groups/{name}"),
            ],
            vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-create".to_string(),
                format!("/Groups/{name}"),
                "PrimaryGroupID".to_string(),
                gid.to_string(),
            ],
            vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-create".to_string(),
                format!("/Groups/{name}"),
                "RealName".to_string(),
                "Helicoid service".to_string(),
            ],
        ] {
            // Never delete a partially-created record by name. It may be
            // foreign; leave it uncertain and let rollback report incomplete.
            require_success(&argv)?;
        }
        Ok(())
    }

    fn create_service_user(&self, name: &str, uid: u32, gid: u32) -> Result<(), String> {
        if name != PRODUCT_SERVICE_ACCOUNT {
            return Err("refusing non-product macOS service account".to_string());
        }
        for argv in [
            vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-create".to_string(),
                format!("/Users/{name}"),
            ],
            vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-create".to_string(),
                format!("/Users/{name}"),
                "UniqueID".to_string(),
                uid.to_string(),
            ],
            vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-create".to_string(),
                format!("/Users/{name}"),
                "PrimaryGroupID".to_string(),
                gid.to_string(),
            ],
            vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-create".to_string(),
                format!("/Users/{name}"),
                "UserShell".to_string(),
                "/usr/bin/false".to_string(),
            ],
            vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-create".to_string(),
                format!("/Users/{name}"),
                "NFSHomeDirectory".to_string(),
                "/var/empty".to_string(),
            ],
            vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-create".to_string(),
                format!("/Users/{name}"),
                "RealName".to_string(),
                "Helicoid service".to_string(),
            ],
            vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-create".to_string(),
                format!("/Users/{name}"),
                "IsHidden".to_string(),
                "1".to_string(),
            ],
            vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-create".to_string(),
                format!("/Users/{name}"),
                "Password".to_string(),
                "*".to_string(),
            ],
            vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-create".to_string(),
                format!("/Users/{name}"),
                "AuthenticationAuthority".to_string(),
                ";DisabledUser;".to_string(),
            ],
        ] {
            // Never delete a partially-created record by name. It may be
            // foreign; leave it uncertain and let rollback report incomplete.
            require_success(&argv)?;
        }
        Ok(())
    }

    fn remove_service_user(&self, name: &str) -> Result<(), String> {
        if name != PRODUCT_SERVICE_ACCOUNT {
            return Err("refusing non-product macOS service account".to_string());
        }
        delete_dscl_record("/Users", name)
    }

    fn remove_service_group(&self, name: &str) -> Result<(), String> {
        if name != PRODUCT_SERVICE_GROUP {
            return Err("refusing non-product macOS service group".to_string());
        }
        delete_dscl_record("/Groups", name)
    }

    fn path_metadata(&self, path: &Path) -> Result<Option<MacosApplyPathMetadata>, String> {
        use std::os::unix::fs::MetadataExt;
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => Ok(Some(MacosApplyPathMetadata {
                is_symlink: metadata.file_type().is_symlink(),
                is_directory: metadata.is_dir(),
                is_regular_file: metadata.is_file(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode(),
                nlink: metadata.nlink(),
                len: metadata.len(),
            })),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("inspect '{}': {error}", path.display())),
        }
    }

    fn create_directory(&self, path: &Path, mode: u32, uid: u32, gid: u32) -> Result<(), String> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        let parent = path
            .parent()
            .ok_or_else(|| "directory has no parent".to_string())?;
        let name = path
            .file_name()
            .ok_or_else(|| "directory has no name".to_string())?;
        let dir_fd = super::adapter::open_dir_nofollow(parent, false)?;
        let c_name = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| "directory name contains NUL".to_string())?;
        // SAFETY: mkdirat on the held parent fd; name is one component.
        if unsafe { libc::mkdirat(dir_fd.as_raw_fd(), c_name.as_ptr(), mode as libc::mode_t) } != 0
        {
            return Err(format!(
                "create directory '{}': {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: openat on the held parent fd; O_NOFOLLOW refuses a swapped
        // symlink at the newly created name.
        let child_fd = unsafe {
            libc::openat(
                dir_fd.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if child_fd < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: remove only the directory we just created.
            unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c_name.as_ptr(), libc::AT_REMOVEDIR) };
            return Err(format!("open new directory '{}': {error}", path.display()));
        }
        // SAFETY: child_fd is owned locally until wrapped or closed.
        let child = unsafe { std::fs::File::from_raw_fd(child_fd) };
        let result = (|| -> Result<(), String> {
            // SAFETY: child is the held directory descriptor.
            if unsafe { libc::fchown(child.as_raw_fd(), uid, gid) } != 0 {
                return Err(format!(
                    "fchown directory '{}': {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: child is the held directory descriptor.
            if unsafe { libc::fchmod(child.as_raw_fd(), mode as libc::mode_t) } != 0 {
                return Err(format!(
                    "fchmod directory '{}': {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: child is the held directory descriptor.
            if unsafe { libc::fsync(child.as_raw_fd()) } != 0 {
                return Err(format!(
                    "fsync directory '{}': {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: fsync the held parent directory after the new entry.
            if unsafe { libc::fsync(dir_fd.as_raw_fd()) } != 0 {
                return Err(format!(
                    "fsync directory parent '{}': {}",
                    parent.display(),
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        })();
        drop(child);
        if result.is_err() {
            // SAFETY: remove only the directory we just created.
            unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c_name.as_ptr(), libc::AT_REMOVEDIR) };
        }
        result
    }

    fn remove_directory(&self, path: &Path) -> Result<(), String> {
        match std::fs::remove_dir(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("remove directory '{}': {error}", path.display())),
        }
    }

    fn write_new_file(
        &self,
        path: &Path,
        contents: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(), String> {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        let parent = path
            .parent()
            .ok_or_else(|| "file has no parent".to_string())?;
        let name = path
            .file_name()
            .ok_or_else(|| "file has no name".to_string())?;
        let dir_fd = super::adapter::open_dir_nofollow(parent, false)?;
        let c_name = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| "file name contains NUL".to_string())?;
        // SAFETY: exclusive create no-follow in the held parent fd.
        let fd = unsafe {
            libc::openat(
                dir_fd.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            return Err(format!(
                "create file '{}': {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: fd is newly created and owned by this function.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let result = (|| -> Result<(), String> {
            file.write_all(contents)
                .map_err(|error| format!("write '{}': {error}", path.display()))?;
            file.sync_all()
                .map_err(|error| format!("fsync '{}': {error}", path.display()))?;
            // SAFETY: file is the held descriptor for the newly created inode.
            if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
                return Err(format!(
                    "fchown '{}': {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: file is the held descriptor for the newly created inode.
            if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
                return Err(format!(
                    "fchmod '{}': {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            file.sync_all()
                .map_err(|error| format!("fsync metadata '{}': {error}", path.display()))?;
            // SAFETY: fsync the held parent directory after the new entry.
            if unsafe { libc::fsync(dir_fd.as_raw_fd()) } != 0 {
                return Err(format!(
                    "fsync parent '{}': {}",
                    parent.display(),
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        })();
        drop(file);
        if result.is_err() {
            // SAFETY: unlink only the exact file we created via its held parent.
            unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c_name.as_ptr(), 0) };
        }
        result
    }

    fn write_state_file(&self, path: &Path, contents: &[u8]) -> Result<(), String> {
        super::adapter::write_file_atomic(path, contents)
    }

    fn remove_file(&self, path: &Path) -> Result<(), String> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("remove file '{}': {error}", path.display())),
        }
    }

    fn read_bounded_file(&self, path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| format!("open '{}': {error}", path.display()))?;
        use std::os::unix::fs::MetadataExt;
        let metadata = file
            .metadata()
            .map_err(|error| format!("inspect '{}': {error}", path.display()))?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
        {
            return Err(format!(
                "'{}' is not a root-owned single-link non-writable file",
                path.display()
            ));
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take((max_bytes as u64) + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read '{}': {error}", path.display()))?;
        if bytes.len() > max_bytes {
            return Err(format!("'{}' exceeds the byte bound", path.display()));
        }
        Ok(bytes)
    }

    fn extended_acl_is_safe(&self, path: &Path) -> Result<bool, String> {
        use std::os::unix::ffi::OsStrExt;

        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "ACL path contains a NUL byte".to_string())?;
        // SAFETY: `c_path` is a valid NUL-terminated path; the returned fd is
        // closed below on every path.
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK
                    | libc::O_NOCTTY,
            )
        };
        if fd < 0 {
            return Err(format!(
                "open '{}' for the extended ACL query: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let status = crate::private_file::query_extended_acl(fd);
        // SAFETY: `fd` was opened above and is not used after this close.
        unsafe { libc::close(fd) };
        match status {
            Ok(crate::private_file::AclStatus::Absent)
            | Ok(crate::private_file::AclStatus::DenyOnly) => Ok(true),
            Ok(crate::private_file::AclStatus::AllowPresent) => Ok(false),
            Err(error) => Err(error.to_string()),
        }
    }

    fn authorize_package_key(&self, verify_key_hex: &str) -> Result<(), String> {
        let key = hex::decode(verify_key_hex)
            .map_err(|error| format!("invalid release verifying key: {error}"))?;
        if key.len() != 32 {
            return Err("release verifying key must be 32 bytes".to_string());
        }
        if TRUSTED_RELEASE_KEYS
            .iter()
            .any(|trusted| trusted.as_slice() == key.as_slice())
        {
            return Ok(());
        }
        Err(
            "no independently trusted release root is configured; macOS install capability is gated off"
                .to_string(),
        )
    }

    fn validate_tls_sources(&self, port: u16) -> Result<TlsSourceEvidence, String> {
        let bind = format!("127.0.0.1:{port}");
        let transport = crate::tls::validate_serve_tls_inputs_with_network_and_name(
            &bind,
            Path::new(TLS_SOURCE_CERTIFICATE_PATH),
            Path::new(TLS_SOURCE_PRIVATE_KEY_PATH),
            false,
            Some(crate::macos_service::LOOPBACK_TLS_SERVER_NAME),
        )
        .map_err(|error| error.to_string())?;
        let key = crate::private_file::read_existing_private_file(
            Path::new(TLS_SOURCE_PRIVATE_KEY_PATH),
            64 * 1024,
        )
        .map_err(|error| error.to_string())?;
        Ok(TlsSourceEvidence {
            certificate_sha256: transport.certificate_sha256().to_string(),
            private_key_sha256: super::manifest::sha256_hex(&key[..]),
        })
    }

    fn copy_tls_file(
        &self,
        source: &Path,
        destination: &Path,
        uid: u32,
        gid: u32,
        expected_sha256: &str,
    ) -> Result<(), String> {
        let bytes = crate::private_file::read_existing_private_file(source, 64 * 1024)
            .map_err(|error| error.to_string())?;
        if super::manifest::sha256_hex(&bytes[..]) != expected_sha256 {
            return Err(format!(
                "TLS source '{}' changed after review",
                source.display()
            ));
        }
        self.write_new_file(destination, &bytes[..], 0o600, uid, gid)
    }

    fn launchd_bootstrap(&self, plist: &Path, label: &str) -> Result<(), String> {
        if label != super::macos_launchd::LAUNCHD_LABEL {
            return Err("refusing non-product launchd label".to_string());
        }
        require_success(&[
            "/bin/launchctl".to_string(),
            "bootstrap".to_string(),
            "system".to_string(),
            plist.to_string_lossy().into_owned(),
        ])
    }

    fn launchd_bootout(&self, label: &str) -> Result<(), String> {
        if label != super::macos_launchd::LAUNCHD_LABEL {
            return Err("refusing non-product launchd label".to_string());
        }
        let argv = [
            "/bin/launchctl".to_string(),
            "bootout".to_string(),
            format!("system/{label}"),
        ];
        match run_fixed(&argv)? {
            (0, _, _) => Ok(()),
            (_, _, stderr)
                if stderr.contains("Could not find service")
                    || stderr.contains("No such process")
                    || stderr.contains("not found") =>
            {
                Ok(())
            }
            (code, _, stderr) => Err(format!(
                "launchctl bootout failed with exit {code}: {}",
                bounded_text(&stderr)
            )),
        }
    }

    fn launchd_is_loaded(&self, label: &str) -> Result<bool, String> {
        if label != super::macos_launchd::LAUNCHD_LABEL {
            return Err("refusing non-product launchd label".to_string());
        }
        let argv = [
            "/bin/launchctl".to_string(),
            "print".to_string(),
            format!("system/{label}"),
        ];
        match run_fixed(&argv)? {
            (0, _, _) => Ok(true),
            (_, _, _) => Ok(false),
        }
    }

    fn service_health(
        &self,
        port: u16,
        expected_certificate_sha256: &str,
        service_uid: u32,
    ) -> Result<bool, String> {
        use std::io::{Read, Write};
        use std::net::{SocketAddr, TcpStream};
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        use std::time::Duration;

        let mut certificate_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(Path::new(super::macos_launchd::TLS_CERTIFICATE_PATH))
            .map_err(|error| format!("open installed TLS certificate: {error}"))?;
        let metadata = certificate_file
            .metadata()
            .map_err(|error| format!("inspect installed TLS certificate: {error}"))?;
        if !metadata.is_file()
            || metadata.uid() != service_uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.len() > 64 * 1024
        {
            return Err("installed TLS certificate has an unsafe shape".to_string());
        }
        if !self.extended_acl_is_safe(Path::new(super::macos_launchd::TLS_CERTIFICATE_PATH))? {
            return Err(
                "installed TLS certificate carries an extended ACL with an ALLOW entry".to_string(),
            );
        }
        let mut certificate_bytes = Vec::new();
        std::io::Read::by_ref(&mut certificate_file)
            .take(64 * 1024)
            .read_to_end(&mut certificate_bytes)
            .map_err(|error| format!("read installed TLS certificate: {error}"))?;
        if super::manifest::sha256_hex(&certificate_bytes) != expected_certificate_sha256 {
            return Err("installed TLS certificate does not match the reviewed digest".to_string());
        }
        let mut certificate_slice: &[u8] = &certificate_bytes[..];
        let certificates: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut certificate_slice)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("parse installed TLS certificate: {error}"))?;
        let leaf = certificates
            .into_iter()
            .next()
            .ok_or_else(|| "installed TLS certificate chain is empty".to_string())?;

        let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut client_config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|error| format!("configure macOS health TLS: {error}"))?
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(PinnedServerCertificate {
                leaf,
                provider,
            }))
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string())
            .map_err(|error| format!("macOS health server name: {error}"))?;
        let connection =
            rustls::ClientConnection::new(std::sync::Arc::new(client_config), server_name)
                .map_err(|error| format!("create macOS health TLS client: {error}"))?;
        let addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .map_err(|error| format!("macOS health address: {error}"))?;
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1))
            .map_err(|error| format!("connect macOS health endpoint: {error}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(|error| format!("set macOS health read timeout: {error}"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .map_err(|error| format!("set macOS health write timeout: {error}"))?;
        let mut tls = rustls::StreamOwned::new(connection, stream);
        tls.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .map_err(|error| format!("write macOS health request: {error}"))?;
        let mut response = Vec::new();
        std::io::Read::by_ref(&mut tls)
            .take(8192)
            .read_to_end(&mut response)
            .map_err(|error| format!("read macOS health response: {error}"))?;
        let text = String::from_utf8_lossy(&response);
        if !text.starts_with("HTTP/1.1 2") {
            return Ok(false);
        }
        let body = text
            .find("\r\n\r\n")
            .map(|index| &text[index + 4..])
            .ok_or_else(|| "macOS health response has no body".to_string())?;
        let health: serde_json::Value = serde_json::from_str(body)
            .map_err(|error| format!("parse macOS health JSON: {error}"))?;
        Ok(health
            .get("status")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|status| matches!(status, "ok" | "degraded"))
            && health
                .get("storage_schema_version")
                .and_then(serde_json::Value::as_i64)
                .is_some())
    }

    fn acquire_lock(&self, path: &Path) -> Result<MacosApplyLock, String> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| format!("open lock '{}': {error}", path.display()))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("inspect lock '{}': {error}", path.display()))?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(format!(
                "lock '{}' is not a private root-owned regular file",
                path.display()
            ));
        }
        if !self.extended_acl_is_safe(path)? {
            return Err(format!(
                "lock '{}' carries an extended ACL with an ALLOW entry",
                path.display()
            ));
        }
        // SAFETY: flock only borrows the valid descriptor while acquiring the
        // lock; the returned guard retains the File for the operation.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK)
                || error.raw_os_error() == Some(libc::EAGAIN)
            {
                return Err("another macOS installer operation holds the lock".to_string());
            }
            return Err(format!("acquire lock '{}': {error}", path.display()));
        }
        Ok(MacosApplyLock::new(move || {
            // SAFETY: the guard owns `file`; unlock only this descriptor.
            let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            drop(file);
        }))
    }
}

#[cfg(target_os = "macos")]
static NSS_ENUM_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(target_os = "macos")]
const MAX_NSS_RECORDS: usize = 100_000;

#[cfg(target_os = "macos")]
fn lookup_user_record_by_uid(uid: u32) -> Result<Option<(String, u32, u32)>, String> {
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 64 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: record and buffer are valid for the call; result points to a
    // local pointer the implementation may set.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(format!("getpwuid_r failed with error {rc}"));
    }
    if result.is_null() {
        return Ok(None);
    }
    let name = c_name(record.pw_name)?
        .ok_or_else(|| "name-service user record has no name".to_string())?;
    Ok(Some((name, record.pw_uid as u32, record.pw_gid as u32)))
}

#[cfg(target_os = "macos")]
fn lookup_user_record_by_name(name: &str) -> Result<Option<(String, u32, u32)>, String> {
    let c_record_name =
        std::ffi::CString::new(name).map_err(|_| "lookup name contains NUL".to_string())?;
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 64 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: record and buffer are valid for the call; result points to a
    // local pointer the implementation may set.
    let rc = unsafe {
        libc::getpwnam_r(
            c_record_name.as_ptr(),
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(format!("getpwnam_r failed with error {rc}"));
    }
    if result.is_null() {
        return Ok(None);
    }
    let name = c_name(record.pw_name)?
        .ok_or_else(|| "name-service user record has no name".to_string())?;
    Ok(Some((name, record.pw_uid as u32, record.pw_gid as u32)))
}

#[cfg(target_os = "macos")]
fn lookup_group_record_by_gid(gid: u32) -> Result<Option<(String, u32)>, String> {
    let mut record: libc::group = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 64 * 1024];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: record and buffer are valid for the call; result points to a
    // local pointer the implementation may set.
    let rc = unsafe {
        libc::getgrgid_r(
            gid,
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(format!("getgrgid_r failed with error {rc}"));
    }
    if result.is_null() {
        return Ok(None);
    }
    let name = c_name(record.gr_name)?
        .ok_or_else(|| "name-service group record has no name".to_string())?;
    Ok(Some((name, record.gr_gid as u32)))
}

#[cfg(target_os = "macos")]
fn lookup_group_record_by_name(name: &str) -> Result<Option<(String, u32)>, String> {
    let c_record_name =
        std::ffi::CString::new(name).map_err(|_| "lookup name contains NUL".to_string())?;
    let mut record: libc::group = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 64 * 1024];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: record and buffer are valid for the call; result points to a
    // local pointer the implementation may set.
    let rc = unsafe {
        libc::getgrnam_r(
            c_record_name.as_ptr(),
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(format!("getgrnam_r failed with error {rc}"));
    }
    if result.is_null() {
        return Ok(None);
    }
    let name = c_name(record.gr_name)?
        .ok_or_else(|| "name-service group record has no name".to_string())?;
    Ok(Some((name, record.gr_gid as u32)))
}

#[cfg(target_os = "macos")]
fn lookup_user_name_by_uid(uid: u32) -> Result<Option<String>, String> {
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 64 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: record and buffer are valid for the call; result points to a
    // local pointer the implementation may set.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(format!("getpwuid_r failed with error {rc}"));
    }
    if result.is_null() {
        return Ok(None);
    }
    c_name(record.pw_name)
}

#[cfg(target_os = "macos")]
fn lookup_user_name_by_name(name: &str) -> Result<Option<String>, String> {
    let c_record_name =
        std::ffi::CString::new(name).map_err(|_| "lookup name contains NUL".to_string())?;
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 64 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: record and buffer are valid for the call; result points to a
    // local pointer the implementation may set.
    let rc = unsafe {
        libc::getpwnam_r(
            c_record_name.as_ptr(),
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(format!("getpwnam_r failed with error {rc}"));
    }
    if result.is_null() {
        return Ok(None);
    }
    c_name(record.pw_name)
}

#[cfg(target_os = "macos")]
fn lookup_group_name_by_name(name: &str) -> Result<Option<String>, String> {
    let c_record_name =
        std::ffi::CString::new(name).map_err(|_| "lookup name contains NUL".to_string())?;
    let mut record: libc::group = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 64 * 1024];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: record and buffer are valid for the call; result points to a
    // local pointer the implementation may set.
    let rc = unsafe {
        libc::getgrnam_r(
            c_record_name.as_ptr(),
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(format!("getgrnam_r failed with error {rc}"));
    }
    if result.is_null() {
        return Ok(None);
    }
    c_name(record.gr_name)
}

#[cfg(target_os = "macos")]
fn lookup_group_name_by_gid(gid: u32) -> Result<Option<String>, String> {
    let mut record: libc::group = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 64 * 1024];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: record and buffer are valid for the call; result points to a
    // local pointer the implementation may set.
    let rc = unsafe {
        libc::getgrgid_r(
            gid,
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(format!("getgrgid_r failed with error {rc}"));
    }
    if result.is_null() {
        return Ok(None);
    }
    c_name(record.gr_name)
}

#[cfg(target_os = "macos")]
fn c_name(name: *const libc::c_char) -> Result<Option<String>, String> {
    if name.is_null() {
        return Err("name-service record has no name".to_string());
    }
    // SAFETY: a non-null name from a successful lookup is NUL-terminated.
    let name = unsafe { std::ffi::CStr::from_ptr(name) };
    let name = name
        .to_str()
        .map_err(|_| "name-service record name is not UTF-8".to_string())?;
    if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
        return Err("name-service record name is malformed".to_string());
    }
    Ok(Some(name.to_string()))
}

#[cfg(target_os = "macos")]
fn nss_identity_absent() -> Result<bool, String> {
    if lookup_user_name_by_name(PRODUCT_SERVICE_ACCOUNT)?.is_some()
        || lookup_group_name_by_name(PRODUCT_SERVICE_GROUP)?.is_some()
    {
        return Ok(false);
    }
    let _guard = NSS_ENUM_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut users = Vec::new();
    unsafe { libc::setpwent() };
    let user_result = loop {
        let record = unsafe { libc::getpwent() };
        if record.is_null() {
            break Ok(());
        }
        if users.len() >= MAX_NSS_RECORDS {
            break Err("name-service user enumeration exceeded its bound".to_string());
        }
        let record = unsafe { &*record };
        match c_name(record.pw_name) {
            Ok(Some(name)) => users.push(name),
            Ok(None) => break Err("name-service user record has no name".to_string()),
            Err(error) => break Err(error),
        }
    };
    unsafe { libc::endpwent() };
    user_result?;
    if users
        .iter()
        .any(|name| name.eq_ignore_ascii_case(PRODUCT_SERVICE_ACCOUNT))
    {
        return Ok(false);
    }

    let mut groups = Vec::new();
    unsafe { libc::setgrent() };
    let group_result = loop {
        let record = unsafe { libc::getgrent() };
        if record.is_null() {
            break Ok(());
        }
        if groups.len() >= MAX_NSS_RECORDS {
            break Err("name-service group enumeration exceeded its bound".to_string());
        }
        let record = unsafe { &*record };
        match c_name(record.gr_name) {
            Ok(Some(name)) => groups.push(name),
            Ok(None) => break Err("name-service group record has no name".to_string()),
            Err(error) => break Err(error),
        }
    };
    unsafe { libc::endgrent() };
    group_result?;
    Ok(!groups
        .iter()
        .any(|name| name.eq_ignore_ascii_case(PRODUCT_SERVICE_GROUP)))
}

#[cfg(target_os = "macos")]
fn nss_id_in_use(id: u32) -> Result<bool, String> {
    if lookup_user_name_by_uid(id)?.is_some() || lookup_group_name_by_gid(id)?.is_some() {
        return Ok(true);
    }
    let _guard = NSS_ENUM_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    unsafe { libc::setpwent() };
    let mut count = 0usize;
    let result = loop {
        let record = unsafe { libc::getpwent() };
        if record.is_null() {
            break Ok(false);
        }
        count += 1;
        if count > MAX_NSS_RECORDS {
            break Err("name-service user enumeration exceeded its bound".to_string());
        }
        let record = unsafe { &*record };
        if record.pw_gid == id as libc::gid_t {
            break Ok(true);
        }
    };
    unsafe { libc::endpwent() };
    result
}

#[cfg(target_os = "macos")]
fn nss_identity_matches(uid: u32, gid: u32) -> Result<bool, String> {
    let direct_uid = lookup_user_record_by_uid(uid)?;
    let direct_name = lookup_user_record_by_name(PRODUCT_SERVICE_ACCOUNT)?;
    let direct_group_gid = lookup_group_record_by_gid(gid)?;
    let direct_group_name = lookup_group_record_by_name(PRODUCT_SERVICE_GROUP)?;
    let direct_ok = matches!(
        direct_uid,
        Some((ref name, found_uid, found_gid))
            if name.eq_ignore_ascii_case(PRODUCT_SERVICE_ACCOUNT)
                && found_uid == uid
                && found_gid == gid
    ) && matches!(
        direct_name,
        Some((ref name, found_uid, found_gid))
            if name.eq_ignore_ascii_case(PRODUCT_SERVICE_ACCOUNT)
                && found_uid == uid
                && found_gid == gid
    ) && matches!(
        direct_group_gid,
        Some((ref name, found_gid))
            if name.eq_ignore_ascii_case(PRODUCT_SERVICE_GROUP) && found_gid == gid
    ) && matches!(
        direct_group_name,
        Some((ref name, found_gid))
            if name.eq_ignore_ascii_case(PRODUCT_SERVICE_GROUP) && found_gid == gid
    );
    if !direct_ok {
        return Ok(false);
    }
    let _guard = NSS_ENUM_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut uid_names = Vec::new();
    let mut primary_names = Vec::new();
    let mut user_count = 0usize;
    unsafe { libc::setpwent() };
    let user_result = loop {
        let record = unsafe { libc::getpwent() };
        if record.is_null() {
            break Ok(());
        }
        user_count += 1;
        if user_count > MAX_NSS_RECORDS {
            break Err("name-service user enumeration exceeded its bound".to_string());
        }
        let record = unsafe { &*record };
        let name = match c_name(record.pw_name) {
            Ok(Some(name)) => name,
            Ok(None) => break Err("name-service user record has no name".to_string()),
            Err(error) => break Err(error),
        };
        if record.pw_uid == uid as libc::uid_t {
            uid_names.push(name.clone());
        }
        if record.pw_gid == gid as libc::gid_t {
            primary_names.push(name);
        }
    };
    unsafe { libc::endpwent() };
    user_result?;

    let mut gid_names = Vec::new();
    let mut group_count = 0usize;
    unsafe { libc::setgrent() };
    let group_result = loop {
        let record = unsafe { libc::getgrent() };
        if record.is_null() {
            break Ok(());
        }
        group_count += 1;
        if group_count > MAX_NSS_RECORDS {
            break Err("name-service group enumeration exceeded its bound".to_string());
        }
        let record = unsafe { &*record };
        if record.gr_gid == gid as libc::gid_t {
            match c_name(record.gr_name) {
                Ok(Some(name)) => gid_names.push(name),
                Ok(None) => break Err("name-service group record has no name".to_string()),
                Err(error) => break Err(error),
            }
        }
    };
    unsafe { libc::endgrent() };
    group_result?;

    Ok(matches!(
        uid_names.as_slice(),
        [name] if name.eq_ignore_ascii_case(PRODUCT_SERVICE_ACCOUNT)
    ) && matches!(
        primary_names.as_slice(),
        [name] if name.eq_ignore_ascii_case(PRODUCT_SERVICE_ACCOUNT)
    ) && matches!(
        gid_names.as_slice(),
        [name] if name.eq_ignore_ascii_case(PRODUCT_SERVICE_GROUP)
    ))
}

#[cfg(target_os = "macos")]
struct PinnedServerCertificate {
    leaf: rustls::pki_types::CertificateDer<'static>,
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
}

#[cfg(target_os = "macos")]
impl std::fmt::Debug for PinnedServerCertificate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedServerCertificate")
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "macos")]
impl rustls::client::danger::ServerCertVerifier for PinnedServerCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.leaf.as_ref() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "macOS health endpoint presented an unpinned certificate".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(target_os = "macos")]
fn delete_dscl_record(node: &str, name: &str) -> Result<(), String> {
    let argv = [
        "/usr/bin/dscl".to_string(),
        ".".to_string(),
        "-delete".to_string(),
        format!("{node}/{name}"),
    ];
    match run_fixed(&argv)? {
        (0, _, _) => Ok(()),
        (_, _, stderr)
            if stderr.contains("eDSRecordNotFound") || stderr.contains("record not found") =>
        {
            Ok(())
        }
        (code, _, stderr) => Err(format!(
            "delete Directory Services record failed with exit {code}: {}",
            bounded_text(&stderr)
        )),
    }
}

#[cfg(target_os = "macos")]
fn require_success(argv: &[String]) -> Result<(), String> {
    match run_fixed(argv)? {
        (0, _, _) => Ok(()),
        (code, _, stderr) => Err(format!(
            "reviewed command '{}' failed with exit {code}: {}",
            argv.first().map(String::as_str).unwrap_or(""),
            bounded_text(&stderr)
        )),
    }
}

#[cfg(target_os = "macos")]
fn run_fixed(argv: &[String]) -> Result<(i32, String, String), String> {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    if argv.is_empty()
        || argv.len() > 8
        || !argv[0].starts_with('/')
        || argv.iter().any(|argument| argument.contains('\0'))
    {
        return Err("reviewed command has an invalid argv".to_string());
    }
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn '{}': {error}", argv[0]))?;
    let stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| "command stdout pipe unavailable".to_string())?;
    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| "command stderr pipe unavailable".to_string())?;
    let stdout_thread = std::thread::spawn(move || read_capped(stdout_pipe));
    let stderr_thread = std::thread::spawn(move || read_capped(stderr_pipe));

    let deadline = Instant::now() + std::time::Duration::from_secs(15);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(format!("command '{}' timed out", argv[0]));
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(format!("wait for '{}': {error}", argv[0]));
            }
        }
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| "command stdout reader panicked".to_string())?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| "command stderr reader panicked".to_string())?;
    Ok((
        status.code().unwrap_or(-1),
        bounded_text(&stdout),
        bounded_text(&stderr),
    ))
}

#[cfg(target_os = "macos")]
fn read_capped(mut pipe: impl std::io::Read) -> String {
    let mut captured = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                if captured.len() < 4096 {
                    let room = 4096 - captured.len();
                    captured.extend_from_slice(&chunk[..read.min(room)]);
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&captured).into_owned()
}

#[cfg(target_os = "macos")]
fn bounded_text(bytes: &str) -> String {
    bytes
        .chars()
        .filter(|character| !character.is_control() || *character == '\n')
        .take(4096)
        .collect()
}

/// Full-resolver absence check used by production plan review.
#[cfg(target_os = "macos")]
pub fn resolver_identity_absent_real() -> AppResult<bool> {
    nss_identity_absent().map_err(AppError::security_state_unavailable)
}

/// Read and validate the fixed operator TLS sources for plan review.
#[cfg(target_os = "macos")]
pub fn plan_tls_evidence(port: u16) -> AppResult<v2::TlsEvidence> {
    let adapter = MacosSystemApplyAdapter::new();
    let evidence = adapter.validate_tls_sources(port).map_err(|error| {
        AppError::forbidden(format!(
            "operator TLS material is unavailable or invalid at the fixed source paths: {error}"
        ))
    })?;
    Ok(v2::TlsEvidence {
        certificate_sha256: evidence.certificate_sha256,
        private_key_sha256: evidence.private_key_sha256,
    })
}

/// Verify the receipt through the real macOS host adapter.
#[cfg(target_os = "macos")]
pub fn verify_runtime_receipt() -> AppResult<bool> {
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    verify_runtime_receipt_with_adapter_for_euid(&MacosSystemApplyAdapter::new(), Some(euid))
}
