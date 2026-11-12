//! Development-only macOS loopback TLS provisioning.
//!
//! This command exists only with `macos-dev-install` on macOS. It creates the
//! fixed `/etc/helicoid/tls` source material used by the guarded macOS apply
//! lifecycle: a self-signed ECDSA certificate covering literal `127.0.0.1`
//! and its owner-private private key.
//!
//! All effects are serialized by the existing persistent installer `flock`.
//! Fixed directories are created/validated with the existing private-store
//! directory policy (root-owned, `0700`-class, no ACL ALLOW entry). Certificate
//! and key are written into a unique private stage directory, fsynced, then
//! installed with `renamex_np(RENAME_EXCL)`: an existing destination is never
//! replaced. A publish marker records the intended digests; its directory
//! rename is fsynced before the first published file rename, so a process
//! crash leaves recovery evidence. These fsyncs (`sync_all`, not macOS
//! `F_FULLFSYNC`) do not guarantee power-loss durability: after a power loss
//! or kernel crash the marker and files may be absent or inconsistent, and a
//! mismatched/malformed marker is refused for operator inspection rather than
//! guessed at. Before the marker is read or used to delete anything, the
//! whole marker parent chain must already exist as root-owned, private,
//! ACL-safe directories; recovery never creates or adopts a parent path. Stale stage directories are removed only when their
//! name is the exact stage prefix plus a UUID, inside a directory that already
//! validates as root-owned/private/ACL-safe, and only after proving root
//! ownership, private mode, safe ACL, and an allowlisted regular-file content
//! set. Operator material without our marker is returned as
//! `existing_unverified` and its directory layout is never adopted; stale
//! stages there are cleaned only if that directory already passes the same
//! read-only validation. No Python, shell, caller path, or environment command
//! is used.

use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

use super::macos_apply::{
    MacosApplyAdapter, MacosApplyPathMetadata, MacosSystemApplyAdapter, StateDirFacts,
    INSTALL_LOCK_PATH,
};
use super::macos_launchd::{
    TLS_SOURCE_CERTIFICATE_PATH, TLS_SOURCE_DIRECTORY, TLS_SOURCE_PRIVATE_KEY_PATH,
};

const STAGE_PREFIX: &str = ".helicoid-tls-stage.";
const MARKER_NAME: &str = ".helicoid-tls-publish.json";
const MARKER_TEMP_NAME: &str = "publish-marker.tmp";
const MAX_TLS_PEM_BYTES: usize = 64 * 1024;
const MAX_MARKER_BYTES: usize = 4096;
const MAX_STALE_STAGES: usize = 64;
const RENAME_EXCL: libc::c_uint = 0x0000_0004;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PublishMarker {
    certificate_sha256: String,
    private_key_sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum MacosTlsProvisionOutcome {
    Provisioned {
        certificate_path: String,
        private_key_path: String,
        certificate_sha256: String,
        private_key_sha256: String,
        authority_host: &'static str,
    },
    Recovered {
        certificate_path: String,
        private_key_path: String,
        certificate_sha256: String,
        private_key_sha256: String,
        authority_host: &'static str,
    },
    ExistingUnverified {
        certificate_path: String,
        private_key_path: String,
        certificate_present: bool,
        private_key_present: bool,
        authority_host: &'static str,
        detail: &'static str,
    },
}

impl MacosTlsProvisionOutcome {
    fn provisioned(marker: &PublishMarker) -> Self {
        Self::Provisioned {
            certificate_path: TLS_SOURCE_CERTIFICATE_PATH.to_string(),
            private_key_path: TLS_SOURCE_PRIVATE_KEY_PATH.to_string(),
            certificate_sha256: marker.certificate_sha256.clone(),
            private_key_sha256: marker.private_key_sha256.clone(),
            authority_host: "127.0.0.1",
        }
    }

    fn recovered(marker: &PublishMarker) -> Self {
        Self::Recovered {
            certificate_path: TLS_SOURCE_CERTIFICATE_PATH.to_string(),
            private_key_path: TLS_SOURCE_PRIVATE_KEY_PATH.to_string(),
            certificate_sha256: marker.certificate_sha256.clone(),
            private_key_sha256: marker.private_key_sha256.clone(),
            authority_host: "127.0.0.1",
        }
    }
}

/// Provision the fixed loopback TLS source material. The caller must already
/// be root; the fixed directory and file paths are never caller-selected.
pub fn provision() -> AppResult<MacosTlsProvisionOutcome> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(AppError::forbidden(
            "macOS TLS provisioning requires root; no TLS source was changed",
        ));
    }

    let adapter = MacosSystemApplyAdapter::new();
    let _lock = adapter
        .acquire_lock(Path::new(INSTALL_LOCK_PATH))
        .map_err(|error| {
            AppError::conflict(
                format!("cannot acquire macOS installer operation lock: {error}"),
                None,
            )
        })?;

    let certificate_path = Path::new(TLS_SOURCE_CERTIFICATE_PATH);
    let private_key_path = Path::new(TLS_SOURCE_PRIVATE_KEY_PATH);

    // A process crash between the two independent no-replace renames must not
    // wedge retry. The marker records both intended digests; recovery either
    // completes an already-published pair or removes only marker-matching
    // files installed by the abandoned attempt. A marker present but
    // mismatched with the files is refused for operator inspection rather
    // than guessed at. A marker always takes precedence over the
    // existing-unverified outcome.
    if let Some(outcome) = recover_publish_marker(
        &adapter,
        Path::new(TLS_SOURCE_DIRECTORY),
        certificate_path,
        private_key_path,
    )? {
        cleanup_stale_stages(&adapter, Path::new(TLS_SOURCE_DIRECTORY))?;
        return Ok(outcome);
    }

    // Existing operator material without our marker is never read, changed, or
    // adopted. This check deliberately runs before private-store adoption so a
    // root-owned, non-writable 0755 /etc/helicoid operator layout can reach the
    // plan's real TLS validation without this helper mutating it.
    if let Some(outcome) =
        existing_unverified_outcome(&adapter, certificate_path, private_key_path)?
    {
        // Stale stage directories are ours, but they are only removed when the
        // TLS source directory already validates as the root-owned, private,
        // ACL-safe directory this module creates. That validation is
        // read-only: it never creates, chmods, or adopts the path. Unvalidated
        // operator layouts are left exactly as found, and cleanup is
        // best-effort so it cannot turn the operator outcome into a hard
        // error.
        if validate_existing_marker_parents(&adapter, Path::new(TLS_SOURCE_DIRECTORY)).is_ok() {
            let _ = cleanup_stale_stages(&adapter, Path::new(TLS_SOURCE_DIRECTORY));
        }
        return Ok(outcome);
    }

    crate::private_file::ensure_private_store_dir(Path::new("/etc/helicoid"))?;
    let tls_dir = crate::private_file::ensure_private_store_dir(Path::new(TLS_SOURCE_DIRECTORY))?;
    cleanup_stale_stages(&adapter, &tls_dir)?;
    ensure_absent(&adapter, certificate_path, "TLS certificate")?;
    ensure_absent(&adapter, private_key_path, "TLS private key")?;

    let (certificate_pem, private_key_pem) = generate_loopback_material()?;
    let stage_dir = create_stage_dir(&adapter, &tls_dir)?;
    let stage_certificate = stage_dir.join("fullchain.pem");
    let stage_private_key = stage_dir.join("private-key.pem");
    let stage_marker = stage_dir.join(MARKER_TEMP_NAME);
    let marker = PublishMarker {
        certificate_sha256: super::manifest::sha256_hex(&certificate_pem),
        private_key_sha256: super::manifest::sha256_hex(&private_key_pem[..]),
    };
    let marker_bytes = serde_json::to_vec(&marker)
        .map_err(|error| AppError::internal(format!("serialize TLS publish marker: {error}")))?;
    let marker_path = tls_dir.join(MARKER_NAME);

    let mut marker_created = false;
    let mut installed_certificate = false;
    let mut installed_private_key = false;
    let result = (|| -> AppResult<MacosTlsProvisionOutcome> {
        crate::private_file::create_new_private_file(&stage_certificate, &certificate_pem)?;
        crate::private_file::create_new_private_file(&stage_private_key, &private_key_pem[..])?;
        crate::private_file::create_new_private_file(&stage_marker, &marker_bytes)?;
        rename_no_replace(&stage_marker, &marker_path)
            .map_err(|error| AppError::internal(format!("install TLS publish marker: {error}")))?;
        marker_created = true;
        // Record the marker *before* the first published rename. A process
        // crash after this fsync leaves recovery evidence for the first key
        // rename; without it the marker rename could be lost. This is fsync
        // (`sync_all`), not macOS F_FULLFSYNC, so power loss is not covered.
        sync_directory(&tls_dir)?;

        // Install the key first, then the certificate. Each rename is atomic
        // and no-replace. The marker makes a process crash between them
        // recoverable on the next invocation; a mismatched marker is refused.
        rename_no_replace(&stage_private_key, private_key_path)
            .map_err(|error| AppError::internal(format!("install TLS private key: {error}")))?;
        installed_private_key = true;
        rename_no_replace(&stage_certificate, certificate_path)
            .map_err(|error| AppError::internal(format!("install TLS certificate: {error}")))?;
        installed_certificate = true;

        sync_directory(&tls_dir)?;

        let certificate_bytes =
            crate::private_file::read_existing_private_file(certificate_path, MAX_TLS_PEM_BYTES)?;
        let key_bytes =
            crate::private_file::read_existing_private_file(private_key_path, MAX_TLS_PEM_BYTES)?;
        if certificate_bytes.is_empty() || key_bytes.is_empty() {
            return Err(AppError::security_state_unavailable(
                "provisioned TLS material is empty",
            ));
        }
        if super::manifest::sha256_hex(&certificate_bytes[..]) != marker.certificate_sha256
            || super::manifest::sha256_hex(&key_bytes[..]) != marker.private_key_sha256
        {
            return Err(AppError::security_state_unavailable(
                "provisioned TLS material changed before publication completed",
            ));
        }
        // Keep the marker after success. It is the idempotent completion
        // evidence that makes a retry after a process crash safe; it contains
        // only public SHA-256 digests.
        sync_directory(&tls_dir)?;
        Ok(MacosTlsProvisionOutcome::provisioned(&marker))
    })();

    if result.is_err() {
        // Roll back only objects this call can prove it created: root-owned,
        // single-link, owner-private, ACL-safe, and still byte-identical to
        // the digests in our marker. Anything else (foreign owner, changed
        // shape, unsafe ACL, digest mismatch) is left untouched as recovery
        // evidence. The marker itself is removed only when both published
        // names are now absent, so a partially rolled back attempt keeps its
        // evidence for the next run's validated recovery.
        let facts = AdapterMarkerFacts(&adapter);
        let cleanup = plan_failed_publish_cleanup(
            &facts,
            &marker_path,
            certificate_path,
            private_key_path,
            &marker,
            &marker_bytes,
            marker_created,
            installed_certificate,
            installed_private_key,
        );
        if cleanup.remove_certificate {
            let _ = std::fs::remove_file(certificate_path);
        }
        if cleanup.remove_private_key {
            let _ = std::fs::remove_file(private_key_path);
        }
        if marker_removal_is_safe_now(&facts, &cleanup, certificate_path, private_key_path) {
            let _ = std::fs::remove_file(&marker_path);
        }
        let _ = std::fs::remove_dir_all(&stage_dir);
        let _ = sync_directory(&tls_dir);
    } else {
        // Successful installs should not leave stage names behind. A failure
        // here is safe: the next run's bounded stale-stage cleanup handles it.
        let _ = std::fs::remove_dir_all(&stage_dir);
    }
    result
}

/// Read-only facts and readers needed to decide and verify marker recovery.
///
/// The real adapter backs this in production; unit tests supply a fake so the
/// fail-closed ordering (validate every parent before any read) stays testable
/// without root or host mutation.
trait MarkerRecoveryFacts: StateDirFacts {
    fn read_bounded_marker(&self, path: &Path, max_bytes: usize) -> Result<Vec<u8>, String>;
    fn read_published_material(
        &self,
        path: &Path,
        max_bytes: usize,
    ) -> AppResult<Zeroizing<Vec<u8>>>;
}

struct AdapterMarkerFacts<'a>(&'a dyn MacosApplyAdapter);

impl StateDirFacts for AdapterMarkerFacts<'_> {
    fn path_metadata(&self, path: &Path) -> Result<Option<MacosApplyPathMetadata>, String> {
        self.0.path_metadata(path)
    }

    fn extended_acl_is_safe(&self, path: &Path) -> Result<bool, String> {
        self.0.extended_acl_is_safe(path)
    }
}

impl MarkerRecoveryFacts for AdapterMarkerFacts<'_> {
    fn read_bounded_marker(&self, path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
        self.0.read_bounded_file(path, max_bytes)
    }

    fn read_published_material(
        &self,
        path: &Path,
        max_bytes: usize,
    ) -> AppResult<Zeroizing<Vec<u8>>> {
        crate::private_file::read_existing_private_file(path, max_bytes)
    }
}

/// Recovery decision derived from read-only facts.
///
/// Applying a plan is the only place that deletes anything, and it only runs
/// after [`plan_marker_recovery`] has proven the whole parent chain.
#[derive(Debug, PartialEq, Eq)]
enum MarkerRecoveryPlan {
    Absent,
    Republish,
    Complete(PublishMarker),
    RemoveCertificate,
    RemovePrivateKey,
}

/// Read-only validation of an existing marker parent chain.
///
/// Mirrors the shared private-store no-follow walker: every component must
/// already exist, be a directory, be root-owned, and not be group/world
/// writable; the final TLS directory must additionally be owner-private
/// (`0700`-class). An *intermediate* root-owned system symlink (macOS
/// `/etc -> private/etc`) is tolerated exactly like that walker, while a
/// foreign-owned link or any final-component symlink is refused. Nothing is
/// created, chmod'd, or adopted.
///
/// `validate_existing_state_dir` cannot be reused directly: it rejects every
/// symlink component, including the root-owned `/etc` link that is the fixed
/// macOS layout for these paths.
fn validate_existing_marker_parents<F: StateDirFacts + ?Sized>(
    facts: &F,
    tls_dir: &Path,
) -> AppResult<()> {
    let mut current = PathBuf::new();
    for component in tls_dir.components() {
        current.push(component);
        let Some(metadata) = facts.path_metadata(&current).map_err(unavailable)? else {
            return Err(AppError::security_state_unavailable(format!(
                "TLS source path '{}' is absent; refusing recovery without an existing verified parent",
                current.display()
            )));
        };
        if metadata.is_symlink {
            let is_final = current.as_path() == tls_dir;
            if metadata.uid != 0 || is_final {
                return Err(AppError::security_state_unavailable(format!(
                    "TLS source path '{}' is a symlink that is not a trusted system ancestor",
                    current.display()
                )));
            }
            // Root-owned system link (e.g. /etc). The remaining components are
            // resolved through it by the kernel and validated below.
            continue;
        }
        if !metadata.is_directory {
            return Err(AppError::security_state_unavailable(format!(
                "TLS source path '{}' is not a directory",
                current.display()
            )));
        }
        if metadata.uid != 0 || metadata.mode & 0o022 != 0 {
            return Err(AppError::security_state_unavailable(format!(
                "TLS source path '{}' is not root-owned or is group/world-writable",
                current.display()
            )));
        }
        if current.as_path() == tls_dir && metadata.mode & 0o077 != 0 {
            return Err(AppError::security_state_unavailable(format!(
                "TLS source directory '{}' is not owner-private",
                current.display()
            )));
        }
        if !facts.extended_acl_is_safe(&current).map_err(unavailable)? {
            return Err(AppError::security_state_unavailable(format!(
                "TLS source path '{}' carries an extended ACL with an ALLOW entry",
                current.display()
            )));
        }
    }
    Ok(())
}

fn plan_marker_recovery<F: MarkerRecoveryFacts + ?Sized>(
    facts: &F,
    tls_dir: &Path,
    certificate_path: &Path,
    private_key_path: &Path,
) -> AppResult<MarkerRecoveryPlan> {
    let marker_path = tls_dir.join(MARKER_NAME);

    // Presence probe only (lstat semantics, final component not followed).
    // Nothing is read or deleted before the parent chain is validated below.
    if facts
        .path_metadata(&marker_path)
        .map_err(unavailable)?
        .is_none()
    {
        return Ok(MarkerRecoveryPlan::Absent);
    }

    // Fail closed BEFORE the marker or the published files are read and before
    // any recovery deletion: every parent must already exist as root-owned,
    // owner-private, ACL-safe. This walker never creates or adopts a directory
    // and rejects symlinked (except trusted root-owned system), foreign-owned,
    // group/world-writable, non-private, or ACL-unsafe components.
    validate_existing_marker_parents(facts, tls_dir)?;

    // Re-probe after validation so the shape decision is bound to the
    // validated tree, never to a pre-validation observation.
    let Some(marker_metadata) = facts.path_metadata(&marker_path).map_err(unavailable)? else {
        return Ok(MarkerRecoveryPlan::Absent);
    };
    if marker_metadata.is_symlink
        || !marker_metadata.is_regular_file
        || marker_metadata.uid != 0
        || marker_metadata.nlink != 1
        || marker_metadata.mode & 0o077 != 0
        || marker_metadata.len > MAX_MARKER_BYTES as u64
        || !facts
            .extended_acl_is_safe(&marker_path)
            .map_err(unavailable)?
    {
        return Err(AppError::security_state_unavailable(
            "TLS publish marker has an unsafe shape",
        ));
    }

    let marker_bytes = facts
        .read_bounded_marker(&marker_path, MAX_MARKER_BYTES)
        .map_err(unavailable)?;
    let certificate = read_optional_final(facts, certificate_path)?;
    let private_key = read_optional_final(facts, private_key_path)?;
    let marker: Option<PublishMarker> = serde_json::from_slice(&marker_bytes).ok();
    let valid_marker = marker.filter(|marker| {
        is_sha256(&marker.certificate_sha256) && is_sha256(&marker.private_key_sha256)
    });

    match recovery_action(
        valid_marker.as_ref(),
        certificate.as_ref().map(|bytes| bytes.as_slice()),
        private_key.as_ref().map(|bytes| bytes.as_slice()),
    ) {
        RecoveryAction::Republish => Ok(MarkerRecoveryPlan::Republish),
        RecoveryAction::Complete => Ok(MarkerRecoveryPlan::Complete(
            valid_marker.expect("complete recovery requires a marker"),
        )),
        RecoveryAction::RemoveCertificate => Ok(MarkerRecoveryPlan::RemoveCertificate),
        RecoveryAction::RemovePrivateKey => Ok(MarkerRecoveryPlan::RemovePrivateKey),
        RecoveryAction::Refuse => Err(AppError::security_state_unavailable(
            "TLS publish marker does not match the partially published files; refusing recovery",
        )),
    }
}

fn recover_publish_marker(
    adapter: &dyn MacosApplyAdapter,
    tls_dir: &Path,
    certificate_path: &Path,
    private_key_path: &Path,
) -> AppResult<Option<MacosTlsProvisionOutcome>> {
    let marker_path = tls_dir.join(MARKER_NAME);
    let plan = plan_marker_recovery(
        &AdapterMarkerFacts(adapter),
        tls_dir,
        certificate_path,
        private_key_path,
    )?;
    match plan {
        MarkerRecoveryPlan::Absent => Ok(None),
        MarkerRecoveryPlan::Republish => {
            // No publication happened, or a malformed/empty marker survived a
            // process crash during marker creation. Remove only the fixed
            // internal marker (inside the now-validated tree) and retry
            // cleanly.
            std::fs::remove_file(&marker_path)
                .map_err(|error| AppError::internal(format!("remove stale TLS marker: {error}")))?;
            sync_directory(tls_dir)?;
            Ok(None)
        }
        MarkerRecoveryPlan::Complete(marker) => {
            // Marker and both files are the completion evidence.
            sync_directory(tls_dir)?;
            Ok(Some(MacosTlsProvisionOutcome::recovered(&marker)))
        }
        MarkerRecoveryPlan::RemoveCertificate => {
            std::fs::remove_file(certificate_path).map_err(|error| {
                AppError::internal(format!("remove partial TLS certificate: {error}"))
            })?;
            std::fs::remove_file(&marker_path).map_err(|error| {
                AppError::internal(format!("remove partial TLS marker: {error}"))
            })?;
            sync_directory(tls_dir)?;
            Ok(None)
        }
        MarkerRecoveryPlan::RemovePrivateKey => {
            std::fs::remove_file(private_key_path).map_err(|error| {
                AppError::internal(format!("remove partial TLS private key: {error}"))
            })?;
            std::fs::remove_file(&marker_path).map_err(|error| {
                AppError::internal(format!("remove partial TLS marker: {error}"))
            })?;
            sync_directory(tls_dir)?;
            Ok(None)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryAction {
    Republish,
    Complete,
    RemoveCertificate,
    RemovePrivateKey,
    Refuse,
}

fn recovery_action(
    marker: Option<&PublishMarker>,
    certificate: Option<&[u8]>,
    private_key: Option<&[u8]>,
) -> RecoveryAction {
    match (marker, certificate, private_key) {
        (_, None, None) => RecoveryAction::Republish,
        (None, _, _) => RecoveryAction::Refuse,
        (Some(marker), Some(certificate), None)
            if super::manifest::sha256_hex(certificate) == marker.certificate_sha256 =>
        {
            RecoveryAction::RemoveCertificate
        }
        (Some(marker), None, Some(private_key))
            if super::manifest::sha256_hex(private_key) == marker.private_key_sha256 =>
        {
            RecoveryAction::RemovePrivateKey
        }
        (Some(marker), Some(certificate), Some(private_key))
            if super::manifest::sha256_hex(certificate) == marker.certificate_sha256
                && super::manifest::sha256_hex(private_key) == marker.private_key_sha256 =>
        {
            RecoveryAction::Complete
        }
        _ => RecoveryAction::Refuse,
    }
}

/// Objects a failed publish may roll back. Every `true` requires proof of
/// ownership established by [`plan_failed_publish_cleanup`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PublishCleanupPlan {
    remove_certificate: bool,
    remove_private_key: bool,
    remove_marker: bool,
}

/// Decide which objects a failed publish may remove.
///
/// A published file or marker is removed only when it is provably still the
/// private, root-owned object this call created. Otherwise cleanup leaves it
/// untouched: that preserves recovery evidence and never deletes an operator
/// or attacker-substituted path. The marker is kept unless both published
/// names are (or became) absent, so the next run's validated recovery can
/// still classify the partial state.
#[allow(clippy::too_many_arguments)]
fn plan_failed_publish_cleanup<F: MarkerRecoveryFacts + ?Sized>(
    facts: &F,
    marker_path: &Path,
    certificate_path: &Path,
    private_key_path: &Path,
    marker: &PublishMarker,
    marker_bytes: &[u8],
    marker_created: bool,
    installed_certificate: bool,
    installed_private_key: bool,
) -> PublishCleanupPlan {
    let remove_certificate = installed_certificate
        && published_file_is_provable_owned(facts, certificate_path, &marker.certificate_sha256);
    let remove_private_key = installed_private_key
        && published_file_is_provable_owned(facts, private_key_path, &marker.private_key_sha256);
    let certificate_gone = remove_certificate || path_is_absent(facts, certificate_path);
    let private_key_gone = remove_private_key || path_is_absent(facts, private_key_path);
    let remove_marker = marker_created
        && certificate_gone
        && private_key_gone
        && marker_is_provable_owned(facts, marker_path, marker_bytes);
    PublishCleanupPlan {
        remove_certificate,
        remove_private_key,
        remove_marker,
    }
}

fn path_is_absent<F: MarkerRecoveryFacts + ?Sized>(facts: &F, path: &Path) -> bool {
    matches!(facts.path_metadata(path), Ok(None))
}

/// Final gate before deleting the publish marker: the plan must allow it and
/// both published names must actually be absent *now* (a planned removal may
/// have failed). Otherwise the marker stays as recovery evidence.
fn marker_removal_is_safe_now<F: MarkerRecoveryFacts + ?Sized>(
    facts: &F,
    cleanup: &PublishCleanupPlan,
    certificate_path: &Path,
    private_key_path: &Path,
) -> bool {
    cleanup.remove_marker
        && path_is_absent(facts, certificate_path)
        && path_is_absent(facts, private_key_path)
}

/// True only when `path` is still exactly the private, root-owned,
/// single-link, ACL-safe regular file whose bytes hash to `expected_sha256`.
/// Any doubt (foreign owner, changed shape, unsafe ACL, unreadable, digest
/// mismatch) returns `false`; cleanup then leaves the object as evidence.
fn published_file_is_provable_owned<F: MarkerRecoveryFacts + ?Sized>(
    facts: &F,
    path: &Path,
    expected_sha256: &str,
) -> bool {
    let Ok(Some(metadata)) = facts.path_metadata(path) else {
        return false;
    };
    if metadata.is_symlink
        || !metadata.is_regular_file
        || metadata.uid != 0
        || metadata.nlink != 1
        || metadata.mode & 0o077 != 0
        || metadata.len > MAX_TLS_PEM_BYTES as u64
        || !matches!(facts.extended_acl_is_safe(path), Ok(true))
    {
        return false;
    }
    match facts.read_published_material(path, MAX_TLS_PEM_BYTES) {
        Ok(bytes) => {
            !bytes.is_empty() && super::manifest::sha256_hex(&bytes[..]) == expected_sha256
        }
        Err(_) => false,
    }
}

/// True only when the marker at `path` is still our private, root-owned,
/// single-link, ACL-safe regular file with exactly the bytes we wrote.
fn marker_is_provable_owned<F: MarkerRecoveryFacts + ?Sized>(
    facts: &F,
    path: &Path,
    expected_bytes: &[u8],
) -> bool {
    let Ok(Some(metadata)) = facts.path_metadata(path) else {
        return false;
    };
    if metadata.is_symlink
        || !metadata.is_regular_file
        || metadata.uid != 0
        || metadata.nlink != 1
        || metadata.mode & 0o077 != 0
        || metadata.len > MAX_MARKER_BYTES as u64
        || !matches!(facts.extended_acl_is_safe(path), Ok(true))
    {
        return false;
    }
    matches!(
        facts.read_bounded_marker(path, MAX_MARKER_BYTES),
        Ok(bytes) if bytes == expected_bytes
    )
}

fn read_optional_final<F: MarkerRecoveryFacts + ?Sized>(
    facts: &F,
    path: &Path,
) -> AppResult<Option<Zeroizing<Vec<u8>>>> {
    let Some(_metadata) = facts.path_metadata(path).map_err(unavailable)? else {
        return Ok(None);
    };
    let bytes = facts.read_published_material(path, MAX_TLS_PEM_BYTES)?;
    if bytes.is_empty() {
        return Err(AppError::security_state_unavailable(format!(
            "published TLS file '{}' is empty",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

fn sync_directory(path: &Path) -> AppResult<()> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| AppError::internal(format!("fsync '{}': {error}", path.display())))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn existing_unverified_outcome(
    adapter: &dyn MacosApplyAdapter,
    certificate_path: &Path,
    private_key_path: &Path,
) -> AppResult<Option<MacosTlsProvisionOutcome>> {
    let certificate_present = adapter
        .path_metadata(certificate_path)
        .map_err(unavailable)?
        .is_some();
    let private_key_present = adapter
        .path_metadata(private_key_path)
        .map_err(unavailable)?
        .is_some();
    if !certificate_present && !private_key_present {
        return Ok(None);
    }
    Ok(Some(MacosTlsProvisionOutcome::ExistingUnverified {
        certificate_path: TLS_SOURCE_CERTIFICATE_PATH.to_string(),
        private_key_path: TLS_SOURCE_PRIVATE_KEY_PATH.to_string(),
        certificate_present,
        private_key_present,
        authority_host: "127.0.0.1",
        detail: "preexisting certificate/key material was not read or modified; plan must validate it before readiness",
    }))
}

fn ensure_absent(adapter: &dyn MacosApplyAdapter, path: &Path, label: &str) -> AppResult<()> {
    match adapter.path_metadata(path).map_err(unavailable)? {
        Some(_) => Err(AppError::conflict(
            format!(
                "{label} '{}' already exists; refusing to overwrite",
                path.display()
            ),
            None,
        )),
        None => Ok(()),
    }
}

fn generate_loopback_material() -> AppResult<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let key = rcgen::KeyPair::generate()
        .map_err(|error| AppError::internal(format!("generate loopback TLS key: {error}")))?;
    let mut params = rcgen::CertificateParams::new(Vec::new())
        .map_err(|error| AppError::internal(format!("create TLS certificate params: {error}")))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "127.0.0.1");
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let certificate = params
        .self_signed(&key)
        .map_err(|error| AppError::internal(format!("self-sign TLS certificate: {error}")))?;
    Ok((
        certificate.pem().into_bytes(),
        Zeroizing::new(key.serialize_pem().into_bytes()),
    ))
}

fn create_stage_dir(adapter: &dyn MacosApplyAdapter, tls_dir: &Path) -> AppResult<PathBuf> {
    let stage = tls_dir.join(format!("{STAGE_PREFIX}{}", uuid::Uuid::new_v4()));
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(&stage).map_err(|error| {
        AppError::internal(format!(
            "create TLS staging directory '{}': {error}",
            stage.display()
        ))
    })?;
    std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700)).map_err(|error| {
        AppError::internal(format!(
            "set TLS staging directory mode '{}': {error}",
            stage.display()
        ))
    })?;
    let safe = adapter.path_metadata(&stage).map_err(unavailable)?;
    let safe_shape = safe.is_some_and(|metadata| {
        !metadata.is_symlink
            && metadata.is_directory
            && metadata.uid == 0
            && metadata.mode & 0o077 == 0
    });
    let acl_safe = adapter.extended_acl_is_safe(&stage).map_err(unavailable)?;
    if !safe_shape || !acl_safe {
        let _ = std::fs::remove_dir_all(&stage);
        return Err(AppError::security_state_unavailable(
            "created TLS staging directory has an unsafe shape",
        ));
    }
    Ok(stage)
}

/// Exact lowercase hyphenated UUID (8-4-4-4-12) shape, as produced by
/// `uuid::Uuid::new_v4()`. Restricting stale-stage candidates to this shape
/// means an unrelated or operator directory that merely shares the stage
/// prefix is never deleted.
fn is_stage_uuid(suffix: &str) -> bool {
    let bytes = suffix.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => *byte == b'-',
        _ => byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'),
    })
}

fn cleanup_stale_stages(adapter: &dyn MacosApplyAdapter, tls_dir: &Path) -> AppResult<()> {
    let entries = std::fs::read_dir(tls_dir).map_err(|error| {
        AppError::security_state_unavailable(format!(
            "read TLS source directory '{}': {error}",
            tls_dir.display()
        ))
    })?;
    let mut stale_count = 0usize;
    for entry in entries {
        let entry = entry.map_err(|error| {
            AppError::security_state_unavailable(format!("read TLS source entry: {error}"))
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        // Only names this module can have created are candidates: the exact
        // prefix plus a lowercase hyphenated UUIDv4. Anything else (for
        // example an operator directory that merely shares the prefix) is
        // left untouched, never deleted.
        let Some(suffix) = name.strip_prefix(STAGE_PREFIX) else {
            continue;
        };
        if !is_stage_uuid(suffix) {
            continue;
        }
        stale_count += 1;
        if stale_count > MAX_STALE_STAGES {
            return Err(AppError::security_state_unavailable(
                "too many stale TLS staging directories; refusing cleanup",
            ));
        }
        let path = entry.path();
        let Some(metadata) = adapter.path_metadata(&path).map_err(unavailable)? else {
            continue;
        };
        if metadata.is_symlink
            || !metadata.is_directory
            || metadata.uid != 0
            || metadata.mode & 0o077 != 0
            || !adapter.extended_acl_is_safe(&path).map_err(unavailable)?
        {
            return Err(AppError::security_state_unavailable(format!(
                "stale TLS staging path '{}' has an unsafe shape; refusing cleanup",
                path.display()
            )));
        }
        let mut children = std::fs::read_dir(&path).map_err(|error| {
            AppError::security_state_unavailable(format!(
                "read stale TLS staging directory '{}': {error}",
                path.display()
            ))
        })?;
        let mut child_count = 0usize;
        for child in children.by_ref() {
            let child = child.map_err(|error| {
                AppError::security_state_unavailable(format!(
                    "read stale TLS staging entry: {error}"
                ))
            })?;
            child_count += 1;
            if child_count > 3 {
                return Err(AppError::security_state_unavailable(format!(
                    "stale TLS staging directory '{}' contains unexpected entries",
                    path.display()
                )));
            }
            let child_name = child.file_name();
            let Some(child_name) = child_name.to_str() else {
                return Err(AppError::security_state_unavailable(
                    "stale TLS staging entry name is not UTF-8",
                ));
            };
            if child_name != "fullchain.pem"
                && child_name != "private-key.pem"
                && child_name != MARKER_TEMP_NAME
            {
                return Err(AppError::security_state_unavailable(format!(
                    "stale TLS staging directory '{}' contains an unapproved entry",
                    path.display()
                )));
            }
            let child_path = child.path();
            let Some(child_metadata) = adapter.path_metadata(&child_path).map_err(unavailable)?
            else {
                return Err(AppError::security_state_unavailable(
                    "stale TLS staging entry disappeared during cleanup",
                ));
            };
            if child_metadata.is_symlink
                || !child_metadata.is_regular_file
                || child_metadata.uid != 0
                || child_metadata.nlink != 1
                || child_metadata.mode & 0o077 != 0
                || child_metadata.len > MAX_TLS_PEM_BYTES as u64
                || !adapter
                    .extended_acl_is_safe(&child_path)
                    .map_err(unavailable)?
            {
                return Err(AppError::security_state_unavailable(format!(
                    "stale TLS staging file '{}' has an unsafe shape; refusing cleanup",
                    child_path.display()
                )));
            }
        }
        std::fs::remove_dir_all(&path).map_err(|error| {
            AppError::security_state_unavailable(format!(
                "remove stale TLS staging directory '{}': {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn rename_no_replace(from: &Path, to: &Path) -> Result<(), String> {
    let from = CString::new(from.as_os_str().as_bytes())
        .map_err(|_| "rename source contains NUL".to_string())?;
    let to = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| "rename destination contains NUL".to_string())?;
    // SAFETY: both C strings are valid for the call; renamex_np does not retain
    // them. RENAME_EXCL makes an existing destination an error.
    let result = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

fn unavailable(error: String) -> AppError {
    AppError::security_state_unavailable(error)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use zeroize::Zeroizing;

    use crate::error::{AppError, AppResult};
    use crate::installer::macos_apply::{MacosApplyPathMetadata, StateDirFacts};

    use super::{
        generate_loopback_material, is_stage_uuid, marker_is_provable_owned,
        marker_removal_is_safe_now, plan_failed_publish_cleanup, plan_marker_recovery,
        published_file_is_provable_owned, recovery_action, rename_no_replace,
        MacosTlsProvisionOutcome, MarkerRecoveryFacts, MarkerRecoveryPlan, PublishCleanupPlan,
        PublishMarker, RecoveryAction, MARKER_NAME,
    };

    const TLS_DIR: &str = "/etc/helicoid/tls";
    const CERTIFICATE_PATH: &str = "/etc/helicoid/tls/fullchain.pem";
    const PRIVATE_KEY_PATH: &str = "/etc/helicoid/tls/private-key.pem";

    fn marker_path() -> PathBuf {
        Path::new(TLS_DIR).join(MARKER_NAME)
    }

    fn directory(uid: u32, mode: u32) -> MacosApplyPathMetadata {
        MacosApplyPathMetadata {
            is_symlink: false,
            is_directory: true,
            is_regular_file: false,
            uid,
            gid: 0,
            mode,
            nlink: 1,
            len: 0,
        }
    }

    fn regular_file(len: u64, uid: u32, mode: u32, nlink: u64) -> MacosApplyPathMetadata {
        MacosApplyPathMetadata {
            is_symlink: false,
            is_directory: false,
            is_regular_file: true,
            uid,
            gid: 0,
            mode,
            nlink,
            len,
        }
    }

    fn symlink() -> MacosApplyPathMetadata {
        MacosApplyPathMetadata {
            is_symlink: true,
            is_directory: false,
            is_regular_file: false,
            uid: 0,
            gid: 0,
            mode: 0o777,
            nlink: 1,
            len: 0,
        }
    }

    fn system_link(uid: u32) -> MacosApplyPathMetadata {
        MacosApplyPathMetadata {
            is_symlink: true,
            is_directory: false,
            is_regular_file: false,
            uid,
            gid: 0,
            mode: 0o755,
            nlink: 1,
            len: 0,
        }
    }

    /// In-memory facts/readers that record every probe and read so tests can
    /// prove the recovery ordering without touching the host.
    #[derive(Default)]
    struct FakeFacts {
        entries: BTreeMap<PathBuf, Result<Option<MacosApplyPathMetadata>, String>>,
        unsafe_acl: BTreeMap<PathBuf, bool>,
        contents: BTreeMap<PathBuf, Vec<u8>>,
        log: RefCell<Vec<String>>,
    }

    impl FakeFacts {
        fn set(&mut self, path: &str, metadata: MacosApplyPathMetadata) {
            self.entries.insert(PathBuf::from(path), Ok(Some(metadata)));
        }

        fn reads(&self) -> Vec<String> {
            self.log
                .borrow()
                .iter()
                .filter(|entry| entry.starts_with("read"))
                .cloned()
                .collect()
        }

        fn validated_before(&self, read_index: usize, prefix: &str) -> bool {
            self.log
                .borrow()
                .iter()
                .position(|entry| entry == &format!("meta:{prefix}"))
                .is_some_and(|index| index < read_index)
        }
    }

    impl StateDirFacts for FakeFacts {
        fn path_metadata(&self, path: &Path) -> Result<Option<MacosApplyPathMetadata>, String> {
            self.log
                .borrow_mut()
                .push(format!("meta:{}", path.display()));
            self.entries.get(path).cloned().unwrap_or(Ok(None))
        }

        fn extended_acl_is_safe(&self, path: &Path) -> Result<bool, String> {
            self.log
                .borrow_mut()
                .push(format!("acl:{}", path.display()));
            Ok(!self.unsafe_acl.get(path).copied().unwrap_or(false))
        }
    }

    impl MarkerRecoveryFacts for FakeFacts {
        fn read_bounded_marker(&self, path: &Path, _max_bytes: usize) -> Result<Vec<u8>, String> {
            self.log
                .borrow_mut()
                .push(format!("read-marker:{}", path.display()));
            self.contents
                .get(path)
                .cloned()
                .ok_or_else(|| format!("no fake marker bytes for '{}'", path.display()))
        }

        fn read_published_material(
            &self,
            path: &Path,
            _max_bytes: usize,
        ) -> AppResult<Zeroizing<Vec<u8>>> {
            self.log
                .borrow_mut()
                .push(format!("read:{}", path.display()));
            self.contents
                .get(path)
                .cloned()
                .map(Zeroizing::new)
                .ok_or_else(|| {
                    AppError::bad_request(format!("no fake bytes for '{}'", path.display()))
                })
        }
    }

    struct Fixture {
        facts: FakeFacts,
        marker: PublishMarker,
        marker_bytes: Vec<u8>,
    }

    impl Fixture {
        fn complete() -> Self {
            let certificate = b"certificate-bytes".to_vec();
            let private_key = b"private-key-bytes".to_vec();
            let marker = PublishMarker {
                certificate_sha256: super::super::manifest::sha256_hex(&certificate),
                private_key_sha256: super::super::manifest::sha256_hex(&private_key),
            };
            let marker_bytes = serde_json::to_vec(&marker).expect("marker JSON");

            let mut facts = FakeFacts::default();
            // Ancestors need not be owner-private, but must be root-owned and
            // not group/world-writable. The final TLS directory must be 0700.
            for (path, mode) in [
                ("/", 0o755),
                ("/etc", 0o755),
                ("/etc/helicoid", 0o700),
                (TLS_DIR, 0o700),
            ] {
                facts.set(path, directory(0, mode));
            }
            facts.set(
                marker_path().to_str().expect("marker path"),
                regular_file(marker_bytes.len() as u64, 0, 0o600, 1),
            );
            facts.set(
                CERTIFICATE_PATH,
                regular_file(certificate.len() as u64, 0, 0o600, 1),
            );
            facts.set(
                PRIVATE_KEY_PATH,
                regular_file(private_key.len() as u64, 0, 0o600, 1),
            );
            facts.contents.insert(marker_path(), marker_bytes.clone());
            facts
                .contents
                .insert(PathBuf::from(CERTIFICATE_PATH), certificate);
            facts
                .contents
                .insert(PathBuf::from(PRIVATE_KEY_PATH), private_key);

            Self {
                facts,
                marker,
                marker_bytes,
            }
        }

        fn plan(&self) -> AppResult<MarkerRecoveryPlan> {
            plan_marker_recovery(
                &self.facts,
                Path::new(TLS_DIR),
                Path::new(CERTIFICATE_PATH),
                Path::new(PRIVATE_KEY_PATH),
            )
        }

        fn cleanup(
            &self,
            marker_created: bool,
            installed_certificate: bool,
            installed_private_key: bool,
        ) -> PublishCleanupPlan {
            plan_failed_publish_cleanup(
                &self.facts,
                &marker_path(),
                Path::new(CERTIFICATE_PATH),
                Path::new(PRIVATE_KEY_PATH),
                &self.marker,
                &self.marker_bytes,
                marker_created,
                installed_certificate,
                installed_private_key,
            )
        }
    }

    #[test]
    fn marker_recovery_validates_every_parent_before_reading_any_material() {
        let fixture = Fixture::complete();
        assert_eq!(
            fixture.plan().expect("complete recovery"),
            MarkerRecoveryPlan::Complete(fixture.marker.clone())
        );

        let log = fixture.facts.log.borrow();
        let first_read = log
            .iter()
            .position(|entry| entry.starts_with("read"))
            .expect("a recovery read happened");
        assert_eq!(
            fixture.facts.reads().len(),
            3,
            "marker and both published files are read: {log:?}"
        );
        for prefix in ["/", "/etc", "/etc/helicoid", TLS_DIR] {
            assert!(
                fixture.facts.validated_before(first_read, prefix),
                "parent '{prefix}' was not validated before the first read: {log:?}"
            );
        }
        assert!(
            log.iter().any(|entry| entry == "acl:/etc/helicoid/tls"),
            "the TLS parent ACL must be checked before use: {log:?}"
        );
    }

    #[test]
    fn marker_recovery_refuses_untrusted_parents_before_any_read() {
        type FixtureMutation = fn(&mut Fixture);
        let cases: Vec<(&str, FixtureMutation)> = vec![
            ("non-private TLS directory", |fixture| {
                fixture.facts.set(TLS_DIR, directory(0, 0o755));
            }),
            ("world-writable /etc/helicoid", |fixture| {
                fixture.facts.set("/etc/helicoid", directory(0, 0o777));
            }),
            ("foreign-owned /etc/helicoid", |fixture| {
                fixture.facts.set("/etc/helicoid", directory(501, 0o700));
            }),
            ("symlinked TLS directory", |fixture| {
                fixture.facts.set(TLS_DIR, symlink());
            }),
            ("ACL-unsafe TLS directory", |fixture| {
                fixture
                    .facts
                    .unsafe_acl
                    .insert(PathBuf::from(TLS_DIR), true);
            }),
            ("absent /etc/helicoid", |fixture| {
                fixture
                    .facts
                    .entries
                    .insert(PathBuf::from("/etc/helicoid"), Ok(None));
            }),
        ];

        for (label, mutate) in cases {
            let mut fixture = Fixture::complete();
            mutate(&mut fixture);
            let error = fixture
                .plan()
                .expect_err("untrusted parent chain must fail closed");
            assert!(
                fixture.facts.reads().is_empty(),
                "{label}: no marker or published-file read may precede validation: {error}"
            );
        }
    }

    #[test]
    fn marker_recovery_tolerates_only_root_owned_system_symlink_ancestors() {
        // macOS exposes the fixed path through the root-owned /etc ->
        // private/etc system link. That link must not wedge recovery.
        let mut fixture = Fixture::complete();
        fixture.facts.set("/etc", system_link(0));
        assert_eq!(
            fixture.plan().expect("root-owned system link ancestor"),
            MarkerRecoveryPlan::Complete(fixture.marker.clone())
        );

        // A foreign-owned link could be repointed by a non-root principal and
        // must fail closed before any read.
        let mut fixture = Fixture::complete();
        fixture.facts.set("/etc", system_link(501));
        assert!(fixture.plan().is_err());
        assert!(
            fixture.facts.reads().is_empty(),
            "foreign-owned ancestor link must be rejected before any read"
        );
    }

    #[test]
    fn marker_recovery_absent_marker_does_not_validate_or_mutate_parents() {
        let facts = FakeFacts::default();
        // No marker entry at all, and no TLS directory entry either.
        let plan = plan_marker_recovery(
            &facts,
            Path::new(TLS_DIR),
            Path::new(CERTIFICATE_PATH),
            Path::new(PRIVATE_KEY_PATH),
        )
        .expect("absent marker");
        assert_eq!(plan, MarkerRecoveryPlan::Absent);

        let log = facts.log.borrow();
        assert_eq!(log.len(), 1, "only the presence probe may run: {log:?}");
        assert!(
            log[0].starts_with("meta:"),
            "probe must be metadata-only: {log:?}"
        );
        assert!(
            log[0].ends_with(MARKER_NAME),
            "probe targets the marker: {log:?}"
        );
        assert!(
            log.iter().all(|entry| !entry.starts_with("acl")),
            "no parent is validated, created, or adopted when no marker exists: {log:?}"
        );
    }

    #[test]
    fn cleanup_removes_only_provably_owned_artifacts() {
        let fixture = Fixture::complete();
        assert_eq!(
            fixture.cleanup(true, true, true),
            PublishCleanupPlan {
                remove_certificate: true,
                remove_private_key: true,
                remove_marker: true,
            }
        );

        // Only the marker was published; both names are absent.
        let mut marker_only = Fixture::complete();
        marker_only
            .facts
            .entries
            .insert(PathBuf::from(CERTIFICATE_PATH), Ok(None));
        marker_only
            .facts
            .entries
            .insert(PathBuf::from(PRIVATE_KEY_PATH), Ok(None));
        assert_eq!(
            marker_only.cleanup(true, false, false),
            PublishCleanupPlan {
                remove_certificate: false,
                remove_private_key: false,
                remove_marker: true,
            }
        );
    }

    #[test]
    fn cleanup_preserves_unproven_artifacts_and_the_marker() {
        type Mutation = fn(&mut Fixture);
        let cases: Vec<(&str, Mutation, PublishCleanupPlan)> = vec![
            (
                "foreign-owned certificate",
                |fixture| {
                    let len = fixture.facts.contents[&PathBuf::from(CERTIFICATE_PATH)].len() as u64;
                    fixture
                        .facts
                        .set(CERTIFICATE_PATH, regular_file(len, 501, 0o600, 1));
                },
                PublishCleanupPlan {
                    remove_certificate: false,
                    remove_private_key: true,
                    remove_marker: false,
                },
            ),
            (
                "group-readable certificate",
                |fixture| {
                    let len = fixture.facts.contents[&PathBuf::from(CERTIFICATE_PATH)].len() as u64;
                    fixture
                        .facts
                        .set(CERTIFICATE_PATH, regular_file(len, 0, 0o644, 1));
                },
                PublishCleanupPlan {
                    remove_certificate: false,
                    remove_private_key: true,
                    remove_marker: false,
                },
            ),
            (
                "hard-linked private key",
                |fixture| {
                    let len = fixture.facts.contents[&PathBuf::from(PRIVATE_KEY_PATH)].len() as u64;
                    fixture
                        .facts
                        .set(PRIVATE_KEY_PATH, regular_file(len, 0, 0o600, 2));
                },
                PublishCleanupPlan {
                    remove_certificate: true,
                    remove_private_key: false,
                    remove_marker: false,
                },
            ),
            (
                "symlinked private key",
                |fixture| {
                    fixture.facts.set(PRIVATE_KEY_PATH, symlink());
                },
                PublishCleanupPlan {
                    remove_certificate: true,
                    remove_private_key: false,
                    remove_marker: false,
                },
            ),
            (
                "ACL-unsafe certificate",
                |fixture| {
                    fixture
                        .facts
                        .unsafe_acl
                        .insert(PathBuf::from(CERTIFICATE_PATH), true);
                },
                PublishCleanupPlan {
                    remove_certificate: false,
                    remove_private_key: true,
                    remove_marker: false,
                },
            ),
            (
                "tampered certificate content",
                |fixture| {
                    fixture
                        .facts
                        .contents
                        .insert(PathBuf::from(CERTIFICATE_PATH), b"tampered".to_vec());
                },
                PublishCleanupPlan {
                    remove_certificate: false,
                    remove_private_key: true,
                    remove_marker: false,
                },
            ),
            (
                "foreign-owned marker",
                |fixture| {
                    let len = fixture.marker_bytes.len() as u64;
                    fixture.facts.set(
                        marker_path().to_str().expect("marker path"),
                        regular_file(len, 501, 0o600, 1),
                    );
                },
                PublishCleanupPlan {
                    remove_certificate: true,
                    remove_private_key: true,
                    remove_marker: false,
                },
            ),
            (
                "tampered marker content",
                |fixture| {
                    fixture.facts.contents.insert(marker_path(), b"{}".to_vec());
                },
                PublishCleanupPlan {
                    remove_certificate: true,
                    remove_private_key: true,
                    remove_marker: false,
                },
            ),
        ];

        for (label, mutate, expected) in cases {
            let mut fixture = Fixture::complete();
            mutate(&mut fixture);
            assert_eq!(
                fixture.cleanup(true, true, true),
                expected,
                "{label}: only provably owned objects may be removed"
            );
        }
    }

    #[test]
    fn marker_removal_requires_actual_absence_after_rollback() {
        let fixture = Fixture::complete();
        let cleanup = fixture.cleanup(true, true, true);
        assert!(cleanup.remove_marker);
        // A failed unlink leaves a published name present; the marker must
        // then survive as recovery evidence.
        assert!(!marker_removal_is_safe_now(
            &fixture.facts,
            &cleanup,
            Path::new(CERTIFICATE_PATH),
            Path::new(PRIVATE_KEY_PATH),
        ));

        let mut absent = Fixture::complete();
        absent
            .facts
            .entries
            .insert(PathBuf::from(CERTIFICATE_PATH), Ok(None));
        absent
            .facts
            .entries
            .insert(PathBuf::from(PRIVATE_KEY_PATH), Ok(None));
        assert!(marker_removal_is_safe_now(
            &absent.facts,
            &cleanup,
            Path::new(CERTIFICATE_PATH),
            Path::new(PRIVATE_KEY_PATH),
        ));
    }

    #[test]
    fn cleanup_keeps_marker_when_a_published_name_still_exists_unowned() {
        let mut fixture = Fixture::complete();
        let len = fixture.facts.contents[&PathBuf::from(PRIVATE_KEY_PATH)].len() as u64;
        fixture
            .facts
            .set(PRIVATE_KEY_PATH, regular_file(len, 501, 0o600, 1));

        let cleanup = fixture.cleanup(true, true, true);
        assert!(cleanup.remove_certificate, "our certificate is proven");
        assert!(!cleanup.remove_private_key, "foreign key is preserved");
        assert!(
            !cleanup.remove_marker,
            "marker survives while a published name remains"
        );
    }

    #[test]
    fn ownership_proof_requires_private_root_owned_content() {
        let fixture = Fixture::complete();
        assert!(published_file_is_provable_owned(
            &fixture.facts,
            Path::new(CERTIFICATE_PATH),
            &fixture.marker.certificate_sha256,
        ));
        assert!(!published_file_is_provable_owned(
            &fixture.facts,
            Path::new(CERTIFICATE_PATH),
            &fixture.marker.private_key_sha256,
        ));
        assert!(marker_is_provable_owned(
            &fixture.facts,
            &marker_path(),
            &fixture.marker_bytes,
        ));
        assert!(!marker_is_provable_owned(
            &fixture.facts,
            &marker_path(),
            b"different",
        ));
    }

    #[test]
    fn stale_stage_names_require_an_exact_uuid_suffix() {
        assert!(is_stage_uuid("0f8fad5b-d9cb-469f-a165-70867728950e"));
        for rejected in [
            "",
            "notes",
            "0f8fad5b-d9cb-469f-a165-70867728950",
            "0f8fad5b-d9cb-469f-a165-70867728950e-extra",
            "0F8FAD5B-D9CB-469F-A165-70867728950E",
            "0f8fad5b_d9cb_469f_a165_70867728950e",
            "../0f8fad5b-d9cb-469f-a165-70867728950e",
            "0f8fad5b-d9cb-469f-a165-70867728950g",
        ] {
            assert!(!is_stage_uuid(rejected), "must reject {rejected:?}");
        }
    }

    #[test]
    fn generated_stage_directory_names_are_recognized() {
        let name = format!("{}{}", super::STAGE_PREFIX, uuid::Uuid::new_v4());
        let suffix = name
            .strip_prefix(super::STAGE_PREFIX)
            .expect("stage prefix present");
        assert!(
            is_stage_uuid(suffix),
            "a stage name this module generates must pass the cleanup gate: {name}"
        );
    }

    #[test]
    fn generated_material_is_a_loopback_server_certificate_and_private_key() {
        let (certificate_pem, private_key_pem) =
            generate_loopback_material().expect("loopback TLS material");
        assert!(private_key_pem
            .as_slice()
            .starts_with(b"-----BEGIN PRIVATE KEY-----"));

        let mut certificate_slice = certificate_pem.as_slice();
        let certificates: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut certificate_slice)
                .collect::<Result<Vec<_>, _>>()
                .expect("certificate PEM");
        let leaf = certificates.first().expect("leaf certificate");
        let leaf = webpki::EndEntityCert::try_from(leaf).expect("end-entity certificate");
        let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string())
            .expect("loopback server name");
        leaf.verify_is_valid_for_subject_name(&server_name)
            .expect("certificate covers literal 127.0.0.1");
    }

    #[test]
    fn atomic_install_never_replaces_an_existing_destination() {
        let directory = tempfile::tempdir().expect("tempdir");
        let source = directory.path().join("stage-key");
        let destination = directory.path().join("final-key");
        std::fs::write(&source, b"new").expect("stage file");
        std::fs::write(&destination, b"old").expect("existing destination");

        assert!(rename_no_replace(&source, &destination).is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"old");
        assert_eq!(std::fs::read(&source).unwrap(), b"new");
    }

    #[test]
    fn outcome_contract_distinguishes_existing_unverified_from_provisioned() {
        let outcome = MacosTlsProvisionOutcome::ExistingUnverified {
            certificate_path: "/etc/helicoid/tls/fullchain.pem".to_string(),
            private_key_path: "/etc/helicoid/tls/private-key.pem".to_string(),
            certificate_present: true,
            private_key_present: false,
            authority_host: "127.0.0.1",
            detail: "existing material is not verified",
        };
        let value = serde_json::to_value(outcome).expect("outcome JSON");
        assert_eq!(value["outcome"], "existing_unverified");
        assert_eq!(value["certificate_present"], true);
        assert_eq!(value["private_key_present"], false);
        assert!(value.get("certificate_sha256").is_none());
        assert!(value.get("private_key_sha256").is_none());
    }

    #[test]
    fn marker_recovery_distinguishes_empty_partial_and_complete_states() {
        let certificate = b"certificate";
        let private_key = b"private-key";
        let marker = PublishMarker {
            certificate_sha256: super::super::manifest::sha256_hex(certificate),
            private_key_sha256: super::super::manifest::sha256_hex(private_key),
        };

        assert_eq!(recovery_action(None, None, None), RecoveryAction::Republish);
        assert_eq!(
            recovery_action(Some(&marker), None, None),
            RecoveryAction::Republish
        );
        assert_eq!(
            recovery_action(Some(&marker), Some(certificate), None),
            RecoveryAction::RemoveCertificate
        );
        assert_eq!(
            recovery_action(Some(&marker), None, Some(private_key)),
            RecoveryAction::RemovePrivateKey
        );
        assert_eq!(
            recovery_action(Some(&marker), Some(certificate), Some(private_key)),
            RecoveryAction::Complete
        );
        assert_eq!(
            recovery_action(None, Some(certificate), Some(private_key)),
            RecoveryAction::Refuse
        );
        assert_eq!(
            recovery_action(Some(&marker), Some(b"other"), Some(private_key)),
            RecoveryAction::Refuse
        );
    }
}
