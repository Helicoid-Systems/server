//! Package manifest verification: Ed25519 signature, SHA-256 integrity,
//! portable path safety, platform/schema/version compatibility.
//!
//! This is library-only verification against a caller-supplied public key. It
//! establishes integrity relative to that key and a trusted target; it is not
//! authenticated key distribution, a working installer, or launchd authority.
//! The key must be supplied independently by app/packaging, never read from the
//! same unsigned package. No signing keys are in the repo. The target is
//! supplied by a trusted server/native caller (which may derive it from
//! authenticated target-host/preflight platform facts). This verifier never
//! infers the target from the untrusted package or from its own local OS.
//!
//! Verification opens the package directory once as a held handle and resolves
//! manifest, signature, artifact, and traversal operations relative to that
//! handle. The returned [`VerifiedManifest`] retains the handle for later
//! digest-checked artifact reads.

use std::collections::HashSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use super::adapter::CommandAdapter;
use super::models::{InstallerTarget, PackageManifest};
#[cfg(unix)]
use super::package_fs::UnixPinnedPackage;
use super::package_fs::{PackageFsError, PinnedEntryKind, PinnedPackage, PinnedReadPolicy};
use crate::error::{AppError, AppResult};
use crate::installer::models::ArtifactEntry;

/// Minimum installer version that this build is compatible with.
const INSTALLER_VERSION: &str = "0.1.0";

/// Canonical server package product identity. Exact match only — aliases,
/// case changes, other components, traversal/NUL and unbounded names refuse.
const EXPECTED_PRODUCT: &str = "hs-server";

/// Allowed artifact path prefix.
const ALLOWED_PREFIX: &str = "artifacts/";

/// Bounds on package parsing. A signed manifest is still attacker-shaped if the
/// signing key is wrong; keep parse and copy work bounded either way.
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_ARTIFACTS: usize = 256;
pub const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARTIFACT_PATH_BYTES: usize = 256;
const MAX_ARTIFACT_SEGMENT_BYTES: usize = 64;
const MAX_ARTIFACT_SEGMENTS: usize = 16;
const MAX_TRAVERSAL_ENTRIES: usize = 8192;

/// Windows reserved DOS device basenames (with or without an extension).
const WINDOWS_RESERVED_BASENAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Verify the full package manifest for the default Linux x86_64 target.
/// Windows/macOS packages are rejected. Prefer
/// [`verify_manifest_for_target`] when the trusted caller has selected a target.
pub fn verify_manifest(
    adapter: &dyn CommandAdapter,
    package_dir: &Path,
    verifying_key_bytes: &[u8; 32],
) -> AppResult<PackageManifest> {
    verify_manifest_for_target(
        adapter,
        package_dir,
        verifying_key_bytes,
        InstallerTarget::LinuxX86_64,
    )
}

/// Exact bytes whose signature was verified, together with an unkeyed digest,
/// the caller-supplied trust-key fingerprint, and the held package handle.
///
/// Fields are private so only the verifier can construct this evidence type.
/// The digest covers the exact manifest bytes, including signed fields the
/// parser does not interpret. The package handle remains pinned after this
/// value is returned. Use [`Self::read_artifact`] for digest-checked bytes, or
/// [`Self::package`] for raw handle operations; never reopen the original path.
/// This is library-level integrity evidence, not authenticated trust or
/// installation authority.
#[derive(Clone)]
pub struct VerifiedManifest {
    manifest: PackageManifest,
    target: InstallerTarget,
    manifest_sha256: String,
    verifying_key_sha256: String,
    package: Arc<dyn PinnedPackage>,
}

impl fmt::Debug for VerifiedManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedManifest")
            .field("manifest", &self.manifest)
            .field("target", &self.target)
            .field("manifest_sha256", &self.manifest_sha256)
            .field("verifying_key_sha256", &self.verifying_key_sha256)
            .finish_non_exhaustive()
    }
}

impl VerifiedManifest {
    /// Parsed manifest whose signature and artifacts were verified.
    pub fn manifest(&self) -> &PackageManifest {
        &self.manifest
    }

    /// Target supplied by the trusted caller and matched by the manifest.
    pub fn target(&self) -> InstallerTarget {
        self.target
    }

    /// Unkeyed SHA-256 snapshot of the exact manifest bytes that were
    /// signature-verified. Not authentication.
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    /// SHA-256 of the operator-supplied Ed25519 verifying key.
    pub fn verifying_key_sha256(&self) -> &str {
        &self.verifying_key_sha256
    }

    /// Held package handle. Reads through this handle cannot be redirected by
    /// replacing the original directory path.
    pub fn package(&self) -> &dyn PinnedPackage {
        self.package.as_ref()
    }

    /// Re-read one manifest-declared artifact through the held package handle,
    /// rejecting a changed size or digest. This is the safe accessor for a
    /// caller that needs artifact bytes after verification.
    pub fn read_artifact(&self, path: &str) -> AppResult<Vec<u8>> {
        let artifact = self
            .manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.path == path)
            .ok_or_else(|| {
                AppError::forbidden(format!("artifact '{path}' is not in the verified manifest"))
            })?;
        let file = self
            .package
            .read_file(path, PinnedReadPolicy::Exact(artifact.size_bytes))
            .map_err(|error| map_artifact_read_error(path, error))?;
        if file.size != artifact.size_bytes
            || file.bytes.len() as u64 != artifact.size_bytes
            || sha256_hex(&file.bytes) != artifact.sha256
        {
            return Err(AppError::forbidden(format!(
                "artifact '{path}' changed after verification"
            )));
        }
        Ok(file.bytes)
    }
}

/// Verify the full package manifest for a trusted target and return the exact
/// verified-byte digest:
/// 1. Open the package directory as a held handle; reject symlink or
///    uninspectable path components
/// 2. Read bounded manifest/signature bytes relative to that handle
/// 3. Strict Ed25519 signature (manifest.sig); refuse weak keys/signatures
/// 4. Require a nonempty artifact list within the existing bound
/// 5. Check product equals the canonical server product identity
/// 6. Check release version is strict major.minor.patch
/// 7. Check platform equals the trusted target's frozen string
/// 8. Check min_schema_version <= SCHEMA_VERSION
/// 9. Check min_installer_version <= INSTALLER_VERSION
/// 10. Validate portable artifact paths and reject duplicates/collisions
/// 11. Verify each artifact through the handle: regular file, exact size,
///     sha256, no symlink traversal
/// 12. Ensure no unknown files in artifacts/ with bounded traversal
/// 13. Re-check the held root identity before returning
pub fn verify_manifest_for_target_verified(
    adapter: &dyn CommandAdapter,
    package_dir: &Path,
    verifying_key_bytes: &[u8; 32],
    target: InstallerTarget,
) -> AppResult<VerifiedManifest> {
    let package_dir = normalize_package_dir(package_dir)?;
    let package = adapter
        .open_pinned_package(&package_dir)
        .map_err(map_package_open_error)?;
    verify_manifest_from_package(package, verifying_key_bytes, target)
}

/// Verify a package through an already-held package handle. The caller owns
/// custody of the handle; no path is reopened by this function. The handle is
/// not a trust anchor: it only selects the bytes verified against the
/// caller-supplied key and target.
pub fn verify_manifest_for_target_pinned(
    package: Arc<dyn PinnedPackage>,
    verifying_key_bytes: &[u8; 32],
    target: InstallerTarget,
) -> AppResult<VerifiedManifest> {
    verify_manifest_from_package(package, verifying_key_bytes, target)
}

/// Verify a real on-disk package through a freshly pinned Unix directory
/// handle. Library-only: this does not install, launch, or authorize a service.
#[cfg(unix)]
pub fn verify_manifest_for_target_real(
    package_dir: &Path,
    verifying_key_bytes: &[u8; 32],
    target: InstallerTarget,
) -> AppResult<VerifiedManifest> {
    let package_dir = normalize_package_dir(package_dir)?;
    let package = UnixPinnedPackage::open(&package_dir).map_err(map_package_open_error)?;
    verify_manifest_from_package(Arc::new(package), verifying_key_bytes, target)
}

fn verify_manifest_from_package(
    package: Arc<dyn PinnedPackage>,
    verifying_key_bytes: &[u8; 32],
    target: InstallerTarget,
) -> AppResult<VerifiedManifest> {
    // Bounded reads are resolved from the held package handle, never from the
    // caller's original path. The digest returned below is computed from
    // exactly these bytes.
    let manifest_bytes =
        match package.read_file("manifest.json", PinnedReadPolicy::Max(MAX_MANIFEST_BYTES)) {
            Ok(file) => file.bytes,
            Err(PackageFsError::Symlink(message)) => {
                return Err(AppError::forbidden(format!(
                    "manifest.json must not be a symlink: {message}"
                )));
            }
            Err(PackageFsError::TooLarge { .. }) => {
                return Err(AppError::unprocessable(format!(
                    "manifest.json exceeds {} bytes",
                    MAX_MANIFEST_BYTES
                )));
            }
            Err(error) => {
                return Err(AppError::bad_request(format!(
                    "cannot read manifest.json: {error}"
                )));
            }
        };
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(AppError::unprocessable(format!(
            "manifest.json exceeds {} bytes",
            MAX_MANIFEST_BYTES
        )));
    }

    let sig_bytes = match package.read_file("manifest.sig", PinnedReadPolicy::Max(64)) {
        Ok(file) => file.bytes,
        Err(PackageFsError::Symlink(message)) => {
            return Err(AppError::forbidden(format!(
                "manifest.sig must not be a symlink: {message}"
            )));
        }
        Err(error) => {
            return Err(AppError::bad_request(format!(
                "cannot read manifest.sig: {error}"
            )));
        }
    };

    // Parse signature.
    if sig_bytes.len() != 64 {
        return Err(AppError::bad_request(format!(
            "manifest.sig must be exactly 64 bytes (got {})",
            sig_bytes.len()
        )));
    }
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AppError::internal("signature array conversion"))?;
    let signature = Signature::from_bytes(&sig_array);

    // Independent trust anchor: refuse weak/noncanonical keys before any use.
    let verifying_key = VerifyingKey::from_bytes(verifying_key_bytes)
        .map_err(|e| AppError::bad_request(format!("invalid verifying key: {e}")))?;
    if verifying_key.is_weak() {
        return Err(AppError::forbidden(
            "verifying key is weak (small-order); refusing package",
        ));
    }

    // Strict verification rejects weak/noncanonical signatures that the
    // ordinary verifier would accept.
    verifying_key
        .verify_strict(&manifest_bytes, &signature)
        .map_err(|_| AppError::forbidden("manifest signature verification failed"))?;

    // Parse manifest JSON.
    let manifest: PackageManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| AppError::bad_request(format!("invalid manifest.json: {e}")))?;

    if manifest.artifacts.is_empty() {
        return Err(AppError::unprocessable(
            "manifest must list at least one artifact",
        ));
    }
    if manifest.artifacts.len() > MAX_ARTIFACTS {
        return Err(AppError::unprocessable(format!(
            "manifest lists {} artifacts (max {MAX_ARTIFACTS})",
            manifest.artifacts.len()
        )));
    }

    // Check contract version.
    if manifest.format_version != 1 {
        return Err(AppError::unprocessable(format!(
            "unsupported manifest format_version: {}",
            manifest.format_version
        )));
    }

    // Product binding: a package signed for another component by the same
    // independently trusted publisher key must not be admitted as a server
    // package. Exact match only — never derived from package values. Fixed
    // error text: untrusted product is not echoed.
    if manifest.product != EXPECTED_PRODUCT {
        return Err(AppError::unprocessable(
            "package product is not the canonical server product",
        ));
    }

    // Release identity: strict major.minor.patch structure. Compatibility
    // floors (min_installer_version / min_schema_version) stay separate below.
    // Fixed error text: untrusted version is not echoed.
    if parse_version_triple(&manifest.version).is_none() {
        return Err(AppError::unprocessable("malformed version"));
    }

    // Check platform against the caller-supplied target (never inferred here
    // from the package or this process's OS).
    check_platform(&manifest.platform, target)?;

    // Schema floor: refuse non-positive or not-yet-supported floors.
    if manifest.min_schema_version < 1 {
        return Err(AppError::unprocessable(format!(
            "package min_schema_version {} is below the supported floor 1",
            manifest.min_schema_version
        )));
    }
    if manifest.min_schema_version > crate::db::SCHEMA_VERSION {
        return Err(AppError::unprocessable(format!(
            "package requires schema version {} but installer supports {}",
            manifest.min_schema_version,
            crate::db::SCHEMA_VERSION
        )));
    }

    // Installer version floor: strict major.minor.patch, no silent zero-fill.
    let min_inst = parse_version_triple(&manifest.min_installer_version).ok_or_else(|| {
        AppError::unprocessable(format!(
            "malformed min_installer_version '{}'",
            manifest.min_installer_version
        ))
    })?;
    let running = parse_version_triple(INSTALLER_VERSION)
        .ok_or_else(|| AppError::internal("INSTALLER_VERSION constant is malformed"))?;
    if min_inst > running {
        return Err(AppError::unprocessable(format!(
            "package requires installer version {} but running {}",
            manifest.min_installer_version, INSTALLER_VERSION
        )));
    }

    // Portable path namespace and collision guards run before any artifact is opened.
    validate_declared_paths(&manifest.artifacts)?;

    // Verify each artifact through the held handle.
    verify_artifacts(package.as_ref(), &manifest.artifacts)?;

    // Ensure no unknown files in artifacts/ directory, with bounded traversal.
    verify_no_unknown_files(package.as_ref(), &manifest.artifacts)?;

    package.verify_root().map_err(|error| {
        AppError::bad_request(format!(
            "package directory changed during verification: {error}"
        ))
    })?;

    Ok(VerifiedManifest {
        manifest,
        target,
        manifest_sha256: sha256_hex(&manifest_bytes),
        verifying_key_sha256: sha256_hex(verifying_key_bytes),
        package,
    })
}

fn normalize_package_dir(package_dir: &Path) -> AppResult<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in package_dir.components() {
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::Normal(name) => normalized.push(name),
            Component::ParentDir => {
                return Err(AppError::bad_request(
                    "package directory must not contain parent traversal",
                ));
            }
            Component::Prefix(_) => {
                return Err(AppError::bad_request(
                    "package directory must not contain a platform prefix",
                ));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(AppError::bad_request("package directory must not be empty"));
    }
    Ok(normalized)
}

fn map_package_open_error(error: PackageFsError) -> AppError {
    if matches!(&error, PackageFsError::Symlink(_)) {
        AppError::forbidden(format!("package directory must not be a symlink: {error}"))
    } else {
        AppError::bad_request(format!("cannot open package directory: {error}"))
    }
}

/// Return only the parsed manifest for legacy callers that do not need the
/// held handle or identity evidence. Verification is identical to
/// [`verify_manifest_for_target_verified`] during the call, but this wrapper
/// drops the pinned handle; privileged callers must use the verified API.
pub fn verify_manifest_for_target(
    adapter: &dyn CommandAdapter,
    package_dir: &Path,
    verifying_key_bytes: &[u8; 32],
    target: InstallerTarget,
) -> AppResult<PackageManifest> {
    let verified =
        verify_manifest_for_target_verified(adapter, package_dir, verifying_key_bytes, target)?;
    Ok(verified.manifest)
}

/// Exact match to the caller-supplied target's frozen platform string.
/// Unknown / target / architecture mismatches all refuse.
fn check_platform(manifest_platform: &str, target: InstallerTarget) -> AppResult<()> {
    let expected = target.platform_str();
    if manifest_platform == expected {
        return Ok(());
    }
    match InstallerTarget::from_platform_str(manifest_platform) {
        None => Err(AppError::unprocessable(format!(
            "unknown package platform '{manifest_platform}' (expected '{expected}')"
        ))),
        Some(other) if other.os_str() == target.os_str() => Err(AppError::unprocessable(format!(
            "package platform '{manifest_platform}' architecture does not match target '{expected}'"
        ))),
        Some(_) => Err(AppError::unprocessable(format!(
            "package platform '{manifest_platform}' does not match target '{expected}'"
        ))),
    }
}

/// Validate every declared artifact path before any artifact is opened.
/// Rejects non-portable names, duplicates, and file/directory collisions.
fn validate_declared_paths(artifacts: &[ArtifactEntry]) -> AppResult<()> {
    let mut seen: HashSet<&str> = HashSet::with_capacity(artifacts.len());
    for artifact in artifacts {
        validate_portable_artifact_path(&artifact.path)?;
        if !seen.insert(artifact.path.as_str()) {
            return Err(AppError::forbidden(format!(
                "duplicate artifact path: {}",
                artifact.path
            )));
        }
        if artifact.size_bytes > MAX_ARTIFACT_BYTES {
            return Err(AppError::unprocessable(format!(
                "artifact '{}' size {} exceeds bound {MAX_ARTIFACT_BYTES}",
                artifact.path, artifact.size_bytes
            )));
        }
    }

    // A declared file cannot also be a declared directory prefix.
    for a in artifacts {
        let prefix = format!("{}/", a.path);
        for b in artifacts {
            if a.path != b.path && b.path.starts_with(prefix.as_str()) {
                return Err(AppError::forbidden(format!(
                    "colliding artifact paths: '{}' and '{}'",
                    a.path, b.path
                )));
            }
        }
    }
    Ok(())
}

/// Portable package-relative artifact path: bounded slash-separated lowercase
/// ASCII segments. Host `Path::components` is not used — backslash traversal,
/// drive/UNC/ADS and Windows aliases must be refused even when verified on a
/// non-Windows host.
fn validate_portable_artifact_path(path: &str) -> AppResult<()> {
    if path.len() > MAX_ARTIFACT_PATH_BYTES {
        return Err(AppError::forbidden(format!(
            "artifact path too long (max {MAX_ARTIFACT_PATH_BYTES} bytes)"
        )));
    }
    if path.is_empty() {
        return Err(AppError::forbidden("artifact path must not be empty"));
    }
    if path.starts_with('/') {
        return Err(AppError::forbidden(format!(
            "artifact path must be relative: {path}"
        )));
    }
    if !path.is_ascii() {
        return Err(AppError::forbidden(format!(
            "artifact path must be ASCII: {path}"
        )));
    }
    // Reject backslash, colon (drive/ADS), NUL and uppercase outright.
    if path
        .bytes()
        .any(|b| b == b'\\' || b == b':' || b == 0 || b.is_ascii_uppercase())
    {
        return Err(AppError::forbidden(format!(
            "artifact path is not portable (backslash, colon, NUL, or uppercase): {path}"
        )));
    }
    if !path.starts_with(ALLOWED_PREFIX) {
        return Err(AppError::forbidden(format!(
            "artifact path not in allowed prefix '{}': {path}",
            ALLOWED_PREFIX
        )));
    }

    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() > MAX_ARTIFACT_SEGMENTS {
        return Err(AppError::forbidden(format!(
            "artifact path has too many segments (max {MAX_ARTIFACT_SEGMENTS}): {path}"
        )));
    }
    for segment in &segments {
        validate_portable_segment(segment, path)?;
    }
    Ok(())
}

fn validate_portable_segment(segment: &str, full_path: &str) -> AppResult<()> {
    if segment.is_empty() {
        return Err(AppError::forbidden(format!(
            "artifact path has empty segment: {full_path}"
        )));
    }
    if segment == "." || segment == ".." {
        return Err(AppError::forbidden(format!(
            "artifact path contains traversal: {full_path}"
        )));
    }
    if segment.len() > MAX_ARTIFACT_SEGMENT_BYTES {
        return Err(AppError::forbidden(format!(
            "artifact path segment too long (max {MAX_ARTIFACT_SEGMENT_BYTES} bytes): {full_path}"
        )));
    }
    if segment.ends_with('.') || segment.ends_with(' ') {
        return Err(AppError::forbidden(format!(
            "artifact path segment has trailing dot or space: {full_path}"
        )));
    }
    if !segment
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(AppError::forbidden(format!(
            "artifact path segment has non-portable characters: {full_path}"
        )));
    }
    // Windows reserved DOS basenames, with or without an extension.
    let stem = segment.split('.').next().unwrap_or(segment);
    if WINDOWS_RESERVED_BASENAMES.contains(&stem) {
        return Err(AppError::forbidden(format!(
            "artifact path uses a reserved device basename: {full_path}"
        )));
    }
    Ok(())
}

/// Verify all artifacts through a pinned package handle: bounded regular-file
/// reads, exact size, sha256, and no symlink traversal.
fn verify_artifacts(package: &dyn PinnedPackage, artifacts: &[ArtifactEntry]) -> AppResult<()> {
    for artifact in artifacts {
        let file = package
            .read_file(&artifact.path, PinnedReadPolicy::Exact(artifact.size_bytes))
            .map_err(|error| map_artifact_read_error(&artifact.path, error))?;

        if file.size != artifact.size_bytes || file.bytes.len() as u64 != artifact.size_bytes {
            return Err(AppError::unprocessable(format!(
                "artifact '{}' size changed during verification",
                artifact.path
            )));
        }

        let actual_hash = sha256_hex(&file.bytes);
        if actual_hash != artifact.sha256 {
            return Err(AppError::forbidden(format!(
                "artifact '{}' SHA-256 mismatch",
                artifact.path
            )));
        }
    }
    Ok(())
}

fn map_artifact_read_error(path: &str, error: PackageFsError) -> AppError {
    match error {
        PackageFsError::Symlink(_)
        | PackageFsError::NotRegular(_)
        | PackageFsError::NotDirectory(_)
        | PackageFsError::InvalidPath(_) => {
            AppError::forbidden(format!("artifact '{path}' is unsafe: {error}"))
        }
        PackageFsError::TooLarge { .. }
        | PackageFsError::SizeMismatch { .. }
        | PackageFsError::Changed(_) => {
            AppError::unprocessable(format!("artifact '{path}' size mismatch: {error}"))
        }
        PackageFsError::Missing(_)
        | PackageFsError::Uninspectable(_)
        | PackageFsError::Unsupported(_)
        | PackageFsError::Other(_) => {
            AppError::bad_request(format!("cannot read artifact '{path}': {error}"))
        }
    }
}

/// Ensure no files exist in artifacts/ that are not listed in the manifest.
/// Traversal is descriptor-relative, depth-bounded, and entry-bounded.
fn verify_no_unknown_files(
    package: &dyn PinnedPackage,
    artifacts: &[ArtifactEntry],
) -> AppResult<()> {
    let known: HashSet<&str> = artifacts.iter().map(|a| a.path.as_str()).collect();
    let mut budget = MAX_TRAVERSAL_ENTRIES;
    match package.list_dir("artifacts") {
        Ok(entries) => {
            check_entries_for_unknown(package, "artifacts", &entries, &known, 0, &mut budget)
        }
        Err(PackageFsError::Missing(_)) => Ok(()),
        Err(error) => Err(map_package_list_error("artifacts", error)),
    }
}

fn check_dir_for_unknown(
    package: &dyn PinnedPackage,
    relative_dir: &str,
    known: &HashSet<&str>,
    depth: usize,
    budget: &mut usize,
) -> AppResult<()> {
    if depth > MAX_ARTIFACT_SEGMENTS {
        return Err(AppError::forbidden(
            "artifacts directory traversal exceeds the depth bound",
        ));
    }
    let entries = package
        .list_dir(relative_dir)
        .map_err(|error| map_package_list_error(relative_dir, error))?;
    check_entries_for_unknown(package, relative_dir, &entries, known, depth, budget)
}

fn check_entries_for_unknown(
    package: &dyn PinnedPackage,
    relative_dir: &str,
    entries: &[super::package_fs::PinnedEntry],
    known: &HashSet<&str>,
    depth: usize,
    budget: &mut usize,
) -> AppResult<()> {
    if entries.len() > *budget {
        return Err(AppError::forbidden(
            "artifacts directory traversal exceeds the entry bound",
        ));
    }
    *budget -= entries.len();

    for entry in entries {
        let entry_rel = format!("{relative_dir}/{}", entry.name);
        if known.contains(entry_rel.as_str()) {
            continue;
        }
        let prefix = format!("{entry_rel}/");
        if known.iter().any(|k| k.starts_with(prefix.as_str())) {
            if entry.kind != PinnedEntryKind::Directory {
                return Err(AppError::forbidden(format!(
                    "package path component is not a directory: {entry_rel}"
                )));
            }
            check_dir_for_unknown(package, &entry_rel, known, depth + 1, budget)?;
            continue;
        }
        return Err(AppError::forbidden(format!(
            "unknown file in artifacts directory: {entry_rel}"
        )));
    }
    Ok(())
}

fn map_package_list_error(relative: &str, error: PackageFsError) -> AppError {
    match error {
        PackageFsError::Symlink(_)
        | PackageFsError::NotRegular(_)
        | PackageFsError::NotDirectory(_)
        | PackageFsError::InvalidPath(_)
        | PackageFsError::TooLarge { .. } => {
            AppError::forbidden(format!("unsafe artifacts path '{relative}': {error}"))
        }
        PackageFsError::Missing(_)
        | PackageFsError::Uninspectable(_)
        | PackageFsError::SizeMismatch { .. }
        | PackageFsError::Changed(_)
        | PackageFsError::Unsupported(_)
        | PackageFsError::Other(_) => {
            AppError::bad_request(format!("cannot list artifacts path '{relative}': {error}"))
        }
    }
}

/// SHA-256 hex digest.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Strict `major.minor.patch` decimal triple. Exactly three components, each
/// digits-only, no leading zeros (except a bare `0`), no overflow. Malformed
/// input yields `None` — it is never coerced to zero.
fn parse_version_triple(s: &str) -> Option<(u32, u32, u32)> {
    let mut parts = s.split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    let patch = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some((
        parse_version_component(major)?,
        parse_version_component(minor)?,
        parse_version_component(patch)?,
    ))
}

fn parse_version_component(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 10 {
        return None;
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str) -> ArtifactEntry {
        ArtifactEntry {
            path: path.to_string(),
            sha256: sha256_hex(b"x"),
            size_bytes: 1,
        }
    }

    #[test]
    fn portable_path_accepts_legacy_linux_fixtures() {
        assert!(validate_portable_artifact_path("artifacts/hs-server").is_ok());
        assert!(validate_portable_artifact_path("artifacts/hs-server.service").is_ok());
        assert!(validate_portable_artifact_path("artifacts/sub/dir/file").is_ok());
        assert!(validate_portable_artifact_path("artifacts/f000").is_ok());
    }

    #[test]
    fn portable_path_rejects_non_portable_names() {
        // Traversal and absolute.
        assert!(validate_portable_artifact_path("artifacts/../etc/passwd").is_err());
        assert!(validate_portable_artifact_path("/etc/passwd").is_err());
        // Backslash / drive / ADS / NUL / uppercase.
        assert!(validate_portable_artifact_path("artifacts\\evil").is_err());
        assert!(validate_portable_artifact_path("artifacts/c:/windows").is_err());
        assert!(validate_portable_artifact_path("artifacts/file:stream").is_err());
        assert!(validate_portable_artifact_path("artifacts/HS-Server").is_err());
        // Empty / trailing dot or space / reserved DOS names.
        assert!(validate_portable_artifact_path("artifacts/").is_err());
        assert!(validate_portable_artifact_path("artifacts/foo.").is_err());
        assert!(validate_portable_artifact_path("artifacts/con").is_err());
        assert!(validate_portable_artifact_path("artifacts/nul.txt").is_err());
        assert!(validate_portable_artifact_path("artifacts/com1.tar.gz").is_err());
        // Not in allowed prefix.
        assert!(validate_portable_artifact_path("secret/backdoor").is_err());
    }

    #[test]
    fn duplicate_and_colliding_paths_reject() {
        let dup = vec![entry("artifacts/a"), entry("artifacts/a")];
        assert!(validate_declared_paths(&dup).is_err());

        let collide = vec![entry("artifacts/a"), entry("artifacts/a/b")];
        assert!(validate_declared_paths(&collide).is_err());

        let ok = vec![entry("artifacts/a"), entry("artifacts/b")];
        assert!(validate_declared_paths(&ok).is_ok());
    }

    #[test]
    fn platform_mismatch_and_unknown_refuse() {
        assert!(check_platform("linux-x86_64", InstallerTarget::LinuxX86_64).is_ok());
        assert!(check_platform("windows-x86_64", InstallerTarget::WindowsX86_64).is_ok());
        assert!(check_platform("macos-arm64", InstallerTarget::MacosArm64).is_ok());
        assert!(check_platform("macos-x86_64", InstallerTarget::MacosX86_64).is_ok());

        // Linux legacy entry rejects Windows/Mac packages.
        assert!(check_platform("windows-x86_64", InstallerTarget::LinuxX86_64).is_err());
        assert!(check_platform("macos-arm64", InstallerTarget::LinuxX86_64).is_err());

        // Architecture mismatch (same OS).
        let err = check_platform("macos-arm64", InstallerTarget::MacosX86_64).unwrap_err();
        assert!(err.to_string().contains("architecture"), "err={err}");

        // Unknown target.
        let err = check_platform("linux-aarch64", InstallerTarget::LinuxX86_64).unwrap_err();
        assert!(err.to_string().contains("unknown"), "err={err}");
    }

    #[test]
    fn version_comparison() {
        let gt = |a: &str, b: &str| parse_version_triple(a) > parse_version_triple(b);
        assert!(gt("0.2.0", "0.1.0"));
        assert!(gt("1.0.0", "0.9.9"));
        assert!(!gt("0.1.0", "0.1.0"));
        assert!(!gt("0.0.9", "0.1.0"));
        assert!(gt("0.1.1", "0.1.0"));
        assert!(gt("99.0.0", "0.1.0"));
    }

    #[test]
    fn version_parse_is_strict() {
        assert_eq!(parse_version_triple("0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_version_triple("99.0.0"), Some((99, 0, 0)));
        // Malformed / truncated / extra / signed / overflow never coerce to 0.
        assert_eq!(parse_version_triple(""), None);
        assert_eq!(parse_version_triple("0.1"), None);
        assert_eq!(parse_version_triple("0.1.0.0"), None);
        assert_eq!(parse_version_triple("abc.0.0"), None);
        assert_eq!(parse_version_triple("-1.0.0"), None);
        assert_eq!(parse_version_triple("01.0.0"), None);
        assert_eq!(parse_version_triple("1.0.0-rc1"), None);
        assert_eq!(parse_version_triple("99999999999.0.0"), None);
    }

    #[test]
    fn sha256_hex_produces_correct_output() {
        // SHA-256 of empty string.
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
