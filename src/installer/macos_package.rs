//! Exact target-bound verification for the approved macOS package shape.
//!
//! This is library-only signed-manifest and artifact verification against a
//! caller-supplied key. It is not authenticated trust, a working macOS
//! installer, or launchd lifecycle authority. It does not observe a service
//! identity, write a plist, load a daemon, or enable installation. The separate
//! read-only `machine::plan_v2_macos` path uses this verifier to produce a
//! review plan; apply/install remains unavailable.

use std::path::Path;

use crate::error::{AppError, AppResult};

use super::adapter::CommandAdapter;
use super::manifest::{self, VerifiedManifest};
use super::models::{ArtifactEntry, InstallerTarget, PackageManifest};
use super::package_fs::{PackageFsError, PinnedEntryKind};

/// The only signed artifact allowed in the approved macOS package.
pub const MACOS_ARTIFACT_PATH: &str = "artifacts/hs-server";

/// Exact package-root entries for the approved macOS package shape.
///
/// This is macOS-only policy. The shared Linux verifier remains
/// artifact-directory-scoped for legacy compatibility.
pub const MACOS_ROOT_ENTRIES: [&str; 3] = ["manifest.json", "manifest.sig", "artifacts"];

/// A verified macOS package whose root entries and signed artifact set match
/// the approved macOS shape: exactly `manifest.json`, `manifest.sig`, and the
/// `artifacts/` directory, with exactly one artifact at
/// `artifacts/hs-server`.
///
/// The inner manifest evidence stays private so a caller can obtain this type
/// only through the verification constructors, which perform the exact root
/// and artifact-set checks after shared signature and content verification.
/// Verification is a point-in-time snapshot; re-verify if package bytes or
/// trust inputs can have changed before any later action.
#[derive(Debug, Clone)]
pub struct VerifiedMacosPackage {
    verified: VerifiedManifest,
}

impl VerifiedMacosPackage {
    /// Shared manifest evidence for the exact signed bytes.
    pub fn verified_manifest(&self) -> &VerifiedManifest {
        &self.verified
    }

    /// Parsed manifest whose signature and artifact were verified.
    pub fn manifest(&self) -> &PackageManifest {
        self.verified.manifest()
    }

    /// Target supplied by the trusted caller and matched by the manifest.
    pub fn target(&self) -> InstallerTarget {
        self.verified.target()
    }

    /// The sole signed artifact, always `artifacts/hs-server`.
    ///
    /// The constructor checks the artifact count and path, so indexing is
    /// total for this type.
    pub fn artifact(&self) -> &ArtifactEntry {
        &self.manifest().artifacts[0]
    }

    /// Re-read the sole artifact through the held package handle with a size
    /// and digest re-check.
    pub fn read_artifact(&self) -> AppResult<Vec<u8>> {
        self.verified.read_artifact(MACOS_ARTIFACT_PATH)
    }
}

/// Verify a signed macOS package and require exactly `artifacts/hs-server`.
///
/// This is library-only verification against a caller-supplied key. It does
/// not authenticate trust, install a service, load launchd, or authorize a
/// macOS apply. Target binding, exact-byte digest, symlink refusal, and bounded
/// descriptor-relative reads come from the shared verifier. This wrapper adds
/// only the exact macOS artifact-set check. It does not inspect the Mach-O
/// architecture, code signature, or notarization ticket; those remain separate
/// policy.
pub fn verify_macos_package_for_target(
    adapter: &dyn CommandAdapter,
    package_dir: &Path,
    verifying_key_bytes: &[u8; 32],
    target: InstallerTarget,
) -> AppResult<VerifiedMacosPackage> {
    require_macos_target(target)?;
    let verified = manifest::verify_manifest_for_target_verified(
        adapter,
        package_dir,
        verifying_key_bytes,
        target,
    )?;
    exact_macos_package(verified)
}

/// Verify a real on-disk macOS package through a pinned Unix directory handle.
///
/// This is still library-only evidence. It does not install, load a daemon, or
/// authorize a macOS apply.
#[cfg(unix)]
pub fn verify_macos_package_for_target_real(
    package_dir: &Path,
    verifying_key_bytes: &[u8; 32],
    target: InstallerTarget,
) -> AppResult<VerifiedMacosPackage> {
    require_macos_target(target)?;
    let verified =
        manifest::verify_manifest_for_target_real(package_dir, verifying_key_bytes, target)?;
    exact_macos_package(verified)
}

fn require_macos_target(target: InstallerTarget) -> AppResult<()> {
    if matches!(
        target,
        InstallerTarget::MacosArm64 | InstallerTarget::MacosX86_64
    ) {
        Ok(())
    } else {
        Err(AppError::bad_request(
            "macOS package verification requires macos-arm64 or macos-x86_64",
        ))
    }
}

fn exact_macos_package(verified: VerifiedManifest) -> AppResult<VerifiedMacosPackage> {
    enforce_exact_root_shape(&verified)?;
    if verified.manifest().artifacts.len() != 1
        || verified.manifest().artifacts[0].path != MACOS_ARTIFACT_PATH
    {
        return Err(AppError::unprocessable(format!(
            "macOS package must contain exactly one artifact: {MACOS_ARTIFACT_PATH}"
        )));
    }
    Ok(VerifiedMacosPackage { verified })
}

/// Enforce the approved macOS root shape through the held package handle.
///
/// Shared verification intentionally walks only `artifacts/` for legacy Linux
/// packages. The macOS wrapper must additionally reject extra root files,
/// directories, or symlinks before a package can be treated as the approved
/// macOS shape.
fn enforce_exact_root_shape(verified: &VerifiedManifest) -> AppResult<()> {
    let entries = verified
        .package()
        .list_dir("")
        .map_err(map_root_list_error)?;

    for entry in &entries {
        if !MACOS_ROOT_ENTRIES.contains(&entry.name.as_str()) {
            return Err(match entry.kind {
                PinnedEntryKind::Symlink => AppError::forbidden(format!(
                    "macOS package root must not contain an extra symlink: {}",
                    entry.name
                )),
                _ => AppError::unprocessable(format!(
                    "macOS package root contains an unapproved entry: {}",
                    entry.name
                )),
            });
        }
    }
    if entries.len() != MACOS_ROOT_ENTRIES.len() {
        return Err(AppError::unprocessable(
            "macOS package root must contain exactly manifest.json, manifest.sig, and artifacts",
        ));
    }
    for expected in MACOS_ROOT_ENTRIES {
        let entry = entries
            .iter()
            .find(|entry| entry.name == expected)
            .ok_or_else(|| {
                AppError::unprocessable(format!(
                    "macOS package root is missing required entry: {expected}"
                ))
            })?;
        let expected_kind = if expected == "artifacts" {
            PinnedEntryKind::Directory
        } else {
            PinnedEntryKind::File
        };
        if entry.kind != expected_kind {
            return Err(match entry.kind {
                PinnedEntryKind::Symlink => AppError::forbidden(format!(
                    "macOS package root entry must not be a symlink: {expected}"
                )),
                _ => AppError::unprocessable(format!(
                    "macOS package root entry has the wrong type: {expected}"
                )),
            });
        }
    }
    Ok(())
}

fn map_root_list_error(error: PackageFsError) -> AppError {
    match error {
        PackageFsError::Symlink(_) | PackageFsError::NotDirectory(_) => {
            AppError::forbidden(format!("cannot inspect macOS package root: {error}"))
        }
        PackageFsError::TooLarge { .. } | PackageFsError::Changed(_) => AppError::unprocessable(
            format!("macOS package root is not bounded or stable: {error}"),
        ),
        PackageFsError::InvalidPath(_)
        | PackageFsError::Missing(_)
        | PackageFsError::Uninspectable(_)
        | PackageFsError::NotRegular(_)
        | PackageFsError::SizeMismatch { .. }
        | PackageFsError::Unsupported(_)
        | PackageFsError::Other(_) => {
            AppError::bad_request(format!("cannot inspect macOS package root: {error}"))
        }
    }
}
