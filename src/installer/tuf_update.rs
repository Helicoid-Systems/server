//! TUF-backed release verification and staging.
//!
//! This is the metadata and package verification half of the updater. It does
//! not replace the running service or claim that a staged package is installed.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use tough::{DefaultTransport, ExpirationEnforcement, Prefix, RepositoryLoader, TargetName};
use url::Url;

use super::adapter::{CommandAdapter, LifecycleLockError};
use super::manifest::verify_manifest_for_target;
use super::models::{InstallerTarget, PackageManifest};
use crate::error::{AppError, AppResult};

const MAX_ROOT_METADATA_BYTES: usize = 1024 * 1024;
const RELEASE_CUSTOM_KEY: &str = "helicoid_release";

/// Application release metadata attached to the signed TUF target entry for
/// `manifest.json`. Artifact byte length and digests remain in TUF's target
/// metadata; the existing package manifest independently binds them as well.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseMetadata {
    pub format_version: u32,
    pub product: String,
    pub version: String,
    pub platform: String,
    pub source_commit: String,
    pub release_sequence: u64,
    pub security_revision: u64,
    pub minimum_security_revision: u64,
    pub min_schema_version: i64,
    pub max_schema_version: i64,
    pub min_installer_version: String,
}

/// The metadata versions accepted from the loaded, signature-verified TUF
/// repository. Tough persists timestamp/snapshot/targets state in the
/// configured datastore to reject older metadata on later loads.
#[derive(Debug, Clone, Serialize)]
pub struct TufMetadataVersions {
    pub root: u64,
    pub timestamp: u64,
    pub snapshot: u64,
    pub targets: u64,
}

/// A package staged only after both TUF target verification and the package's
/// existing independent Ed25519 manifest signature check have succeeded.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedTufRelease {
    pub contract_version: u32,
    pub release: ReleaseMetadata,
    pub metadata_versions: TufMetadataVersions,
    pub package_dir: PathBuf,
    pub manifest: PackageManifest,
}

/// Verify repository metadata with an out-of-band trusted root, persist TUF's
/// rollback datastore, download the signed package targets, and verify the
/// existing package signature and artifact list before returning its staging
/// directory. The caller chooses `target` from trusted host/preflight facts.
pub async fn verify_and_stage_release(
    adapter: &dyn CommandAdapter,
    trusted_root: &[u8],
    metadata_base_url: Url,
    targets_base_url: Url,
    manifest_target: &str,
    package_verifying_key: &[u8; 32],
    target: InstallerTarget,
    state_dir: &Path,
) -> AppResult<VerifiedTufRelease> {
    if trusted_root.is_empty() || trusted_root.len() > MAX_ROOT_METADATA_BYTES {
        return Err(AppError::unprocessable(format!(
            "trusted TUF root metadata must be between 1 and {MAX_ROOT_METADATA_BYTES} bytes"
        )));
    }
    validate_repository_url(&metadata_base_url)?;
    validate_repository_url(&targets_base_url)?;
    validate_state_dir(state_dir)?;
    let _operation_lock = adapter
        .acquire_lifecycle_operation_lock(state_dir)
        .map_err(|error| match error {
            LifecycleLockError::Busy => AppError::conflict(
                "another installer lifecycle operation is already in progress",
                None,
            ),
            LifecycleLockError::Unavailable(error) => {
                AppError::internal(format!("cannot acquire installer lifecycle lock: {error}"))
            }
        })?;

    let manifest_name = canonical_target_name(manifest_target)?;
    let release_dir = validate_release_target(manifest_name.raw(), target)?;

    let tuf_dir = state_dir.join("tuf");
    ensure_private_directory(&tuf_dir)?;
    let datastore = tuf_dir.join("datastore");
    ensure_private_directory(&datastore)?;

    let trusted_root = trusted_root.to_vec();
    let repository = RepositoryLoader::new(&trusted_root, metadata_base_url, targets_base_url)
        .transport(DefaultTransport::new())
        .datastore(&datastore)
        .expiration_enforcement(ExpirationEnforcement::Safe)
        .load()
        .await
        .map_err(|error| {
            AppError::forbidden(format!("TUF repository verification failed: {error}"))
        })?;

    if repository.targets().signed.targets.len() > 100_000 {
        return Err(AppError::unprocessable(
            "TUF targets metadata contains too many targets",
        ));
    }
    let signed_target = repository
        .targets()
        .signed
        .targets
        .get(&manifest_name)
        .ok_or_else(|| {
            AppError::not_found("TUF repository does not contain the requested release manifest")
        })?;
    if signed_target.length == 0 || signed_target.length > 1024 * 1024 {
        return Err(AppError::unprocessable(
            "TUF release manifest target exceeds the supported size",
        ));
    }
    let metadata_value = signed_target
        .custom
        .get(RELEASE_CUSTOM_KEY)
        .cloned()
        .ok_or_else(|| AppError::unprocessable("release target lacks helicoid_release metadata"))?;
    let release: ReleaseMetadata = serde_json::from_value(metadata_value).map_err(|_| {
        AppError::unprocessable("release target has invalid helicoid_release metadata")
    })?;
    validate_release_metadata(&release, target)?;

    let signature_name = canonical_target_name(&format!("{release_dir}/manifest.sig"))?;
    let signature_target = require_target(&repository, &signature_name)?;
    if signature_target.length != 64 {
        return Err(AppError::unprocessable(
            "TUF package signature target must be exactly 64 bytes",
        ));
    }

    let staging_root = state_dir.join("updates");
    ensure_private_directory(&staging_root)?;
    let stage_dir = create_unique_stage(&staging_root)?;
    let mut cleanup = RemoveOnDrop(Some(stage_dir.clone()));

    repository
        .save_target(&manifest_name, &stage_dir, Prefix::None)
        .await
        .map_err(|error| {
            AppError::forbidden(format!("TUF manifest target verification failed: {error}"))
        })?;
    repository
        .save_target(&signature_name, &stage_dir, Prefix::None)
        .await
        .map_err(|error| {
            AppError::forbidden(format!("TUF signature target verification failed: {error}"))
        })?;

    let package_dir = stage_dir.join(&release_dir);
    let manifest_bytes = adapter
        .read_file(&package_dir.join("manifest.json"))
        .map_err(|error| {
            AppError::bad_request(format!("read verified TUF manifest target: {error}"))
        })?;
    if manifest_bytes.len() > 1024 * 1024 {
        return Err(AppError::unprocessable(
            "verified TUF manifest target exceeds the supported size",
        ));
    }
    let parsed_manifest: PackageManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| AppError::unprocessable("verified TUF manifest target is invalid JSON"))?;
    if parsed_manifest.artifacts.is_empty() || parsed_manifest.artifacts.len() > 256 {
        return Err(AppError::unprocessable(
            "verified TUF manifest target has an invalid artifact count",
        ));
    }
    if parsed_manifest.product != release.product
        || parsed_manifest.version != release.version
        || parsed_manifest.platform != release.platform
        || parsed_manifest.min_schema_version != release.min_schema_version
        || parsed_manifest.min_installer_version != release.min_installer_version
    {
        return Err(AppError::forbidden(
            "TUF release metadata does not match the package manifest",
        ));
    }

    for artifact in &parsed_manifest.artifacts {
        let target_path = canonical_target_name(&format!("{release_dir}/{}", artifact.path))?;
        let tuf_target = require_target(&repository, &target_path)?;
        if tuf_target.length > super::manifest::MAX_ARTIFACT_BYTES {
            return Err(AppError::unprocessable(format!(
                "TUF artifact target '{}' exceeds the supported size",
                artifact.path
            )));
        }
        repository
            .save_target(&target_path, &stage_dir, Prefix::None)
            .await
            .map_err(|error| {
                AppError::forbidden(format!("TUF artifact target verification failed: {error}"))
            })?;
    }

    // Re-run package verification after the TUF targets have been materialized.
    // This validates the Ed25519 package signature and all artifact bytes/sizes.
    let manifest =
        verify_manifest_for_target(adapter, &package_dir, package_verifying_key, target)?;

    let metadata_versions = TufMetadataVersions {
        root: repository.root().signed.version.get(),
        timestamp: repository.timestamp().signed.version.get(),
        snapshot: repository.snapshot().signed.version.get(),
        targets: repository.targets().signed.version.get(),
    };

    // Ensure staged targets are read-only by default after all verification.
    make_tree_read_only(&package_dir)?;
    cleanup.0 = None;

    Ok(VerifiedTufRelease {
        contract_version: 1,
        release,
        metadata_versions,
        package_dir,
        manifest,
    })
}

fn validate_repository_url(url: &Url) -> AppResult<()> {
    if !matches!(url.scheme(), "https" | "http" | "file")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (matches!(url.scheme(), "https" | "http") && url.host_str().is_none())
    {
        return Err(AppError::bad_request(
            "TUF repository URLs must use HTTPS, HTTP, or file URLs without credentials, query, or fragment",
        ));
    }
    Ok(())
}

fn validate_state_dir(state_dir: &Path) -> AppResult<()> {
    if !state_dir.is_absolute()
        || state_dir
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(AppError::bad_request(
            "TUF state directory must be an absolute path without parent traversal",
        ));
    }
    ensure_private_directory(state_dir)
}

fn ensure_private_directory(path: &Path) -> AppResult<()> {
    reject_symlink_ancestors(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AppError::forbidden(format!(
                    "TUF state path is not a regular directory: {}",
                    path.display()
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o022 != 0 {
                    return Err(AppError::forbidden(format!(
                        "TUF state directory is group- or world-writable: {}",
                        path.display()
                    )));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|error| {
                AppError::internal(format!(
                    "create TUF state directory '{}': {error}",
                    path.display()
                ))
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
                    AppError::internal(format!(
                        "protect TUF state directory '{}': {error}",
                        path.display()
                    ))
                })?;
            }
        }
        Err(error) => {
            return Err(AppError::internal(format!(
                "inspect TUF state directory '{}': {error}",
                path.display()
            )))
        }
    }
    Ok(())
}

fn reject_symlink_ancestors(path: &Path) -> AppResult<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AppError::forbidden(format!(
                    "TUF state path traverses a symbolic link: {}",
                    current.display()
                )))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(AppError::internal(format!(
                    "inspect TUF state path '{}': {error}",
                    current.display()
                )))
            }
        }
    }
    Ok(())
}

fn canonical_target_name(value: &str) -> AppResult<TargetName> {
    let name = TargetName::try_from(value)
        .map_err(|_| AppError::bad_request("invalid TUF target path"))?;
    if name.raw() != name.resolved() || name.raw().len() > 512 || name.raw().starts_with('/') {
        return Err(AppError::bad_request("TUF target path is not canonical"));
    }
    Ok(name)
}

fn validate_release_target(value: &str, target: InstallerTarget) -> AppResult<String> {
    let parts: Vec<&str> = value.split('/').collect();
    if parts.len() != 4
        || parts[0] != "releases"
        || parts[1] != target.platform_str()
        || parts[3] != "manifest.json"
        || !valid_version(parts[2])
    {
        return Err(AppError::bad_request(
            "release manifest target must be releases/<trusted-platform>/<version>/manifest.json",
        ));
    }
    Ok(parts[..3].join("/"))
}

fn validate_release_metadata(metadata: &ReleaseMetadata, target: InstallerTarget) -> AppResult<()> {
    if metadata.format_version != 1
        || metadata.product != "hs-server"
        || metadata.platform != target.platform_str()
        || !valid_version(&metadata.version)
        || metadata.release_sequence == 0
        || metadata.security_revision == 0
        || metadata.minimum_security_revision == 0
        || metadata.security_revision < metadata.minimum_security_revision
        || metadata.min_schema_version < 1
        || metadata.max_schema_version < metadata.min_schema_version
        || !(metadata.min_schema_version..=metadata.max_schema_version)
            .contains(&crate::db::SCHEMA_VERSION)
        || !valid_version(&metadata.min_installer_version)
        || !valid_source_commit(&metadata.source_commit)
    {
        return Err(AppError::unprocessable(
            "TUF release metadata is malformed or incompatible with this installer",
        ));
    }
    Ok(())
}

fn valid_version(value: &str) -> bool {
    let mut components = value.split('.');
    let Some(major) = components.next() else {
        return false;
    };
    let Some(minor) = components.next() else {
        return false;
    };
    let Some(patch) = components.next() else {
        return false;
    };
    components.next().is_none()
        && [major, minor, patch].into_iter().all(|part| {
            !part.is_empty()
                && (part == "0" || !part.starts_with('0'))
                && part.len() <= 10
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u32>().is_ok()
        })
}

fn valid_source_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

fn require_target<'a>(
    repository: &'a tough::Repository,
    name: &TargetName,
) -> AppResult<&'a tough::schema::Target> {
    repository
        .targets()
        .signed
        .targets
        .get(name)
        .ok_or_else(|| {
            AppError::unprocessable(format!(
                "TUF release package is missing required target '{}'",
                name.raw()
            ))
        })
}

fn create_unique_stage(parent: &Path) -> AppResult<PathBuf> {
    for _ in 0..16 {
        let path = parent.join(format!(
            "stage-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(
                        |error| {
                            AppError::internal(format!("protect TUF staging directory: {error}"))
                        },
                    )?;
                }
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(AppError::internal(format!(
                    "create TUF staging directory: {error}"
                )))
            }
        }
    }
    Err(AppError::internal(
        "could not allocate a unique TUF staging directory",
    ))
}

fn make_tree_read_only(path: &Path) -> AppResult<()> {
    for entry in fs::read_dir(path)
        .map_err(|error| AppError::internal(format!("inspect staged release directory: {error}")))?
    {
        let entry = entry.map_err(|error| {
            AppError::internal(format!("inspect staged release entry: {error}"))
        })?;
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path).map_err(|error| {
            AppError::internal(format!("inspect staged release entry: {error}"))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(AppError::forbidden(
                "TUF staged package contains a symbolic link",
            ));
        }
        if metadata.is_dir() {
            make_tree_read_only(&entry_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&entry_path, fs::Permissions::from_mode(0o500)).map_err(
                    |error| {
                        AppError::internal(format!("protect staged package directory: {error}"))
                    },
                )?;
            }
        } else if metadata.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&entry_path, fs::Permissions::from_mode(0o400)).map_err(
                    |error| AppError::internal(format!("protect staged package file: {error}")),
                )?;
            }
        } else {
            return Err(AppError::forbidden(
                "TUF staged package contains a non-regular file",
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o500)).map_err(|error| {
            AppError::internal(format!("protect staged package directory: {error}"))
        })?;
    }
    Ok(())
}

struct RemoveOnDrop(Option<PathBuf>);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}
