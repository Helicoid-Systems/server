//! Package manifest verification: Ed25519 signature, SHA-256 integrity,
//! path safety, platform/schema/version compatibility.
//!
//! Trust anchor (verifying key) is supplied independently by app/packaging,
//! never read from the same unsigned package. No signing keys in repo.

use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use super::adapter::CommandAdapter;
use super::models::PackageManifest;
use crate::error::{AppError, AppResult};
use crate::installer::models::ArtifactEntry;

/// Minimum installer version that this build is compatible with.
const INSTALLER_VERSION: &str = "0.1.0";

/// Allowed artifact path prefix.
const ALLOWED_PREFIX: &str = "artifacts/";

/// Bounds on package parsing. A signed manifest is still attacker-shaped if the
/// signing key is wrong; keep parse and copy work bounded either way.
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_ARTIFACTS: usize = 256;
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARTIFACT_PATH_BYTES: usize = 256;

/// Verify the full package manifest:
/// 1. Parse manifest.json
/// 2. Verify Ed25519 signature (manifest.sig)
/// 3. Check platform = linux-x86_64
/// 4. Check min_schema_version <= SCHEMA_VERSION
/// 5. Check min_installer_version <= INSTALLER_VERSION
/// 6. Verify each artifact: safe path, sha256, size, no symlinks
/// 7. Ensure no unknown files in artifacts/ directory
pub fn verify_manifest(
    adapter: &dyn CommandAdapter,
    package_dir: &Path,
    verifying_key_bytes: &[u8; 32],
) -> AppResult<PackageManifest> {
    let manifest_path = package_dir.join("manifest.json");
    let sig_path = package_dir.join("manifest.sig");

    // Read manifest bytes.
    let manifest_bytes = adapter
        .read_file(&manifest_path)
        .map_err(|e| AppError::bad_request(format!("cannot read manifest.json: {e}")))?;

    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(AppError::unprocessable(format!(
            "manifest.json exceeds {} bytes",
            MAX_MANIFEST_BYTES
        )));
    }

    // Read signature bytes.
    let sig_bytes = adapter
        .read_file(&sig_path)
        .map_err(|e| AppError::bad_request(format!("cannot read manifest.sig: {e}")))?;

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

    // Verify Ed25519 signature.
    let verifying_key = VerifyingKey::from_bytes(verifying_key_bytes)
        .map_err(|e| AppError::bad_request(format!("invalid verifying key: {e}")))?;

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(&manifest_bytes, &signature)
        .map_err(|_| AppError::forbidden("manifest signature verification failed"))?;

    // Parse manifest JSON.
    let manifest: PackageManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| AppError::bad_request(format!("invalid manifest.json: {e}")))?;

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

    // Check platform.
    if manifest.platform != "linux-x86_64" {
        return Err(AppError::unprocessable(format!(
            "package platform '{}' does not match target linux-x86_64",
            manifest.platform
        )));
    }

    // Check schema version.
    if manifest.min_schema_version > crate::db::SCHEMA_VERSION {
        return Err(AppError::unprocessable(format!(
            "package requires schema version {} but installer supports {}",
            manifest.min_schema_version,
            crate::db::SCHEMA_VERSION
        )));
    }

    // Check installer version floor.
    if version_gt(&manifest.min_installer_version, INSTALLER_VERSION) {
        return Err(AppError::unprocessable(format!(
            "package requires installer version {} but running {}",
            manifest.min_installer_version, INSTALLER_VERSION
        )));
    }

    // Verify each artifact.
    verify_artifacts(adapter, package_dir, &manifest.artifacts)?;

    // Ensure no unknown files in artifacts/ directory.
    verify_no_unknown_files(adapter, package_dir, &manifest.artifacts)?;

    Ok(manifest)
}

/// Verify all artifacts: safe path, no symlinks, sha256, size.
fn verify_artifacts(
    adapter: &dyn CommandAdapter,
    package_dir: &Path,
    artifacts: &[ArtifactEntry],
) -> AppResult<()> {
    for artifact in artifacts {
        // Path safety: must be relative.
        if artifact.path.starts_with('/') {
            return Err(AppError::forbidden(format!(
                "artifact path must be relative: {}",
                artifact.path
            )));
        }

        if artifact.path.len() > MAX_ARTIFACT_PATH_BYTES {
            return Err(AppError::forbidden(format!(
                "artifact path too long (max {MAX_ARTIFACT_PATH_BYTES} bytes)"
            )));
        }

        // No traversal.
        if contains_traversal(&artifact.path) {
            return Err(AppError::forbidden(format!(
                "artifact path contains traversal: {}",
                artifact.path
            )));
        }

        // Must start with allowed prefix.
        if !artifact.path.starts_with(ALLOWED_PREFIX) {
            return Err(AppError::forbidden(format!(
                "artifact path not in allowed prefix '{}': {}",
                ALLOWED_PREFIX, artifact.path
            )));
        }

        if artifact.size_bytes > MAX_ARTIFACT_BYTES {
            return Err(AppError::unprocessable(format!(
                "artifact '{}' size {} exceeds bound {MAX_ARTIFACT_BYTES}",
                artifact.path, artifact.size_bytes
            )));
        }

        // Reject symlinked parents inside the package (escape via a/b -> /etc).
        reject_symlink_parents(adapter, package_dir, &artifact.path)?;

        // Check for symlinks.
        let full_path = package_dir.join(&artifact.path);
        let meta = adapter.symlink_metadata(&full_path).map_err(|e| {
            AppError::bad_request(format!("cannot stat artifact '{}': {e}", artifact.path))
        })?;

        if meta.is_symlink {
            return Err(AppError::forbidden(format!(
                "artifact is a symlink (not allowed): {}",
                artifact.path
            )));
        }

        // Verify size.
        if meta.len != artifact.size_bytes {
            return Err(AppError::unprocessable(format!(
                "artifact '{}' size mismatch: expected {} got {}",
                artifact.path, artifact.size_bytes, meta.len
            )));
        }

        // Verify SHA-256.
        let file_bytes = adapter.read_file(&full_path).map_err(|e| {
            AppError::bad_request(format!("cannot read artifact '{}': {e}", artifact.path))
        })?;

        let actual_hash = sha256_hex(&file_bytes);
        if actual_hash != artifact.sha256 {
            return Err(AppError::forbidden(format!(
                "artifact '{}' SHA-256 mismatch",
                artifact.path
            )));
        }
    }
    Ok(())
}

/// Ensure no files exist in artifacts/ that are not listed in the manifest.
fn verify_no_unknown_files(
    adapter: &dyn CommandAdapter,
    package_dir: &Path,
    artifacts: &[ArtifactEntry],
) -> AppResult<()> {
    let artifacts_dir = package_dir.join("artifacts");
    if !adapter.path_exists(&artifacts_dir) {
        return Ok(());
    }

    let entries = adapter
        .list_dir(&artifacts_dir)
        .map_err(|e| AppError::bad_request(format!("cannot list artifacts directory: {e}")))?;

    let known_paths: std::collections::HashSet<&str> =
        artifacts.iter().map(|a| a.path.as_str()).collect();

    for entry in entries {
        let entry_path = format!("artifacts/{entry}");
        if !known_paths.contains(entry_path.as_str()) {
            return Err(AppError::forbidden(format!(
                "unknown file in artifacts directory: {entry_path}"
            )));
        }
    }

    Ok(())
}

/// Check if a path contains `..` traversal components.
fn contains_traversal(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

/// Reject a package-relative path whose parent chain inside the package
/// contains a symlink. A symlinked parent would let a verified artifact be
/// read from (or later written to) a location outside the package tree.
fn reject_symlink_parents(
    adapter: &dyn CommandAdapter,
    package_dir: &Path,
    relative: &str,
) -> AppResult<()> {
    let mut current = package_dir.to_path_buf();
    let mut components: Vec<&str> = relative
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    // Drop the final file name; only parents are under review.
    components.pop();
    for component in components {
        current.push(component);
        if !adapter.path_exists(&current) {
            continue;
        }
        let meta = adapter.symlink_metadata(&current).map_err(|e| {
            AppError::bad_request(format!(
                "cannot stat package path '{}': {e}",
                current.display()
            ))
        })?;
        if meta.is_symlink {
            return Err(AppError::forbidden(format!(
                "package path component is a symlink: {}",
                relative
            )));
        }
    }
    Ok(())
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

/// Simple version comparison for semver-like strings (major.minor.patch).
/// Returns true if a > b.
fn version_gt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> (u64, u64, u64) {
        let parts: Vec<&str> = s.split('.').collect();
        let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        (major, minor, patch)
    };
    parse(a) > parse(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_detection() {
        assert!(contains_traversal("artifacts/../etc/passwd"));
        assert!(contains_traversal("foo/bar/../../baz"));
        assert!(!contains_traversal("artifacts/hs-server"));
        assert!(!contains_traversal("artifacts/sub/dir/file"));
    }

    #[test]
    fn version_comparison() {
        assert!(version_gt("0.2.0", "0.1.0"));
        assert!(version_gt("1.0.0", "0.9.9"));
        assert!(!version_gt("0.1.0", "0.1.0"));
        assert!(!version_gt("0.0.9", "0.1.0"));
        assert!(version_gt("0.1.1", "0.1.0"));
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
