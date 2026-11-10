//! Real-filesystem regression tests for pinned package-directory custody.
//!
//! Every package here is a disposable directory with throwaway Ed25519 keys.
//! No service is installed, no privileged operation is used, and no package
//! script is involved.

#![cfg(unix)]

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use hs_server::error::ErrorCode;
use hs_server::installer::macos_package::verify_macos_package_for_target_real;
use hs_server::installer::manifest::{self, verify_manifest_for_target_real};
use hs_server::installer::models::{ArtifactEntry, InstallerTarget, PackageManifest};
use hs_server::installer::package_fs::{PinnedPackage, PinnedReadPolicy, UnixPinnedPackage};
use serde_json::Value;

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path().canonicalize().expect("canonical tempdir");
    (temp, base)
}

fn manifest_for(platform: &str, path: &str, bytes: &[u8]) -> PackageManifest {
    PackageManifest {
        format_version: 1,
        product: "hs-server".to_string(),
        version: "0.1.0".to_string(),
        platform: platform.to_string(),
        min_schema_version: 1,
        min_installer_version: "0.1.0".to_string(),
        artifacts: vec![ArtifactEntry {
            path: path.to_string(),
            sha256: manifest::sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        }],
    }
}

fn write_manifest_and_signature(
    root: &Path,
    key: &SigningKey,
    manifest: &PackageManifest,
) -> Vec<u8> {
    fs::create_dir_all(root.join("artifacts")).expect("artifacts dir");
    let json = serde_json::to_vec_pretty(manifest).expect("manifest JSON");
    let signature = key.sign(&json);
    fs::write(root.join("manifest.json"), &json).expect("manifest write");
    fs::write(root.join("manifest.sig"), signature.to_bytes()).expect("signature write");
    json
}

fn write_artifact(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("artifact parent");
    }
    fs::write(path, bytes).expect("artifact write");
}

fn write_package(
    root: &Path,
    key: &SigningKey,
    manifest: &PackageManifest,
    bytes: &[u8],
) -> Vec<u8> {
    let json = write_manifest_and_signature(root, key, manifest);
    write_artifact(root, &manifest.artifacts[0].path, bytes);
    json
}

fn make_fifo(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fifo parent");
    }
    let name = CString::new(path.as_os_str().as_bytes()).expect("fifo path");
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
}

#[test]
fn real_package_holds_custody_after_path_replacement() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    let key = signing_key(7);
    let manifest = manifest_for("macos-arm64", "artifacts/hs-server", b"real-server");
    let json = write_package(&root, &key, &manifest, b"real-server");

    let verified = verify_manifest_for_target_real(
        &root,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect("real package verifies");
    assert_eq!(verified.manifest_sha256(), manifest::sha256_hex(&json));
    assert_eq!(
        verified
            .package()
            .read_file(
                "artifacts/hs-server",
                PinnedReadPolicy::Exact(b"real-server".len() as u64),
            )
            .expect("pinned artifact read")
            .bytes,
        b"real-server"
    );

    // Replace the caller's path with a different, otherwise valid package.
    let moved = base.join("moved");
    fs::rename(&root, &moved).expect("rename original package");
    let other = manifest_for("macos-arm64", "artifacts/hs-server", b"other-server");
    write_package(&root, &key, &other, b"other-server");

    // The verified handle still reads the original inode, not the new path.
    assert_eq!(
        verified
            .package()
            .read_file(
                "artifacts/hs-server",
                PinnedReadPolicy::Exact(b"real-server".len() as u64),
            )
            .expect("pinned artifact read after replacement")
            .bytes,
        b"real-server"
    );
    verified.package().verify_root().expect("root identity");
    assert_eq!(verified.manifest_sha256(), manifest::sha256_hex(&json));
    assert_eq!(
        verified
            .read_artifact("artifacts/hs-server")
            .expect("re-read through held handle"),
        b"real-server"
    );

    // A mutate-in-place after verification fails the held-handle digest check.
    fs::write(moved.join("artifacts/hs-server"), b"evil-server").expect("mutate source");
    let error = verified
        .read_artifact("artifacts/hs-server")
        .expect_err("changed artifact must refuse");
    assert_eq!(error.code(), ErrorCode::Forbidden);
}

#[test]
fn real_package_rejects_trailing_slash_symlink_and_dangling_symlink() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    let key = signing_key(7);
    let manifest = manifest_for("macos-arm64", "artifacts/hs-server", b"server");
    write_package(&root, &key, &manifest, b"server");

    let with_trailing = PathBuf::from(format!("{}/", root.display()));
    verify_manifest_for_target_real(
        &with_trailing,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect("trailing slash is normalized, not followed");

    let alias = base.join("alias");
    symlink(&root, &alias).expect("package symlink");
    let alias_trailing = PathBuf::from(format!("{}/", alias.display()));
    let error = verify_manifest_for_target_real(
        &alias_trailing,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect_err("symlinked package path must refuse");
    assert_eq!(error.code(), ErrorCode::Forbidden);

    let dangling = base.join("dangling");
    symlink(base.join("missing"), &dangling).expect("dangling symlink");
    let error = verify_manifest_for_target_real(
        &dangling,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect_err("dangling package symlink must refuse");
    assert_eq!(error.code(), ErrorCode::Forbidden);

    let ancestor_alias = base.join("ancestor-alias");
    symlink(&base, &ancestor_alias).expect("ancestor symlink");
    let through_ancestor = ancestor_alias.join("package");
    let error = verify_manifest_for_target_real(
        &through_ancestor,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect_err("symlinked ancestor must refuse");
    assert_eq!(error.code(), ErrorCode::Forbidden);
}

#[test]
fn real_package_fifo_manifest_is_refused_without_hanging() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    fs::create_dir_all(&root).expect("package dir");
    make_fifo(&root.join("manifest.json"));

    let key = signing_key(7);
    let error = verify_manifest_for_target_real(
        &root,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect_err("FIFO manifest must refuse");
    assert_eq!(error.code(), ErrorCode::BadRequest);
}

#[test]
fn real_package_artifact_fifo_is_refused() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    let key = signing_key(7);
    let bytes = b"real-server";
    let manifest = manifest_for("macos-arm64", "artifacts/hs-server", bytes);
    write_manifest_and_signature(&root, &key, &manifest);
    make_fifo(&root.join("artifacts/hs-server"));

    let error = verify_manifest_for_target_real(
        &root,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect_err("FIFO artifact must refuse");
    assert_eq!(error.code(), ErrorCode::Forbidden);
}

#[test]
fn real_package_oversized_manifest_remains_unprocessable() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    fs::create_dir_all(&root).expect("package dir");
    fs::write(root.join("manifest.json"), vec![b' '; 1024 * 1024 + 1]).expect("oversize manifest");

    let key = signing_key(7);
    let error = verify_manifest_for_target_real(
        &root,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect_err("oversized manifest must refuse");
    assert_eq!(error.code(), ErrorCode::Unprocessable);
    assert!(error.to_string().contains("exceeds"), "error={error}");
}

#[test]
fn real_package_oversized_artifact_is_unprocessable_and_bounded() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    let key = signing_key(7);
    let manifest = manifest_for("macos-arm64", "artifacts/hs-server", b"four");
    write_manifest_and_signature(&root, &key, &manifest);
    write_artifact(&root, "artifacts/hs-server", b"five!");

    let error = verify_manifest_for_target_real(
        &root,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect_err("oversized artifact must refuse");
    assert_eq!(error.code(), ErrorCode::Unprocessable);
}

#[test]
fn real_package_unreadable_directory_is_bad_request() {
    if unsafe { libc::geteuid() } == 0 {
        // Root bypasses directory permissions; the TestAdapter metadata-failure
        // regression covers the fail-closed mapping deterministically.
        return;
    }
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    let key = signing_key(7);
    let manifest = manifest_for("macos-arm64", "artifacts/hs-server", b"server");
    write_package(&root, &key, &manifest, b"server");
    let mut permissions = fs::metadata(&root).expect("root metadata").permissions();
    permissions.set_mode(0o000);
    fs::set_permissions(&root, permissions).expect("remove read");

    let error = verify_manifest_for_target_real(
        &root,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect_err("unreadable package must refuse");
    let mut restore = fs::metadata(&root).expect("root metadata").permissions();
    restore.set_mode(0o700);
    fs::set_permissions(&root, restore).expect("restore read");
    assert_eq!(error.code(), ErrorCode::BadRequest);
}

#[test]
fn real_package_non_directory_metadata_is_bad_request() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    fs::write(&root, b"not a directory").expect("regular file at package path");

    let key = signing_key(7);
    let error = verify_manifest_for_target_real(
        &root,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect_err("non-directory package must refuse");
    assert_eq!(error.code(), ErrorCode::BadRequest);
}

#[test]
fn real_package_unknown_file_traversal_is_bounded() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    let key = signing_key(7);
    let nested = "artifacts/sub/dir/file";
    let manifest = manifest_for("macos-arm64", nested, b"nested");
    write_package(&root, &key, &manifest, b"nested");
    for index in 0..4096 {
        fs::write(
            root.join("artifacts/sub/dir")
                .join(format!("unknown-{index:04}")),
            b"",
        )
        .expect("unknown file");
    }

    let error = verify_manifest_for_target_real(
        &root,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect_err("oversized directory listing must refuse");
    assert_eq!(error.code(), ErrorCode::Forbidden);
}

#[test]
fn package_root_rejects_group_writable_directory() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    fs::create_dir_all(&root).expect("package dir");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).expect("group-writable root");

    let error = UnixPinnedPackage::open(&root).expect_err("group-writable root must refuse");
    assert!(
        error.to_string().contains("group- or world-writable"),
        "unexpected error: {error}"
    );
}

#[test]
fn package_ancestor_rejects_group_writable_directory() {
    let (_temp, base) = canonical_tempdir();
    let wide = base.join("wide");
    let root = wide.join("package");
    fs::create_dir_all(&root).expect("package dir");
    fs::set_permissions(&wide, fs::Permissions::from_mode(0o770)).expect("group-writable parent");

    let error = UnixPinnedPackage::open(&root).expect_err("group-writable ancestor must refuse");
    assert!(
        error.to_string().contains("group- or world-writable"),
        "unexpected error: {error}"
    );
}

#[test]
fn pinned_package_rechecks_root_permissions_before_returning_evidence() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    fs::create_dir_all(&root).expect("package dir");
    let package = UnixPinnedPackage::open(&root).expect("pin clean root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).expect("group-writable root");

    let error = package
        .verify_root()
        .expect_err("widened root must be refused");
    assert!(
        error.to_string().contains("group- or world-writable"),
        "unexpected error: {error}"
    );
}

#[test]
fn direct_pinned_reader_rejects_an_oversized_file_without_reopening() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    fs::create_dir_all(&root).expect("package dir");
    fs::write(root.join("large"), vec![b'x'; 32]).expect("large file");

    let package = UnixPinnedPackage::open(&root).expect("pin package");
    let error = package
        .read_file("large", PinnedReadPolicy::Max(16))
        .expect_err("bound must refuse");
    assert!(error.to_string().contains("exceeds"), "error={error}");
}

#[test]
fn real_macos_package_rejects_extra_root_file() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    let key = signing_key(7);
    let manifest = manifest_for("macos-arm64", "artifacts/hs-server", b"server");
    write_package(&root, &key, &manifest, b"server");
    fs::write(root.join("README"), b"unapproved").expect("extra root file");

    let error = verify_macos_package_for_target_real(
        &root,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect_err("extra root file must refuse");
    assert_eq!(error.code(), ErrorCode::Unprocessable);
}

#[test]
fn real_macos_package_rejects_extra_root_symlink() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    let key = signing_key(7);
    let manifest = manifest_for("macos-arm64", "artifacts/hs-server", b"server");
    write_package(&root, &key, &manifest, b"server");
    symlink(root.join("manifest.json"), root.join("extra-root-link")).expect("extra root symlink");

    let error = verify_macos_package_for_target_real(
        &root,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect_err("extra root symlink must refuse");
    assert_eq!(error.code(), ErrorCode::Forbidden);
}

#[test]
fn real_macos_wrapper_returns_the_exact_artifact_set() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    let key = signing_key(7);
    let manifest = manifest_for("macos-arm64", "artifacts/hs-server", b"server");
    write_package(&root, &key, &manifest, b"server");

    let verified = verify_macos_package_for_target_real(
        &root,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect("real macOS package verifies");
    assert_eq!(verified.target(), InstallerTarget::MacosArm64);
    assert_eq!(verified.artifact().path, "artifacts/hs-server");
    assert_eq!(
        verified
            .verified_manifest()
            .read_artifact("artifacts/hs-server")
            .expect("pinned artifact"),
        b"server"
    );
}

#[test]
fn real_manifest_digest_is_exact_signed_bytes() {
    let (_temp, base) = canonical_tempdir();
    let root = base.join("package");
    let key = signing_key(7);
    let manifest = manifest_for("macos-arm64", "artifacts/hs-server", b"server");
    let mut value = serde_json::to_value(&manifest).expect("manifest value");
    value.as_object_mut().expect("manifest object").insert(
        "unknown_extension".to_string(),
        Value::String("exact".to_string()),
    );
    let json = serde_json::to_vec_pretty(&value).expect("manifest JSON");
    fs::create_dir_all(root.join("artifacts")).expect("artifacts");
    fs::write(root.join("manifest.json"), &json).expect("manifest");
    fs::write(root.join("manifest.sig"), key.sign(&json).to_bytes()).expect("signature");
    fs::write(root.join("artifacts/hs-server"), b"server").expect("artifact");

    let verified = verify_manifest_for_target_real(
        &root,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect("verify");
    assert_eq!(verified.manifest_sha256(), manifest::sha256_hex(&json));
}
