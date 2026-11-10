//! Exact verified-byte manifest identity tests for the shared verifier seam.
//!
//! Packages are in-memory `TestAdapter` fixtures signed with throwaway test
//! keys. No real signing key, system path, or installation operation is used.

use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey};
use hs_server::error::ErrorCode;
use hs_server::installer::adapter::TestAdapter;
use hs_server::installer::macos_package::{verify_macos_package_for_target, MACOS_ARTIFACT_PATH};
use hs_server::installer::manifest::{self, verify_manifest_for_target_verified};
use hs_server::installer::models::{ArtifactEntry, InstallerTarget, PackageManifest};
use serde_json::Value;

const PACKAGE_DIR: &str = "/tmp/helicoid-verified-manifest";

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn base_manifest() -> PackageManifest {
    PackageManifest {
        format_version: 1,
        product: "hs-server".to_string(),
        version: "0.1.0".to_string(),
        platform: "macos-arm64".to_string(),
        min_schema_version: 1,
        min_installer_version: "0.1.0".to_string(),
        artifacts: vec![ArtifactEntry {
            path: "artifacts/hs-server".to_string(),
            sha256: manifest::sha256_hex(b"real-server"),
            size_bytes: b"real-server".len() as u64,
        }],
    }
}

fn write_package_files(
    adapter: &TestAdapter,
    key: &SigningKey,
    manifest_json: &[u8],
    files: &[(&str, &[u8])],
) {
    let package_dir = PathBuf::from(PACKAGE_DIR);
    let signature = key.sign(manifest_json);
    let mut fs = adapter.fs.lock().unwrap();
    fs.insert(package_dir.join("manifest.json"), manifest_json.to_vec());
    fs.insert(
        package_dir.join("manifest.sig"),
        signature.to_bytes().to_vec(),
    );
    for (path, bytes) in files {
        fs.insert(package_dir.join(path), bytes.to_vec());
    }
}

fn write_package(adapter: &TestAdapter, key: &SigningKey, manifest_json: &[u8], artifact: &[u8]) {
    write_package_files(
        adapter,
        key,
        manifest_json,
        &[("artifacts/hs-server", artifact)],
    );
}

fn signed_json_with_unknown_field(unknown_value: &str) -> (Vec<u8>, Vec<u8>) {
    let manifest = base_manifest();
    let mut value = serde_json::to_value(&manifest).expect("manifest value");
    value.as_object_mut().expect("manifest object").insert(
        "unknown_extension".to_string(),
        Value::String(unknown_value.to_string()),
    );
    let json = serde_json::to_vec_pretty(&value).expect("manifest JSON");
    (json, b"real-server".to_vec())
}

#[test]
fn digest_is_of_exact_signed_bytes_with_unknown_fields() {
    let key = signing_key(7);
    let target = InstallerTarget::MacosArm64;

    let adapter_a = TestAdapter::new();
    let (json_a, artifact_a) = signed_json_with_unknown_field("alpha");
    write_package(&adapter_a, &key, &json_a, &artifact_a);
    let verified_a = verify_manifest_for_target_verified(
        &adapter_a,
        std::path::Path::new(PACKAGE_DIR),
        &key.verifying_key().to_bytes(),
        target,
    )
    .expect("first package");

    let adapter_b = TestAdapter::new();
    let (json_b, artifact_b) = signed_json_with_unknown_field("beta");
    write_package(&adapter_b, &key, &json_b, &artifact_b);
    let verified_b = verify_manifest_for_target_verified(
        &adapter_b,
        std::path::Path::new(PACKAGE_DIR),
        &key.verifying_key().to_bytes(),
        target,
    )
    .expect("second package");

    assert_eq!(verified_a.target(), target);
    assert_eq!(verified_a.manifest_sha256(), manifest::sha256_hex(&json_a));
    assert_eq!(verified_b.manifest_sha256(), manifest::sha256_hex(&json_b));
    assert_ne!(verified_a.manifest_sha256(), verified_b.manifest_sha256());
    assert_eq!(
        verified_a.verifying_key_sha256(),
        manifest::sha256_hex(&key.verifying_key().to_bytes())
    );
    assert_eq!(verified_a.manifest().product, "hs-server");
}

#[test]
fn manifest_and_signature_symlinks_are_refused() {
    let key = signing_key(7);
    let target = InstallerTarget::MacosArm64;
    let (manifest_json, artifact) = signed_json_with_unknown_field("symlink");
    let package_dir = PathBuf::from(PACKAGE_DIR);

    let manifest_symlink = TestAdapter::new();
    write_package(&manifest_symlink, &key, &manifest_json, &artifact);
    manifest_symlink
        .symlinks
        .lock()
        .unwrap()
        .insert(package_dir.join("manifest.json"));
    let error = verify_manifest_for_target_verified(
        &manifest_symlink,
        &package_dir,
        &key.verifying_key().to_bytes(),
        target,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Forbidden);

    let signature_symlink = TestAdapter::new();
    write_package(&signature_symlink, &key, &manifest_json, &artifact);
    signature_symlink
        .symlinks
        .lock()
        .unwrap()
        .insert(package_dir.join("manifest.sig"));
    let error = verify_manifest_for_target_verified(
        &signature_symlink,
        &package_dir,
        &key.verifying_key().to_bytes(),
        target,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Forbidden);
}

#[test]
fn package_directory_symlink_and_uninspectable_metadata_are_refused() {
    let key = signing_key(7);
    let (json, artifact) = signed_json_with_unknown_field("directory");
    let directory = PathBuf::from(PACKAGE_DIR);
    let adapter = TestAdapter::new();
    write_package(&adapter, &key, &json, &artifact);
    adapter.symlinks.lock().unwrap().insert(directory.clone());
    let with_trailing_separator = PathBuf::from(format!("{PACKAGE_DIR}/"));
    let error = verify_manifest_for_target_verified(
        &adapter,
        &with_trailing_separator,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Forbidden);

    adapter.symlinks.lock().unwrap().clear();
    adapter
        .uninspectable_paths
        .lock()
        .unwrap()
        .insert(directory.clone());
    let error = verify_manifest_for_target_verified(
        &adapter,
        &directory,
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::BadRequest);
}

#[test]
fn bounded_manifest_and_signature_reads_refuse_oversize_before_parse() {
    let key = signing_key(7);
    let target = InstallerTarget::MacosArm64;
    let package_dir = PathBuf::from(PACKAGE_DIR);

    let oversized_manifest = TestAdapter::new();
    let (manifest_json, artifact) = signed_json_with_unknown_field("oversize");
    write_package(&oversized_manifest, &key, &manifest_json, &artifact);
    oversized_manifest.fs.lock().unwrap().insert(
        package_dir.join("manifest.json"),
        vec![0u8; 1024 * 1024 + 1],
    );
    let error = verify_manifest_for_target_verified(
        &oversized_manifest,
        &package_dir,
        &key.verifying_key().to_bytes(),
        target,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unprocessable);
    assert!(error.to_string().contains("exceeds"));

    let oversized_signature = TestAdapter::new();
    write_package(&oversized_signature, &key, &manifest_json, &artifact);
    oversized_signature
        .fs
        .lock()
        .unwrap()
        .insert(package_dir.join("manifest.sig"), vec![0u8; 65]);
    let error = verify_manifest_for_target_verified(
        &oversized_signature,
        &package_dir,
        &key.verifying_key().to_bytes(),
        target,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert!(error.to_string().contains("exceeds"));
}

#[test]
fn malformed_signed_json_is_refused_after_signature_verification() {
    let key = signing_key(7);
    let target = InstallerTarget::MacosArm64;
    let adapter = TestAdapter::new();
    let package_dir = PathBuf::from(PACKAGE_DIR);
    let malformed = b"{not valid manifest json".to_vec();
    let signature = key.sign(&malformed);
    {
        let mut fs = adapter.fs.lock().unwrap();
        fs.insert(package_dir.join("manifest.json"), malformed);
        fs.insert(
            package_dir.join("manifest.sig"),
            signature.to_bytes().to_vec(),
        );
        fs.insert(package_dir.join("artifacts/hs-server"), b"server".to_vec());
    }

    let error = verify_manifest_for_target_verified(
        &adapter,
        &package_dir,
        &key.verifying_key().to_bytes(),
        target,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::BadRequest);
}

#[test]
fn macos_exact_package_accepts_only_hs_server_artifact() {
    let key = signing_key(7);
    let adapter = TestAdapter::new();
    let (manifest_json, artifact) = signed_json_with_unknown_field("exact");
    write_package(&adapter, &key, &manifest_json, &artifact);
    let verified = verify_macos_package_for_target(
        &adapter,
        std::path::Path::new(PACKAGE_DIR),
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect("exact macOS package");
    assert_eq!(verified.target(), InstallerTarget::MacosArm64);
    assert_eq!(verified.manifest().artifacts.len(), 1);
    assert_eq!(verified.artifact().path, MACOS_ARTIFACT_PATH);
    assert_eq!(
        verified.verified_manifest().target(),
        InstallerTarget::MacosArm64
    );
}

#[test]
fn macos_package_rejects_extra_and_missing_signed_artifacts() {
    let key = signing_key(7);

    let extra_adapter = TestAdapter::new();
    let mut extra = base_manifest();
    extra.artifacts.push(ArtifactEntry {
        path: "artifacts/helicoid-server".to_string(),
        sha256: manifest::sha256_hex(b"unexpected-tui"),
        size_bytes: b"unexpected-tui".len() as u64,
    });
    let extra_json = serde_json::to_vec_pretty(&extra).expect("extra manifest");
    write_package_files(
        &extra_adapter,
        &key,
        &extra_json,
        &[
            ("artifacts/hs-server", b"real-server"),
            ("artifacts/helicoid-server", b"unexpected-tui"),
        ],
    );
    let error = verify_macos_package_for_target(
        &extra_adapter,
        std::path::Path::new(PACKAGE_DIR),
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unprocessable);

    let missing_adapter = TestAdapter::new();
    let mut missing = base_manifest();
    missing.artifacts = vec![ArtifactEntry {
        path: "artifacts/hs-server.service".to_string(),
        sha256: manifest::sha256_hex(b"not-a-macos-package"),
        size_bytes: b"not-a-macos-package".len() as u64,
    }];
    let missing_json = serde_json::to_vec_pretty(&missing).expect("missing manifest");
    write_package_files(
        &missing_adapter,
        &key,
        &missing_json,
        &[("artifacts/hs-server.service", b"not-a-macos-package")],
    );
    let error = verify_macos_package_for_target(
        &missing_adapter,
        std::path::Path::new(PACKAGE_DIR),
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unprocessable);
}

#[test]
fn macos_package_rejects_non_macos_targets() {
    let key = signing_key(7);
    let adapter = TestAdapter::new();
    let (manifest_json, artifact) = signed_json_with_unknown_field("non-macos");
    write_package(&adapter, &key, &manifest_json, &artifact);
    let error = verify_macos_package_for_target(
        &adapter,
        std::path::Path::new(PACKAGE_DIR),
        &key.verifying_key().to_bytes(),
        InstallerTarget::LinuxX86_64,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::BadRequest);
}

#[test]
fn legacy_target_wrapper_still_returns_the_manifest() {
    let key = signing_key(7);
    let adapter = TestAdapter::new();
    let (manifest_json, artifact) = signed_json_with_unknown_field("legacy");
    write_package(&adapter, &key, &manifest_json, &artifact);
    let manifest = hs_server::installer::manifest::verify_manifest_for_target(
        &adapter,
        std::path::Path::new(PACKAGE_DIR),
        &key.verifying_key().to_bytes(),
        InstallerTarget::MacosArm64,
    )
    .expect("legacy wrapper");
    assert_eq!(manifest.product, "hs-server");
    assert_eq!(manifest.platform, "macos-arm64");
}
