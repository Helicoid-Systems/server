//! Target-bound installer package verification: four frozen targets, strict
//! Ed25519 trust, portable artifact paths. Reuses `TestAdapter` fixtures.

use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hs_server::error::ErrorCode;
use hs_server::installer::adapter::{CommandAdapter, TestAdapter};
use hs_server::installer::manifest::{self, verify_manifest, verify_manifest_for_target};
use hs_server::installer::models::*;

/// Deterministic disposable test seed (not a production key).
fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn primary_signing_key() -> SigningKey {
    signing_key(7)
}

fn foreign_signing_key() -> SigningKey {
    signing_key(9)
}

fn manifest_for_platform(platform: &str) -> PackageManifest {
    PackageManifest {
        format_version: 1,
        product: "hs-server".to_string(),
        version: "0.1.0".to_string(),
        platform: platform.to_string(),
        min_schema_version: 1,
        min_installer_version: "0.1.0".to_string(),
        artifacts: vec![
            ArtifactEntry {
                path: "artifacts/hs-server".to_string(),
                sha256: manifest::sha256_hex(b"fake-binary-content"),
                size_bytes: b"fake-binary-content".len() as u64,
            },
            ArtifactEntry {
                path: "artifacts/hs-server.service".to_string(),
                sha256: manifest::sha256_hex(b"[Unit]\nDescription=hs\n"),
                size_bytes: b"[Unit]\nDescription=hs\n".len() as u64,
            },
            ArtifactEntry {
                path: "artifacts/sub/dir/file".to_string(),
                sha256: manifest::sha256_hex(b"nested-fixture"),
                size_bytes: b"nested-fixture".len() as u64,
            },
        ],
    }
}

/// Write a signed package for `platform` using `signing_key`.
/// Returns the package dir. Extra raw artifact bytes are inserted as-is.
fn write_package(
    adapter: &TestAdapter,
    signing_key: &SigningKey,
    manifest: &PackageManifest,
    extra: &[(String, Vec<u8>)],
) -> PathBuf {
    let package_dir = PathBuf::from("/tmp/test-package-targets");
    let manifest_json = serde_json::to_vec_pretty(manifest).unwrap();
    let signature = signing_key.sign(&manifest_json);
    let mut fs = adapter.fs.lock().unwrap();
    fs.insert(package_dir.join("manifest.json"), manifest_json);
    fs.insert(
        package_dir.join("manifest.sig"),
        signature.to_bytes().to_vec(),
    );
    for artifact in &manifest.artifacts {
        let content = match artifact.path.as_str() {
            "artifacts/hs-server" => b"fake-binary-content".to_vec(),
            "artifacts/hs-server.service" => b"[Unit]\nDescription=hs\n".to_vec(),
            "artifacts/sub/dir/file" => b"nested-fixture".to_vec(),
            _ => b"other".to_vec(),
        };
        fs.insert(package_dir.join(&artifact.path), content);
    }
    for (path, bytes) in extra {
        fs.insert(package_dir.join(path), bytes.clone());
    }
    drop(fs);
    package_dir
}

fn verify_all_targets_ok(signing_key: &SigningKey) {
    for target in InstallerTarget::ALL {
        let adapter = TestAdapter::new();
        let manifest = manifest_for_platform(target.platform_str());
        let package_dir = write_package(&adapter, signing_key, &manifest, &[]);
        let result = verify_manifest_for_target(
            &adapter,
            &package_dir,
            &signing_key.verifying_key().to_bytes(),
            target,
        );
        assert!(
            result.is_ok(),
            "target {:?} must verify: {:?}",
            target,
            result.err()
        );
        let verified = result.unwrap();
        assert_eq!(verified.platform, target.platform_str());
        assert_eq!(verified.product, "hs-server");
    }
}

// ---------------------------------------------------------------------------
// Four exact targets with real Ed25519 signatures
// ---------------------------------------------------------------------------

#[test]
fn all_four_targets_verify_with_real_signatures() {
    // One independently supplied key covers all four targets (same trust key).
    let signing_key = primary_signing_key();
    verify_all_targets_ok(&signing_key);
}

#[test]
fn linux_legacy_entry_accepts_only_linux_packages() {
    let signing_key = primary_signing_key();

    let adapter = TestAdapter::new();
    let linux = manifest_for_platform("linux-x86_64");
    let package_dir = write_package(&adapter, &signing_key, &linux, &[]);
    assert!(verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes()
    )
    .is_ok());

    for platform in ["windows-x86_64", "macos-arm64", "macos-x86_64"] {
        let adapter = TestAdapter::new();
        let manifest = manifest_for_platform(platform);
        let package_dir = write_package(&adapter, &signing_key, &manifest, &[]);
        let result = verify_manifest(
            &adapter,
            &package_dir,
            &signing_key.verifying_key().to_bytes(),
        );
        assert!(result.is_err(), "linux entry must reject {platform}");
        assert_eq!(result.unwrap_err().code(), ErrorCode::Unprocessable);
    }
}

// ---------------------------------------------------------------------------
// Wrong key / signature / target / architecture / unknown
// ---------------------------------------------------------------------------

#[test]
fn wrong_key_refuses_on_every_target() {
    let signing_key = primary_signing_key();
    let wrong_key = foreign_signing_key();
    for target in InstallerTarget::ALL {
        let adapter = TestAdapter::new();
        let manifest = manifest_for_platform(target.platform_str());
        let package_dir = write_package(&adapter, &signing_key, &manifest, &[]);
        let result = verify_manifest_for_target(
            &adapter,
            &package_dir,
            &wrong_key.verifying_key().to_bytes(),
            target,
        );
        assert!(result.is_err(), "wrong key must refuse for {target:?}");
        assert_eq!(result.unwrap_err().code(), ErrorCode::Forbidden);
    }
}

#[test]
fn wrong_signature_refuses_on_every_target() {
    let signing_key = primary_signing_key();
    for target in InstallerTarget::ALL {
        let adapter = TestAdapter::new();
        let mut manifest = manifest_for_platform(target.platform_str());
        // Flip a byte in the signed payload after signing by rebuilding with a
        // different version string after the package is written.
        let package_dir = write_package(&adapter, &signing_key, &manifest, &[]);
        manifest.version = "999.0.0".into();
        let tampered = serde_json::to_vec_pretty(&manifest).unwrap();
        adapter
            .fs
            .lock()
            .unwrap()
            .insert(package_dir.join("manifest.json"), tampered);

        let result = verify_manifest_for_target(
            &adapter,
            &package_dir,
            &signing_key.verifying_key().to_bytes(),
            target,
        );
        assert!(
            result.is_err(),
            "tampered signature must refuse for {target:?}"
        );
        assert_eq!(result.unwrap_err().code(), ErrorCode::Forbidden);
    }
}

#[test]
fn target_mismatch_refuses() {
    let signing_key = primary_signing_key();
    // Windows package against the Linux target.
    let adapter = TestAdapter::new();
    let manifest = manifest_for_platform("windows-x86_64");
    let package_dir = write_package(&adapter, &signing_key, &manifest, &[]);
    let err = verify_manifest_for_target(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
        InstallerTarget::LinuxX86_64,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unprocessable);
    assert!(
        err.to_string().contains("does not match target"),
        "err={err}"
    );

    // Linux package against the Windows target.
    let adapter = TestAdapter::new();
    let manifest = manifest_for_platform("linux-x86_64");
    let package_dir = write_package(&adapter, &signing_key, &manifest, &[]);
    let err = verify_manifest_for_target(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
        InstallerTarget::WindowsX86_64,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unprocessable);
}

#[test]
fn architecture_mismatch_refuses() {
    let signing_key = primary_signing_key();
    let adapter = TestAdapter::new();
    let manifest = manifest_for_platform("macos-arm64");
    let package_dir = write_package(&adapter, &signing_key, &manifest, &[]);
    let err = verify_manifest_for_target(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
        InstallerTarget::MacosX86_64,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unprocessable);
    assert!(err.to_string().contains("architecture"), "err={err}");
}

#[test]
fn unknown_target_refuses() {
    let signing_key = primary_signing_key();
    for platform in ["linux-aarch64", "darwin-x86_64", "macos-intel", "win32", ""] {
        let adapter = TestAdapter::new();
        let manifest = manifest_for_platform(platform);
        let package_dir = write_package(&adapter, &signing_key, &manifest, &[]);
        let err = verify_manifest_for_target(
            &adapter,
            &package_dir,
            &signing_key.verifying_key().to_bytes(),
            InstallerTarget::LinuxX86_64,
        )
        .unwrap_err();
        assert_eq!(
            err.code(),
            ErrorCode::Unprocessable,
            "platform={platform:?}"
        );
        assert!(
            err.to_string().contains("unknown"),
            "platform={platform:?} err={err}"
        );
    }
}

// ---------------------------------------------------------------------------
// Weak key / noncanonical signature: strict refusal
// ---------------------------------------------------------------------------

/// Compressed Edwards identity point `(0, 1)`: y = 1 little-endian, sign = 0.
/// Small-order (`is_weak()`).
fn weak_key_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
}

/// Signature with R = identity and S = 0. Under the identity key the ordinary
/// Ed25519 verifier accepts this for any message; `verify_strict` refuses.
fn weak_sig_bytes() -> [u8; 64] {
    let mut s = [0u8; 64];
    s[0] = 1;
    s
}

fn weak_key_package(adapter: &TestAdapter, platform: &str) -> PathBuf {
    let signing_key = primary_signing_key();
    let manifest = manifest_for_platform(platform);
    let package_dir = write_package(adapter, &signing_key, &manifest, &[]);
    // Replace the signature with the crafted weak one; the trust key is identity.
    adapter
        .fs
        .lock()
        .unwrap()
        .insert(package_dir.join("manifest.sig"), weak_sig_bytes().to_vec());
    package_dir
}

#[test]
fn weak_key_is_refused_and_old_nonstrict_verifier_accepted_it() {
    // Red/green: the previous `Verifier::verify` path accepts this weak
    // key + signature for any message. The target-bound verifier must refuse.
    let adapter = TestAdapter::new();
    let package_dir = weak_key_package(&adapter, "linux-x86_64");
    let manifest_bytes = adapter
        .read_file(&package_dir.join("manifest.json"))
        .expect("manifest bytes");

    let key_bytes = weak_key_bytes();
    let weak = VerifyingKey::from_bytes(&key_bytes).expect("weak key decodes");
    assert!(weak.is_weak(), "fixture key must be small-order");
    let sig = ed25519_dalek::Signature::from_bytes(&weak_sig_bytes());

    // Actual first observation: the old non-strict verifier ACCEPTS.
    let old = weak.verify(&manifest_bytes, &sig);
    assert!(
        old.is_ok(),
        "red/green precondition: old non-strict verify must accept the weak case (got {old:?})"
    );

    // Strict path and the package verifier must refuse.
    assert!(weak.verify_strict(&manifest_bytes, &sig).is_err());

    let result = verify_manifest_for_target(
        &adapter,
        &package_dir,
        &key_bytes,
        InstallerTarget::LinuxX86_64,
    );
    let err = result.expect_err("weak key must refuse");
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(
        err.to_string().contains("weak") || err.to_string().contains("signature"),
        "err={err}"
    );
}

#[test]
fn noncanonical_signature_refuses() {
    let signing_key = primary_signing_key();
    let adapter = TestAdapter::new();
    let manifest = manifest_for_platform("linux-x86_64");
    let package_dir = write_package(&adapter, &signing_key, &manifest, &[]);

    // S + L is a non-canonical encoding of the same scalar; the ordinary
    // verifier's InternalSignature check and verify_strict both refuse it.
    let good = adapter
        .read_file(&package_dir.join("manifest.sig"))
        .expect("sig");
    let mut malleable = good.clone();
    // Set the high bit of S (byte 63) to force S >= L.
    malleable[63] |= 0xe0;
    if malleable == good {
        malleable[32] ^= 0x01;
    }
    adapter
        .fs
        .lock()
        .unwrap()
        .insert(package_dir.join("manifest.sig"), malleable);

    let result = verify_manifest_for_target(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
        InstallerTarget::LinuxX86_64,
    );
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), ErrorCode::Forbidden);
}

#[test]
fn valid_signature_still_verifies_after_strict_upgrade() {
    let signing_key = primary_signing_key();
    verify_all_targets_ok(&signing_key);
}

// ---------------------------------------------------------------------------
// Portable paths: refuse before any affected artifact is opened
// ---------------------------------------------------------------------------

fn package_with_path(
    adapter: &TestAdapter,
    signing_key: &SigningKey,
    platform: &str,
    bad_path: &str,
) -> PathBuf {
    let mut manifest = manifest_for_platform(platform);
    // Replace one artifact with a hostile path. Its fixture bytes deliberately
    // mismatch the declared size/hash, so path refusal must happen first.
    manifest.artifacts[0].path = bad_path.to_string();
    write_package(adapter, signing_key, &manifest, &[])
}

#[test]
fn portable_path_violations_refuse_on_every_target() {
    let signing_key = primary_signing_key();
    let hostile = [
        "artifacts/../etc/passwd",
        "artifacts/..\\..\\windows\\system32",
        "artifacts\\evil",
        "artifacts/c:/windows/system32/evil",
        "artifacts/file:ads",
        "artifacts/file\0suffix",
        "",
        "artifacts/foo.",
        "artifacts/foo ",
        "artifacts/CON",
        "artifacts/nul.txt",
        "artifacts/com1.tar.gz",
        "artifacts/UPPER",
        "/etc/passwd",
        "artifacts//double",
        "artifacts/./dot",
    ];
    for target in InstallerTarget::ALL {
        for bad in hostile {
            let adapter = TestAdapter::new();
            let package_dir = package_with_path(&adapter, &signing_key, target.platform_str(), bad);
            let result = verify_manifest_for_target(
                &adapter,
                &package_dir,
                &signing_key.verifying_key().to_bytes(),
                target,
            );
            let err = result.expect_err(&format!("target {target:?} must refuse path {bad:?}"));
            assert_eq!(err.code(), ErrorCode::Forbidden, "path={bad:?} err={err}");
        }
    }
}

#[test]
fn nested_linux_fixture_names_still_verify() {
    let signing_key = primary_signing_key();
    let adapter = TestAdapter::new();
    let manifest = manifest_for_platform("linux-x86_64");
    assert!(manifest
        .artifacts
        .iter()
        .any(|a| a.path == "artifacts/sub/dir/file"));
    let package_dir = write_package(&adapter, &signing_key, &manifest, &[]);
    let result = verify_manifest_for_target(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
        InstallerTarget::LinuxX86_64,
    );
    assert!(
        result.is_ok(),
        "nested fixtures must verify: {:?}",
        result.err()
    );
}

#[test]
fn duplicate_declared_paths_refuse_before_artifact_reads() {
    let signing_key = primary_signing_key();
    let adapter = TestAdapter::new();
    let mut manifest = manifest_for_platform("linux-x86_64");
    let dup = manifest.artifacts[0].clone();
    manifest.artifacts.push(dup);
    let package_dir = write_package(&adapter, &signing_key, &manifest, &[]);
    let err = verify_manifest_for_target(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
        InstallerTarget::LinuxX86_64,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(err.to_string().contains("duplicate"), "err={err}");
}

#[test]
fn colliding_file_directory_paths_refuse() {
    let signing_key = primary_signing_key();
    let adapter = TestAdapter::new();
    let mut manifest = manifest_for_platform("linux-x86_64");
    manifest.artifacts.push(ArtifactEntry {
        path: "artifacts/hs-server/inner".to_string(),
        sha256: manifest::sha256_hex(b"x"),
        size_bytes: 1,
    });
    let package_dir = write_package(&adapter, &signing_key, &manifest, &[]);
    let err = verify_manifest_for_target(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
        InstallerTarget::LinuxX86_64,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(err.to_string().contains("collid"), "err={err}");
}

// ---------------------------------------------------------------------------
// Unknown-file walk: nested leaves and symlinked directories
// ---------------------------------------------------------------------------

#[test]
fn unknown_nested_file_under_known_dir_refuses() {
    let signing_key = primary_signing_key();
    let adapter = TestAdapter::new();
    let manifest = manifest_for_platform("linux-x86_64");
    let package_dir = write_package(
        &adapter,
        &signing_key,
        &manifest,
        &[("artifacts/sub/dir/ghost".into(), b"unlisted".to_vec())],
    );
    let err = verify_manifest_for_target(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
        InstallerTarget::LinuxX86_64,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(err.to_string().contains("unknown file"), "err={err}");
}

#[test]
fn symlinked_nested_dir_refuses_before_unknown_walk_descends() {
    // A symlinked parent of a declared nested artifact is refused by the
    // artifact symlink-parent guard (before any unknown-file walk).
    let signing_key = primary_signing_key();
    let adapter = TestAdapter::new();
    let manifest = manifest_for_platform("linux-x86_64");
    let package_dir = write_package(&adapter, &signing_key, &manifest, &[]);
    adapter
        .symlinks
        .lock()
        .unwrap()
        .insert(package_dir.join("artifacts/sub"));
    let err = verify_manifest_for_target(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
        InstallerTarget::LinuxX86_64,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(err.to_string().contains("symlink"), "err={err}");
}

// ---------------------------------------------------------------------------
// Version / schema metadata floors (strict parse, red/green on signed packages)
// ---------------------------------------------------------------------------

fn package_with_meta(
    adapter: &TestAdapter,
    signing_key: &SigningKey,
    min_installer_version: &str,
    min_schema_version: i64,
) -> PathBuf {
    let mut manifest = manifest_for_platform("linux-x86_64");
    manifest.min_installer_version = min_installer_version.to_string();
    manifest.min_schema_version = min_schema_version;
    write_package(adapter, signing_key, &manifest, &[])
}

#[test]
fn valid_version_and_schema_floors_still_verify() {
    let signing_key = primary_signing_key();
    for (ver, schema) in [("0.1.0", 1i64), ("0.1.0", 2), ("0.0.0", 1)] {
        let adapter = TestAdapter::new();
        let package_dir = package_with_meta(&adapter, &signing_key, ver, schema);
        let result = verify_manifest_for_target(
            &adapter,
            &package_dir,
            &signing_key.verifying_key().to_bytes(),
            InstallerTarget::LinuxX86_64,
        );
        assert!(
            result.is_ok(),
            "min_installer={ver} min_schema={schema} must verify: {:?}",
            result.err()
        );
    }
}

#[test]
fn higher_installer_floor_still_refuses() {
    let signing_key = primary_signing_key();
    let adapter = TestAdapter::new();
    let package_dir = package_with_meta(&adapter, &signing_key, "99.0.0", 1);
    let err = verify_manifest_for_target(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
        InstallerTarget::LinuxX86_64,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unprocessable);
    assert!(err.to_string().contains("installer version"), "err={err}");
}

#[test]
fn malformed_installer_version_refuses_instead_of_zero_fill() {
    // The previous parser coerced invalid fields to zero and ignored extra
    // components. Some malformed values passed its floor check; all must
    // now fail parsing, including those it happened to reject as too new.
    let signing_key = primary_signing_key();
    for bad in [
        "abc.0.0",
        "0.1",
        "0.1.0.0",
        "1.0.0-rc1",
        "-1.0.0",
        "01.0.0",
        "99999999999.0.0",
        "",
    ] {
        let adapter = TestAdapter::new();
        let package_dir = package_with_meta(&adapter, &signing_key, bad, 1);
        let err = verify_manifest_for_target(
            &adapter,
            &package_dir,
            &signing_key.verifying_key().to_bytes(),
            InstallerTarget::LinuxX86_64,
        )
        .expect_err(&format!("min_installer_version={bad:?} must refuse"));
        assert_eq!(
            err.code(),
            ErrorCode::Unprocessable,
            "min_installer_version={bad:?} err={err}"
        );
        assert!(
            err.to_string().contains("malformed min_installer_version"),
            "min_installer_version={bad:?} err={err}"
        );
    }
}

#[test]
fn non_positive_schema_floor_refuses() {
    let signing_key = primary_signing_key();
    for schema in [0i64, -1, i64::MIN] {
        let adapter = TestAdapter::new();
        let package_dir = package_with_meta(&adapter, &signing_key, "0.1.0", schema);
        let err = verify_manifest_for_target(
            &adapter,
            &package_dir,
            &signing_key.verifying_key().to_bytes(),
            InstallerTarget::LinuxX86_64,
        )
        .expect_err(&format!("min_schema_version={schema} must refuse"));
        assert_eq!(err.code(), ErrorCode::Unprocessable, "schema={schema}");
        assert!(
            err.to_string().contains("min_schema_version"),
            "schema={schema} err={err}"
        );
    }
}

#[test]
fn above_supported_schema_floor_still_refuses() {
    let signing_key = primary_signing_key();
    let adapter = TestAdapter::new();
    let package_dir = package_with_meta(&adapter, &signing_key, "0.1.0", 999);
    let err = verify_manifest_for_target(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
        InstallerTarget::LinuxX86_64,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unprocessable);
    assert!(err.to_string().contains("schema version"), "err={err}");
}

#[test]
fn frozen_platform_strings_are_exact() {
    assert_eq!(InstallerTarget::LinuxX86_64.platform_str(), "linux-x86_64");
    assert_eq!(
        InstallerTarget::WindowsX86_64.platform_str(),
        "windows-x86_64"
    );
    assert_eq!(InstallerTarget::MacosArm64.platform_str(), "macos-arm64");
    assert_eq!(InstallerTarget::MacosX86_64.platform_str(), "macos-x86_64");
    assert_eq!(
        InstallerTarget::from_platform_str("macos-x86_64"),
        Some(InstallerTarget::MacosX86_64)
    );
    assert_eq!(InstallerTarget::from_platform_str("macos-intel"), None);
}

// ---------------------------------------------------------------------------
// Product / release-version / artifact-list binding (signed packages)
// ---------------------------------------------------------------------------

/// Signed package that is otherwise valid (correct artifact bytes/hash/size,
/// valid min requirements, real signature). Only `product`, `version`, or the
/// artifact list may be hostile.
fn package_with_identity(
    adapter: &TestAdapter,
    signing_key: &SigningKey,
    product: &str,
    version: &str,
    artifacts: Vec<ArtifactEntry>,
) -> PathBuf {
    let mut manifest = manifest_for_platform("linux-x86_64");
    manifest.product = product.to_string();
    manifest.version = version.to_string();
    manifest.artifacts = artifacts;
    write_package(adapter, signing_key, &manifest, &[])
}

fn default_artifacts() -> Vec<ArtifactEntry> {
    manifest_for_platform("linux-x86_64").artifacts
}

#[test]
fn wrong_product_signed_with_trusted_key_refuses() {
    // Same independently trusted test key; only `product` is hostile.
    let signing_key = primary_signing_key();
    let hostile_owned: Vec<String> = vec![
        // Aliases and case changes.
        "HS-Server".into(),
        "hs-Server".into(),
        "hs_server".into(),
        "hsserver".into(),
        "hs-server ".into(),
        " hs-server".into(),
        "hs-server.".into(),
        "hs-server-v2".into(),
        "HS-SERVER".into(),
        // Other components.
        "hs-manager".into(),
        "hs-computer".into(),
        "helicoid".into(),
        "hs-client".into(),
        // Traversal / NUL / unbounded.
        "hs-server/../evil".into(),
        "../hs-server".into(),
        "hs-server/..".into(),
        "hs-server\u{0}".into(),
        "hs\u{0}-server".into(),
        "hs-server\n".into(),
        "x".repeat(1024),
        "hs-server/".repeat(32),
        String::new(),
    ];
    for bad in &hostile_owned {
        let adapter = TestAdapter::new();
        let package_dir =
            package_with_identity(&adapter, &signing_key, bad, "0.1.0", default_artifacts());
        let err = verify_manifest_for_target(
            &adapter,
            &package_dir,
            &signing_key.verifying_key().to_bytes(),
            InstallerTarget::LinuxX86_64,
        )
        .expect_err(&format!("product={bad:?} must refuse"));
        assert_eq!(
            err.code(),
            ErrorCode::Unprocessable,
            "product={bad:?} err={err}"
        );
        // Fixed descriptive error: untrusted product is not echoed.
        assert_eq!(
            err.to_string(),
            "package product is not the canonical server product",
            "product={bad:?} err={err}"
        );
    }
}

#[test]
fn malformed_release_version_with_valid_min_requirements_refuses() {
    // min_installer_version and min_schema_version stay valid; only the
    // release `version` field is malformed.
    let signing_key = primary_signing_key();
    for bad in [
        "",
        "0.1",
        "0.1.0.0",
        "abc.0.0",
        "1.0.0-rc1",
        "-1.0.0",
        "01.0.0",
        "99999999999.0.0",
        "1.2.3.4",
        "v0.1.0",
        " 0.1.0",
        "0.1.0 ",
    ] {
        let adapter = TestAdapter::new();
        let package_dir = package_with_identity(
            &adapter,
            &signing_key,
            "hs-server",
            bad,
            default_artifacts(),
        );
        let err = verify_manifest_for_target(
            &adapter,
            &package_dir,
            &signing_key.verifying_key().to_bytes(),
            InstallerTarget::LinuxX86_64,
        )
        .expect_err(&format!("version={bad:?} must refuse"));
        assert_eq!(
            err.code(),
            ErrorCode::Unprocessable,
            "version={bad:?} err={err}"
        );
        // Fixed descriptive error: untrusted version is not echoed.
        assert_eq!(
            err.to_string(),
            "malformed version",
            "version={bad:?} err={err}"
        );
    }
}

#[test]
fn empty_artifact_list_with_valid_signature_refuses() {
    let signing_key = primary_signing_key();
    let adapter = TestAdapter::new();
    let package_dir = package_with_identity(&adapter, &signing_key, "hs-server", "0.1.0", vec![]);
    let err = verify_manifest_for_target(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
        InstallerTarget::LinuxX86_64,
    )
    .expect_err("empty artifact list must refuse");
    assert_eq!(err.code(), ErrorCode::Unprocessable);
    assert_eq!(
        err.to_string(),
        "manifest must list at least one artifact",
        "err={err}"
    );
}

#[test]
fn canonical_release_versions_still_verify() {
    let signing_key = primary_signing_key();
    for ver in [
        "0.0.0",
        "0.1.0",
        "1.2.3",
        "10.20.30",
        "0.0.1",
        "4294967295.0.0",
    ] {
        let adapter = TestAdapter::new();
        let mut manifest = manifest_for_platform("linux-x86_64");
        manifest.version = ver.to_string();
        let package_dir = write_package(&adapter, &signing_key, &manifest, &[]);
        let result = verify_manifest_for_target(
            &adapter,
            &package_dir,
            &signing_key.verifying_key().to_bytes(),
            InstallerTarget::LinuxX86_64,
        );
        assert!(
            result.is_ok(),
            "version={ver} must verify: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().version, ver);
    }
}
