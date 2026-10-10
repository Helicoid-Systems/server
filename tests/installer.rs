//! Adversarial installer tests: manifest verification, phase journal,
//! preflight, apply/resume/remove, and no-fake-ready behavior.
//!
//! Uses injected TestAdapter fixtures and at least one real disposable
//! package verification path with actual Ed25519 signatures.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use hs_server::error::ErrorCode;
use hs_server::installer::adapter::{CommandAdapter, TestAdapter};
use hs_server::installer::machine;
use hs_server::installer::manifest;
use hs_server::installer::models::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn generate_signing_key() -> SigningKey {
    use rand::Rng;
    let mut rng = rand::rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

fn create_test_manifest(product: &str, version: &str) -> PackageManifest {
    PackageManifest {
        format_version: 1,
        product: product.to_string(),
        version: version.to_string(),
        platform: "linux-x86_64".to_string(),
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
                sha256: manifest::sha256_hex(
                    b"[Unit]\nDescription=Helicoid Systems coordination server\n",
                ),
                size_bytes: b"[Unit]\nDescription=Helicoid Systems coordination server\n".len()
                    as u64,
            },
        ],
    }
}

fn create_preflight_ok() -> PreflightResult {
    PreflightResult {
        contract_version: CONTRACT_VERSION,
        ok: true,
        checks: PreflightChecks {
            os: CheckResult {
                ok: true,
                value: "ubuntu".into(),
                version: Some("26.04".into()),
                reason: None,
            },
            arch: CheckResult {
                ok: true,
                value: "x86_64".into(),
                version: None,
                reason: None,
            },
            privileges: PrivilegesCheck {
                ok: true,
                is_root: true,
                reason: None,
            },
            storage: StorageCheck {
                ok: true,
                total_bytes: 100 * 1024 * 1024 * 1024,
                available_bytes: 50 * 1024 * 1024 * 1024,
                min_required_bytes: 1024 * 1024 * 1024,
                reason: None,
            },
            ports: PortsCheck {
                ok: true,
                listeners: vec![],
                conflicts: vec![],
            },
            paths: PathsCheck {
                ok: true,
                checked: vec![],
            },
            services: ServicesCheck {
                ok: true,
                existing_units: vec![],
                conflicts: vec![],
            },
            existing_install: ExistingInstallCheck {
                detected: false,
                version: None,
                state: None,
            },
        },
    }
}

fn create_preflight_failed() -> PreflightResult {
    let mut pf = create_preflight_ok();
    pf.ok = false;
    pf.checks.os.ok = false;
    pf.checks.os.reason = Some("unsupported OS".into());
    pf
}

fn setup_package(
    adapter: &TestAdapter,
    signing_key: &SigningKey,
    manifest_override: Option<PackageManifest>,
) -> PathBuf {
    let package_dir = PathBuf::from("/tmp/test-package");

    let manifest = manifest_override.unwrap_or_else(|| create_test_manifest("hs-server", "0.1.0"));
    let manifest_json = serde_json::to_vec_pretty(&manifest).unwrap();

    // Sign the manifest.
    let signature = signing_key.sign(&manifest_json);

    // Write manifest, signature, and artifact files.
    let mut fs = adapter.fs.lock().unwrap();
    fs.insert(package_dir.join("manifest.json"), manifest_json);
    fs.insert(
        package_dir.join("manifest.sig"),
        signature.to_bytes().to_vec(),
    );
    fs.insert(
        package_dir.join("artifacts/hs-server"),
        b"fake-binary-content".to_vec(),
    );
    fs.insert(
        package_dir.join("artifacts/hs-server.service"),
        b"[Unit]\nDescription=Helicoid Systems coordination server\n".to_vec(),
    );

    package_dir
}

/// Set up a signed package with a valid verify_key for apply/resume tests.
/// Returns (verify_key_hex, package_dir_string).
fn setup_signed_package(adapter: &TestAdapter) -> (String, String) {
    let signing_key = generate_signing_key();
    let package_dir = PathBuf::from("/tmp/test-package");
    let manifest = create_test_manifest("hs-server", "0.1.0");
    let manifest_json = serde_json::to_vec(&manifest).unwrap();
    let signature = signing_key.sign(&manifest_json);
    let mut fs = adapter.fs.lock().unwrap();
    fs.insert(package_dir.join("manifest.json"), manifest_json);
    fs.insert(
        package_dir.join("manifest.sig"),
        signature.to_bytes().to_vec(),
    );
    fs.insert(
        package_dir.join("artifacts/hs-server"),
        b"fake-binary-content".to_vec(),
    );
    fs.insert(
        package_dir.join("artifacts/hs-server.service"),
        b"[Unit]\nDescription=Helicoid Systems coordination server\n".to_vec(),
    );
    drop(fs);
    let verify_key = hex::encode(signing_key.verifying_key().to_bytes());
    (verify_key, package_dir.display().to_string())
}

fn commands_contain(adapter: &TestAdapter, cmd: &str) -> bool {
    adapter
        .commands
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.command == cmd)
}

#[allow(dead_code)]
fn commands_count(adapter: &TestAdapter, cmd: &str) -> usize {
    adapter
        .commands
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c.command == cmd)
        .count()
}

// ---------------------------------------------------------------------------
// Manifest verification: real Ed25519 signature path
// ---------------------------------------------------------------------------

#[test]
fn manifest_valid_signature_verifies() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();
    let package_dir = setup_package(&adapter, &signing_key, None);

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(
        result.is_ok(),
        "valid manifest must verify: {:?}",
        result.err()
    );
    let m = result.unwrap();
    assert_eq!(m.product, "hs-server");
    assert_eq!(m.version, "0.1.0");
    assert_eq!(m.platform, "linux-x86_64");
}

#[test]
fn manifest_wrong_key_rejects() {
    let signing_key = generate_signing_key();
    let wrong_key = generate_signing_key();
    let adapter = TestAdapter::new();
    let package_dir = setup_package(&adapter, &signing_key, None);

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &wrong_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(err.to_string().contains("signature"), "err={err}");
}

#[test]
fn manifest_tampered_content_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();
    let package_dir = setup_package(&adapter, &signing_key, None);

    // Tamper with the manifest after signing.
    {
        let mut fs = adapter.fs.lock().unwrap();
        let tampered = serde_json::json!({
            "format_version": 1,
            "product": "hs-server",
            "version": "999.0.0",  // tampered version
            "platform": "linux-x86_64",
            "min_schema_version": 1,
            "min_installer_version": "0.1.0",
            "artifacts": []
        });
        fs.insert(
            package_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&tampered).unwrap(),
        );
    }

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), ErrorCode::Forbidden);
}

// ---------------------------------------------------------------------------
// Manifest: wrong hash / wrong size / malicious paths
// ---------------------------------------------------------------------------

#[test]
fn manifest_wrong_sha256_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();

    let mut manifest = create_test_manifest("hs-server", "0.1.0");
    manifest.artifacts[0].sha256 =
        "0000000000000000000000000000000000000000000000000000000000000000".into();
    let package_dir = setup_package(&adapter, &signing_key, Some(manifest));

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(err.to_string().contains("SHA-256"), "err={err}");
}

#[test]
fn manifest_wrong_size_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();

    let mut manifest = create_test_manifest("hs-server", "0.1.0");
    manifest.artifacts[0].size_bytes = 999999;
    let package_dir = setup_package(&adapter, &signing_key, Some(manifest));

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), ErrorCode::Unprocessable);
}

#[test]
fn manifest_absolute_path_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();

    let mut manifest = create_test_manifest("hs-server", "0.1.0");
    manifest.artifacts[0].path = "/etc/passwd".into();
    // Recompute hash for the actual content.
    manifest.artifacts[0].sha256 = manifest::sha256_hex(b"fake-binary-content");
    manifest.artifacts[0].size_bytes = b"fake-binary-content".len() as u64;
    let package_dir = setup_package(&adapter, &signing_key, Some(manifest));

    // We also need to write the file at the absolute path location for the check to reach it.
    // But the adapter path_exists will check the absolute path, which won't be under the package.
    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    // Should fail with forbidden (absolute path) or bad_request (file not found).
    assert!(
        matches!(
            result.unwrap_err().code(),
            ErrorCode::Forbidden | ErrorCode::BadRequest
        ),
        "absolute path must be rejected"
    );
}

#[test]
fn manifest_traversal_path_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();

    let mut manifest = create_test_manifest("hs-server", "0.1.0");
    manifest.artifacts[0].path = "artifacts/../../../etc/passwd".into();
    let package_dir = setup_package(&adapter, &signing_key, Some(manifest));

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(err.to_string().contains("traversal"));
}

#[test]
fn manifest_path_not_in_allowed_prefix_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();

    let mut manifest = create_test_manifest("hs-server", "0.1.0");
    manifest.artifacts[0].path = "secret/backdoor".into();
    let package_dir = setup_package(&adapter, &signing_key, Some(manifest));

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(err.to_string().contains("not in allowed prefix"));
}

#[test]
fn manifest_unknown_file_in_artifacts_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();
    let package_dir = setup_package(&adapter, &signing_key, None);

    // Add an extra file not listed in the manifest.
    {
        let mut fs = adapter.fs.lock().unwrap();
        fs.insert(
            package_dir.join("artifacts/extra-binary"),
            b"sneaky-content".to_vec(),
        );
    }

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(err.to_string().contains("unknown file"));
}

#[test]
fn manifest_wrong_platform_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();

    let mut manifest = create_test_manifest("hs-server", "0.1.0");
    manifest.platform = "windows-x86_64".into();
    let package_dir = setup_package(&adapter, &signing_key, Some(manifest));

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unprocessable);
    assert!(err.to_string().contains("platform"));
}

#[test]
fn manifest_schema_version_downgrade_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();

    let mut manifest = create_test_manifest("hs-server", "0.1.0");
    manifest.min_schema_version = 999;
    let package_dir = setup_package(&adapter, &signing_key, Some(manifest));

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unprocessable);
    assert!(err.to_string().contains("schema version"));
}

#[test]
fn manifest_installer_version_downgrade_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();

    let mut manifest = create_test_manifest("hs-server", "0.1.0");
    manifest.min_installer_version = "99.0.0".into();
    let package_dir = setup_package(&adapter, &signing_key, Some(manifest));

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unprocessable);
    assert!(err.to_string().contains("installer version"));
}

// ---------------------------------------------------------------------------
// Preflight checks
// ---------------------------------------------------------------------------

#[test]
fn preflight_ubuntu_26_ok() {
    let adapter = TestAdapter::new();
    let input = PreflightInput {
        contract_version: CONTRACT_VERSION,
        target: PreflightTarget {
            host: "test-host".into(),
            port: 22,
        },
    };
    let result = machine::preflight(&adapter, &input).unwrap();
    assert!(result.ok);
    assert!(result.checks.os.ok);
    assert!(result.checks.arch.ok);
    assert!(result.checks.privileges.ok);
    assert!(result.checks.storage.ok);
    assert!(result.checks.ports.ok);
}

#[test]
fn preflight_wrong_os_fails() {
    let mut adapter = TestAdapter::new();
    adapter.os_info = ("debian".into(), "12.0".into());
    let input = PreflightInput {
        contract_version: CONTRACT_VERSION,
        target: PreflightTarget {
            host: "test-host".into(),
            port: 22,
        },
    };
    let result = machine::preflight(&adapter, &input).unwrap();
    assert!(!result.ok);
    assert!(!result.checks.os.ok);
}

#[test]
fn preflight_wrong_arch_fails() {
    let mut adapter = TestAdapter::new();
    adapter.arch = "aarch64".into();
    let input = PreflightInput {
        contract_version: CONTRACT_VERSION,
        target: PreflightTarget {
            host: "test-host".into(),
            port: 22,
        },
    };
    let result = machine::preflight(&adapter, &input).unwrap();
    assert!(!result.ok);
    assert!(!result.checks.arch.ok);
}

#[test]
fn preflight_not_root_fails() {
    let mut adapter = TestAdapter::new();
    adapter.is_root = false;
    let input = PreflightInput {
        contract_version: CONTRACT_VERSION,
        target: PreflightTarget {
            host: "test-host".into(),
            port: 22,
        },
    };
    let result = machine::preflight(&adapter, &input).unwrap();
    assert!(!result.ok);
    assert!(!result.checks.privileges.ok);
}

#[test]
fn preflight_insufficient_storage_fails() {
    let mut adapter = TestAdapter::new();
    adapter.storage = (1024 * 1024 * 1024, 100 * 1024 * 1024); // Only 100MB available.
    let input = PreflightInput {
        contract_version: CONTRACT_VERSION,
        target: PreflightTarget {
            host: "test-host".into(),
            port: 22,
        },
    };
    let result = machine::preflight(&adapter, &input).unwrap();
    assert!(!result.ok);
    assert!(!result.checks.storage.ok);
}

#[test]
fn preflight_occupied_required_port_fails() {
    let adapter = TestAdapter::new();
    adapter
        .port_listeners
        .lock()
        .unwrap()
        .insert((8920, "tcp".into()), "nginx".into());
    let input = PreflightInput {
        contract_version: CONTRACT_VERSION,
        target: PreflightTarget {
            host: "test-host".into(),
            port: 22,
        },
    };
    let result = machine::preflight(&adapter, &input).unwrap();
    assert!(!result.ok);
    assert!(!result.checks.ports.ok);
    assert!(!result.checks.ports.conflicts.is_empty());
}

#[test]
fn preflight_existing_install_fails() {
    let adapter = TestAdapter::new();
    // Simulate existing installation.
    adapter.fs.lock().unwrap().insert(
        PathBuf::from("/opt/helicoid/.installer/journal.json"),
        b"{}".to_vec(),
    );
    let input = PreflightInput {
        contract_version: CONTRACT_VERSION,
        target: PreflightTarget {
            host: "test-host".into(),
            port: 22,
        },
    };
    let result = machine::preflight(&adapter, &input).unwrap();
    assert!(!result.ok);
    assert!(result.checks.existing_install.detected);
}

#[test]
fn preflight_symlinked_product_path_fails() {
    let adapter = TestAdapter::new();
    adapter
        .symlinks
        .lock()
        .unwrap()
        .insert(PathBuf::from("/opt/helicoid"));
    // Also plant a key under the path so path_exists reports true.
    adapter
        .fs
        .lock()
        .unwrap()
        .insert(PathBuf::from("/opt/helicoid/elsewhere"), b"x".to_vec());
    let input = PreflightInput {
        contract_version: CONTRACT_VERSION,
        target: PreflightTarget {
            host: "test-host".into(),
            port: 22,
        },
    };
    let result = machine::preflight(&adapter, &input).unwrap();
    assert!(!result.ok);
    assert!(!result.checks.paths.ok);
    assert!(result
        .checks
        .paths
        .checked
        .iter()
        .any(|c| c.path == "/opt/helicoid" && c.reason.as_deref() == Some("path is a symlink")));
}

// ---------------------------------------------------------------------------
// Manifest: bounded parsing
// ---------------------------------------------------------------------------

#[test]
fn manifest_oversized_manifest_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();
    let package_dir = PathBuf::from("/tmp/test-package");

    // Build a validly signed manifest, then replace it with an oversized body
    // under the same signature by padding a trailing field the parser still
    // accepts — simplest proof is a raw oversize read rejection after signing.
    let manifest = create_test_manifest("hs-server", "0.1.0");
    let mut manifest_json = serde_json::to_vec_pretty(&manifest).unwrap();
    // Pad the JSON with a huge comment-free string field via whitespace.
    // serde_json ignores trailing whitespace only after the value; add padding
    // before the closing brace instead.
    let pad = " ".repeat(1024 * 1024 + 1);
    let mut padded = String::from_utf8(manifest_json.clone()).unwrap();
    let last_brace = padded.rfind('}').unwrap();
    padded.insert_str(last_brace, &pad);
    manifest_json = padded.into_bytes();
    let signature = signing_key.sign(&manifest_json);
    {
        let mut fs = adapter.fs.lock().unwrap();
        fs.insert(package_dir.join("manifest.json"), manifest_json);
        fs.insert(
            package_dir.join("manifest.sig"),
            signature.to_bytes().to_vec(),
        );
    }

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("exceeds"));
}

#[test]
fn manifest_too_many_artifacts_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();

    let mut manifest = create_test_manifest("hs-server", "0.1.0");
    // 257 entries exceeds MAX_ARTIFACTS (256).
    manifest.artifacts = (0..257)
        .map(|i| ArtifactEntry {
            path: format!("artifacts/f{i:03}"),
            sha256: manifest::sha256_hex(b"x"),
            size_bytes: 1,
        })
        .collect();
    let package_dir = setup_package(&adapter, &signing_key, Some(manifest));

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("artifacts"));
}

#[test]
fn manifest_symlinked_artifact_parent_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();
    let package_dir = setup_package(&adapter, &signing_key, None);
    // Make artifacts/ a symlink pointing outside the package.
    adapter
        .symlinks
        .lock()
        .unwrap()
        .insert(package_dir.join("artifacts"));

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("symlink"),
        "symlinked package parent must be rejected: {err}"
    );
}

// ---------------------------------------------------------------------------
// Plan: no verifying key fails
// ---------------------------------------------------------------------------

#[test]
fn plan_without_verify_key_fails() {
    let adapter = TestAdapter::new();
    let input = PlanInput {
        contract_version: CONTRACT_VERSION,
        preflight: create_preflight_ok(),
        package_dir: "/tmp/test-package".into(),
    };
    let result = machine::plan(&adapter, &input, None).unwrap();
    assert!(!result.ok);
    assert!(!result.manifest_verified);
    assert!(result.error.unwrap().contains("no verifying key"));
}

#[test]
fn plan_with_failed_preflight_fails() {
    let adapter = TestAdapter::new();
    let input = PlanInput {
        contract_version: CONTRACT_VERSION,
        preflight: create_preflight_failed(),
        package_dir: "/tmp/test-package".into(),
    };
    let key = [0u8; 32];
    let result = machine::plan(&adapter, &input, Some(&key)).unwrap();
    assert!(!result.ok);
    assert!(result.error.unwrap().contains("preflight"));
}

// ---------------------------------------------------------------------------
// Apply: occupied port, stale review, confirm check
// ---------------------------------------------------------------------------

#[test]
fn apply_requires_confirm() {
    let adapter = TestAdapter::new();
    let plan = create_install_plan();
    let input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan,
        preflight: create_preflight_ok(),
        confirm: false,
        package_dir: None,
        verify_key: None,
    };
    let err = machine::apply(&adapter, &input, Path::new("/tmp/test-state")).unwrap_err();
    assert_eq!(err.code(), ErrorCode::BadRequest);
    assert!(err.to_string().contains("confirm"));
}

#[test]
fn apply_requires_ok_preflight() {
    let adapter = TestAdapter::new();
    let plan = create_install_plan();
    let input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan,
        preflight: create_preflight_failed(),
        confirm: true,
        package_dir: None,
        verify_key: None,
    };
    let err = machine::apply(&adapter, &input, Path::new("/tmp/test-state")).unwrap_err();
    assert_eq!(err.code(), ErrorCode::BadRequest);
    assert!(err.to_string().contains("preflight"));
}

#[test]
fn apply_rejects_stale_review_digest() {
    let adapter = TestAdapter::new();
    let (verify_key, pkg_dir) = setup_signed_package(&adapter);
    let mut plan = create_install_plan();
    plan.review_digest = "stale-digest".into();
    let input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan,
        preflight: create_preflight_ok(),
        confirm: true,
        package_dir: Some(pkg_dir),
        verify_key: Some(verify_key),
    };
    let err = machine::apply(&adapter, &input, Path::new("/tmp/test-state")).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(err.to_string().contains("canonical plan"));
}

#[test]
fn apply_rejects_occupied_port() {
    let adapter = TestAdapter::new();
    adapter
        .port_listeners
        .lock()
        .unwrap()
        .insert((8920, "tcp".into()), "nginx".into());
    let plan = create_install_plan();
    let input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan,
        preflight: create_preflight_ok(),
        confirm: true,
        package_dir: None,
        verify_key: None,
    };
    let err = machine::apply(&adapter, &input, Path::new("/tmp/test-state")).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Conflict);
    assert!(err.to_string().contains("occupied"));
}

// ---------------------------------------------------------------------------
// Full apply cycle with real file/journal path
// ---------------------------------------------------------------------------

#[test]
fn full_apply_creates_resources_and_journal() {
    let adapter = TestAdapter::new();
    let (verify_key, pkg_dir) = setup_signed_package(&adapter);
    let plan = create_install_plan();
    let state_dir = PathBuf::from("/opt/helicoid/.installer");

    let input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan: plan.clone(),
        preflight: create_preflight_ok(),
        confirm: true,
        package_dir: Some(pkg_dir),
        verify_key: Some(verify_key),
    };

    let result = machine::apply(&adapter, &input, &state_dir).unwrap();
    assert!(result.ok, "apply must succeed: {:?}", result.errors);
    assert_eq!(result.phase, "completed");
    assert!(result
        .phases_completed
        .contains(&"service_user".to_string()));
    assert!(result.phases_completed.contains(&"directories".to_string()));
    assert!(result.phases_completed.contains(&"units".to_string()));
    assert!(result.phases_completed.contains(&"firewall".to_string()));

    // Verify service user was created.
    assert!(commands_contain(&adapter, "useradd"));
    assert!(adapter.existing_users.lock().unwrap().contains("hs-server"));

    // Verify firewall rules were added.
    assert!(commands_contain(&adapter, "ufw"));

    // Verify journal was saved.
    let journal_path = state_dir.join("journal.json");
    assert!(adapter.path_exists(&journal_path));

    // Verify installed manifest was saved.
    let manifest_path = state_dir.join("installed.json");
    assert!(adapter.path_exists(&manifest_path));

    // Verify no-fake-ready: server_ready_for_enrollment must be false.
    assert!(!result.server_ready_for_enrollment);
    assert!(!result.bootstrap_ready);
}

// ---------------------------------------------------------------------------
// Retry idempotency: re-running completed apply is a no-op
// ---------------------------------------------------------------------------

#[test]
fn apply_retry_is_idempotent() {
    let adapter = TestAdapter::new();
    let (verify_key, pkg_dir) = setup_signed_package(&adapter);
    let plan = create_install_plan();
    let state_dir = PathBuf::from("/opt/helicoid/.installer");

    let input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan: plan.clone(),
        preflight: create_preflight_ok(),
        confirm: true,
        package_dir: Some(pkg_dir),
        verify_key: Some(verify_key),
    };

    // First apply.
    let r1 = machine::apply(&adapter, &input, &state_dir).unwrap();
    assert!(r1.ok);

    let cmds_before = adapter.commands.lock().unwrap().len();

    // Second apply (retry).
    let r2 = machine::apply(&adapter, &input, &state_dir).unwrap();
    assert!(r2.ok);

    let cmds_after = adapter.commands.lock().unwrap().len();
    // Retry should not create additional commands (idempotent).
    assert_eq!(
        cmds_before, cmds_after,
        "retry must be idempotent (no new commands)"
    );
}

// ---------------------------------------------------------------------------
// Interruption / resume: simulate failure mid-apply
// ---------------------------------------------------------------------------

#[test]
fn apply_failure_halts_and_resume_continues() {
    let adapter = TestAdapter::new();
    let (verify_key, pkg_dir) = setup_signed_package(&adapter);
    let plan = create_install_plan();
    let state_dir = PathBuf::from("/opt/helicoid/.installer");

    // Inject failure for unit enable (signed unit is already copied, but enable still runs).
    adapter
        .force_failures
        .lock()
        .unwrap()
        .insert("enable_unit".into(), "simulated unit failure".into());

    let input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan: plan.clone(),
        preflight: create_preflight_ok(),
        confirm: true,
        package_dir: Some(pkg_dir),
        verify_key: Some(verify_key),
    };

    // First apply: fails at units phase.
    let r1 = machine::apply(&adapter, &input, &state_dir).unwrap();
    assert!(!r1.ok);
    assert_eq!(r1.phase, "units");
    assert!(r1.phases_completed.contains(&"service_user".to_string()));
    assert!(r1.phases_completed.contains(&"directories".to_string()));
    assert!(!r1.phases_completed.contains(&"units".to_string()));

    // Verify journal shows failure.
    let journal_path = state_dir.join("journal.json");
    let journal_bytes = adapter.read_file(&journal_path).unwrap();
    let journal: Journal = serde_json::from_slice(&journal_bytes).unwrap();
    assert_eq!(
        journal.phases.get("units").unwrap().status,
        PhaseStatus::Failed
    );

    // Clear the failure.
    adapter.force_failures.lock().unwrap().remove("enable_unit");

    // Resume.
    let r2 = machine::resume(&adapter, &input, &state_dir).unwrap();
    assert!(
        r2.ok,
        "resume must succeed after clearing failure: {:?}",
        r2.errors
    );
    assert_eq!(r2.phase, "completed");
}

// ---------------------------------------------------------------------------
// Cancellation / rollback
// ---------------------------------------------------------------------------

#[test]
fn cancel_tracked_resources_are_rollbackable() {
    let adapter = TestAdapter::new();
    let (verify_key, pkg_dir) = setup_signed_package(&adapter);
    let plan = create_install_plan();
    let state_dir = PathBuf::from("/opt/helicoid/.installer");

    // Fail at firewall phase.
    adapter
        .force_failures
        .lock()
        .unwrap()
        .insert("firewall_allow".into(), "ufw not available".into());

    let input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan: plan.clone(),
        preflight: create_preflight_ok(),
        confirm: true,
        package_dir: Some(pkg_dir),
        verify_key: Some(verify_key),
    };

    let result = machine::apply(&adapter, &input, &state_dir).unwrap();
    assert!(!result.ok);
    assert_eq!(result.phase, "firewall");

    // Verify resources up to firewall were tracked.
    let journal_path = state_dir.join("journal.json");
    let journal_bytes = adapter.read_file(&journal_path).unwrap();
    let journal: Journal = serde_json::from_slice(&journal_bytes).unwrap();
    assert!(!journal.resources_created.service_users.is_empty());
    assert!(!journal.resources_created.directories.is_empty());
    assert!(!journal.resources_created.units.is_empty());

    // Remove should clean up tracked resources.
    adapter.force_failures.lock().unwrap().clear();
    let remove_input = RemoveInput {
        contract_version: CONTRACT_VERSION,
        state_dir: state_dir.to_string_lossy().to_string(),
        delete_data: false,
        confirm: true,
    };
    let remove_result = machine::remove(&adapter, &remove_input).unwrap();
    assert!(
        remove_result.ok,
        "remove must succeed: {:?}",
        remove_result.errors
    );
    assert!(remove_result.data_preserved);
    assert!(commands_contain(&adapter, "userdel"));
    assert!(commands_contain(&adapter, "remove_unit"));
}

// ---------------------------------------------------------------------------
// Journal fault injection
// ---------------------------------------------------------------------------

#[test]
fn journal_fault_prevents_apply() {
    let adapter = TestAdapter::new();
    let (verify_key, pkg_dir) = setup_signed_package(&adapter);
    let plan = create_install_plan();
    let state_dir = PathBuf::from("/opt/helicoid/.installer");

    // Write a corrupt journal.
    adapter
        .fs
        .lock()
        .unwrap()
        .insert(state_dir.join("journal.json"), b"not valid json".to_vec());

    let input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan: plan.clone(),
        preflight: create_preflight_ok(),
        confirm: true,
        package_dir: Some(pkg_dir),
        verify_key: Some(verify_key),
    };

    let err = machine::apply(&adapter, &input, &state_dir).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Internal);
    assert!(err.to_string().contains("corrupt journal"));
}

#[test]
fn journal_plan_mismatch_rejects() {
    let adapter = TestAdapter::new();
    let (verify_key, pkg_dir) = setup_signed_package(&adapter);
    let plan = create_install_plan();
    let state_dir = PathBuf::from("/opt/helicoid/.installer");

    // Write a journal with a different plan digest.
    let mut journal = Journal {
        contract_version: CONTRACT_VERSION,
        plan_digest: "different-digest".into(),
        started_at: "2026-01-15T10:30:00Z".into(),
        updated_at: "2026-01-15T10:30:00Z".into(),
        current_phase: "pending".into(),
        phases: BTreeMap::new(),
        resources_created: ResourcesCreated::default(),
        resources: Vec::new(),
    };
    journal.phases.insert(
        "service_user".into(),
        PhaseEntry {
            status: PhaseStatus::Pending,
            started_at: None,
            completed_at: None,
            error: None,
        },
    );
    adapter.fs.lock().unwrap().insert(
        state_dir.join("journal.json"),
        serde_json::to_vec_pretty(&journal).unwrap(),
    );

    let input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan: plan.clone(),
        preflight: create_preflight_ok(),
        confirm: true,
        package_dir: Some(pkg_dir),
        verify_key: Some(verify_key),
    };

    let err = machine::apply(&adapter, &input, &state_dir).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Conflict);
    assert!(err.to_string().contains("different plan"));
}

// ---------------------------------------------------------------------------
// Inspect: not installed
// ---------------------------------------------------------------------------

#[test]
fn inspect_reports_not_installed_when_no_journal() {
    let adapter = TestAdapter::new();
    let input = InspectInput {
        contract_version: CONTRACT_VERSION,
        state_dir: "/opt/helicoid/.installer".into(),
    };
    let result = machine::inspect(&adapter, &input).unwrap();
    assert!(!result.installed);
    assert!(result.version.is_none());
}

#[test]
fn inspect_reports_installed_after_apply() {
    let adapter = TestAdapter::new();
    let (verify_key, pkg_dir) = setup_signed_package(&adapter);
    let plan = create_install_plan();
    let state_dir = PathBuf::from("/opt/helicoid/.installer");

    let apply_input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan: plan.clone(),
        preflight: create_preflight_ok(),
        confirm: true,
        package_dir: Some(pkg_dir),
        verify_key: Some(verify_key),
    };
    machine::apply(&adapter, &apply_input, &state_dir).unwrap();

    let inspect_input = InspectInput {
        contract_version: CONTRACT_VERSION,
        state_dir: state_dir.to_string_lossy().to_string(),
    };
    let result = machine::inspect(&adapter, &inspect_input).unwrap();
    assert!(result.installed);
    assert_eq!(result.version.unwrap(), "0.1.0");
    assert_eq!(result.phase.unwrap(), "completed");
    assert_eq!(result.service_user.unwrap(), "hs-server");
    assert!(result.last_operation_ok);
}

// ---------------------------------------------------------------------------
// Safe remove preserves data / unrelated resources
// ---------------------------------------------------------------------------

#[test]
fn remove_preserves_data_by_default() {
    let adapter = TestAdapter::new();
    let (verify_key, pkg_dir) = setup_signed_package(&adapter);
    let plan = create_install_plan();
    let state_dir = PathBuf::from("/opt/helicoid/.installer");

    let apply_input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan: plan.clone(),
        preflight: create_preflight_ok(),
        confirm: true,
        package_dir: Some(pkg_dir),
        verify_key: Some(verify_key),
    };
    machine::apply(&adapter, &apply_input, &state_dir).unwrap();

    // Add some unrelated data.
    adapter.fs.lock().unwrap().insert(
        PathBuf::from("/var/lib/helicoid/data/hs-server.db"),
        b"precious-data".to_vec(),
    );

    let remove_input = RemoveInput {
        contract_version: CONTRACT_VERSION,
        state_dir: state_dir.to_string_lossy().to_string(),
        delete_data: false,
        confirm: true,
    };
    let result = machine::remove(&adapter, &remove_input).unwrap();
    assert!(result.ok, "remove must succeed: {:?}", result.errors);
    assert!(result.data_preserved);
    assert!(result.data_dir.is_some());
    assert!(result.backup_dir.is_some());

    // Verify data file still exists.
    assert!(adapter.path_exists(Path::new("/var/lib/helicoid/data/hs-server.db")));
}

#[test]
fn remove_requires_confirm() {
    let adapter = TestAdapter::new();
    let remove_input = RemoveInput {
        contract_version: CONTRACT_VERSION,
        state_dir: "/opt/helicoid/.installer".into(),
        delete_data: false,
        confirm: false,
    };
    let err = machine::remove(&adapter, &remove_input).unwrap_err();
    assert_eq!(err.code(), ErrorCode::BadRequest);
}

#[test]
fn remove_with_delete_data_removes_data() {
    let adapter = TestAdapter::new();
    let (verify_key, pkg_dir) = setup_signed_package(&adapter);
    let plan = create_install_plan();
    let state_dir = PathBuf::from("/opt/helicoid/.installer");

    let apply_input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan: plan.clone(),
        preflight: create_preflight_ok(),
        confirm: true,
        package_dir: Some(pkg_dir),
        verify_key: Some(verify_key),
    };
    machine::apply(&adapter, &apply_input, &state_dir).unwrap();

    let remove_input = RemoveInput {
        contract_version: CONTRACT_VERSION,
        state_dir: state_dir.to_string_lossy().to_string(),
        delete_data: true,
        confirm: true,
    };
    let result = machine::remove(&adapter, &remove_input).unwrap();
    assert!(result.ok);
    assert!(!result.data_preserved);
    assert!(result.data_dir.is_none());
}

// ---------------------------------------------------------------------------
// No-fake-ready behavior
// ---------------------------------------------------------------------------

#[test]
fn apply_never_marks_server_ready_for_enrollment() {
    let adapter = TestAdapter::new();
    let (verify_key, pkg_dir) = setup_signed_package(&adapter);
    let plan = create_install_plan();
    let state_dir = PathBuf::from("/opt/helicoid/.installer");

    let input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan: plan.clone(),
        preflight: create_preflight_ok(),
        confirm: true,
        package_dir: Some(pkg_dir),
        verify_key: Some(verify_key),
    };

    let result = machine::apply(&adapter, &input, &state_dir).unwrap();
    assert!(
        !result.server_ready_for_enrollment,
        "installer must never mark server_ready_for_enrollment"
    );
    assert!(
        !result.bootstrap_ready,
        "installer must never mark bootstrap_ready"
    );
}

// ---------------------------------------------------------------------------
// Manifest: missing manifest.sig
// ---------------------------------------------------------------------------

#[test]
fn manifest_missing_signature_file_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();
    let package_dir = setup_package(&adapter, &signing_key, None);

    // Remove the signature file.
    adapter
        .fs
        .lock()
        .unwrap()
        .remove(&package_dir.join("manifest.sig"));

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), ErrorCode::BadRequest);
}

// ---------------------------------------------------------------------------
// Manifest: missing manifest.json
// ---------------------------------------------------------------------------

#[test]
fn manifest_missing_manifest_file_rejects() {
    let signing_key = generate_signing_key();
    let adapter = TestAdapter::new();
    let package_dir = setup_package(&adapter, &signing_key, None);

    // Remove the manifest file.
    adapter
        .fs
        .lock()
        .unwrap()
        .remove(&package_dir.join("manifest.json"));

    let result = manifest::verify_manifest(
        &adapter,
        &package_dir,
        &signing_key.verifying_key().to_bytes(),
    );
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), ErrorCode::BadRequest);
}

// ---------------------------------------------------------------------------
// Apply: failed preflight blocks apply
// ---------------------------------------------------------------------------

#[test]
fn apply_with_failed_preflight_blocks() {
    let adapter = TestAdapter::new();
    let plan = create_install_plan();
    let state_dir = PathBuf::from("/tmp/test-state-block");

    let input = ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan,
        preflight: create_preflight_failed(),
        confirm: true,
        package_dir: None,
        verify_key: None,
    };

    let err = machine::apply(&adapter, &input, &state_dir).unwrap_err();
    assert_eq!(err.code(), ErrorCode::BadRequest);
}

// ---------------------------------------------------------------------------
// Helpers for building test plans
// ---------------------------------------------------------------------------

fn create_install_plan() -> InstallPlan {
    let mut plan = machine::generate_canonical_plan("hs-server", "0.1.0");
    plan.review_digest = machine::compute_plan_digest(&plan);
    plan
}
