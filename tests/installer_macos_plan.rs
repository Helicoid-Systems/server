//! Focused macOS plan and apply lifecycle tests.
//!
//! Packages are disposable signed directories; host, identity, and apply facts
//! are injected. No test creates a real account, writes a real product path,
//! invokes launchctl, or binds a port.

#![cfg(unix)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ed25519_dalek::{Signer, SigningKey};
use hs_server::error::ErrorCode;
use hs_server::installer::lifecycle_v2 as v2;
use hs_server::installer::machine;
use hs_server::installer::macos_identity::{
    IdentityObservation, IdentityQuery, MacosIdentityObserver, PRODUCT_SERVICE_ACCOUNT,
};
use hs_server::installer::macos_launchd::{
    CommandObservation, LaunchdQuery, MacosLaunchdObserver, PathMetadata, CONFIGURATION_DIRECTORY,
    DATA_PATH, EXECUTABLE_PATH, LAUNCHD_LABEL, LAUNCHD_PLIST_PATH, PRODUCT_ROOT_PATH,
};
use hs_server::installer::manifest;
use hs_server::installer::models::{ArtifactEntry, PackageManifest};
use serde_json::Value;

const BACKUP_PATH: &str = "/Library/Application Support/Helicoid-Backups";
const PORT: u16 = 8920;

struct FakeLaunchdObserver {
    observations: Mutex<HashMap<LaunchdQuery, CommandObservation>>,
    paths: Mutex<HashMap<PathBuf, PathMetadata>>,
    storage: Mutex<(u64, u64)>,
}

impl FakeLaunchdObserver {
    fn with_valid_host(architecture: &str) -> Self {
        let observer = Self {
            observations: Mutex::new(HashMap::new()),
            paths: Mutex::new(HashMap::new()),
            storage: Mutex::new((100 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024)),
        };
        observer.set_observation(
            LaunchdQuery::EffectiveUid,
            CommandObservation::success("0\n"),
        );
        observer.set_observation(
            LaunchdQuery::OperatingSystemVersion,
            CommandObservation::success("15.6.1\n"),
        );
        observer.set_observation(
            LaunchdQuery::LocalArchitecture,
            CommandObservation::success(format!("{architecture}\n")),
        );
        observer.set_observation(
            LaunchdQuery::LaunchdJobPresence,
            CommandObservation::failure(
                113,
                "Bad request.\nCould not find service \"com.helicoid.server\" in domain for system\n",
            ),
        );
        observer.set_observation(
            LaunchdQuery::TcpPortListeners { port: PORT },
            CommandObservation::failure(1, ""),
        );
        for path in [
            "/",
            "/Library",
            "/Library/Application Support",
            "/Library/LaunchDaemons",
        ] {
            observer.set_path(path, root_directory());
        }
        observer
    }

    fn set_observation(&self, query: LaunchdQuery, observation: CommandObservation) {
        self.observations.lock().unwrap().insert(query, observation);
    }

    fn set_path(&self, path: &str, metadata: PathMetadata) {
        self.paths
            .lock()
            .unwrap()
            .insert(PathBuf::from(path), metadata);
    }

    fn set_storage(&self, available: u64) {
        self.storage.lock().unwrap().1 = available;
    }
}

impl MacosLaunchdObserver for FakeLaunchdObserver {
    fn observe(&self, query: LaunchdQuery) -> Result<CommandObservation, String> {
        self.observations
            .lock()
            .unwrap()
            .get(&query)
            .cloned()
            .ok_or_else(|| format!("no fixture for {}", query.name()))
    }

    fn lstat(&self, path: &Path) -> Result<Option<PathMetadata>, String> {
        Ok(self.paths.lock().unwrap().get(path).copied())
    }

    fn extended_acl_is_safe(&self, _path: &Path) -> Result<bool, String> {
        Ok(true)
    }

    fn storage(&self, _path: &Path) -> Result<(u64, u64), String> {
        Ok(*self.storage.lock().unwrap())
    }
}

struct FakeIdentity {
    account: Result<IdentityObservation, String>,
    group_present: bool,
}

impl FakeIdentity {
    fn absent() -> Self {
        Self {
            account: Ok(IdentityObservation::failure(
                100,
                "eDSRecordNotFound: record not found\n",
            )),
            group_present: false,
        }
    }

    fn absent_with_existing_group() -> Self {
        Self {
            account: Ok(IdentityObservation::failure(
                100,
                "eDSRecordNotFound: record not found\n",
            )),
            group_present: true,
        }
    }

    fn unverified_existing() -> Self {
        let record = "\
Password: *
PrimaryGroupID: 4242
RecordName: _helicoid
RecordType: dsRecTypeStandard:Users
UniqueID: 4242
UserShell: /bin/zsh
";
        Self {
            account: Ok(IdentityObservation::success(record)),
            group_present: false,
        }
    }

    fn unavailable() -> Self {
        Self {
            account: Err("directory service unavailable".to_string()),
            group_present: false,
        }
    }
}

impl MacosIdentityObserver for FakeIdentity {
    fn observe(&self, query: IdentityQuery) -> Result<IdentityObservation, String> {
        match query {
            IdentityQuery::AccountRecord => self.account.clone(),
            IdentityQuery::GroupRecord => {
                if !self
                    .account
                    .as_ref()
                    .is_ok_and(|observation| observation.stderr.contains("eDSRecordNotFound"))
                {
                    return Err(format!("unexpected identity query: {query:?}"));
                }
                if self.group_present {
                    Ok(IdentityObservation::success(
                        "RecordName: _helicoid\nRecordType: dsRecTypeStandard:Groups\n",
                    ))
                } else {
                    Ok(IdentityObservation::failure(
                        100,
                        "eDSRecordNotFound: record not found\n",
                    ))
                }
            }
            other => Err(format!("unexpected identity query: {other:?}")),
        }
    }
}

fn test_tls_evidence() -> v2::TlsEvidence {
    v2::TlsEvidence {
        certificate_sha256: "11".repeat(32),
        private_key_sha256: "22".repeat(32),
    }
}

fn plan_v2_test(
    observer: &FakeLaunchdObserver,
    identity: &FakeIdentity,
    input: &v2::PlanInput,
    key: &[u8; 32],
) -> hs_server::AppResult<v2::PlanResult> {
    machine::plan_v2_macos_with_observers(observer, identity, input, key, &test_tls_evidence())
}

fn root_directory() -> PathMetadata {
    PathMetadata {
        is_symlink: false,
        is_directory: true,
        uid: 0,
        gid: 0,
        mode: 0o755,
    }
}

fn configuration() -> v2::DeploymentConfiguration {
    v2::DeploymentConfiguration {
        deployment_kind: v2::DeploymentKind::MacosLaunchd,
        network: v2::NetworkConfiguration {
            scope: v2::NetworkScope::LoopbackDevelopment,
            authority_port: PORT,
            bind_address: None,
            client_hostname: None,
        },
        storage: v2::StorageConfiguration {
            data_directory: DATA_PATH.to_string(),
            backup_directory: BACKUP_PATH.to_string(),
            preserve_data_on_remove: true,
        },
    }
}

fn preflight_input() -> v2::PreflightInput {
    v2::PreflightInput {
        contract_version: v2::CONTRACT_VERSION,
        configuration: configuration(),
    }
}

fn plan_input(observer: &FakeLaunchdObserver, package_dir: &Path) -> v2::PlanInput {
    let preflight = hs_server::installer::macos_launchd::preflight_v2(observer, &preflight_input())
        .expect("read-only preflight");
    v2::PlanInput {
        contract_version: v2::CONTRACT_VERSION,
        configuration: configuration(),
        preflight,
        package_dir: package_dir.to_string_lossy().into_owned(),
    }
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn manifest_for(platform: &str, bytes: &[u8]) -> PackageManifest {
    PackageManifest {
        format_version: 1,
        product: "hs-server".to_string(),
        version: "0.1.0".to_string(),
        platform: platform.to_string(),
        min_schema_version: 1,
        min_installer_version: "0.1.0".to_string(),
        artifacts: vec![ArtifactEntry {
            path: "artifacts/hs-server".to_string(),
            sha256: manifest::sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        }],
    }
}

fn write_package(root: &Path, key: &SigningKey, platform: &str, bytes: &[u8]) -> [u8; 32] {
    std::fs::create_dir_all(root.join("artifacts")).expect("artifacts dir");
    let manifest = manifest_for(platform, bytes);
    let json = serde_json::to_vec_pretty(&manifest).expect("manifest JSON");
    let signature = key.sign(&json);
    std::fs::write(root.join("manifest.json"), &json).expect("manifest write");
    std::fs::write(root.join("manifest.sig"), signature.to_bytes()).expect("signature write");
    std::fs::write(root.join("artifacts/hs-server"), bytes).expect("artifact write");
    key.verifying_key().to_bytes()
}

fn temp_package(platform: &str) -> (tempfile::TempDir, PathBuf, [u8; 32]) {
    temp_package_with_seed(platform, 11)
}

fn temp_package_with_seed(platform: &str, seed: u8) -> (tempfile::TempDir, PathBuf, [u8; 32]) {
    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path().canonicalize().expect("canonical tempdir");
    let root = base.join("package");
    let key = signing_key(seed);
    let public_key = write_package(&root, &key, platform, b"signed-server");
    (temp, root, public_key)
}

fn temp_package_with_extra_manifest_field(
    platform: &str,
) -> (tempfile::TempDir, PathBuf, [u8; 32]) {
    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path().canonicalize().expect("canonical tempdir");
    let root = base.join("package");
    let key = signing_key(11);
    let bytes = b"signed-server";
    let manifest = manifest_for(platform, bytes);
    let mut value = serde_json::to_value(&manifest).expect("manifest value");
    value.as_object_mut().expect("manifest object").insert(
        "review_extension".to_string(),
        Value::String("bound".to_string()),
    );
    let json = serde_json::to_vec_pretty(&value).expect("manifest JSON");
    let signature = key.sign(&json);
    std::fs::create_dir_all(root.join("artifacts")).expect("artifacts dir");
    std::fs::write(root.join("manifest.json"), &json).expect("manifest write");
    std::fs::write(root.join("manifest.sig"), signature.to_bytes()).expect("signature write");
    std::fs::write(root.join("artifacts/hs-server"), bytes).expect("artifact write");
    (temp, root, key.verifying_key().to_bytes())
}

#[test]
fn absent_identity_plans_a_fresh_install() {
    let observer = FakeLaunchdObserver::with_valid_host("arm64");
    let (_temp, package, public_key) = temp_package("macos-arm64");
    let input = plan_input(&observer, &package);

    let result =
        plan_v2_test(&observer, &FakeIdentity::absent(), &input, &public_key).expect("plan result");

    assert!(result.ok, "unexpected plan error: {:?}", result.error);
    let package_evidence = result.package_evidence.clone().expect("package evidence");
    assert_eq!(package_evidence.target, "macos-arm64");
    assert_eq!(package_evidence.manifest_sha256.len(), 64);
    assert_eq!(package_evidence.verifying_key_sha256.len(), 64);
    assert_eq!(package_evidence.artifact_path, "artifacts/hs-server");
    assert_eq!(package_evidence.artifact_sha256.len(), 64);
    assert_eq!(
        package_evidence.artifact_size_bytes,
        b"signed-server".len() as u64
    );
    let tls_evidence = result.tls_evidence.clone().expect("TLS evidence");
    assert_eq!(tls_evidence.certificate_sha256, "11".repeat(32));
    assert_eq!(tls_evidence.private_key_sha256, "22".repeat(32));
    let identity_evidence = result.identity_evidence.clone().expect("identity evidence");
    assert_eq!(identity_evidence.service_account, PRODUCT_SERVICE_ACCOUNT);
    assert_eq!(identity_evidence.service_group, "_helicoid");
    assert_eq!(identity_evidence.decision, "account_absent_group_absent");
    let plan = result.plan.expect("plan");
    assert_eq!(plan.product, "hs-server");
    assert_eq!(plan.version, "0.1.0");
    assert_eq!(plan.service_user.name, PRODUCT_SERVICE_ACCOUNT);
    assert!(
        plan.service_user.create,
        "the reviewed plan must record the fresh service-account creation"
    );
    assert!(result.reviewed_plan_digest.is_some());
    assert!(plan
        .files
        .iter()
        .any(|file| file.destination == EXECUTABLE_PATH));
    assert!(plan
        .directories
        .iter()
        .any(|directory| directory.path == DATA_PATH));
    assert!(plan
        .directories
        .iter()
        .any(|directory| directory.path == CONFIGURATION_DIRECTORY));
    assert!(
        !plan
            .directories
            .iter()
            .any(|directory| directory.path == BACKUP_PATH),
        "unused caller-selected backup paths must not be created"
    );
    assert!(plan
        .directories
        .iter()
        .any(|directory| directory.path == PRODUCT_ROOT_PATH));
    assert_eq!(plan.units.len(), 1);
    assert_eq!(plan.units[0].name, LAUNCHD_LABEL);
    assert_eq!(plan.listeners.len(), 1);
    assert_eq!(plan.listeners[0].port, PORT);
    assert!(plan
        .not_implemented
        .iter()
        .any(|item| item.contains("readiness")));
    assert!(plan
        .not_implemented
        .iter()
        .any(|item| item.contains("removal")));
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("readiness")));
    assert!(!result
        .capabilities
        .supported_actions
        .contains(&v2::LifecycleAction::Install));
    assert!(!result
        .capabilities
        .supported_actions
        .contains(&v2::LifecycleAction::Resume));

    let mut package_entries = std::fs::read_dir(&package)
        .expect("package directory")
        .map(|entry| {
            entry
                .expect("package entry")
                .file_name()
                .into_string()
                .expect("UTF-8 entry")
        })
        .collect::<Vec<_>>();
    package_entries.sort();
    assert_eq!(
        package_entries,
        vec![
            "artifacts".to_string(),
            "manifest.json".to_string(),
            "manifest.sig".to_string()
        ],
        "planning must not add or remove package files"
    );
}

#[test]
fn existing_identity_is_refused_without_an_independent_receipt() {
    let observer = FakeLaunchdObserver::with_valid_host("arm64");
    let (_temp, package, public_key) = temp_package("macos-arm64");
    let input = plan_input(&observer, &package);

    let result = plan_v2_test(
        &observer,
        &FakeIdentity::unverified_existing(),
        &input,
        &public_key,
    )
    .expect("structured refusal");

    assert!(!result.ok);
    assert!(result.plan.is_none());
    assert!(result.reviewed_plan_digest.is_none());
    let error = result.error.expect("refusal error");
    assert!(error.contains("existing service account '_helicoid' is refused"));
    assert!(error.contains("no independently verifiable product ownership evidence exists"));
    assert!(error.contains("Helicoid-owned receipt"));
}

#[test]
fn identity_refusal_precedes_package_verification() {
    let observer = FakeLaunchdObserver::with_valid_host("arm64");
    let input = plan_input(
        &observer,
        Path::new("/nonexistent-helicoid-package-for-ordering"),
    );
    let public_key = signing_key(11).verifying_key().to_bytes();

    let result = plan_v2_test(
        &observer,
        &FakeIdentity::unverified_existing(),
        &input,
        &public_key,
    )
    .expect("structured refusal");
    assert!(!result.ok);
    let error = result.error.expect("refusal error");
    assert!(error.contains("existing service account"));
    assert!(
        !error.contains("package verification failed"),
        "identity refusal must precede package access: {error}"
    );
}

#[test]
fn absent_user_with_existing_group_is_refused_as_not_fresh() {
    let observer = FakeLaunchdObserver::with_valid_host("arm64");
    let (_temp, package, public_key) = temp_package("macos-arm64");
    let input = plan_input(&observer, &package);

    let result = plan_v2_test(
        &observer,
        &FakeIdentity::absent_with_existing_group(),
        &input,
        &public_key,
    )
    .expect("structured refusal");

    assert!(!result.ok);
    assert!(result.plan.is_none());
    assert!(result.package_evidence.is_none());
    assert!(result.identity_evidence.is_none());
    let error = result.error.expect("refusal error");
    assert!(error.contains("absent but the fixed group '_helicoid' already exists"));
    assert!(error.contains("not a fresh service identity"));
}

#[test]
fn unavailable_identity_is_security_state_unavailable() {
    let observer = FakeLaunchdObserver::with_valid_host("arm64");
    let (_temp, package, public_key) = temp_package("macos-arm64");
    let input = plan_input(&observer, &package);

    let error =
        plan_v2_test(&observer, &FakeIdentity::unavailable(), &input, &public_key).unwrap_err();
    assert_eq!(error.code(), ErrorCode::SecurityStateUnavailable);
}

#[test]
fn changed_host_preflight_refuses_a_stale_plan_review() {
    let observer = FakeLaunchdObserver::with_valid_host("arm64");
    let (_temp, package, public_key) = temp_package("macos-arm64");
    let input = plan_input(&observer, &package);
    observer.set_path(
        PRODUCT_ROOT_PATH,
        PathMetadata {
            is_symlink: false,
            is_directory: false,
            uid: 0,
            gid: 0,
            mode: 0o644,
        },
    );

    let error = plan_v2_test(&observer, &FakeIdentity::absent(), &input, &public_key).unwrap_err();
    assert_eq!(error.code(), ErrorCode::Conflict);
}

#[test]
fn volatile_free_space_does_not_invalidate_the_review() {
    let observer = FakeLaunchdObserver::with_valid_host("arm64");
    let (_temp, package, public_key) = temp_package("macos-arm64");
    let input = plan_input(&observer, &package);
    observer.set_storage(49 * 1024 * 1024 * 1024);

    let result =
        plan_v2_test(&observer, &FakeIdentity::absent(), &input, &public_key).expect("plan result");
    assert!(result.ok, "unexpected plan error: {:?}", result.error);
    let first_digest = result.reviewed_plan_digest.expect("first digest");

    observer.set_storage(48 * 1024 * 1024 * 1024);
    let second = plan_v2_test(&observer, &FakeIdentity::absent(), &input, &public_key)
        .expect("second plan result");
    assert!(second.ok, "unexpected plan error: {:?}", second.error);
    assert_eq!(
        second.reviewed_plan_digest.expect("second digest"),
        first_digest,
        "volatile free-space bytes must not enter the stable digest"
    );
}

#[test]
fn changing_insufficient_storage_counts_is_not_a_stale_review() {
    let observer = FakeLaunchdObserver::with_valid_host("arm64");
    observer.set_storage(1024 * 1024 * 1024);
    let (_temp, package, public_key) = temp_package("macos-arm64");
    let input = plan_input(&observer, &package);
    observer.set_storage(1536 * 1024 * 1024);

    let result =
        plan_v2_test(&observer, &FakeIdentity::absent(), &input, &public_key).expect("plan result");
    assert!(!result.ok);
    assert!(result.plan.is_none());
    assert!(result
        .error
        .as_deref()
        .is_some_and(|error| error.contains("preflight checks failed")));
}

#[test]
fn package_target_is_derived_from_the_observed_architecture() {
    let arm_observer = FakeLaunchdObserver::with_valid_host("arm64");
    let (_arm_temp, arm_package, arm_key) = temp_package("macos-arm64");
    let arm_input = plan_input(&arm_observer, &arm_package);
    let arm_result = plan_v2_test(&arm_observer, &FakeIdentity::absent(), &arm_input, &arm_key)
        .expect("arm plan result");
    assert!(arm_result.ok, "{:?}", arm_result.error);
    assert_eq!(
        arm_result.plan.expect("arm plan").files[0].destination,
        EXECUTABLE_PATH
    );

    let intel_observer = FakeLaunchdObserver::with_valid_host("x86_64");
    let (_intel_temp, intel_package, intel_key) = temp_package("macos-x86_64");
    let intel_input = plan_input(&intel_observer, &intel_package);
    let intel_result = plan_v2_test(
        &intel_observer,
        &FakeIdentity::absent(),
        &intel_input,
        &intel_key,
    )
    .expect("intel plan result");
    assert!(intel_result.ok, "{:?}", intel_result.error);

    let mismatch_observer = FakeLaunchdObserver::with_valid_host("arm64");
    let mismatch_input = plan_input(&mismatch_observer, &intel_package);
    let mismatch = plan_v2_test(
        &mismatch_observer,
        &FakeIdentity::absent(),
        &mismatch_input,
        &intel_key,
    )
    .expect("mismatch result");
    assert!(!mismatch.ok);
    assert!(mismatch.plan.is_none());
    assert!(mismatch
        .error
        .as_deref()
        .is_some_and(|error| error.contains("package verification failed")));
}

#[test]
fn inconsistent_preflight_ok_flags_are_refused() {
    let observer = FakeLaunchdObserver::with_valid_host("arm64");
    let (_temp, package, public_key) = temp_package("macos-arm64");
    let mut input = plan_input(&observer, &package);
    input.preflight.host_checks.ok = false;

    let error = plan_v2_test(&observer, &FakeIdentity::absent(), &input, &public_key).unwrap_err();
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert!(error
        .to_string()
        .contains("preflight.ok must match host_checks.ok"));
}

#[test]
fn reviewed_digest_binds_exact_manifest_key_target_and_artifact() {
    let observer = FakeLaunchdObserver::with_valid_host("arm64");

    let (_base_temp, base_package, base_key) = temp_package("macos-arm64");
    let base_input = plan_input(&observer, &base_package);
    let base = plan_v2_test(&observer, &FakeIdentity::absent(), &base_input, &base_key)
        .expect("base plan");
    assert!(base.ok, "{:?}", base.error);
    let base_digest = base.reviewed_plan_digest.expect("base digest");
    let base_evidence = base.package_evidence.expect("base evidence");

    // Same signed manifest bytes and artifact, different caller-supplied key.
    let (_key_temp, key_package, key_key) = temp_package_with_seed("macos-arm64", 12);
    let key_input = plan_input(&observer, &key_package);
    let key_plan =
        plan_v2_test(&observer, &FakeIdentity::absent(), &key_input, &key_key).expect("key plan");
    assert!(key_plan.ok, "{:?}", key_plan.error);
    let key_evidence = key_plan.package_evidence.expect("key evidence");
    assert_eq!(
        key_evidence.manifest_sha256, base_evidence.manifest_sha256,
        "the manifest bytes should be identical"
    );
    assert_ne!(
        key_evidence.verifying_key_sha256,
        base_evidence.verifying_key_sha256
    );
    assert_ne!(
        key_plan.reviewed_plan_digest.expect("key digest"),
        base_digest
    );

    // Same key and artifact, different exact signed manifest bytes.
    let (_manifest_temp, manifest_package, manifest_key) =
        temp_package_with_extra_manifest_field("macos-arm64");
    let manifest_input = plan_input(&observer, &manifest_package);
    let manifest_plan = plan_v2_test(
        &observer,
        &FakeIdentity::absent(),
        &manifest_input,
        &manifest_key,
    )
    .expect("manifest plan");
    assert!(manifest_plan.ok, "{:?}", manifest_plan.error);
    let manifest_evidence = manifest_plan.package_evidence.expect("manifest evidence");
    assert_ne!(
        manifest_evidence.manifest_sha256,
        base_evidence.manifest_sha256
    );
    assert_ne!(
        manifest_plan.reviewed_plan_digest.expect("manifest digest"),
        base_digest
    );

    // A different target/package platform also changes the digest.
    let intel_observer = FakeLaunchdObserver::with_valid_host("x86_64");
    let (_intel_temp, intel_package, intel_key) = temp_package("macos-x86_64");
    let intel_input = plan_input(&intel_observer, &intel_package);
    let intel_plan = plan_v2_test(
        &intel_observer,
        &FakeIdentity::absent(),
        &intel_input,
        &intel_key,
    )
    .expect("intel plan");
    assert!(intel_plan.ok, "{:?}", intel_plan.error);
    let intel_evidence = intel_plan.package_evidence.expect("intel evidence");
    assert_eq!(intel_evidence.target, "macos-x86_64");
    assert_ne!(
        intel_plan.reviewed_plan_digest.expect("intel digest"),
        base_digest
    );
}

#[test]
fn wrong_package_key_or_failed_preflight_yields_no_plan() {
    let observer = FakeLaunchdObserver::with_valid_host("arm64");
    let (_temp, package, public_key) = temp_package("macos-arm64");
    let input = plan_input(&observer, &package);
    let wrong_key = signing_key(12).verifying_key().to_bytes();

    let wrong_key_result = plan_v2_test(&observer, &FakeIdentity::absent(), &input, &wrong_key)
        .expect("wrong key result");
    assert!(!wrong_key_result.ok);
    assert!(wrong_key_result.plan.is_none());
    assert!(wrong_key_result
        .error
        .as_deref()
        .is_some_and(|error| error.contains("package verification failed")));

    let failed_preflight_observer = FakeLaunchdObserver::with_valid_host("arm64");
    failed_preflight_observer.set_path(
        LAUNCHD_PLIST_PATH,
        PathMetadata {
            is_symlink: false,
            is_directory: false,
            uid: 0,
            gid: 0,
            mode: 0o644,
        },
    );
    let failed_input = plan_input(&failed_preflight_observer, &package);
    let failed_result = plan_v2_test(
        &failed_preflight_observer,
        &FakeIdentity::absent(),
        &failed_input,
        &public_key,
    )
    .expect("failed preflight result");
    assert!(!failed_result.ok);
    assert!(failed_result.plan.is_none());
}

#[cfg(target_os = "macos")]
mod cli {
    //! macOS-only CLI evidence for the installer path and the fail-closed
    //! service entry. These tests invoke the real binary; they do not install,
    //! load, elevate, or write a system resource.

    use std::io::Write;
    use std::process::{Command, Output, Stdio};

    use serde_json::Value;

    fn run_installer(arguments: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_hs-server"))
            .args(["installer"])
            .args(arguments)
            .env("RUST_LOG", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn hs-server");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes())
            .expect("write installer stdin");
        child.wait_with_output().expect("wait for hs-server")
    }

    fn preflight_input() -> String {
        serde_json::json!({
            "contract_version": 2,
            "configuration": {
                "deployment_kind": "macos_launchd",
                "network": {
                    "scope": "loopback_development",
                    "authority_port": 8920
                },
                "storage": {
                    "data_directory": "/Library/Application Support/Helicoid/Data",
                    "backup_directory": "/private/tmp/helicoid-backup-fixture",
                    "preserve_data_on_remove": true
                }
            }
        })
        .to_string()
    }

    #[test]
    fn cli_capabilities_keep_install_gated_off() {
        let output = run_installer(&["capabilities-v2"], "");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).expect("capabilities JSON");

        assert_eq!(value["contract_version"], 2);
        assert_eq!(
            value["supported_deployment_kinds"],
            serde_json::json!(["macos_launchd"])
        );
        assert_eq!(
            value["supported_actions"],
            serde_json::json!(["preflight", "plan"])
        );
        assert_eq!(value["cancellation"], serde_json::json!(false));
        assert_eq!(value["durable_operation_journal"], serde_json::json!(false));
        assert!(value["reasons_unavailable"]["enrollment_readiness"]
            .as_str()
            .is_some_and(|reason| reason.contains("development-only")));
    }

    #[test]
    fn cli_preflight_v2_emits_existing_contract_without_readiness_claims() {
        let output = run_installer(&["preflight-v2"], &preflight_input());
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).expect("preflight JSON");

        assert_eq!(value["contract_version"], 2);
        assert_eq!(value["configuration"]["deployment_kind"], "macos_launchd");
        assert_eq!(value["configuration"]["network"]["authority_port"], 8920);
        assert_eq!(value["host_checks"]["contract_version"], 1);

        let paths = value["host_checks"]["checks"]["paths"]["checked"]
            .as_array()
            .expect("path evidence");
        for expected in [
            "/Library/Application Support/Helicoid",
            "/Library/Application Support/Helicoid/Data",
            "/Library/LaunchDaemons/com.helicoid.server.plist",
            "/private/tmp/helicoid-backup-fixture",
        ] {
            assert!(
                paths.iter().any(|path| path["path"] == expected),
                "missing reviewed path {expected}"
            );
        }

        assert_eq!(
            value["capabilities"]["supported_deployment_kinds"],
            serde_json::json!(["macos_launchd"])
        );
        assert_eq!(
            value["capabilities"]["supported_actions"],
            serde_json::json!(["preflight", "plan"])
        );
        assert!(value.get("service_installed").is_none());
        assert!(value.get("bootstrap_ready").is_none());
        assert!(value.get("server_ready_for_enrollment").is_none());
    }

    #[test]
    fn cli_rejects_unavailable_mutation_commands_on_macos() {
        let output = run_installer(&["remove-v2"], "");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("only installer")
                && stderr.contains("apply-v2")
                && stderr.contains("cancel-v2"),
            "unexpected stderr: {stderr}"
        );
    }

    #[test]
    fn cli_apply_v2_is_recognized_and_fails_closed_on_invalid_input() {
        let output = run_installer(&["apply-v2"], "{}");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("invalid v2 apply input"),
            "apply-v2 must be a recognized command, stderr: {stderr}"
        );
    }

    #[test]
    fn cli_plan_v2_is_wired_without_enabling_install() {
        let output = run_installer(
            &[
                "plan-v2",
                "--package-dir",
                "/nonexistent-helicoid-package",
                "--verify-key",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ],
            "{}",
        );
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("invalid v2 plan input"),
            "plan-v2 must be a recognized read-only command, stderr: {stderr}"
        );
        assert!(
            !stderr.contains("only installer capabilities-v2"),
            "plan-v2 must not be rejected as an unavailable command: {stderr}"
        );
    }

    #[test]
    fn cli_rejects_linux_deployment_input_on_macos() {
        let linux = serde_json::json!({
            "contract_version": 2,
            "configuration": {
                "deployment_kind": "linux_systemd",
                "network": {
                    "scope": "loopback_development",
                    "authority_port": 8787
                },
                "storage": {
                    "data_directory": "/var/lib/helicoid/data",
                    "backup_directory": "/var/lib/helicoid/backups",
                    "preserve_data_on_remove": true
                }
            }
        })
        .to_string();

        let output = run_installer(&["preflight-v2"], &linux);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("macOS launchd deployment"),
            "unexpected stderr: {stderr}"
        );
    }

    #[test]
    fn cli_fixed_service_verb_fails_closed_without_starting() {
        let output = Command::new(env!("CARGO_BIN_EXE_hs-server"))
            .arg("macos-service")
            .env("RUST_LOG", "off")
            .output()
            .expect("run hs-server macos-service");
        assert!(
            !output.status.success(),
            "the prepared macOS service must not start in this build"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("refusing")
                || stderr.contains("must not run as root")
                || stderr.contains("cannot verify"),
            "unexpected fail-closed diagnostic: {stderr}"
        );
        assert!(
            !stderr.contains("listening"),
            "the service must not reach the listener: {stderr}"
        );
    }
}

mod apply_lifecycle {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use hs_server::installer::macos_apply::{
        apply_v2_with_adapter, cancel_v2_with_adapter, status_v2_with_adapter,
        verify_runtime_receipt_with_adapter, verify_runtime_receipt_with_adapter_for_euid,
        MacosApplyAdapter, MacosApplyLock, MacosApplyPathMetadata, TlsSourceEvidence,
        INSTALL_LOCK_PATH, INSTALL_RECEIPT_PATH, INSTALL_STATE_DIRECTORY,
    };
    use hs_server::installer::macos_identity::{
        GroupRecordFacts, IdentityObservation, IdentityQuery, IdentityRefusal,
        ServiceIdentityDecision, UserRecordFacts,
    };

    struct FakeApplyHost {
        state: Mutex<FakeState>,
        preflight: v2::PreflightResult,
        tls_ok: bool,
        launchd_bootstrap_fails: bool,
        health_ok: bool,
        create_data_on_bootstrap: bool,
        group_create_foreign_failure: bool,
        tls_source_changed: bool,
        fail_journal_writes: bool,
        fail_terminal_record_write: bool,
        bootout_leaves_loaded: bool,
        write_corrupt_receipt: bool,
        lock_held: Arc<Mutex<bool>>,
    }

    struct FakeState {
        user: Option<UserRecordFacts>,
        group: Option<GroupRecordFacts>,
        paths: BTreeMap<PathBuf, MacosApplyPathMetadata>,
        files: BTreeMap<PathBuf, Vec<u8>>,
        created_user: bool,
        created_group: bool,
        launchd_loaded: bool,
        launchd_bootstraps: usize,
        launchd_bootouts: usize,
    }

    impl FakeApplyHost {
        fn new(preflight: v2::PreflightResult) -> Self {
            let mut paths = BTreeMap::new();
            for path in [
                "/",
                "/var",
                "/var/lib",
                "/Library",
                "/Library/Application Support",
                "/Library/LaunchDaemons",
            ] {
                paths.insert(
                    PathBuf::from(path),
                    MacosApplyPathMetadata {
                        is_symlink: false,
                        is_directory: true,
                        is_regular_file: false,
                        uid: 0,
                        gid: 0,
                        mode: 0o755,
                        nlink: 1,
                        len: 0,
                    },
                );
            }
            Self {
                state: Mutex::new(FakeState {
                    user: None,
                    group: None,
                    paths,
                    files: BTreeMap::new(),
                    created_user: false,
                    created_group: false,
                    launchd_loaded: false,
                    launchd_bootstraps: 0,
                    launchd_bootouts: 0,
                }),
                preflight,
                tls_ok: true,
                launchd_bootstrap_fails: false,
                health_ok: true,
                create_data_on_bootstrap: false,
                group_create_foreign_failure: false,
                tls_source_changed: false,
                fail_journal_writes: false,
                fail_terminal_record_write: false,
                bootout_leaves_loaded: false,
                write_corrupt_receipt: false,
                lock_held: Arc::new(Mutex::new(false)),
            }
        }

        fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
            self.state.lock().unwrap()
        }
    }

    impl MacosApplyAdapter for FakeApplyHost {
        fn now_iso8601(&self) -> String {
            "2026-11-10T00:00:00Z".to_string()
        }

        fn effective_uid(&self) -> Result<u32, String> {
            Ok(0)
        }

        fn preflight(
            &self,
            _configuration: &v2::DeploymentConfiguration,
        ) -> hs_server::AppResult<v2::PreflightResult> {
            Ok(self.preflight.clone())
        }

        fn identity_decision(&self) -> ServiceIdentityDecision {
            let state = self.state();
            match (state.user.is_some(), state.group.is_some()) {
                (false, false) => ServiceIdentityDecision::AccountAbsentObservation,
                (true, true) => ServiceIdentityDecision::ExistingAccountRefused {
                    reasons: vec![IdentityRefusal::OwnershipNotVerified],
                },
                _ => ServiceIdentityDecision::Unavailable {
                    reason: "partial fixture identity".to_string(),
                },
            }
        }

        fn observe_user(&self) -> Result<Option<UserRecordFacts>, String> {
            Ok(self.state().user.clone())
        }

        fn observe_group(&self) -> Result<Option<GroupRecordFacts>, String> {
            Ok(self.state().group.clone())
        }

        fn identity_search(&self, _query: IdentityQuery) -> Result<IdentityObservation, String> {
            Ok(IdentityObservation::success(""))
        }

        fn resolver_identity_absent(&self) -> Result<bool, String> {
            let state = self.state();
            Ok(state.user.is_none() && state.group.is_none())
        }

        fn resolver_id_in_use(&self, id: u32) -> Result<bool, String> {
            let state = self.state();
            Ok(state.user.as_ref().is_some_and(|user| {
                user.unique_id == i64::from(id) || user.primary_group_id == i64::from(id)
            }) || state
                .group
                .as_ref()
                .is_some_and(|group| group.primary_group_id == i64::from(id)))
        }

        fn resolver_user_by_uid(&self, uid: u32) -> Result<Option<String>, String> {
            Ok(self.state().user.as_ref().and_then(|user| {
                (user.unique_id == i64::from(uid)).then(|| user.record_names[0].clone())
            }))
        }

        fn resolver_group_by_gid(&self, gid: u32) -> Result<Option<String>, String> {
            Ok(self.state().group.as_ref().and_then(|group| {
                (group.primary_group_id == i64::from(gid)).then(|| group.record_names[0].clone())
            }))
        }

        fn resolver_identity_matches(&self, uid: u32, gid: u32) -> Result<bool, String> {
            let state = self.state();
            Ok(state.user.as_ref().is_some_and(|user| {
                user.unique_id == i64::from(uid)
                    && user.primary_group_id == i64::from(gid)
                    && user.record_names.len() == 1
                    && user.record_names[0] == "_helicoid"
            }) && state.group.as_ref().is_some_and(|group| {
                group.primary_group_id == i64::from(gid)
                    && group.record_names.len() == 1
                    && group.record_names[0] == "_helicoid"
            }))
        }

        fn create_service_group(&self, name: &str, gid: u32) -> Result<(), String> {
            let mut state = self.state();
            if state.group.is_some() {
                return Err("group already exists".to_string());
            }
            if self.group_create_foreign_failure {
                state.group = Some(GroupRecordFacts {
                    record_names: vec![name.to_string()],
                    record_type: "dsRecTypeStandard:Groups".to_string(),
                    primary_group_id: i64::from(gid) + 1,
                    group_membership: Vec::new(),
                });
                return Err("fixture created a foreign group".to_string());
            }
            state.group = Some(GroupRecordFacts {
                record_names: vec![name.to_string()],
                record_type: "dsRecTypeStandard:Groups".to_string(),
                primary_group_id: i64::from(gid),
                group_membership: Vec::new(),
            });
            state.created_group = true;
            Ok(())
        }

        fn create_service_user(&self, name: &str, uid: u32, gid: u32) -> Result<(), String> {
            let mut state = self.state();
            if state.user.is_some() {
                return Err("user already exists".to_string());
            }
            state.user = Some(UserRecordFacts {
                record_names: vec![name.to_string()],
                record_type: "dsRecTypeStandard:Users".to_string(),
                unique_id: i64::from(uid),
                primary_group_id: i64::from(gid),
                user_shell: "/usr/bin/false".to_string(),
                password: "*".to_string(),
                authentication_authority: Vec::new(),
            });
            state.created_user = true;
            Ok(())
        }

        fn remove_service_user(&self, _name: &str) -> Result<(), String> {
            let mut state = self.state();
            state.user = None;
            Ok(())
        }

        fn remove_service_group(&self, _name: &str) -> Result<(), String> {
            let mut state = self.state();
            state.group = None;
            Ok(())
        }

        fn path_metadata(&self, path: &Path) -> Result<Option<MacosApplyPathMetadata>, String> {
            Ok(self.state().paths.get(path).copied())
        }

        fn create_directory(
            &self,
            path: &Path,
            mode: u32,
            uid: u32,
            gid: u32,
        ) -> Result<(), String> {
            let mut state = self.state();
            if state.paths.contains_key(path) {
                return Err("path already exists".to_string());
            }
            state.paths.insert(
                path.to_path_buf(),
                MacosApplyPathMetadata {
                    is_symlink: false,
                    is_directory: true,
                    is_regular_file: false,
                    uid,
                    gid,
                    mode,
                    nlink: 1,
                    len: 0,
                },
            );
            Ok(())
        }

        fn remove_directory(&self, path: &Path) -> Result<(), String> {
            let mut state = self.state();
            if state.paths.keys().any(|candidate| {
                candidate.as_path() != path && candidate.as_path().starts_with(path)
            }) {
                return Err("directory is not empty".to_string());
            }
            state.paths.remove(path);
            Ok(())
        }

        fn write_new_file(
            &self,
            path: &Path,
            contents: &[u8],
            mode: u32,
            uid: u32,
            gid: u32,
        ) -> Result<(), String> {
            let mut state = self.state();
            if state.paths.contains_key(path) {
                return Err("path already exists".to_string());
            }
            let bytes = if self.write_corrupt_receipt && path == Path::new(INSTALL_RECEIPT_PATH) {
                b"{}".to_vec()
            } else {
                contents.to_vec()
            };
            state.paths.insert(
                path.to_path_buf(),
                MacosApplyPathMetadata {
                    is_symlink: false,
                    is_directory: false,
                    is_regular_file: true,
                    uid,
                    gid,
                    mode,
                    nlink: 1,
                    len: bytes.len() as u64,
                },
            );
            state.files.insert(path.to_path_buf(), bytes);
            Ok(())
        }

        fn write_state_file(&self, path: &Path, contents: &[u8]) -> Result<(), String> {
            if self.fail_journal_writes
                && path.file_name().and_then(|name| name.to_str()) == Some("journal.json")
            {
                return Err("fixture journal write failure".to_string());
            }
            if self.fail_terminal_record_write
                && path.file_name().and_then(|name| name.to_str()) == Some("operation-v2.json")
                && std::str::from_utf8(contents)
                    .map(|text| text.contains("\"outcome\""))
                    .unwrap_or(false)
            {
                return Err("fixture terminal record write failure".to_string());
            }
            let mut state = self.state();
            state.paths.insert(
                path.to_path_buf(),
                MacosApplyPathMetadata {
                    is_symlink: false,
                    is_directory: false,
                    is_regular_file: true,
                    uid: 0,
                    gid: 0,
                    mode: 0o600,
                    nlink: 1,
                    len: contents.len() as u64,
                },
            );
            state.files.insert(path.to_path_buf(), contents.to_vec());
            Ok(())
        }

        fn remove_file(&self, path: &Path) -> Result<(), String> {
            let mut state = self.state();
            state.paths.remove(path);
            state.files.remove(path);
            Ok(())
        }

        fn read_bounded_file(&self, path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
            let state = self.state();
            let bytes = state
                .files
                .get(path)
                .ok_or_else(|| "file is absent".to_string())?;
            if bytes.len() > max_bytes {
                return Err("file exceeds bound".to_string());
            }
            Ok(bytes.clone())
        }

        fn extended_acl_is_safe(&self, _path: &Path) -> Result<bool, String> {
            Ok(true)
        }

        fn authorize_package_key(&self, _verify_key_hex: &str) -> Result<(), String> {
            Ok(())
        }

        fn validate_tls_sources(&self, _port: u16) -> Result<TlsSourceEvidence, String> {
            if self.tls_ok {
                Ok(TlsSourceEvidence {
                    certificate_sha256: "11".repeat(32),
                    private_key_sha256: "22".repeat(32),
                })
            } else {
                Err("TLS source fixture is invalid".to_string())
            }
        }

        fn copy_tls_file(
            &self,
            _source: &Path,
            destination: &Path,
            uid: u32,
            gid: u32,
            _expected_sha256: &str,
        ) -> Result<(), String> {
            if self.tls_source_changed {
                return Err("TLS source changed after review".to_string());
            }
            self.write_new_file(destination, b"fixture-tls", 0o600, uid, gid)
        }

        fn launchd_bootstrap(&self, _plist: &Path, _label: &str) -> Result<(), String> {
            if self.launchd_bootstrap_fails {
                return Err("fixture bootstrap failure".to_string());
            }
            if self.create_data_on_bootstrap {
                self.write_new_file(
                    &Path::new(DATA_PATH).join("hs-server.db"),
                    b"fixture-database",
                    0o600,
                    400,
                    400,
                )?;
            }
            let mut state = self.state();
            state.launchd_bootstraps += 1;
            state.launchd_loaded = true;
            Ok(())
        }

        fn launchd_bootout(&self, _label: &str) -> Result<(), String> {
            let mut state = self.state();
            state.launchd_bootouts += 1;
            if !self.bootout_leaves_loaded {
                state.launchd_loaded = false;
            }
            Ok(())
        }

        fn launchd_is_loaded(&self, _label: &str) -> Result<bool, String> {
            Ok(self.state().launchd_loaded)
        }

        fn service_health(
            &self,
            _port: u16,
            _expected_certificate_sha256: &str,
            _service_uid: u32,
        ) -> Result<bool, String> {
            Ok(self.health_ok)
        }

        fn acquire_lock(&self, _path: &Path) -> Result<MacosApplyLock, String> {
            let mut held = self.lock_held.lock().unwrap();
            if *held {
                return Err("another operation holds the fixture lock".to_string());
            }
            *held = true;
            let lock = self.lock_held.clone();
            Ok(MacosApplyLock::new(move || {
                *lock.lock().unwrap() = false;
            }))
        }
    }

    fn apply_input(observer: &FakeLaunchdObserver) -> (v2::ApplyInput, [u8; 32]) {
        let (_temp, package, public_key) = temp_package("macos-arm64");
        let input = plan_input(observer, &package);
        let result = plan_v2_test(observer, &FakeIdentity::absent(), &input, &public_key)
            .expect("plan result");
        let apply = v2::ApplyInput {
            contract_version: v2::CONTRACT_VERSION,
            configuration: configuration(),
            preflight: input.preflight.clone(),
            plan: result.plan.expect("planned install"),
            reviewed_plan_digest: result.reviewed_plan_digest.expect("reviewed digest"),
            confirm: true,
            package_dir: package.to_string_lossy().into_owned(),
            verify_key: hex::encode(&public_key[..]),
        };
        (apply, public_key)
    }

    fn state_dir() -> PathBuf {
        PathBuf::from(INSTALL_STATE_DIRECTORY)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_macos_adapter_has_no_trusted_release_root() {
        let adapter = hs_server::installer::macos_apply::MacosSystemApplyAdapter::new();
        let error = adapter
            .authorize_package_key(&"00".repeat(32))
            .expect_err("no trusted release root is configured");
        assert!(error.contains("gated off"), "unexpected error: {error}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_macos_adapter_refuses_non_root_before_any_effect() {
        // A root runner would make this test perform privileged host changes;
        // skip rather than risk an unplanned install. CI macOS runners are
        // unprivileged and exercise the fail-closed root gate.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let (input, _key) = apply_input(&observer);
        let state_root = tempfile::tempdir().expect("tempdir");
        let state_dir = state_root
            .path()
            .canonicalize()
            .expect("canonical")
            .join("installer");
        let error = hs_server::installer::machine::apply_v2_macos(&input, &state_dir)
            .expect_err("non-root apply must refuse");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert!(
            !state_dir.exists(),
            "root refusal must precede state effects"
        );
    }

    #[test]
    fn fresh_apply_creates_identity_files_tls_receipt_and_launchd() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let host = FakeApplyHost::new(preflight);
        let (input, _key) = apply_input(&observer);

        let status = apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply");
        assert_eq!(status.state, v2::OperationState::Completed);
        assert!(status.service_installed);
        assert!(!status.bootstrap_ready);
        assert!(!status.server_ready_for_enrollment);
        assert_eq!(status.result.code, "installed");

        let state = host.state();
        assert!(state.created_user);
        assert!(state.created_group);
        assert_eq!(state.launchd_bootstraps, 1);
        assert!(state.launchd_loaded);
        assert!(state.files.contains_key(Path::new(EXECUTABLE_PATH)));
        assert!(state.files.contains_key(Path::new(
            hs_server::installer::macos_launchd::CONFIGURATION_PATH
        )));
        assert!(state.files.contains_key(Path::new(
            hs_server::installer::macos_launchd::LAUNCHD_PLIST_PATH
        )));
        assert!(state.files.contains_key(Path::new(INSTALL_RECEIPT_PATH)));
        assert!(state.files.contains_key(Path::new(
            hs_server::installer::macos_launchd::TLS_CERTIFICATE_PATH
        )));
        assert!(state.files.contains_key(Path::new(
            hs_server::installer::macos_launchd::TLS_PRIVATE_KEY_PATH
        )));
        let journal_path = state_dir().join("journal.json");
        let operation_path = state_dir().join("operation-v2.json");
        assert!(state.files.contains_key(&journal_path));
        assert!(state.files.contains_key(&operation_path));
        drop(state);

        assert!(verify_runtime_receipt_with_adapter(&host).expect("valid receipt"));

        let mut state = host.state();
        state.user.as_mut().expect("user").unique_id = 999;
        drop(state);
        let error = verify_runtime_receipt_with_adapter(&host)
            .expect_err("changed UID must invalidate the receipt");
        assert_eq!(error.code(), ErrorCode::SecurityStateUnavailable);
    }

    #[test]
    fn receipt_is_bound_to_the_running_effective_uid() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let host = FakeApplyHost::new(preflight);
        let (input, _key) = apply_input(&observer);
        apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply");

        assert!(
            verify_runtime_receipt_with_adapter_for_euid(&host, Some(400)).expect("matching euid")
        );
        let error = verify_runtime_receipt_with_adapter_for_euid(&host, Some(401))
            .expect_err("wrong euid must fail closed");
        assert_eq!(error.code(), ErrorCode::SecurityStateUnavailable);
    }

    #[test]
    fn receipt_rejects_a_name_mismatched_identity() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let host = FakeApplyHost::new(preflight);
        let (input, _key) = apply_input(&observer);
        apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply");
        {
            let mut state = host.state();
            state.user.as_mut().expect("user").record_names[0] = "foreign_account".to_string();
        }
        let error =
            verify_runtime_receipt_with_adapter(&host).expect_err("name mismatch must fail closed");
        assert_eq!(error.code(), ErrorCode::SecurityStateUnavailable);
    }

    #[test]
    fn existing_identity_is_refused_before_any_mutation() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let host = FakeApplyHost::new(preflight);
        let mut state = host.state();
        state.user = Some(UserRecordFacts {
            record_names: vec![PRODUCT_SERVICE_ACCOUNT.to_string()],
            record_type: "dsRecTypeStandard:Users".to_string(),
            unique_id: 501,
            primary_group_id: 20,
            user_shell: "/bin/zsh".to_string(),
            password: "*".to_string(),
            authentication_authority: Vec::new(),
        });
        state.group = Some(GroupRecordFacts {
            record_names: vec!["staff".to_string()],
            record_type: "dsRecTypeStandard:Groups".to_string(),
            primary_group_id: 20,
            group_membership: Vec::new(),
        });
        drop(state);
        let (input, _key) = apply_input(&observer);

        let error = apply_v2_with_adapter(&host, &input, &state_dir()).expect_err("must refuse");
        assert_eq!(error.code(), ErrorCode::Conflict);
        let state = host.state();
        assert!(!state.created_user);
        assert!(!state.created_group);
        assert_eq!(state.launchd_bootstraps, 0);
        assert!(!state.paths.contains_key(Path::new(EXECUTABLE_PATH)));
    }

    #[test]
    fn changed_reviewed_digest_is_refused_before_any_effect() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let host = FakeApplyHost::new(preflight);
        let (mut input, _key) = apply_input(&observer);
        input.reviewed_plan_digest = "00".repeat(32);

        let error = apply_v2_with_adapter(&host, &input, &state_dir()).expect_err("must refuse");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        let state = host.state();
        assert!(!state.created_user);
        assert!(!state.created_group);
        assert!(!state.paths.contains_key(Path::new(EXECUTABLE_PATH)));
    }

    #[test]
    fn invalid_tls_is_refused_before_identity_or_filesystem_effects() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let mut host = FakeApplyHost::new(preflight);
        host.tls_ok = false;
        let (input, _key) = apply_input(&observer);

        let error = apply_v2_with_adapter(&host, &input, &state_dir()).expect_err("must refuse");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        let state = host.state();
        assert!(!state.created_user);
        assert!(!state.created_group);
        assert!(!state.paths.contains_key(Path::new(EXECUTABLE_PATH)));
    }

    #[test]
    fn stale_lock_file_does_not_wedge_apply() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let host = FakeApplyHost::new(preflight);
        let state_dir = state_dir();
        {
            let mut state = host.state();
            state.paths.insert(
                state_dir.clone(),
                MacosApplyPathMetadata {
                    is_symlink: false,
                    is_directory: true,
                    is_regular_file: false,
                    uid: 0,
                    gid: 0,
                    mode: 0o700,
                    nlink: 1,
                    len: 0,
                },
            );
            state.paths.insert(
                PathBuf::from(INSTALL_LOCK_PATH),
                MacosApplyPathMetadata {
                    is_symlink: false,
                    is_directory: false,
                    is_regular_file: true,
                    uid: 0,
                    gid: 0,
                    mode: 0o600,
                    nlink: 1,
                    len: 8,
                },
            );
        }
        let (input, _key) = apply_input(&observer);
        let status = apply_v2_with_adapter(&host, &input, &state_dir).expect("apply");
        assert_eq!(status.state, v2::OperationState::Completed);
    }

    #[test]
    fn concurrent_operation_lock_is_refused() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let host = FakeApplyHost::new(preflight);
        let _first = host
            .acquire_lock(Path::new(INSTALL_LOCK_PATH))
            .expect("first lock");
        let error = host
            .acquire_lock(Path::new(INSTALL_LOCK_PATH))
            .expect_err("second lock must be busy");
        assert!(error.contains("holds the fixture lock"));
    }

    #[test]
    fn uncertain_group_rollback_keeps_identity_and_reports_incomplete() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let mut host = FakeApplyHost::new(preflight);
        host.group_create_foreign_failure = true;
        let (input, _key) = apply_input(&observer);

        let status = apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply result");
        assert_eq!(status.state, v2::OperationState::AttentionRequired);
        assert_eq!(status.result.code, "rollback_incomplete");
        let state = host.state();
        assert!(state.group.is_some(), "uncertain group must not be deleted");
        assert!(!state.created_user);
        assert!(state.files.contains_key(&state_dir().join("journal.json")));
    }

    #[test]
    fn tls_source_change_after_validation_rolls_back() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let mut host = FakeApplyHost::new(preflight);
        host.tls_source_changed = true;
        let (input, _key) = apply_input(&observer);

        let status = apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply result");
        assert_eq!(status.state, v2::OperationState::AttentionRequired);
        assert_eq!(status.result.code, "rolled_back");
        let state = host.state();
        assert!(state.user.is_none());
        assert!(state.group.is_none());
        assert!(!state.files.contains_key(&state_dir().join("journal.json")));
    }

    #[test]
    fn failed_health_without_owned_data_rolls_back_completely() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let mut host = FakeApplyHost::new(preflight);
        host.health_ok = false;
        let (input, _key) = apply_input(&observer);

        let status = apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply result");
        assert_eq!(status.state, v2::OperationState::AttentionRequired);
        assert_eq!(status.result.code, "rolled_back");
        assert!(!status.service_installed);
        let state = host.state();
        assert!(state.user.is_none());
        assert!(state.group.is_none());
        assert!(!state.launchd_loaded);
        assert!(!state.files.contains_key(&state_dir().join("journal.json")));
    }

    #[test]
    fn completed_journal_without_final_record_is_not_reported_installed() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let host = FakeApplyHost::new(preflight);
        let (input, _key) = apply_input(&observer);
        apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply");

        let record_path = state_dir().join("operation-v2.json");
        let mut record: serde_json::Value = {
            let state = host.state();
            serde_json::from_slice(state.files.get(&record_path).expect("record")).expect("json")
        };
        record
            .as_object_mut()
            .expect("record object")
            .remove("outcome");
        host.write_state_file(
            &record_path,
            &serde_json::to_vec(&record).expect("record bytes"),
        )
        .expect("replace record");

        let status = status_v2_with_adapter(
            &host,
            &v2::StatusInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
            &state_dir(),
        )
        .expect("status");
        assert_eq!(status.state, v2::OperationState::AttentionRequired);
        assert!(!status.service_installed);
        assert!(
            !status.cancellation_available,
            "unverified completion requires explicit recovery, not normal cancel"
        );
    }

    #[test]
    fn journal_with_unconstrained_path_is_refused() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let host = FakeApplyHost::new(preflight);
        let (input, _key) = apply_input(&observer);
        apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply");

        let journal_path = state_dir().join("journal.json");
        let mut journal: serde_json::Value = {
            let state = host.state();
            serde_json::from_slice(state.files.get(&journal_path).expect("journal")).expect("json")
        };
        journal["resources"]
            .as_array_mut()
            .expect("resources")
            .push(serde_json::json!({
                "resource_type": "file",
                "identity": "/tmp/unconstrained-delete-target",
                "status": "completed"
            }));
        host.write_state_file(
            &journal_path,
            &serde_json::to_vec(&journal).expect("journal bytes"),
        )
        .expect("replace journal");

        let error = status_v2_with_adapter(
            &host,
            &v2::StatusInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
            &state_dir(),
        )
        .expect_err("unconstrained journal path must fail closed");
        assert_eq!(error.code(), ErrorCode::SecurityStateUnavailable);
    }

    #[test]
    fn failed_health_with_nonempty_data_keeps_account_and_journal() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let mut host = FakeApplyHost::new(preflight);
        host.health_ok = false;
        host.create_data_on_bootstrap = true;
        let (input, _key) = apply_input(&observer);

        let status = apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply result");
        assert_eq!(status.state, v2::OperationState::AttentionRequired);
        assert_eq!(status.result.code, "rollback_incomplete");
        assert!(!status.service_installed);
        let state = host.state();
        assert!(
            state.user.is_some(),
            "account must remain for nonempty data"
        );
        assert!(state.group.is_some(), "group must remain for nonempty data");
        let journal_path = state_dir().join("journal.json");
        assert!(state.files.contains_key(&journal_path));
        assert!(state
            .files
            .contains_key(&Path::new(DATA_PATH).join("hs-server.db")));
    }

    fn cancel_input(operation_id: String, confirm_unverified_completion: bool) -> v2::CancelInput {
        v2::CancelInput {
            contract_version: v2::CONTRACT_VERSION,
            configuration: configuration(),
            operation_id,
            confirm: true,
            confirm_unverified_completion,
        }
    }

    #[test]
    fn cancel_retries_incomplete_rollback_and_preserves_nonempty_data() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let mut host = FakeApplyHost::new(preflight);
        host.health_ok = false;
        host.create_data_on_bootstrap = true;
        let (input, _key) = apply_input(&observer);
        let failed = apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply result");
        assert_eq!(failed.result.code, "rollback_incomplete");
        let operation_id = failed.operation_id.expect("operation id");

        let first = cancel_v2_with_adapter(
            &host,
            &cancel_input(operation_id.clone(), false),
            &state_dir(),
        )
        .expect("cancel result");
        assert_eq!(first.result.code, "rollback_incomplete");
        {
            let state = host.state();
            assert!(
                state.user.is_some(),
                "account must remain for nonempty data"
            );
            assert!(state.group.is_some(), "group must remain for nonempty data");
        }

        // Safe operator remediation: remove only the fixture database outside
        // the installer, then retry rollback. The installer never deletes it.
        let database_path = Path::new(DATA_PATH).join("hs-server.db");
        {
            let mut state = host.state();
            state.paths.remove(&database_path);
            state.files.remove(&database_path);
        }
        let second = cancel_v2_with_adapter(&host, &cancel_input(operation_id, true), &state_dir())
            .expect("cancel retry");
        assert_eq!(second.state, v2::OperationState::Cancelled);
        let state = host.state();
        assert!(state.user.is_none());
        assert!(state.group.is_none());
        assert!(!state.files.contains_key(&state_dir().join("journal.json")));
    }

    #[test]
    fn cancel_refuses_unverified_completed_journal_until_explicit_recovery() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let host = FakeApplyHost::new(preflight);
        let (input, _key) = apply_input(&observer);
        let completed = apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply");
        let operation_id = completed.operation_id.expect("operation id");

        let record_path = state_dir().join("operation-v2.json");
        let mut record: serde_json::Value = {
            let state = host.state();
            serde_json::from_slice(state.files.get(&record_path).expect("record")).expect("json")
        };
        record
            .as_object_mut()
            .expect("record object")
            .remove("outcome");
        host.write_state_file(
            &record_path,
            &serde_json::to_vec(&record).expect("record bytes"),
        )
        .expect("replace record");

        let refused = cancel_v2_with_adapter(
            &host,
            &cancel_input(operation_id.clone(), false),
            &state_dir(),
        )
        .expect_err("unverified completed journal must not be cancelled implicitly");
        assert_eq!(refused.code(), ErrorCode::Conflict);
        assert!(host.state().user.is_some());

        let recovered =
            cancel_v2_with_adapter(&host, &cancel_input(operation_id, true), &state_dir())
                .expect("explicit recovery");
        assert_eq!(recovered.state, v2::OperationState::Cancelled);
        let state = host.state();
        assert!(state.user.is_none());
        assert!(state.group.is_none());
    }

    #[test]
    fn cancel_preserves_unproven_intent_resources() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let host = FakeApplyHost::new(preflight);
        let (input, _key) = apply_input(&observer);
        let completed = apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply");
        let operation_id = completed.operation_id.expect("operation id");

        let record_path = state_dir().join("operation-v2.json");
        let mut record: serde_json::Value = {
            let state = host.state();
            serde_json::from_slice(state.files.get(&record_path).expect("record")).expect("json")
        };
        record
            .as_object_mut()
            .expect("record object")
            .remove("outcome");
        host.write_state_file(
            &record_path,
            &serde_json::to_vec(&record).expect("record bytes"),
        )
        .expect("replace record");

        let journal_path = state_dir().join("journal.json");
        let mut journal: serde_json::Value = {
            let state = host.state();
            serde_json::from_slice(state.files.get(&journal_path).expect("journal")).expect("json")
        };
        for resource in journal["resources"].as_array_mut().expect("resources") {
            if resource["resource_type"] == "file" {
                resource["status"] = serde_json::json!("intent");
            }
        }
        host.write_state_file(
            &journal_path,
            &serde_json::to_vec(&journal).expect("journal bytes"),
        )
        .expect("replace journal");

        let status = cancel_v2_with_adapter(&host, &cancel_input(operation_id, true), &state_dir())
            .expect("cancel result");
        assert_eq!(status.result.code, "rollback_incomplete");
        let state = host.state();
        assert!(state.user.is_some());
        assert!(state.group.is_some());
        assert!(state.files.contains_key(Path::new(EXECUTABLE_PATH)));
    }

    #[test]
    fn rollback_journal_write_failure_is_reported_not_claimed() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let mut host = FakeApplyHost::new(preflight);
        host.health_ok = false;
        host.create_data_on_bootstrap = true;
        let (input, _key) = apply_input(&observer);
        let failed = apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply result");
        assert_eq!(failed.result.code, "rollback_incomplete");
        let operation_id = failed.operation_id.expect("operation id");
        host.fail_journal_writes = true;

        let error = cancel_v2_with_adapter(&host, &cancel_input(operation_id, false), &state_dir())
            .expect_err("journal persistence failure must be returned");
        assert_eq!(error.code(), ErrorCode::Internal);
    }

    #[test]
    fn terminal_record_write_failure_keeps_journal() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let mut host = FakeApplyHost::new(preflight);
        host.health_ok = false;
        host.fail_terminal_record_write = true;
        let (input, _key) = apply_input(&observer);

        let error = apply_v2_with_adapter(&host, &input, &state_dir())
            .expect_err("terminal record failure must be returned");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert!(
            host.state()
                .files
                .contains_key(&state_dir().join("journal.json")),
            "journal must survive a terminal record write failure"
        );
    }

    #[test]
    fn cancel_terminal_record_failure_keeps_journal_after_remediation() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let mut host = FakeApplyHost::new(preflight);
        host.health_ok = false;
        host.create_data_on_bootstrap = true;
        let (input, _key) = apply_input(&observer);
        let failed = apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply result");
        let operation_id = failed.operation_id.expect("operation id");
        let database_path = Path::new(DATA_PATH).join("hs-server.db");
        {
            let mut state = host.state();
            state.paths.remove(&database_path);
            state.files.remove(&database_path);
        }
        host.fail_terminal_record_write = true;

        let error = cancel_v2_with_adapter(&host, &cancel_input(operation_id, true), &state_dir())
            .expect_err("cancel terminal record failure must be returned");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert!(
            host.state()
                .files
                .contains_key(&state_dir().join("journal.json")),
            "journal must survive a cancel record write failure"
        );
    }

    #[test]
    fn completed_launchd_bootout_requires_confirmed_stopped() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let mut host = FakeApplyHost::new(preflight);
        host.write_corrupt_receipt = true;
        host.bootout_leaves_loaded = true;
        let (input, _key) = apply_input(&observer);

        let status = apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply result");
        assert_eq!(status.result.code, "rollback_incomplete");
        let state = host.state();
        assert!(state.user.is_some());
        assert!(state.group.is_some());
        assert!(state.launchd_loaded);
        assert!(state.files.contains_key(Path::new(INSTALL_RECEIPT_PATH)));
        assert!(state
            .files
            .contains_key(Path::new(super::LAUNCHD_PLIST_PATH)));
        let journal_path = state_dir().join("journal.json");
        assert!(state.files.contains_key(&journal_path));
    }

    #[test]
    fn launchd_failure_rolls_back_every_created_resource() {
        let observer = FakeLaunchdObserver::with_valid_host("arm64");
        let preflight = hs_server::installer::macos_launchd::preflight_v2(
            &observer,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: configuration(),
            },
        )
        .expect("preflight");
        let mut host = FakeApplyHost::new(preflight);
        host.launchd_bootstrap_fails = true;
        let (input, _key) = apply_input(&observer);

        let status = apply_v2_with_adapter(&host, &input, &state_dir()).expect("apply result");
        assert_eq!(status.state, v2::OperationState::AttentionRequired);
        assert!(!status.service_installed);
        assert_eq!(status.result.code, "rolled_back");
        let state = host.state();
        assert!(state.user.is_none());
        assert!(state.group.is_none());
        assert!(!state.launchd_loaded);
        assert!(state.launchd_bootouts >= 1);
        assert!(!state.paths.contains_key(Path::new(EXECUTABLE_PATH)));
        assert!(!state.files.contains_key(Path::new(INSTALL_RECEIPT_PATH)));
        assert!(!state.files.contains_key(Path::new(
            hs_server::installer::macos_launchd::LAUNCHD_PLIST_PATH
        )));
        let journal_path = state_dir().join("journal.json");
        assert!(!state.files.contains_key(&journal_path));
    }
}
