//! Focused read-only macOS plan-v2 tests.
//!
//! Packages are disposable signed directories; host and identity facts are
//! injected. No test creates an account, writes a product path, invokes
//! launchctl, binds a port, or enables apply/install.

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
fn absent_identity_plans_a_read_only_fresh_install() {
    let observer = FakeLaunchdObserver::with_valid_host("arm64");
    let (_temp, package, public_key) = temp_package("macos-arm64");
    let input = plan_input(&observer, &package);

    let result = machine::plan_v2_macos_with_observers(
        &observer,
        &FakeIdentity::absent(),
        &input,
        &public_key,
    )
    .expect("plan result");

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
    let identity_evidence = result.identity_evidence.clone().expect("identity evidence");
    assert_eq!(identity_evidence.service_account, PRODUCT_SERVICE_ACCOUNT);
    assert_eq!(identity_evidence.service_group, "_helicoid");
    assert_eq!(identity_evidence.decision, "account_absent_group_absent");
    let plan = result.plan.expect("plan");
    assert_eq!(plan.product, "hs-server");
    assert_eq!(plan.version, "0.1.0");
    assert_eq!(plan.service_user.name, PRODUCT_SERVICE_ACCOUNT);
    assert!(
        !plan.service_user.create,
        "the read-only plan must not claim to create the service account"
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
    assert!(plan
        .directories
        .iter()
        .any(|directory| directory.path == BACKUP_PATH));
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
        .any(|item| item.contains("_helicoid service account")));
    assert!(plan
        .not_implemented
        .iter()
        .any(|item| item.contains("launchd plist")));
    assert!(plan
        .not_implemented
        .iter()
        .any(|item| item.contains("Apply/install")));
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("read-only")));
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

    let result = machine::plan_v2_macos_with_observers(
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

    let result = machine::plan_v2_macos_with_observers(
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

    let result = machine::plan_v2_macos_with_observers(
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

    let error = machine::plan_v2_macos_with_observers(
        &observer,
        &FakeIdentity::unavailable(),
        &input,
        &public_key,
    )
    .unwrap_err();
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

    let error = machine::plan_v2_macos_with_observers(
        &observer,
        &FakeIdentity::absent(),
        &input,
        &public_key,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Conflict);
}

#[test]
fn volatile_free_space_does_not_invalidate_the_review() {
    let observer = FakeLaunchdObserver::with_valid_host("arm64");
    let (_temp, package, public_key) = temp_package("macos-arm64");
    let input = plan_input(&observer, &package);
    observer.set_storage(49 * 1024 * 1024 * 1024);

    let result = machine::plan_v2_macos_with_observers(
        &observer,
        &FakeIdentity::absent(),
        &input,
        &public_key,
    )
    .expect("plan result");
    assert!(result.ok, "unexpected plan error: {:?}", result.error);
    let first_digest = result.reviewed_plan_digest.expect("first digest");

    observer.set_storage(48 * 1024 * 1024 * 1024);
    let second = machine::plan_v2_macos_with_observers(
        &observer,
        &FakeIdentity::absent(),
        &input,
        &public_key,
    )
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

    let result = machine::plan_v2_macos_with_observers(
        &observer,
        &FakeIdentity::absent(),
        &input,
        &public_key,
    )
    .expect("plan result");
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
    let arm_result = machine::plan_v2_macos_with_observers(
        &arm_observer,
        &FakeIdentity::absent(),
        &arm_input,
        &arm_key,
    )
    .expect("arm plan result");
    assert!(arm_result.ok, "{:?}", arm_result.error);
    assert_eq!(
        arm_result.plan.expect("arm plan").files[0].destination,
        EXECUTABLE_PATH
    );

    let intel_observer = FakeLaunchdObserver::with_valid_host("x86_64");
    let (_intel_temp, intel_package, intel_key) = temp_package("macos-x86_64");
    let intel_input = plan_input(&intel_observer, &intel_package);
    let intel_result = machine::plan_v2_macos_with_observers(
        &intel_observer,
        &FakeIdentity::absent(),
        &intel_input,
        &intel_key,
    )
    .expect("intel plan result");
    assert!(intel_result.ok, "{:?}", intel_result.error);

    let mismatch_observer = FakeLaunchdObserver::with_valid_host("arm64");
    let mismatch_input = plan_input(&mismatch_observer, &intel_package);
    let mismatch = machine::plan_v2_macos_with_observers(
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

    let error = machine::plan_v2_macos_with_observers(
        &observer,
        &FakeIdentity::absent(),
        &input,
        &public_key,
    )
    .unwrap_err();
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
    let base = machine::plan_v2_macos_with_observers(
        &observer,
        &FakeIdentity::absent(),
        &base_input,
        &base_key,
    )
    .expect("base plan");
    assert!(base.ok, "{:?}", base.error);
    let base_digest = base.reviewed_plan_digest.expect("base digest");
    let base_evidence = base.package_evidence.expect("base evidence");

    // Same signed manifest bytes and artifact, different caller-supplied key.
    let (_key_temp, key_package, key_key) = temp_package_with_seed("macos-arm64", 12);
    let key_input = plan_input(&observer, &key_package);
    let key_plan = machine::plan_v2_macos_with_observers(
        &observer,
        &FakeIdentity::absent(),
        &key_input,
        &key_key,
    )
    .expect("key plan");
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
    let manifest_plan = machine::plan_v2_macos_with_observers(
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
    let intel_plan = machine::plan_v2_macos_with_observers(
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

    let wrong_key_result = machine::plan_v2_macos_with_observers(
        &observer,
        &FakeIdentity::absent(),
        &input,
        &wrong_key,
    )
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
    let failed_result = machine::plan_v2_macos_with_observers(
        &failed_preflight_observer,
        &FakeIdentity::absent(),
        &failed_input,
        &public_key,
    )
    .expect("failed preflight result");
    assert!(!failed_result.ok);
    assert!(failed_result.plan.is_none());
}
