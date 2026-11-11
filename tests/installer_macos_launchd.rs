//! Disposable-fixture tests for the read-only macOS launchd v2 preflight adapter.
//!
//! Most host observations, path stats, and storage figures come from an
//! in-memory fake. On macOS, two focused tests touch real filesystem metadata:
//! one performs a read-only ACL query on `/Library`, and one creates a
//! disposable owned temp directory under `$DELTA_SCRATCH_DIR` (or the system
//! temp directory when unset) to exercise real ALLOW and DENY extended ACLs
//! through the production observer. No test touches a user/system path, invokes
//! `launchctl`, binds a port, asks for privilege, or mutates launchd.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hs_server::error::ErrorCode;
use hs_server::installer::adapter::TestAdapter;
use hs_server::installer::lifecycle_v2 as v2;
use hs_server::installer::machine;
use hs_server::installer::macos_launchd::*;
use hs_server::installer::models;

/// Caller-selected backup fixture. It is intentionally not a product constant:
/// the Manager ownership plan does not define a backup path. Its parent is a
/// root-owned system directory so the clean fixture passes ancestor checks.
const BACKUP_PATH: &str = "/Library/Application Support/Helicoid-Backups";

#[derive(Clone, Copy)]
enum FakeAcl {
    DenyOnly,
    Allow,
    Error,
}

struct FakeObserver {
    observations: Mutex<HashMap<LaunchdQuery, CommandObservation>>,
    paths: Mutex<HashMap<PathBuf, PathMetadata>>,
    acls: Mutex<HashMap<PathBuf, FakeAcl>>,
    calls: Mutex<Vec<LaunchdQuery>>,
    fail_query: Mutex<Option<LaunchdQuery>>,
    fail_lstat: Mutex<bool>,
    fail_storage: Mutex<bool>,
    storage: Mutex<(u64, u64)>,
}

impl FakeObserver {
    fn new() -> Self {
        Self {
            observations: Mutex::new(HashMap::new()),
            paths: Mutex::new(HashMap::new()),
            acls: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            fail_query: Mutex::new(None),
            fail_lstat: Mutex::new(false),
            fail_storage: Mutex::new(false),
            storage: Mutex::new((100 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024)),
        }
    }

    fn with_valid_host(port: u16) -> Self {
        let observer = Self::new();
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
            CommandObservation::success("arm64\n"),
        );
        observer.set_observation(
            LaunchdQuery::LaunchdJobPresence,
            CommandObservation::failure(
                113,
                "Bad request.\nCould not find service \"com.helicoid.server\" in domain for system\n",
            ),
        );
        observer.set_observation(
            LaunchdQuery::TcpPortListeners { port },
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

    fn set_acl(&self, path: &str, acl: FakeAcl) {
        self.acls.lock().unwrap().insert(PathBuf::from(path), acl);
    }

    fn fail_query(&self, query: LaunchdQuery) {
        *self.fail_query.lock().unwrap() = Some(query);
    }

    fn fail_lstat(&self) {
        *self.fail_lstat.lock().unwrap() = true;
    }

    fn fail_storage(&self) {
        *self.fail_storage.lock().unwrap() = true;
    }

    fn set_storage(&self, total: u64, available: u64) {
        *self.storage.lock().unwrap() = (total, available);
    }

    fn calls(&self) -> Vec<LaunchdQuery> {
        self.calls.lock().unwrap().clone()
    }
}

impl MacosLaunchdObserver for FakeObserver {
    fn observe(&self, query: LaunchdQuery) -> Result<CommandObservation, String> {
        self.calls.lock().unwrap().push(query);
        if *self.fail_query.lock().unwrap() == Some(query) {
            return Err("fixture command failure".to_string());
        }
        self.observations
            .lock()
            .unwrap()
            .get(&query)
            .cloned()
            .ok_or_else(|| format!("no fixture for {}", query.name()))
    }

    fn lstat(&self, path: &Path) -> Result<Option<PathMetadata>, String> {
        if *self.fail_lstat.lock().unwrap() {
            return Err("fixture metadata failure".to_string());
        }
        Ok(self.paths.lock().unwrap().get(path).copied())
    }

    fn extended_acl_is_safe(&self, path: &Path) -> Result<bool, String> {
        match self.acls.lock().unwrap().get(path).copied() {
            None | Some(FakeAcl::DenyOnly) => Ok(true),
            Some(FakeAcl::Allow) => Ok(false),
            Some(FakeAcl::Error) => Err("fixture ACL query failure".to_string()),
        }
    }

    fn storage(&self, _path: &Path) -> Result<(u64, u64), String> {
        if *self.fail_storage.lock().unwrap() {
            return Err("fixture storage failure".to_string());
        }
        Ok(*self.storage.lock().unwrap())
    }
}

fn root_directory() -> PathMetadata {
    directory(0, 0, 0o755)
}

fn directory(uid: u32, gid: u32, mode: u32) -> PathMetadata {
    PathMetadata {
        is_symlink: false,
        is_directory: true,
        uid,
        gid,
        mode,
    }
}

fn present() -> PathMetadata {
    PathMetadata {
        is_symlink: false,
        is_directory: false,
        uid: 0,
        gid: 0,
        mode: 0o644,
    }
}

fn symlink() -> PathMetadata {
    PathMetadata {
        is_symlink: true,
        is_directory: false,
        uid: 0,
        gid: 0,
        mode: 0o777,
    }
}

fn configuration(port: u16) -> v2::DeploymentConfiguration {
    configuration_with_backup(port, BACKUP_PATH)
}

fn configuration_with_backup(port: u16, backup_directory: &str) -> v2::DeploymentConfiguration {
    v2::DeploymentConfiguration {
        deployment_kind: v2::DeploymentKind::MacosLaunchd,
        network: v2::NetworkConfiguration {
            scope: v2::NetworkScope::LoopbackDevelopment,
            authority_port: port,
            bind_address: None,
            client_hostname: None,
        },
        storage: v2::StorageConfiguration {
            data_directory: DATA_PATH.to_string(),
            backup_directory: backup_directory.to_string(),
            preserve_data_on_remove: true,
        },
    }
}

fn input(port: u16) -> v2::PreflightInput {
    v2::PreflightInput {
        contract_version: v2::CONTRACT_VERSION,
        configuration: configuration(port),
    }
}

fn input_with_backup(port: u16, backup_directory: &str) -> v2::PreflightInput {
    v2::PreflightInput {
        contract_version: v2::CONTRACT_VERSION,
        configuration: configuration_with_backup(port, backup_directory),
    }
}

#[cfg(target_os = "macos")]
const ACL_TYPE_EXTENDED: i32 = 0x0000_0100;
#[cfg(target_os = "macos")]
const ACL_FIRST_ENTRY: i32 = 0;
#[cfg(target_os = "macos")]
const ACL_EXTENDED_ALLOW: i32 = 1;
#[cfg(target_os = "macos")]
const ACL_EXTENDED_DENY: i32 = 2;
#[cfg(target_os = "macos")]
const ACL_WRITE_DATA: i32 = 1 << 2;

#[cfg(target_os = "macos")]
fn acl_test_tempdir() -> tempfile::TempDir {
    let base = std::env::var_os("DELTA_SCRATCH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    assert!(
        base.is_dir(),
        "DELTA_SCRATCH_DIR is not a directory: {}",
        base.display()
    );
    let directory = tempfile::Builder::new()
        .prefix("helicoid-macos-acl-")
        .tempdir_in(&base)
        .unwrap_or_else(|error| {
            panic!(
                "create disposable ACL fixture under {}: {error}",
                base.display()
            )
        });
    assert!(
        directory.path().starts_with(&base),
        "ACL fixture escaped scratch base {}: {}",
        base.display(),
        directory.path().display()
    );
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        std::fs::metadata(directory.path())
            .expect("stat disposable ACL fixture")
            .uid(),
        unsafe { libc::geteuid() },
        "ACL fixture must be owned by the test process"
    );
    directory
}

/// Apply one native extended ACL entry to `path`. No shell and no qualifier:
/// the entry applies to everyone.
#[cfg(target_os = "macos")]
fn set_everyone_acl(path: &Path, tag: i32, permission: i32) {
    type AclT = *mut libc::c_void;
    type AclEntryT = *mut libc::c_void;
    type AclPermsetT = *mut libc::c_void;

    extern "C" {
        fn acl_init(count: libc::c_int) -> AclT;
        fn acl_create_entry(acl_p: *mut AclT, entry_p: *mut AclEntryT) -> libc::c_int;
        fn acl_set_tag_type(entry: AclEntryT, tag: i32) -> libc::c_int;
        fn acl_get_permset(entry: AclEntryT, permset_p: *mut AclPermsetT) -> libc::c_int;
        fn acl_add_perm(permset: AclPermsetT, perm: i32) -> libc::c_int;
        fn acl_set_fd(fd: libc::c_int, acl: AclT) -> libc::c_int;
        fn acl_free(obj: *mut libc::c_void) -> libc::c_int;
    }

    use std::os::unix::io::AsRawFd;

    let directory = std::fs::File::open(path)
        .unwrap_or_else(|error| panic!("open '{}' for ACL setup: {error}", path.display()));
    unsafe {
        let mut acl = acl_init(1);
        assert!(!acl.is_null(), "acl_init failed");
        let mut entry: AclEntryT = std::ptr::null_mut();
        assert_eq!(
            acl_create_entry(&mut acl, &mut entry),
            0,
            "acl_create_entry"
        );
        assert_eq!(acl_set_tag_type(entry, tag), 0, "acl_set_tag_type");
        let mut permset: AclPermsetT = std::ptr::null_mut();
        assert_eq!(acl_get_permset(entry, &mut permset), 0, "acl_get_permset");
        assert_eq!(acl_add_perm(permset, permission), 0, "acl_add_perm");
        assert_eq!(
            acl_set_fd(directory.as_raw_fd(), acl),
            0,
            "acl_set_fd on '{}': {}",
            path.display(),
            std::io::Error::last_os_error()
        );
        acl_free(acl.cast());
    }
}

/// Confirm the ACL installed on `path` contains `expected` as its first entry.
#[cfg(target_os = "macos")]
fn assert_first_acl_tag(path: &Path, expected: i32) {
    type AclT = *mut libc::c_void;
    type AclEntryT = *mut libc::c_void;

    extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, typ: i32) -> AclT;
        fn acl_get_entry(acl: AclT, entry_id: i32, entry_p: *mut AclEntryT) -> libc::c_int;
        fn acl_get_tag_type(entry: AclEntryT, tag_type_p: *mut i32) -> libc::c_int;
        fn acl_free(obj: *mut libc::c_void) -> libc::c_int;
    }

    use std::os::unix::io::AsRawFd;

    let directory = std::fs::File::open(path)
        .unwrap_or_else(|error| panic!("open '{}' for ACL readback: {error}", path.display()));
    unsafe {
        let acl = acl_get_fd_np(directory.as_raw_fd(), ACL_TYPE_EXTENDED);
        assert!(
            !acl.is_null(),
            "no extended ACL was installed on '{}'",
            path.display()
        );
        let mut entry: AclEntryT = std::ptr::null_mut();
        assert_eq!(
            acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry),
            0,
            "acl_get_entry on '{}'",
            path.display()
        );
        let mut tag = 0;
        assert_eq!(acl_get_tag_type(entry, &mut tag), 0, "acl_get_tag_type");
        assert_eq!(tag, expected, "unexpected ACL tag on '{}'", path.display());
        acl_free(acl.cast());
    }
}

fn path_check<'a>(result: &'a v2::PreflightResult, path: &str) -> &'a models::PathCheck {
    result
        .host_checks
        .checks
        .paths
        .checked
        .iter()
        .find(|check| check.path == path)
        .unwrap_or_else(|| panic!("missing path check {path}"))
}

// ---------------------------------------------------------------------------
// Manager ownership values
// ---------------------------------------------------------------------------

#[test]
fn fixed_values_match_the_manager_ownership_plan() {
    assert_eq!(PRODUCT_ROOT_PATH, "/Library/Application Support/Helicoid");
    assert_eq!(DATA_PATH, "/Library/Application Support/Helicoid/Data");
    assert_eq!(LAUNCHD_LABEL, "com.helicoid.server");
    assert_eq!(
        LAUNCHD_PLIST_PATH,
        "/Library/LaunchDaemons/com.helicoid.server.plist"
    );
    assert_eq!(
        EXECUTABLE_PATH,
        "/Library/Application Support/Helicoid/bin/hs-server"
    );
    assert_eq!(
        CONFIGURATION_PATH,
        "/Library/Application Support/Helicoid/Configuration/service.json"
    );
    assert_eq!(
        TLS_CERTIFICATE_PATH,
        "/Library/Application Support/Helicoid/TLS/fullchain.pem"
    );
    assert_eq!(
        TLS_PRIVATE_KEY_PATH,
        "/Library/Application Support/Helicoid/TLS/private-key.pem"
    );
    assert_eq!(DEFAULT_AUTHORITY_PORT, 8920);
    assert_eq!(MIN_FREE_BYTES, 2 * 1024 * 1024 * 1024);
    assert!(DATA_PATH.starts_with(PRODUCT_ROOT_PATH));
    assert!(LAUNCHD_PLIST_PATH.contains(LAUNCHD_LABEL));
}

// ---------------------------------------------------------------------------
// Existing v2 contract
// ---------------------------------------------------------------------------

#[test]
fn clean_preflight_emits_the_existing_v2_contract() {
    let observer = FakeObserver::with_valid_host(8920);
    let result = preflight_v2(&observer, &input(8920)).unwrap();

    assert!(result.ok);
    assert_eq!(result.contract_version, v2::CONTRACT_VERSION);
    assert_eq!(result.configuration, configuration(8920));
    assert_eq!(
        result.host_checks.contract_version,
        models::CONTRACT_VERSION
    );
    assert!(result.host_checks.ok);

    assert_eq!(result.capabilities.contract_version, v2::CONTRACT_VERSION);
    assert_eq!(
        result.capabilities.supported_deployment_kinds,
        vec![v2::DeploymentKind::MacosLaunchd],
        "the macOS adapter advertises only the launchd deployment kind"
    );
    #[cfg(not(feature = "macos-dev-install"))]
    {
        assert_eq!(
            result.capabilities.supported_actions,
            vec![v2::LifecycleAction::Preflight, v2::LifecycleAction::Plan]
        );
        assert!(!result
            .capabilities
            .supported_actions
            .contains(&v2::LifecycleAction::Install));
        assert!(!result.capabilities.cancellation);
        assert!(!result.capabilities.durable_operation_journal);
        assert!(result
            .capabilities
            .reasons_unavailable
            .get("macos_launchd")
            .is_some_and(|reason| reason.contains("gated off")));
    }
    #[cfg(feature = "macos-dev-install")]
    {
        assert_eq!(
            result.capabilities.supported_actions,
            vec![
                v2::LifecycleAction::Preflight,
                v2::LifecycleAction::Plan,
                v2::LifecycleAction::Install,
                v2::LifecycleAction::Cancel,
                v2::LifecycleAction::Inspect,
            ]
        );
        assert!(result.capabilities.cancellation);
        assert!(result.capabilities.durable_operation_journal);
        assert!(result
            .capabilities
            .reasons_unavailable
            .get("macos_launchd")
            .is_some_and(|reason| reason.contains("development-only")));
    }
    assert!(result
        .capabilities
        .reasons_unavailable
        .get("enrollment_readiness")
        .is_some_and(|reason| reason.contains("development-only")));

    assert!(result.tls_certificate_sha256.is_none());
    assert!(!result.tls_subject_name_verified);
    assert!(result.docker_compose_runtime.is_none());

    for path in [
        PRODUCT_ROOT_PATH,
        DATA_PATH,
        LAUNCHD_PLIST_PATH,
        BACKUP_PATH,
    ] {
        let check = path_check(&result, path);
        assert!(!check.exists, "{path} must be absent in the clean fixture");
    }
    assert!(result
        .host_checks
        .checks
        .ports
        .listeners
        .iter()
        .any(|listener| listener.port == 8920 && !listener.occupied));
    assert!(result.host_checks.checks.services.existing_units.is_empty());
    assert!(!result.host_checks.checks.existing_install.detected);

    // Only the five reviewed read-only observations, and no account identity
    // or mutation command.
    assert_eq!(
        observer.calls(),
        vec![
            LaunchdQuery::EffectiveUid,
            LaunchdQuery::OperatingSystemVersion,
            LaunchdQuery::LocalArchitecture,
            LaunchdQuery::LaunchdJobPresence,
            LaunchdQuery::TcpPortListeners { port: 8920 },
        ]
    );
}

#[test]
fn preflight_result_round_trips_through_existing_v2_plan_input() {
    let observer = FakeObserver::with_valid_host(8920);
    let preflight = preflight_v2(&observer, &input(8920)).unwrap();
    let plan_input = v2::PlanInput {
        contract_version: v2::CONTRACT_VERSION,
        configuration: configuration(8920),
        preflight,
        package_dir: "/tmp/helicoid-package-fixture".to_string(),
    };

    let encoded = serde_json::to_value(&plan_input).unwrap();
    assert_eq!(encoded["contract_version"], v2::CONTRACT_VERSION);
    assert_eq!(
        encoded["preflight"]["host_checks"]["contract_version"],
        models::CONTRACT_VERSION
    );
    assert_eq!(
        encoded["preflight"]["capabilities"]["contract_version"],
        v2::CONTRACT_VERSION
    );

    let decoded: v2::PlanInput = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.configuration, configuration(8920));
    assert_eq!(decoded.preflight.host_checks.contract_version, 1);
    assert_eq!(
        decoded.preflight.capabilities.supported_deployment_kinds,
        vec![v2::DeploymentKind::MacosLaunchd]
    );
}

#[test]
fn generic_v2_lifecycle_entry_points_still_reject_macos() {
    let adapter = TestAdapter::new();
    let error = machine::preflight_v2(&adapter, &input(8920)).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::NotImplemented,
        "machine::preflight_v2 must keep rejecting macOS until the Linux lifecycle is intentionally adapted"
    );

    let observer = FakeObserver::with_valid_host(8920);
    let plan_input = v2::PlanInput {
        contract_version: v2::CONTRACT_VERSION,
        configuration: configuration(8920),
        preflight: preflight_v2(&observer, &input(8920)).unwrap(),
        package_dir: "/tmp/helicoid-package-fixture".to_string(),
    };
    let error = machine::plan_v2(&adapter, &plan_input, None).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::NotImplemented,
        "the generic Linux plan path must not accept a macOS deployment"
    );
}

// ---------------------------------------------------------------------------
// Request/configuration validation
// ---------------------------------------------------------------------------

#[test]
fn rejects_non_macos_deployment_and_network_scopes() {
    let observer = FakeObserver::with_valid_host(8920);

    let mut linux = input(8920);
    linux.configuration.deployment_kind = v2::DeploymentKind::LinuxSystemd;
    assert_eq!(
        preflight_v2(&observer, &linux).unwrap_err().code(),
        ErrorCode::NotImplemented
    );

    let mut lan = input(8920);
    lan.configuration.network.scope = v2::NetworkScope::Lan;
    assert_eq!(
        preflight_v2(&observer, &lan).unwrap_err().code(),
        ErrorCode::NotImplemented
    );

    let mut public = input(8920);
    public.configuration.network.scope = v2::NetworkScope::PublicEdge;
    assert_eq!(
        preflight_v2(&observer, &public).unwrap_err().code(),
        ErrorCode::NotImplemented
    );

    let mut bound = input(8920);
    bound.configuration.network.bind_address = Some("192.168.1.10".to_string());
    assert_eq!(
        preflight_v2(&observer, &bound).unwrap_err().code(),
        ErrorCode::BadRequest
    );
}

#[test]
fn rejects_fields_outside_the_manager_ownership_plan() {
    let observer = FakeObserver::with_valid_host(8920);

    let mut nested_data = input(8920);
    nested_data.configuration.storage.data_directory = format!("{DATA_PATH}/nested");
    assert_eq!(
        preflight_v2(&observer, &nested_data).unwrap_err().code(),
        ErrorCode::BadRequest
    );

    let privileged_port = input(80);
    assert_eq!(
        preflight_v2(&observer, &privileged_port)
            .unwrap_err()
            .code(),
        ErrorCode::BadRequest
    );

    let mut relative_backup = input(8920);
    relative_backup.configuration.storage.backup_directory = "relative/backups".to_string();
    assert_eq!(
        preflight_v2(&observer, &relative_backup)
            .unwrap_err()
            .code(),
        ErrorCode::BadRequest
    );

    let mut traversal = input(8920);
    traversal.configuration.storage.backup_directory = "/tmp/../escape".to_string();
    assert_eq!(
        preflight_v2(&observer, &traversal).unwrap_err().code(),
        ErrorCode::BadRequest
    );

    let mut overlapping = input(8920);
    overlapping.configuration.storage.backup_directory = DATA_PATH.to_string();
    assert_eq!(
        preflight_v2(&observer, &overlapping).unwrap_err().code(),
        ErrorCode::BadRequest
    );

    let mut wrong_version = input(8920);
    wrong_version.contract_version = 1;
    assert_eq!(
        preflight_v2(&observer, &wrong_version).unwrap_err().code(),
        ErrorCode::BadRequest
    );

    assert_eq!(
        preflight_v2(&observer, &privileged_port)
            .unwrap_err()
            .code(),
        ErrorCode::BadRequest
    );
}

#[test]
fn rejects_backup_inside_product_or_launchdaemons_paths() {
    let observer = FakeObserver::with_valid_host(8920);

    for backup in [
        "/Library/Application Support/Helicoid/Backups",
        "/Library/Application Support/Helicoid/Data/Backups",
        "/Library/LaunchDaemons/HelicoidBackups",
        "/Library",
        "/library/application support/helicoid/backups",
        "/LIBRARY/APPLICATION SUPPORT/HELICOID/DATA/backups",
        "/library/launchdaemons/HelicoidBackups",
        "/LiBrArY",
    ] {
        assert_eq!(
            preflight_v2(&observer, &input_with_backup(8920, backup))
                .unwrap_err()
                .code(),
            ErrorCode::BadRequest,
            "{backup} must not be accepted as a backup destination"
        );
    }
}

#[test]
fn case_distinct_sibling_backup_path_remains_accepted() {
    let observer = FakeObserver::with_valid_host(8920);
    let result = preflight_v2(
        &observer,
        &input_with_backup(8920, "/Library/Application Support/Helicoid-Backups"),
    )
    .unwrap();
    assert!(result.ok, "{:?}", result.host_checks.checks.paths);
}

#[test]
fn rejects_non_ascii_backup_components_conservatively() {
    let observer = FakeObserver::with_valid_host(8920);
    for backup in [
        "/Library/Application Support/Helicoid-Backup-é",
        "/Library/Application Support/Helicoid-Backup-e\u{301}",
        "/Library/Application Support/Helicoid-备份",
    ] {
        let error = preflight_v2(&observer, &input_with_backup(8920, backup)).unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::BadRequest,
            "{backup} must be refused to avoid APFS normalization aliasing"
        );
        assert!(
            error.to_string().contains("non-ASCII"),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn uses_the_selected_authority_port() {
    let observer = FakeObserver::with_valid_host(8923);
    let result = preflight_v2(&observer, &input(8923)).unwrap();

    assert!(result.ok);
    assert!(result
        .host_checks
        .checks
        .ports
        .listeners
        .iter()
        .any(|listener| listener.port == 8923 && !listener.occupied));
    let calls = observer.calls();
    assert!(calls.contains(&LaunchdQuery::TcpPortListeners { port: 8923 }));
    assert!(!calls.contains(&LaunchdQuery::TcpPortListeners { port: 8920 }));
}

// ---------------------------------------------------------------------------
// Ownership/path evidence
// ---------------------------------------------------------------------------

#[test]
fn existing_manager_paths_are_conflicts() {
    for (path, metadata) in [
        (PRODUCT_ROOT_PATH, present()),
        (DATA_PATH, present()),
        (LAUNCHD_PLIST_PATH, present()),
    ] {
        let observer = FakeObserver::with_valid_host(8920);
        observer.set_path(path, metadata);
        let result = preflight_v2(&observer, &input(8920)).unwrap();

        assert!(!result.ok, "{path} must block a fresh preflight");
        let check = path_check(&result, path);
        assert!(check.exists);
        assert!(check.reason.is_some());
        assert!(result.host_checks.checks.existing_install.detected);
    }
}

#[test]
fn existing_plist_is_also_a_service_conflict() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_path(LAUNCHD_PLIST_PATH, present());
    let result = preflight_v2(&observer, &input(8920)).unwrap();

    assert!(!result.host_checks.checks.services.ok);
    assert!(result
        .host_checks
        .checks
        .services
        .existing_units
        .contains(&LAUNCHD_LABEL.to_string()));
}

#[test]
fn existing_backup_path_is_a_conflict_without_an_ownership_claim() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_path(BACKUP_PATH, present());
    let result = preflight_v2(&observer, &input(8920)).unwrap();

    assert!(!result.ok);
    assert!(!result.host_checks.checks.paths.ok);
    let check = path_check(&result, BACKUP_PATH);
    assert!(check.exists);
    assert!(!check.owned_by_us);
    assert!(check
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("ACLs were not inspected")));
}

#[test]
fn symlinked_manager_path_is_a_conflict() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_path(PRODUCT_ROOT_PATH, symlink());
    let result = preflight_v2(&observer, &input(8920)).unwrap();

    assert!(!result.ok);
    assert!(path_check(&result, PRODUCT_ROOT_PATH)
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("symlink")));
}

#[test]
fn symlinked_ancestor_is_a_conflict() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_path("/Library/Application Support", symlink());
    let result = preflight_v2(&observer, &input(8920)).unwrap();

    assert!(!result.ok);
    assert!(path_check(&result, PRODUCT_ROOT_PATH)
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("ancestor")));
}

#[test]
fn absent_backup_parent_is_not_clean() {
    let backup = "/tmp/helicoid-backup-fixture";
    let observer = FakeObserver::with_valid_host(8920);
    let result = preflight_v2(&observer, &input_with_backup(8920, backup)).unwrap();

    assert!(!result.ok);
    assert!(!result.host_checks.checks.paths.ok);
    let check = path_check(&result, backup);
    assert!(!check.exists);
    assert!(check
        .reason
        .as_deref()
        .is_some_and(|reason| { reason.contains("/tmp") && reason.contains("does not exist") }));
}

#[test]
fn tmp_and_var_symlink_ancestors_are_refused_with_a_useful_diagnostic() {
    for (ancestor, backup) in [
        ("/tmp", "/tmp/helicoid-backup-fixture"),
        ("/var", "/var/helicoid-backup-fixture"),
    ] {
        let observer = FakeObserver::with_valid_host(8920);
        observer.set_path(ancestor, symlink());
        let result = preflight_v2(&observer, &input_with_backup(8920, backup)).unwrap();

        assert!(!result.ok, "{ancestor} symlink must not pass preflight");
        assert!(!result.host_checks.checks.paths.ok);
        let check = path_check(&result, backup);
        let reason = check.reason.as_deref().expect("refusal reason");
        assert!(
            reason.contains(ancestor) && reason.contains("symlink"),
            "unexpected reason: {reason}"
        );
        assert!(
            reason.contains("refusing to follow"),
            "unexpected reason: {reason}"
        );
    }
}

#[test]
fn unsafe_backup_parent_is_not_clean() {
    let backup = "/tmp/helicoid-backup-fixture";

    let world_writable = FakeObserver::with_valid_host(8920);
    world_writable.set_path("/tmp", directory(0, 0, 0o1777));
    let result = preflight_v2(&world_writable, &input_with_backup(8920, backup)).unwrap();
    assert!(!result.ok);
    assert!(!result.host_checks.checks.paths.ok);
    let check = path_check(&result, backup);
    assert!(!check.exists);
    assert!(check
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("group- or world-writable")));

    let foreign_owner = FakeObserver::with_valid_host(8920);
    foreign_owner.set_path("/tmp", directory(501, 20, 0o755));
    let result = preflight_v2(&foreign_owner, &input_with_backup(8920, backup)).unwrap();
    assert!(!result.ok);
    assert!(!result.host_checks.checks.paths.ok);
    let check = path_check(&result, backup);
    assert!(!check.exists);
    assert!(check
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("owned by uid:gid 501:20, not root")));
}

#[test]
fn extended_acl_allow_on_ancestor_is_not_clean() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_acl("/Library/Application Support", FakeAcl::Allow);
    let result = preflight_v2(&observer, &input(8920)).unwrap();

    assert!(!result.ok);
    assert!(!result.host_checks.checks.paths.ok);
    let check = path_check(&result, PRODUCT_ROOT_PATH);
    assert!(!check.exists);
    assert!(check
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("extended ACL with an ALLOW entry")));
}

#[test]
fn extended_acl_on_absent_backup_parent_is_not_clean() {
    let backup = "/Library/HelicoidBackupParent/Backups";
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_path("/Library/HelicoidBackupParent", directory(0, 0, 0o755));
    observer.set_acl("/Library/HelicoidBackupParent", FakeAcl::Allow);
    let result = preflight_v2(&observer, &input_with_backup(8920, backup)).unwrap();

    assert!(!result.ok);
    assert!(!result.host_checks.checks.paths.ok);
    let check = path_check(&result, backup);
    assert!(!check.exists);
    assert!(check
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("extended ACL with an ALLOW entry")));
}

#[test]
fn extended_acl_query_failure_is_not_clean() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_acl("/Library", FakeAcl::Error);
    let result = preflight_v2(&observer, &input(8920)).unwrap();

    assert!(!result.ok);
    assert!(!result.host_checks.checks.paths.ok);
    let check = path_check(&result, PRODUCT_ROOT_PATH);
    assert!(!check.exists);
    assert!(check
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("cannot inspect extended ACL")));
}

#[test]
fn deny_only_acl_on_ancestor_is_accepted() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_acl("/Library", FakeAcl::DenyOnly);
    let result = preflight_v2(&observer, &input(8920)).unwrap();

    assert!(result.ok, "{:?}", result.host_checks.checks.paths);
}

#[cfg(target_os = "macos")]
#[test]
fn production_acl_probe_reads_a_system_directory() {
    let result = MacosSystemObserver.extended_acl_is_safe(Path::new("/Library"));
    assert!(
        result.is_ok(),
        "native ACL query on /Library failed: {result:?}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn production_observer_rejects_real_allow_acl_and_accepts_deny_only() {
    let directory = acl_test_tempdir();
    let observer = MacosSystemObserver::new();
    let path = directory.path();

    // The disposable temp directory is owned by this test process and starts
    // without a widening ACL. No skip: if the native ACL API is unavailable,
    // the setup/query below fails with the platform error rather than passing.
    assert_eq!(
        observer.extended_acl_is_safe(path),
        Ok(true),
        "fresh owned temp directory unexpectedly has a widening ACL"
    );

    set_everyone_acl(path, ACL_EXTENDED_ALLOW, ACL_WRITE_DATA);
    assert_first_acl_tag(path, ACL_EXTENDED_ALLOW);
    assert_eq!(
        observer.extended_acl_is_safe(path),
        Ok(false),
        "production observer must refuse a real ALLOW ACL"
    );

    set_everyone_acl(path, ACL_EXTENDED_DENY, ACL_WRITE_DATA);
    assert_first_acl_tag(path, ACL_EXTENDED_DENY);
    assert_eq!(
        observer.extended_acl_is_safe(path),
        Ok(true),
        "production observer must accept a real DENY-only ACL"
    );
}

#[test]
fn loaded_job_is_a_service_conflict_even_without_a_plist() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_observation(
        LaunchdQuery::LaunchdJobPresence,
        CommandObservation::success("system/com.helicoid.server = {\n}\n"),
    );
    let result = preflight_v2(&observer, &input(8920)).unwrap();

    assert!(!result.ok);
    assert!(!result.host_checks.checks.services.ok);
    assert!(result
        .host_checks
        .checks
        .services
        .existing_units
        .contains(&LAUNCHD_LABEL.to_string()));
    assert!(result.host_checks.checks.existing_install.detected);
}

#[test]
fn occupied_selected_port_is_a_conflict() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_observation(
        LaunchdQuery::TcpPortListeners { port: 8920 },
        CommandObservation::success("p4242\nfcwd\ncunrelated-server\n"),
    );
    let result = preflight_v2(&observer, &input(8920)).unwrap();

    assert!(!result.ok);
    assert!(!result.host_checks.checks.ports.ok);
    assert!(result
        .host_checks
        .checks
        .ports
        .conflicts
        .iter()
        .any(|conflict| conflict.process == "unrelated-server (pid 4242)"));
}

// ---------------------------------------------------------------------------
// Fail-closed checks
// ---------------------------------------------------------------------------

#[test]
fn non_root_port_state_is_unverified_not_occupied() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_observation(
        LaunchdQuery::EffectiveUid,
        CommandObservation::success("501\n"),
    );
    let result = preflight_v2(&observer, &input(8920)).unwrap();

    assert!(!result.ok);
    assert!(!result.host_checks.checks.privileges.ok);
    assert!(!result.host_checks.checks.privileges.is_root);
    assert!(!result.host_checks.checks.ports.ok);
    let ports = &result.host_checks.checks.ports;
    assert!(ports.listeners.iter().all(|listener| !listener.occupied));
    assert!(ports.listeners.iter().any(|listener| listener
        .process
        .as_deref()
        .is_some_and(|process| process.contains("unverified"))));
    assert!(ports.listeners.iter().any(|listener| listener
        .process
        .as_deref()
        .is_some_and(|process| process.contains("administrator access"))));
    assert!(ports.conflicts.is_empty());
    assert!(!observer
        .calls()
        .contains(&LaunchdQuery::TcpPortListeners { port: 8920 }));
}

#[test]
fn old_macos_or_unsupported_architecture_fails() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_observation(
        LaunchdQuery::OperatingSystemVersion,
        CommandObservation::success("14.7.1\n"),
    );
    let result = preflight_v2(&observer, &input(8920)).unwrap();
    assert!(!result.ok);
    assert!(!result.host_checks.checks.os.ok);

    let observer = FakeObserver::with_valid_host(8920);
    observer.set_observation(
        LaunchdQuery::LocalArchitecture,
        CommandObservation::success("i386\n"),
    );
    let result = preflight_v2(&observer, &input(8920)).unwrap();
    assert!(!result.ok);
    assert!(!result.host_checks.checks.arch.ok);
}

#[test]
fn insufficient_storage_fails() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_storage(10 * 1024 * 1024 * 1024, 1024 * 1024 * 1024);
    let result = preflight_v2(&observer, &input(8920)).unwrap();

    assert!(!result.ok);
    assert!(!result.host_checks.checks.storage.ok);
    assert!(result
        .host_checks
        .checks
        .storage
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("insufficient")));
}

#[test]
fn observation_failure_is_security_state_unavailable() {
    for query in [
        LaunchdQuery::EffectiveUid,
        LaunchdQuery::OperatingSystemVersion,
        LaunchdQuery::LocalArchitecture,
        LaunchdQuery::LaunchdJobPresence,
    ] {
        let observer = FakeObserver::with_valid_host(8920);
        observer.fail_query(query);
        let error = preflight_v2(&observer, &input(8920)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::SecurityStateUnavailable);
    }
}

#[test]
fn metadata_and_storage_failures_are_failed_checks_not_free() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.fail_lstat();
    let result = preflight_v2(&observer, &input(8920)).unwrap();
    assert!(!result.ok);
    assert!(!result.host_checks.checks.paths.ok);

    let observer = FakeObserver::with_valid_host(8920);
    observer.fail_storage();
    let result = preflight_v2(&observer, &input(8920)).unwrap();
    assert!(!result.ok);
    assert!(!result.host_checks.checks.storage.ok);
}

#[test]
fn port_query_failure_is_unverified_not_occupied() {
    let observer = FakeObserver::with_valid_host(8920);
    observer.set_observation(
        LaunchdQuery::TcpPortListeners { port: 8920 },
        CommandObservation::failure(1, "lsof: permission denied\n"),
    );
    let result = preflight_v2(&observer, &input(8920)).unwrap();

    assert!(!result.ok);
    assert!(!result.host_checks.checks.ports.ok);
    let ports = &result.host_checks.checks.ports;
    assert!(ports.listeners.iter().all(|listener| !listener.occupied));
    assert!(ports.listeners.iter().any(|listener| listener
        .process
        .as_deref()
        .is_some_and(|process| process.contains("query error (unverified)"))));
    assert!(ports.conflicts.is_empty());
}

#[test]
fn launchctl_success_output_is_bounded_before_presence_is_accepted() {
    let oversized = CommandObservation::success("x".repeat(64 * 1024 + 1));
    let error = parse_launchd_job_presence(&oversized).expect_err("oversized success must fail");
    assert!(error.contains("exceeds"), "unexpected error: {error}");

    let too_many_lines = CommandObservation::success("x\n".repeat(257));
    let error =
        parse_launchd_job_presence(&too_many_lines).expect_err("line-heavy success must fail");
    assert!(error.contains("exceeds"), "unexpected error: {error}");
}

#[test]
fn malformed_observations_fail_closed() {
    let oversized = CommandObservation::success("0".repeat(64 * 1024 + 1));
    assert!(parse_effective_uid(&oversized).is_err());

    let too_many_lines = CommandObservation::success("0\n".repeat(257));
    assert!(parse_effective_uid(&too_many_lines).is_err());

    let nul = CommandObservation::success("0\0\n");
    assert!(parse_effective_uid(&nul).is_err());

    let extra_line = CommandObservation::success("0\n501\n");
    assert!(parse_effective_uid(&extra_line).is_err());

    let bad_version = CommandObservation::success("15.6\nextra\n");
    assert!(parse_operating_system_version(&bad_version).is_err());

    // `i386` is syntactically valid but unsupported by the check layer.
    let unsupported_arch = CommandObservation::success("i386\n");
    assert_eq!(parse_local_architecture(&unsupported_arch).unwrap(), "i386");
    let malformed_arch = CommandObservation::success("arm64\nextra\n");
    assert!(parse_local_architecture(&malformed_arch).is_err());

    let ambiguous_launchd = CommandObservation::failure(1, "Operation not permitted\n");
    assert!(parse_launchd_job_presence(&ambiguous_launchd).is_err());

    let not_found = CommandObservation::failure(
        113,
        "Bad request.\nCould not find service \"com.helicoid.server\" in domain for system\n",
    );
    assert!(!parse_launchd_job_presence(&not_found).unwrap());

    let empty_lsof_success = CommandObservation::success("");
    assert!(parse_tcp_port_listeners(&empty_lsof_success).is_err());

    // A multibyte first character must be an error, not a slice panic.
    let multibyte_tag = CommandObservation::success("é\n");
    assert!(parse_tcp_port_listeners(&multibyte_tag).is_err());
    let multibyte_after_records = CommandObservation::success("p42\ncnginx\nü\n");
    assert!(parse_tcp_port_listeners(&multibyte_after_records).is_err());

    let unexpected_lsof_field = CommandObservation::success("p42\nxunexpected\n");
    assert!(parse_tcp_port_listeners(&unexpected_lsof_field).is_err());

    let listener = CommandObservation::success("p42\ncnginx\n");
    assert_eq!(
        parse_tcp_port_listeners(&listener).unwrap(),
        vec!["nginx (pid 42)".to_string()]
    );

    // Real lsof with -Fpc can emit f records; they must not break an occupied
    // listener parse or make the listener look free.
    let listener_with_fd_records = CommandObservation::success("p42\nfcwd\ncnginx\nf3\n");
    assert_eq!(
        parse_tcp_port_listeners(&listener_with_fd_records).unwrap(),
        vec!["nginx (pid 42)".to_string()]
    );
    assert!(parse_tcp_port_listeners(&CommandObservation::success("f3\np42\ncnginx\n")).is_err());

    let no_listener = CommandObservation::failure(1, "");
    assert!(parse_tcp_port_listeners(&no_listener).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Shell-free, bounded observation
// ---------------------------------------------------------------------------

#[test]
fn reviewed_commands_are_fixed_absolute_argv_without_shell_interpolation() {
    let queries = [
        LaunchdQuery::EffectiveUid,
        LaunchdQuery::OperatingSystemVersion,
        LaunchdQuery::LocalArchitecture,
        LaunchdQuery::LaunchdJobPresence,
        LaunchdQuery::TcpPortListeners { port: 8920 },
    ];

    for query in queries {
        let argv = query.reviewed_argv();
        assert!(!argv.is_empty());
        assert!(argv[0].starts_with('/'), "{:?} must be absolute", argv[0]);
        assert!(argv.len() <= 6);
        for argument in &argv {
            assert!(!argument.contains('\0'));
            assert!(!argument.contains('\n'));
            for forbidden in ["sh", "bash", "-c", ";", "|", "$", "`"] {
                assert!(
                    !argument.contains(forbidden),
                    "{query:?} argument {argument:?} contains {forbidden}"
                );
            }
        }
    }

    let job = LaunchdQuery::LaunchdJobPresence.reviewed_argv();
    assert_eq!(job[0], "/bin/launchctl");
    assert_eq!(job[1], "print");
    assert_eq!(job[2], format!("system/{LAUNCHD_LABEL}"));

    let port = LaunchdQuery::TcpPortListeners { port: 8920 }.reviewed_argv();
    assert!(port.contains(&"-iTCP:8920".to_string()));
    assert!(LAUNCHD_PLIST_PATH.ends_with(&format!("{LAUNCHD_LABEL}.plist")));
}
