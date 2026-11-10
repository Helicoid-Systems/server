//! macOS launchd service configuration/runtime boundary tests.
//!
//! Every host fact is injected. No test writes a product path, creates TLS
//! material, binds a socket, invokes sudo, or loads a launchd job. The only
//! process invocation is `--help`, which exits before the service entry runs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use hs_server::error::ErrorCode;
use hs_server::installer::macos_identity::{IdentityRefusal, ServiceIdentityDecision};
use hs_server::macos_service::{
    authorize_service_identity, plan_reviewed_configuration, MacosServiceFacts,
    ServicePathMetadata, DEFAULT_AUTHORITY_PORT, MAX_AUTHORITY_PORT, MAX_SERVICE_CONFIG_BYTES,
    MIN_UNPRIVILEGED_AUTHORITY_PORT, PRODUCT_ROOT_PATH, SERVICE_ACCOUNT, SERVICE_CONFIG_DIRECTORY,
    SERVICE_CONFIG_PATH, SERVICE_DATABASE_PATH, SERVICE_DATA_DIRECTORY,
    SERVICE_TLS_CERTIFICATE_PATH, SERVICE_TLS_DIRECTORY, SERVICE_TLS_PRIVATE_KEY_PATH,
};
use serde_json::{json, Value};

#[cfg(unix)]
use hs_server::macos_service::LOOPBACK_TLS_SERVER_NAME;

const SERVICE_UID: u32 = 250;

struct FakeHost {
    effective_uid: u32,
    real_uid: u32,
    account: Option<String>,
    identity_error: Option<String>,
    account_error: Option<String>,
    identity_decision: ServiceIdentityDecision,
    entries: BTreeMap<PathBuf, ServicePathMetadata>,
    acl: BTreeMap<PathBuf, Result<bool, String>>,
    lstat_errors: BTreeSet<PathBuf>,
}

impl FakeHost {
    fn valid() -> Self {
        let mut host = Self {
            effective_uid: SERVICE_UID,
            real_uid: SERVICE_UID,
            account: Some(SERVICE_ACCOUNT.to_string()),
            identity_error: None,
            account_error: None,
            identity_decision: ServiceIdentityDecision::ExistingAccountRefused {
                reasons: vec![IdentityRefusal::OwnershipNotVerified],
            },
            entries: BTreeMap::new(),
            acl: BTreeMap::new(),
            lstat_errors: BTreeSet::new(),
        };
        host.directory("/", 0, 0o755);
        host.directory("/Library", 0, 0o755);
        host.directory("/Library/Application Support", 0, 0o755);
        host.directory(PRODUCT_ROOT_PATH, 0, 0o755);
        host.directory(SERVICE_CONFIG_DIRECTORY, 0, 0o755);
        host.file(SERVICE_CONFIG_PATH, 0, 0o644);
        host.directory(SERVICE_DATA_DIRECTORY, SERVICE_UID, 0o700);
        host.directory(SERVICE_TLS_DIRECTORY, SERVICE_UID, 0o700);
        host.file(SERVICE_TLS_CERTIFICATE_PATH, SERVICE_UID, 0o600);
        host.file(SERVICE_TLS_PRIVATE_KEY_PATH, SERVICE_UID, 0o600);
        host
    }

    fn directory(&mut self, path: &str, uid: u32, mode: u32) {
        self.entries.insert(
            PathBuf::from(path),
            ServicePathMetadata::directory(uid, uid, mode),
        );
    }

    fn file(&mut self, path: &str, uid: u32, mode: u32) {
        self.entries.insert(
            PathBuf::from(path),
            ServicePathMetadata::regular_file(uid, uid, mode),
        );
    }

    fn make_symlink(&mut self, path: &str) {
        self.entries.insert(
            PathBuf::from(path),
            ServicePathMetadata::symlink(0, 0, 0o777),
        );
    }

    fn remove(&mut self, path: &str) {
        self.entries.remove(Path::new(path));
    }

    fn set_uid(&mut self, path: &str, uid: u32) {
        self.entries
            .get_mut(Path::new(path))
            .expect("fixture path")
            .uid = uid;
    }

    fn set_mode(&mut self, path: &str, mode: u32) {
        self.entries
            .get_mut(Path::new(path))
            .expect("fixture path")
            .mode = mode;
    }

    fn set_nlink(&mut self, path: &str, nlink: u64) {
        self.entries
            .get_mut(Path::new(path))
            .expect("fixture path")
            .nlink = nlink;
    }

    fn set_acl(&mut self, path: &str, value: Result<bool, String>) {
        self.acl.insert(PathBuf::from(path), value);
    }

    fn set_lstat_error(&mut self, path: &str) {
        self.lstat_errors.insert(PathBuf::from(path));
    }
}

impl MacosServiceFacts for FakeHost {
    fn effective_uid(&self) -> Result<u32, String> {
        match &self.identity_error {
            Some(error) => Err(error.clone()),
            None => Ok(self.effective_uid),
        }
    }

    fn real_uid(&self) -> Result<u32, String> {
        Ok(self.real_uid)
    }

    fn account_name_for_uid(&self, _uid: u32) -> Result<Option<String>, String> {
        match &self.account_error {
            Some(error) => Err(error.clone()),
            None => Ok(self.account.clone()),
        }
    }

    fn service_identity_decision(&self) -> ServiceIdentityDecision {
        self.identity_decision.clone()
    }

    fn lstat(&self, path: &Path) -> Result<Option<ServicePathMetadata>, String> {
        if self.lstat_errors.contains(path) {
            return Err("lstat unavailable".to_string());
        }
        Ok(self.entries.get(path).copied())
    }

    fn extended_acl_is_safe(&self, path: &Path) -> Result<bool, String> {
        match self.acl.get(path) {
            Some(Ok(value)) => Ok(*value),
            Some(Err(error)) => Err(error.clone()),
            None => Ok(true),
        }
    }
}

fn reviewed_configuration() -> Value {
    json!({
        "config_version": 1,
        "deployment_kind": "macos_launchd",
        "network": {
            "scope": "loopback_development",
            "authority_port": DEFAULT_AUTHORITY_PORT
        },
        "storage": {
            "data_directory": SERVICE_DATA_DIRECTORY
        },
        "tls": {
            "certificate_path": SERVICE_TLS_CERTIFICATE_PATH,
            "private_key_path": SERVICE_TLS_PRIVATE_KEY_PATH
        }
    })
}

fn config_bytes(configuration: &Value) -> Vec<u8> {
    serde_json::to_vec(configuration).expect("serialize reviewed configuration")
}

fn assert_rejected_bytes(host: &FakeHost, bytes: &[u8], expected: ErrorCode) {
    let error =
        plan_reviewed_configuration(host, bytes).expect_err("configuration must be refused");
    assert_eq!(error.code(), expected, "unexpected error: {error}");
}

fn assert_rejected(host: &FakeHost, configuration: &Value, expected: ErrorCode) {
    assert_rejected_bytes(host, &config_bytes(configuration), expected);
}

fn assert_identity_rejected(host: &FakeHost, expected: ErrorCode) -> String {
    let error = authorize_service_identity(host).expect_err("identity must be refused");
    assert_eq!(error.code(), expected, "unexpected error: {error}");
    error.to_string()
}

fn assert_configuration_rejected(
    host: &FakeHost,
    expected: ErrorCode,
    mutate: impl FnOnce(&mut Value),
) {
    let mut configuration = reviewed_configuration();
    mutate(&mut configuration);
    assert_rejected(host, &configuration, expected);
}

#[test]
fn reviewed_configuration_plan_is_fixed_and_loopback() {
    let host = FakeHost::valid();
    let plan = plan_reviewed_configuration(&host, &config_bytes(&reviewed_configuration()))
        .expect("the reviewed configuration must produce a plan");

    assert_eq!(plan.account, SERVICE_ACCOUNT);
    assert_eq!(
        plan.bind_address,
        format!("127.0.0.1:{DEFAULT_AUTHORITY_PORT}")
    );
    assert_eq!(plan.data_directory, PathBuf::from(SERVICE_DATA_DIRECTORY));
    assert_eq!(plan.database_path, PathBuf::from(SERVICE_DATABASE_PATH));
    assert_eq!(
        plan.certificate_path,
        PathBuf::from(SERVICE_TLS_CERTIFICATE_PATH)
    );
    assert_eq!(
        plan.private_key_path,
        PathBuf::from(SERVICE_TLS_PRIVATE_KEY_PATH)
    );
}

#[test]
fn fixed_paths_are_derived_from_the_reviewed_product_directories() {
    assert_eq!(
        Path::new(SERVICE_CONFIG_PATH).parent(),
        Some(Path::new(SERVICE_CONFIG_DIRECTORY))
    );
    assert_eq!(
        Path::new(SERVICE_DATABASE_PATH).parent(),
        Some(Path::new(SERVICE_DATA_DIRECTORY))
    );
    assert_eq!(
        SERVICE_DATABASE_PATH,
        format!("{SERVICE_DATA_DIRECTORY}/hs-server.db")
    );
    assert_eq!(
        Path::new(SERVICE_TLS_CERTIFICATE_PATH).parent(),
        Some(Path::new(SERVICE_TLS_DIRECTORY))
    );
    assert_eq!(
        Path::new(SERVICE_TLS_PRIVATE_KEY_PATH).parent(),
        Some(Path::new(SERVICE_TLS_DIRECTORY))
    );
    for directory in [
        SERVICE_CONFIG_DIRECTORY,
        SERVICE_DATA_DIRECTORY,
        SERVICE_TLS_DIRECTORY,
    ] {
        assert!(Path::new(directory).starts_with(PRODUCT_ROOT_PATH));
    }
    assert_ne!(SERVICE_CONFIG_DIRECTORY, SERVICE_DATA_DIRECTORY);
    assert_ne!(SERVICE_CONFIG_DIRECTORY, SERVICE_TLS_DIRECTORY);
    assert_ne!(SERVICE_DATA_DIRECTORY, SERVICE_TLS_DIRECTORY);
}

#[test]
fn reviewed_authority_port_range_is_unprivileged() {
    assert_eq!(MIN_UNPRIVILEGED_AUTHORITY_PORT, 1024);
    assert_eq!(MAX_AUTHORITY_PORT, u16::MAX);
    assert!(
        (MIN_UNPRIVILEGED_AUTHORITY_PORT..=MAX_AUTHORITY_PORT).contains(&DEFAULT_AUTHORITY_PORT)
    );
}

#[test]
fn default_authority_port_matches_the_existing_tls_default() {
    assert_eq!(DEFAULT_AUTHORITY_PORT, 8920);
    assert_eq!(
        format!("127.0.0.1:{DEFAULT_AUTHORITY_PORT}"),
        hs_server::tls::DEFAULT_TLS_BIND
    );
}

#[test]
fn reviewed_unprivileged_authority_ports_are_honored_in_the_literal_loopback_bind() {
    let host = FakeHost::valid();

    for port in [
        MIN_UNPRIVILEGED_AUTHORITY_PORT,
        8787,
        DEFAULT_AUTHORITY_PORT,
        8921,
        MAX_AUTHORITY_PORT,
    ] {
        let mut configuration = reviewed_configuration();
        configuration["network"]["authority_port"] = json!(port);
        let plan = plan_reviewed_configuration(&host, &config_bytes(&configuration))
            .expect("an unprivileged reviewed port must produce a plan");

        assert_eq!(plan.bind_address, format!("127.0.0.1:{port}"));
        let address: std::net::SocketAddr = plan
            .bind_address
            .parse()
            .expect("the plan bind must be a socket address");
        assert!(address.ip().is_loopback());
        assert_eq!(address.port(), port);
    }
}

#[test]
fn omitted_authority_port_defaults_to_the_reviewed_default() {
    let host = FakeHost::valid();
    let mut configuration = reviewed_configuration();
    configuration["network"]
        .as_object_mut()
        .expect("network object")
        .remove("authority_port");

    let plan = plan_reviewed_configuration(&host, &config_bytes(&configuration))
        .expect("an omitted authority port must use the reviewed default");
    assert_eq!(
        plan.bind_address,
        format!("127.0.0.1:{DEFAULT_AUTHORITY_PORT}")
    );
}

#[test]
fn privileged_zero_and_out_of_range_authority_ports_are_rejected() {
    let host = FakeHost::valid();

    for port in [0u16, 1, 80, 443, 1023] {
        assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
            configuration["network"]["authority_port"] = json!(port);
        });
    }

    for value in [
        json!(65536u32),
        json!(70000u32),
        json!(u32::MAX),
        json!(-1),
        json!(8921.5),
        json!("8921"),
        json!(null),
    ] {
        assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
            configuration["network"]["authority_port"] = value.clone();
        });
    }
}

#[test]
fn root_or_non_service_identity_is_rejected() {
    let mut host = FakeHost::valid();
    host.effective_uid = 0;
    host.real_uid = 0;
    host.account = Some("root".to_string());
    assert_identity_rejected(&host, ErrorCode::Forbidden);

    let mut host = FakeHost::valid();
    host.account = Some("alice".to_string());
    assert_identity_rejected(&host, ErrorCode::Forbidden);

    let mut host = FakeHost::valid();
    host.account = Some("_Helicoid".to_string());
    assert_identity_rejected(&host, ErrorCode::Forbidden);

    let mut host = FakeHost::valid();
    host.real_uid = SERVICE_UID + 1;
    assert_identity_rejected(&host, ErrorCode::Forbidden);
}

#[test]
fn unverifiable_identity_is_rejected() {
    let mut host = FakeHost::valid();
    host.account = None;
    assert_identity_rejected(&host, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.identity_error = Some("geteuid unavailable".to_string());
    assert_identity_rejected(&host, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.account_error = Some("directory service unavailable".to_string());
    assert_identity_rejected(&host, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.identity_decision = ServiceIdentityDecision::AccountAbsentObservation;
    assert_identity_rejected(&host, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.identity_decision = ServiceIdentityDecision::AccountAbsentGroupPresentObservation;
    assert_identity_rejected(&host, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.identity_decision = ServiceIdentityDecision::Unavailable {
        reason: "directory services unavailable".to_string(),
    };
    assert_identity_rejected(&host, ErrorCode::SecurityStateUnavailable);
}

#[test]
fn approved_name_alone_does_not_authorize_startup() {
    // The process principal and account name are the approved ones, but this
    // build has no trusted product-ownership evidence. The existing
    // macos_identity seam refuses the account with OwnershipNotVerified.
    let host = FakeHost::valid();
    let message = assert_identity_rejected(&host, ErrorCode::SecurityStateUnavailable);
    assert!(
        message.contains("ownership") || message.contains("not verified"),
        "the refusal must name the missing ownership evidence: {message}"
    );
}

#[test]
fn reviewed_plan_does_not_bypass_the_identity_ownership_gate() {
    let host = FakeHost::valid();
    assert!(
        plan_reviewed_configuration(&host, &config_bytes(&reviewed_configuration())).is_ok(),
        "the prepared configuration/path policy should still be testable"
    );
    assert_identity_rejected(&host, ErrorCode::SecurityStateUnavailable);
}

#[test]
fn absent_or_symlinked_configuration_path_is_rejected() {
    let configuration = reviewed_configuration();

    let mut host = FakeHost::valid();
    host.remove(SERVICE_CONFIG_PATH);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.make_symlink(SERVICE_CONFIG_PATH);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.make_symlink(SERVICE_CONFIG_DIRECTORY);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.remove(SERVICE_CONFIG_DIRECTORY);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.directory(SERVICE_CONFIG_PATH, 0, 0o755);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);
}

#[test]
fn configuration_file_must_be_root_owned_not_writable_and_single_link() {
    let configuration = reviewed_configuration();

    let mut host = FakeHost::valid();
    host.set_uid(SERVICE_CONFIG_PATH, 501);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_mode(SERVICE_CONFIG_PATH, 0o666);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_mode(SERVICE_CONFIG_PATH, 0o646);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_nlink(SERVICE_CONFIG_PATH, 2);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_lstat_error(SERVICE_CONFIG_PATH);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);
}

#[test]
fn configuration_ancestors_must_be_root_owned_real_directories() {
    let configuration = reviewed_configuration();

    let mut host = FakeHost::valid();
    host.make_symlink("/Library");
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_uid("/Library", 501);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_mode("/Library", 0o777);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.remove("/Library/Application Support");
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_mode(PRODUCT_ROOT_PATH, 0o775);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_uid(SERVICE_CONFIG_DIRECTORY, 501);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_lstat_error("/Library/Application Support");
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);
}

#[test]
fn configuration_permissions_must_allow_non_root_read_and_traverse() {
    let configuration = reviewed_configuration();

    let mut host = FakeHost::valid();
    host.set_mode(SERVICE_CONFIG_PATH, 0o600);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_mode(SERVICE_CONFIG_PATH, 0o640);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_mode(SERVICE_CONFIG_DIRECTORY, 0o700);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_mode(PRODUCT_ROOT_PATH, 0o700);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    // Execute-only is not enough for the held-directory reader, which opens
    // ancestors read-only before opening the config by name.
    let mut host = FakeHost::valid();
    host.set_mode("/Library", 0o711);
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut readable = FakeHost::valid();
    readable.set_mode(SERVICE_CONFIG_PATH, 0o644);
    readable.set_mode(SERVICE_CONFIG_DIRECTORY, 0o755);
    assert!(plan_reviewed_configuration(&readable, &config_bytes(&configuration)).is_ok());
}

#[test]
fn configuration_acl_must_be_absent_or_deny_only() {
    let configuration = reviewed_configuration();

    let mut host = FakeHost::valid();
    host.set_acl(SERVICE_CONFIG_PATH, Ok(false));
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_acl(
        SERVICE_CONFIG_DIRECTORY,
        Err("ACL query unsupported".to_string()),
    );
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);

    let mut host = FakeHost::valid();
    host.set_acl("/Library", Ok(false));
    assert_rejected(&host, &configuration, ErrorCode::SecurityStateUnavailable);
}

#[test]
fn malformed_or_non_object_json_is_rejected() {
    let host = FakeHost::valid();
    for bytes in [
        b"".as_slice(),
        b"{".as_slice(),
        b"null".as_slice(),
        b"[]".as_slice(),
        b"\"text\"".as_slice(),
        b"{\"config_version\":1}".as_slice(),
    ] {
        assert_rejected_bytes(&host, bytes, ErrorCode::BadRequest);
    }
}

#[test]
fn oversized_configuration_is_rejected() {
    let host = FakeHost::valid();
    let oversized = vec![b' '; MAX_SERVICE_CONFIG_BYTES + 1];
    assert_rejected_bytes(&host, &oversized, ErrorCode::BadRequest);
}

#[test]
fn unknown_fields_and_duplicate_keys_are_rejected() {
    let host = FakeHost::valid();

    assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
        configuration["unexpected"] = json!(true);
    });
    assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
        configuration["network"]["bind_address"] = json!("0.0.0.0");
    });
    assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
        configuration["network"]["client_hostname"] = json!("example.invalid");
    });
    assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
        configuration["tls"]["unexpected"] = json!("value");
    });

    let duplicate_top_level = format!(
        "{{\"config_version\":1,\"config_version\":1,\"deployment_kind\":\"macos_launchd\",\"network\":{{\"scope\":\"loopback_development\",\"authority_port\":{DEFAULT_AUTHORITY_PORT}}},\"storage\":{{\"data_directory\":\"{SERVICE_DATA_DIRECTORY}\"}},\"tls\":{{\"certificate_path\":\"{SERVICE_TLS_CERTIFICATE_PATH}\",\"private_key_path\":\"{SERVICE_TLS_PRIVATE_KEY_PATH}\"}}}}"
    );
    assert_rejected_bytes(&host, duplicate_top_level.as_bytes(), ErrorCode::BadRequest);

    let duplicate_nested = format!(
        "{{\"config_version\":1,\"deployment_kind\":\"macos_launchd\",\"network\":{{\"scope\":\"loopback_development\",\"scope\":\"loopback_development\",\"authority_port\":{DEFAULT_AUTHORITY_PORT}}},\"storage\":{{\"data_directory\":\"{SERVICE_DATA_DIRECTORY}\"}},\"tls\":{{\"certificate_path\":\"{SERVICE_TLS_CERTIFICATE_PATH}\",\"private_key_path\":\"{SERVICE_TLS_PRIVATE_KEY_PATH}\"}}}}"
    );
    assert_rejected_bytes(&host, duplicate_nested.as_bytes(), ErrorCode::BadRequest);
}

#[test]
fn wrong_version_kind_scope_and_paths_are_rejected() {
    let host = FakeHost::valid();

    assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
        configuration["config_version"] = json!(2);
    });
    assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
        configuration["deployment_kind"] = json!("linux_systemd");
    });
    assert_configuration_rejected(&host, ErrorCode::NotImplemented, |configuration| {
        configuration["network"]["scope"] = json!("lan");
    });
    assert_configuration_rejected(&host, ErrorCode::NotImplemented, |configuration| {
        configuration["network"]["scope"] = json!("private_dns");
    });
    assert_configuration_rejected(&host, ErrorCode::NotImplemented, |configuration| {
        configuration["network"]["scope"] = json!("public_edge");
    });
    assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
        configuration["storage"]["data_directory"] = json!("/tmp/helicoid-data");
    });
    assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
        configuration["storage"]["data_directory"] = json!(format!("{SERVICE_DATA_DIRECTORY}/"));
    });
    assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
        configuration["storage"]["data_directory"] = json!(format!("{PRODUCT_ROOT_PATH}/../Data"));
    });
    assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
        configuration["storage"]["data_directory"] = json!(null);
    });
    assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
        configuration["tls"]["certificate_path"] = json!("/tmp/fullchain.pem");
    });
    assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
        configuration["tls"]["private_key_path"] = json!("/tmp/private-key.pem");
    });
    assert_configuration_rejected(&host, ErrorCode::BadRequest, |configuration| {
        configuration
            .as_object_mut()
            .expect("configuration object")
            .remove("tls");
    });
}

#[test]
fn absent_or_unsafe_product_data_directory_is_rejected() {
    let host = FakeHost::valid();
    let configuration = reviewed_configuration();

    let mut fixture = FakeHost::valid();
    fixture.remove(SERVICE_DATA_DIRECTORY);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.make_symlink(SERVICE_DATA_DIRECTORY);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_uid(SERVICE_DATA_DIRECTORY, SERVICE_UID + 1);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_mode(SERVICE_DATA_DIRECTORY, 0o755);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_mode(SERVICE_DATA_DIRECTORY, 0o770);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_mode(SERVICE_DATA_DIRECTORY, 0o500);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_acl(SERVICE_DATA_DIRECTORY, Ok(false));
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_acl(
        SERVICE_DATA_DIRECTORY,
        Err("ACL query unsupported".to_string()),
    );
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_lstat_error(SERVICE_DATA_DIRECTORY);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.file(SERVICE_DATA_DIRECTORY, SERVICE_UID, 0o700);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    // The valid fixture itself still plans.
    assert!(plan_reviewed_configuration(&host, &config_bytes(&configuration)).is_ok());
}

#[test]
fn absent_or_unsafe_tls_directory_is_rejected() {
    let configuration = reviewed_configuration();

    let mut fixture = FakeHost::valid();
    fixture.remove(SERVICE_TLS_DIRECTORY);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.make_symlink(SERVICE_TLS_DIRECTORY);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_uid(SERVICE_TLS_DIRECTORY, SERVICE_UID + 1);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_mode(SERVICE_TLS_DIRECTORY, 0o777);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_mode(SERVICE_TLS_DIRECTORY, 0o770);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_mode(SERVICE_TLS_DIRECTORY, 0o300);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut readable = FakeHost::valid();
    readable.set_mode(SERVICE_TLS_DIRECTORY, 0o500);
    assert!(plan_reviewed_configuration(&readable, &config_bytes(&configuration)).is_ok());

    let mut fixture = FakeHost::valid();
    fixture.set_acl(
        SERVICE_TLS_DIRECTORY,
        Err("ACL query unsupported".to_string()),
    );
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.file(SERVICE_TLS_DIRECTORY, SERVICE_UID, 0o700);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    // The existing private-file parent rule allows traversal without group or
    // world write, so a 0750 TLS directory remains valid.
    let mut traversable = FakeHost::valid();
    traversable.set_mode(SERVICE_TLS_DIRECTORY, 0o750);
    assert!(plan_reviewed_configuration(&traversable, &config_bytes(&configuration)).is_ok());
}

#[test]
fn tls_material_must_be_service_owned_private_and_single_link() {
    let configuration = reviewed_configuration();

    for path in [SERVICE_TLS_CERTIFICATE_PATH, SERVICE_TLS_PRIVATE_KEY_PATH] {
        let mut fixture = FakeHost::valid();
        fixture.remove(path);
        assert_rejected(
            &fixture,
            &configuration,
            ErrorCode::SecurityStateUnavailable,
        );

        let mut fixture = FakeHost::valid();
        fixture.make_symlink(path);
        assert_rejected(
            &fixture,
            &configuration,
            ErrorCode::SecurityStateUnavailable,
        );

        let mut fixture = FakeHost::valid();
        fixture.set_uid(path, SERVICE_UID + 1);
        assert_rejected(
            &fixture,
            &configuration,
            ErrorCode::SecurityStateUnavailable,
        );

        let mut fixture = FakeHost::valid();
        fixture.set_mode(path, 0o644);
        assert_rejected(
            &fixture,
            &configuration,
            ErrorCode::SecurityStateUnavailable,
        );

        let mut fixture = FakeHost::valid();
        fixture.set_mode(path, 0o640);
        assert_rejected(
            &fixture,
            &configuration,
            ErrorCode::SecurityStateUnavailable,
        );

        let mut fixture = FakeHost::valid();
        fixture.set_mode(path, 0o200);
        assert_rejected(
            &fixture,
            &configuration,
            ErrorCode::SecurityStateUnavailable,
        );

        let mut fixture = FakeHost::valid();
        fixture.set_nlink(path, 2);
        assert_rejected(
            &fixture,
            &configuration,
            ErrorCode::SecurityStateUnavailable,
        );

        let mut fixture = FakeHost::valid();
        fixture.set_lstat_error(path);
        assert_rejected(
            &fixture,
            &configuration,
            ErrorCode::SecurityStateUnavailable,
        );

        let mut fixture = FakeHost::valid();
        fixture.directory(path, SERVICE_UID, 0o700);
        assert_rejected(
            &fixture,
            &configuration,
            ErrorCode::SecurityStateUnavailable,
        );
    }
}

#[test]
fn tls_acl_must_be_absent_or_deny_only() {
    let configuration = reviewed_configuration();

    let mut fixture = FakeHost::valid();
    fixture.set_acl(SERVICE_TLS_CERTIFICATE_PATH, Ok(false));
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_acl(
        SERVICE_TLS_PRIVATE_KEY_PATH,
        Err("ACL query unsupported".to_string()),
    );
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );
}

#[test]
fn product_root_must_be_a_root_owned_real_directory() {
    let configuration = reviewed_configuration();

    let mut fixture = FakeHost::valid();
    fixture.remove(PRODUCT_ROOT_PATH);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.make_symlink(PRODUCT_ROOT_PATH);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_uid(PRODUCT_ROOT_PATH, 501);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_mode(PRODUCT_ROOT_PATH, 0o777);
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );

    let mut fixture = FakeHost::valid();
    fixture.set_acl(PRODUCT_ROOT_PATH, Ok(false));
    assert_rejected(
        &fixture,
        &configuration,
        ErrorCode::SecurityStateUnavailable,
    );
}

#[cfg(unix)]
fn private_tempdir() -> (tempfile::TempDir, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().canonicalize().expect("canonicalize");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("chmod private tempdir");
    (directory, path)
}

#[cfg(unix)]
fn write_tls_fixture(base: &Path, label: &str, sans: &[&str]) -> (PathBuf, PathBuf) {
    let key = rcgen::KeyPair::generate().expect("generate disposable test key");
    let params = rcgen::CertificateParams::new(
        sans.iter()
            .map(|san| (*san).to_string())
            .collect::<Vec<_>>(),
    )
    .expect("certificate params");
    let certificate = params
        .self_signed(&key)
        .expect("self-sign disposable test certificate");

    let certificate_path = base.join(format!("{label}.crt"));
    let key_path = base.join(format!("{label}.key"));
    hs_server::private_file::create_new_private_file(
        &certificate_path,
        certificate.pem().as_bytes(),
    )
    .expect("write disposable test certificate");
    hs_server::private_file::create_new_private_file(&key_path, key.serialize_pem().as_bytes())
        .expect("write disposable test key");
    (certificate_path, key_path)
}

#[cfg(unix)]
#[test]
fn loopback_tls_entry_requires_certificate_coverage_of_127_0_0_1() {
    let (_directory, base) = private_tempdir();

    let (certificate, key) = write_tls_fixture(&base, "good", &[LOOPBACK_TLS_SERVER_NAME]);
    let transport = hs_server::tls::validate_serve_tls_inputs_with_network_and_name(
        "127.0.0.1:8921",
        &certificate,
        &key,
        false,
        Some(LOOPBACK_TLS_SERVER_NAME),
    )
    .expect("a certificate covering 127.0.0.1 must validate");
    assert!(transport.addr().ip().is_loopback());
    assert_eq!(transport.addr().port(), 8921);

    let (wrong_certificate, wrong_key) = write_tls_fixture(&base, "wrong", &["127.0.0.2"]);
    let missing_store = base.join("missing-store").join("hs-server.db");
    let error = hs_server::tls::run_serve_tls_with_network_and_name(
        &missing_store,
        "127.0.0.1:8921",
        &wrong_certificate,
        &wrong_key,
        false,
        Some(LOOPBACK_TLS_SERVER_NAME),
    )
    .expect_err("a certificate not covering 127.0.0.1 must be refused before the store opens");
    assert!(
        error.to_string().contains("does not cover"),
        "unexpected error: {error}"
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn non_macos_runtime_entry_is_unavailable() {
    let error = hs_server::macos_service::run().expect_err("must be unavailable");
    assert_eq!(error.code(), ErrorCode::NotImplemented);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn non_macos_cli_rejects_fixed_service_verb() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_hs-server"))
        .arg("macos-service")
        .env("RUST_LOG", "off")
        .output()
        .expect("run hs-server");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("only on macOS"), "stderr: {stderr}");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_cli_help_for_fixed_service_verb_does_not_start_the_service() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_hs-server"))
        .args(["macos-service", "--help"])
        .env("RUST_LOG", "off")
        .output()
        .expect("run hs-server");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage: hs-server macos-service"),
        "stdout: {stdout}"
    );
}
