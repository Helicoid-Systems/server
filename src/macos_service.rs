//! Prepared fixed macOS launchd service configuration and runtime entry.
//!
//! The signed Manager app will eventually ship an immutable launchd plist
//! that starts the bundled `hs-server` with exactly one argument:
//! `macos-service`. The plist supplies no user-controlled argv, and this
//! command reads no command-line options. Reviewed runtime settings live in a
//! root-owned configuration file at a fixed product path.
//!
//! # Fixed product paths
//!
//! - configuration: `/Library/Application Support/Helicoid/Configuration/service.json`
//! - data: `/Library/Application Support/Helicoid/Data`
//! - database: `/Library/Application Support/Helicoid/Data/hs-server.db`
//! - TLS certificate: `/Library/Application Support/Helicoid/TLS/fullchain.pem`
//! - TLS private key: `/Library/Application Support/Helicoid/TLS/private-key.pem`
//!
//! The configuration file is root-owned, not group- or world-writable, and
//! readable by the non-root service (`0644`-class); a root-only `0600` file is
//! refused. It is read through a held descriptor after every ancestor is
//! verified as a real root-owned directory that grants the non-root service
//! read/traverse access (`0755`-class; root-only `0700` is refused), has no
//! group/world write bit, and has no extended ACL ALLOW entry. An absent path,
//! a symlink component, an unverified ACL, an oversized or malformed document,
//! a duplicate or unknown JSON key, and every value outside the reviewed
//! constraints below are refused before any listener or database effect.
//!
//! Reviewed configuration (version 1):
//!
//! ```json
//! {
//!   "config_version": 1,
//!   "deployment_kind": "macos_launchd",
//!   "network": {
//!     "scope": "loopback_development",
//!     "authority_port": 8920
//!   },
//!   "storage": {
//!     "data_directory": "/Library/Application Support/Helicoid/Data"
//!   },
//!   "tls": {
//!     "certificate_path": "/Library/Application Support/Helicoid/TLS/fullchain.pem",
//!     "private_key_path": "/Library/Application Support/Helicoid/TLS/private-key.pem"
//!   }
//! }
//! ```
//!
//! `authority_port` is optional; when omitted it defaults to the Manager
//! default, 8920. An explicit value must be an unprivileged port in
//! `1024..=65535`. The prepared plan always builds the bind as literal
//! `127.0.0.1:<authority_port>`; the configuration cannot select another
//! address.
//!
//! # Ownership gate
//!
//! [`authorize_service_identity`] reuses the existing
//! [`crate::installer::macos_identity`] seam. That seam refuses every existing
//! account because it has no product-ownership evidence of its own. Startup
//! therefore fails closed unless the reviewed macOS apply lifecycle wrote a
//! root-owned install receipt and [`crate::installer::macos_apply`] verified it
//! against the observed account/group. A plan alone is not authorization, and
//! an absent or invalid receipt cannot start the service.
//!
//! # Runtime rules
//!
//! The process must have equal, nonzero real/effective UIDs and resolve to the
//! fixed `_helicoid` account. That name check is necessary but not sufficient:
//! [`authorize_service_identity`] additionally requires the existing
//! product-identity seam to return an accepted, product-owned account decision.
//! No accepted decision exists in this build, so startup fails closed even for
//! `_helicoid`.
//!
//! The data directory must already exist owner-only (`0700`-class), owned by
//! `_helicoid`, and grant owner read/write/traverse access. The TLS directory
//! must be owned by `_helicoid`, grant owner read/traverse access, and not be
//! group/world-writable. Certificate and key files must be owner-private
//! (`0600`-class), owner-readable, single-link regular files owned by
//! `_helicoid`. These are the existing [`crate::private_file`] rules applied to
//! the fixed product paths, with explicit effective-access checks.
//!
//! The prepared serve entry is
//! [`crate::tls::run_serve_tls_with_network_and_name`] on literal loopback with
//! the reviewed authority port and a certificate required to cover
//! `127.0.0.1`. There is no plaintext fallback, no caller-selected address, and
//! no remote network scope in this slice. The loopback listener uses the
//! existing local application router (`crate::app`), which includes local
//! development/bootstrap routes; it is **not** the v2-only network router and
//! does not establish Manager/endpoint enrollment, remote authority, or
//! production readiness. Remote scopes remain unreviewed and are refused.
//!
//! # What this module does not do
//!
//! - install, load, enable, disable, or unload a launchd job;
//! - create the `_helicoid` account, product directories, configuration, TLS
//!   material, or database;
//! - generate configuration or open install/apply/readiness gates;
//! - accept a caller-selected executable, path, port, scope, or argument;
//! - claim bootstrap, endpoint enrollment, remote authority, or production
//!   readiness.
//!
//! [`plan_reviewed_configuration`] is the injectable pre-authorization policy
//! seam used by tests and by the future runtime wiring. It performs no process
//! authorization and never reads or writes the host. [`authorize_service_identity`]
//! is the startup gate and currently fails closed for every account. The
//! macOS system-facts implementation observes the local host and holds the
//! configuration file descriptor across validation and read.

use std::path::{Path, PathBuf};

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{AppError, AppResult};
use crate::installer::lifecycle_v2::{DeploymentKind, NetworkScope};
use crate::installer::macos_identity::{IdentityRefusal, ServiceIdentityDecision};

/// Product root owned by root and shared by the reviewed macOS paths.
///
/// Reuses the installer preflight's Manager-owned product root so the runtime
/// and the reviewed installation path cannot drift.
pub const PRODUCT_ROOT_PATH: &str = crate::installer::macos_launchd::PRODUCT_ROOT_PATH;
/// Fixed root-owned configuration directory.
pub const SERVICE_CONFIG_DIRECTORY: &str = crate::installer::macos_launchd::CONFIGURATION_DIRECTORY;
/// Fixed root-owned configuration document written by reviewed setup.
pub const SERVICE_CONFIG_PATH: &str = crate::installer::macos_launchd::CONFIGURATION_PATH;
/// Fixed data directory owned by `_helicoid` (existing Manager-owned path).
///
/// Reuses the installer preflight's Manager-owned data path.
pub const SERVICE_DATA_DIRECTORY: &str = crate::installer::macos_launchd::DATA_PATH;
/// Fixed database name under the reviewed data directory.
pub const SERVICE_DATABASE_PATH: &str = "/Library/Application Support/Helicoid/Data/hs-server.db";
/// Fixed TLS directory owned by `_helicoid`.
pub const SERVICE_TLS_DIRECTORY: &str = crate::installer::macos_launchd::TLS_DIRECTORY;
/// Fixed certificate-chain path.
pub const SERVICE_TLS_CERTIFICATE_PATH: &str =
    crate::installer::macos_launchd::TLS_CERTIFICATE_PATH;
/// Fixed private-key path.
pub const SERVICE_TLS_PRIVATE_KEY_PATH: &str =
    crate::installer::macos_launchd::TLS_PRIVATE_KEY_PATH;
/// Fixed service account. No caller supplies or selects this value.
pub const SERVICE_ACCOUNT: &str = crate::installer::macos_identity::PRODUCT_SERVICE_ACCOUNT;
/// Literal loopback address the TLS certificate must cover for this service.
pub const LOOPBACK_TLS_SERVER_NAME: &str = "127.0.0.1";
/// Default authority port when the reviewed configuration omits one.
pub const DEFAULT_AUTHORITY_PORT: u16 = crate::installer::macos_launchd::DEFAULT_AUTHORITY_PORT;
/// Lowest unprivileged authority port accepted by the reviewed configuration.
pub const MIN_UNPRIVILEGED_AUTHORITY_PORT: u16 = 1024;
/// Highest authority port accepted by the reviewed configuration.
pub const MAX_AUTHORITY_PORT: u16 = u16::MAX;
/// Configuration document version understood by this build.
pub const SERVICE_CONFIG_VERSION: u32 = 1;
/// Hard bound on configuration bytes.
pub const MAX_SERVICE_CONFIG_BYTES: usize = 16 * 1024;

/// Reviewed configuration document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfiguration {
    pub config_version: u32,
    pub deployment_kind: DeploymentKind,
    pub network: ServiceNetworkConfiguration,
    pub storage: ServiceStorageConfiguration,
    pub tls: ServiceTlsConfiguration,
}

/// Loopback-only network settings. `bind_address` is not a reviewed field.
///
/// `authority_port` defaults to [`DEFAULT_AUTHORITY_PORT`] when omitted. An
/// explicit value is accepted only in
/// [`MIN_UNPRIVILEGED_AUTHORITY_PORT`]..=[`MAX_AUTHORITY_PORT`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceNetworkConfiguration {
    pub scope: NetworkScope,
    #[serde(default = "default_authority_port")]
    pub authority_port: u16,
}

fn default_authority_port() -> u16 {
    DEFAULT_AUTHORITY_PORT
}

/// Fixed storage setting. The data path is present for review, not selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStorageConfiguration {
    pub data_directory: String,
}

/// Fixed TLS material paths. The paths are present for review, not selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceTlsConfiguration {
    pub certificate_path: String,
    pub private_key_path: String,
}

/// Reviewed pre-authorization plan. Paths and the executable are fixed; the
/// bind is literal loopback HTTPS with the reviewed authority port. The plan
/// cannot carry a caller-selected address, executable, path, or plaintext bind.
/// A plan is not an identity or ownership authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRuntimePlan {
    pub account: &'static str,
    pub bind_address: String,
    pub data_directory: PathBuf,
    pub database_path: PathBuf,
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
}

/// Observed path facts used by the policy seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServicePathMetadata {
    pub is_symlink: bool,
    pub is_directory: bool,
    pub is_regular_file: bool,
    pub uid: u32,
    pub gid: u32,
    /// Raw `st_mode`, including file-type bits. Permission checks mask it.
    pub mode: u32,
    pub nlink: u64,
}

impl ServicePathMetadata {
    /// A real directory with a single observed link count.
    pub fn directory(uid: u32, gid: u32, mode: u32) -> Self {
        Self {
            is_symlink: false,
            is_directory: true,
            is_regular_file: false,
            uid,
            gid,
            mode,
            nlink: 1,
        }
    }

    /// A regular file with a single observed link count.
    pub fn regular_file(uid: u32, gid: u32, mode: u32) -> Self {
        Self {
            is_symlink: false,
            is_directory: false,
            is_regular_file: true,
            uid,
            gid,
            mode,
            nlink: 1,
        }
    }

    /// A symlink observation. Its target is never followed.
    pub fn symlink(uid: u32, gid: u32, mode: u32) -> Self {
        Self {
            is_symlink: true,
            is_directory: false,
            is_regular_file: false,
            uid,
            gid,
            mode,
            nlink: 1,
        }
    }
}

/// Injectable, read-only host facts for the macOS service policy.
///
/// Tests supply in-memory fixtures. The production implementation is the
/// macOS-only `MacosSystemServiceFacts`. No method mutates the host.
pub trait MacosServiceFacts {
    fn effective_uid(&self) -> Result<u32, String>;
    fn real_uid(&self) -> Result<u32, String>;
    fn account_name_for_uid(&self, uid: u32) -> Result<Option<String>, String>;
    /// Existing trusted account/product-ownership seam. The production
    /// implementation delegates to `macos_identity`; this build has no
    /// accepted decision variant.
    fn service_identity_decision(&self) -> ServiceIdentityDecision;
    fn lstat(&self, path: &Path) -> Result<Option<ServicePathMetadata>, String>;
    /// True only when the path has no extended ACL or only DENY entries.
    /// Any ALLOW entry, unsupported filesystem, or query error must be
    /// returned as `false` or an error; mode bits alone are not sufficient.
    fn extended_acl_is_safe(&self, path: &Path) -> Result<bool, String>;
}

/// Parse and validate a reviewed configuration and its fixed path facts.
///
/// This is a pre-authorization policy seam: it does not authorize the process,
/// account, or product ownership. The runtime must call
/// [`authorize_service_identity`] first. It never reads or writes the host.
pub fn plan_reviewed_configuration(
    facts: &dyn MacosServiceFacts,
    config_bytes: &[u8],
) -> AppResult<ServiceRuntimePlan> {
    let service_uid = facts.effective_uid().map_err(|error| {
        AppError::security_state_unavailable(format!(
            "cannot determine the service principal for path ownership checks: {}",
            bounded_detail(&error)
        ))
    })?;
    plan_reviewed_configuration_for_uid(facts, config_bytes, service_uid)
}

fn plan_reviewed_configuration_for_uid(
    facts: &dyn MacosServiceFacts,
    config_bytes: &[u8],
    service_uid: u32,
) -> AppResult<ServiceRuntimePlan> {
    // The configuration path is checked before its bytes are interpreted so an
    // absent, symlinked, or writable configuration never becomes input.
    validate_config_path(facts)?;

    let configuration = parse_configuration(config_bytes)?;
    validate_configuration(&configuration)?;
    let authority_port = configuration.network.authority_port;

    validate_root_chain(facts, Path::new(PRODUCT_ROOT_PATH), "product root")?;
    validate_service_directory(
        facts,
        Path::new(SERVICE_DATA_DIRECTORY),
        service_uid,
        true,
        "service data directory",
    )?;
    validate_service_directory(
        facts,
        Path::new(SERVICE_TLS_DIRECTORY),
        service_uid,
        false,
        "service TLS directory",
    )?;
    validate_service_private_file(
        facts,
        Path::new(SERVICE_TLS_CERTIFICATE_PATH),
        service_uid,
        "TLS certificate",
    )?;
    validate_service_private_file(
        facts,
        Path::new(SERVICE_TLS_PRIVATE_KEY_PATH),
        service_uid,
        "TLS private key",
    )?;

    Ok(ServiceRuntimePlan {
        account: SERVICE_ACCOUNT,
        bind_address: format!("127.0.0.1:{authority_port}"),
        data_directory: PathBuf::from(SERVICE_DATA_DIRECTORY),
        database_path: PathBuf::from(SERVICE_DATABASE_PATH),
        certificate_path: PathBuf::from(SERVICE_TLS_CERTIFICATE_PATH),
        private_key_path: PathBuf::from(SERVICE_TLS_PRIVATE_KEY_PATH),
    })
}

/// Startup identity/ownership gate.
///
/// A matching `_helicoid` name is necessary but not sufficient. Without
/// explicit receipt evidence this gate fails closed for every existing account,
/// because the read-only `macos_identity` seam always reports missing
/// product-ownership evidence. [`authorize_service_identity_with_ownership`]
/// is the only path that may accept an existing account, and only after the
/// caller verifies the root-owned install receipt.
pub fn authorize_service_identity(facts: &dyn MacosServiceFacts) -> AppResult<()> {
    authorize_service_identity_with_ownership(facts, false)
}

/// Startup gate with explicit receipt-based ownership evidence.
///
/// `ownership_verified` may be true only after the caller has verified the
/// root-owned install receipt against the observed account/group and package
/// evidence. It accepts an existing account only when the identity seam reports
/// no problem other than its own missing ownership variant.
pub fn authorize_service_identity_with_ownership(
    facts: &dyn MacosServiceFacts,
    ownership_verified: bool,
) -> AppResult<()> {
    let effective_uid = facts.effective_uid().map_err(|error| {
        AppError::security_state_unavailable(format!(
            "cannot determine the effective service identity: {}",
            bounded_detail(&error)
        ))
    })?;
    let real_uid = facts.real_uid().map_err(|error| {
        AppError::security_state_unavailable(format!(
            "cannot determine the real service identity: {}",
            bounded_detail(&error)
        ))
    })?;

    if effective_uid == 0 || real_uid == 0 {
        return Err(AppError::forbidden(format!(
            "the macOS service must not run as root; launchd must start it as {SERVICE_ACCOUNT}"
        )));
    }
    if real_uid != effective_uid {
        return Err(AppError::forbidden(
            "the macOS service real and effective identities differ; refusing a setuid or switched-identity launch",
        ));
    }

    let account = facts.account_name_for_uid(effective_uid).map_err(|error| {
        AppError::security_state_unavailable(format!(
            "cannot resolve the local service account: {}",
            bounded_detail(&error)
        ))
    })?;
    match account {
        Some(name) if name == SERVICE_ACCOUNT => {}
        Some(_) => {
            return Err(AppError::forbidden(format!(
                "the macOS service must run as the fixed account {SERVICE_ACCOUNT}; refusing uid {effective_uid}"
            )))
        }
        None => {
            return Err(AppError::security_state_unavailable(format!(
                "no local account record resolves uid {effective_uid}; cannot verify the fixed service identity"
            )))
        }
    }

    // Exhaustive match with no accepting arm. If a future trusted seam adds an
    // accepted variant, this match fails to compile until the product decision
    // is reviewed here.
    match facts.service_identity_decision() {
        ServiceIdentityDecision::ExistingAccountRefused { reasons }
            if ownership_verified && reasons.len() == 1 && reasons[0] == IdentityRefusal::OwnershipNotVerified =>
        {
            Ok(())
        }
        ServiceIdentityDecision::ExistingAccountRefused { reasons } => {
            let reasons = reasons
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            Err(AppError::security_state_unavailable(format!(
                "the fixed service account is present but product ownership is not verified; refusing to start: {}",
                bounded_detail(&reasons)
            )))
        }
        ServiceIdentityDecision::AccountAbsentObservation => {
            Err(AppError::security_state_unavailable(
                "the fixed service account and group are absent; no reviewed creation or product ownership evidence source exists; refusing to start",
            ))
        }
        ServiceIdentityDecision::AccountAbsentGroupPresentObservation => {
            Err(AppError::security_state_unavailable(
                "the fixed service account is absent but its service group exists; this is not a fresh identity; refusing to start",
            ))
        }
        ServiceIdentityDecision::Unavailable { reason } => {
            Err(AppError::security_state_unavailable(format!(
                "cannot verify the fixed service identity or product ownership: {}",
                bounded_detail(&reason)
            )))
        }
    }
}

fn parse_configuration(config_bytes: &[u8]) -> AppResult<ServiceConfiguration> {
    if config_bytes.is_empty() {
        return Err(AppError::bad_request("service configuration is empty"));
    }
    if config_bytes.len() > MAX_SERVICE_CONFIG_BYTES {
        return Err(AppError::bad_request(format!(
            "service configuration exceeds {MAX_SERVICE_CONFIG_BYTES} bytes"
        )));
    }
    if config_bytes.contains(&0) {
        return Err(AppError::bad_request(
            "service configuration contains a NUL byte",
        ));
    }

    let strict: StrictJson = serde_json::from_slice(config_bytes).map_err(|error| {
        AppError::bad_request(format!(
            "service configuration is not valid JSON: {}",
            bounded_detail(&error.to_string())
        ))
    })?;
    let configuration: ServiceConfiguration =
        serde_json::from_value(strict.into_value()).map_err(|error| {
            AppError::bad_request(format!(
                "service configuration does not match the reviewed schema: {}",
                bounded_detail(&error.to_string())
            ))
        })?;
    Ok(configuration)
}

fn validate_configuration(configuration: &ServiceConfiguration) -> AppResult<()> {
    if configuration.config_version != SERVICE_CONFIG_VERSION {
        return Err(AppError::bad_request(format!(
            "unsupported service configuration version {}; expected {}",
            configuration.config_version, SERVICE_CONFIG_VERSION
        )));
    }
    if configuration.deployment_kind != DeploymentKind::MacosLaunchd {
        return Err(AppError::bad_request(
            "service configuration deployment_kind must be macos_launchd",
        ));
    }
    if configuration.network.scope != NetworkScope::LoopbackDevelopment {
        return Err(AppError::not_implemented(
            "only the reviewed loopback_development service scope is supported; remote network scopes are not authorized",
        ));
    }
    if !(MIN_UNPRIVILEGED_AUTHORITY_PORT..=MAX_AUTHORITY_PORT)
        .contains(&configuration.network.authority_port)
    {
        return Err(AppError::bad_request(format!(
            "service authority_port must be an unprivileged port {}..={}",
            MIN_UNPRIVILEGED_AUTHORITY_PORT, MAX_AUTHORITY_PORT
        )));
    }
    if configuration.storage.data_directory != SERVICE_DATA_DIRECTORY {
        return Err(AppError::bad_request(
            "service data_directory must be the fixed product data path",
        ));
    }
    if configuration.tls.certificate_path != SERVICE_TLS_CERTIFICATE_PATH {
        return Err(AppError::bad_request(
            "service certificate_path must be the fixed product TLS path",
        ));
    }
    if configuration.tls.private_key_path != SERVICE_TLS_PRIVATE_KEY_PATH {
        return Err(AppError::bad_request(
            "service private_key_path must be the fixed product TLS path",
        ));
    }
    Ok(())
}

fn validate_config_path(facts: &dyn MacosServiceFacts) -> AppResult<()> {
    validate_root_chain(
        facts,
        Path::new(SERVICE_CONFIG_DIRECTORY),
        "service configuration directory",
    )?;
    validate_root_owned_file(
        facts,
        Path::new(SERVICE_CONFIG_PATH),
        "service configuration file",
    )
}

/// Every ancestor, including `path` itself, must be an existing real directory
/// owned by root, not group- or world-writable, readable/traversable by the
/// non-root service, and have no ACL ALLOW entry.
fn validate_root_chain(facts: &dyn MacosServiceFacts, path: &Path, label: &str) -> AppResult<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = require_entry(facts, ancestor, label)?;
        if metadata.is_symlink {
            return Err(AppError::security_state_unavailable(format!(
                "{label} ancestor {} is a symlink; refusing to follow it",
                ancestor.display()
            )));
        }
        if !metadata.is_directory {
            return Err(AppError::security_state_unavailable(format!(
                "{label} ancestor {} is not a directory",
                ancestor.display()
            )));
        }
        if metadata.uid != 0 {
            return Err(AppError::security_state_unavailable(format!(
                "{label} ancestor {} is owned by uid:gid {}:{}, not root",
                ancestor.display(),
                metadata.uid,
                metadata.gid
            )));
        }
        if metadata.mode & 0o022 != 0 {
            return Err(AppError::security_state_unavailable(format!(
                "{label} ancestor {} is group- or world-writable (mode {:04o})",
                ancestor.display(),
                metadata.mode & 0o777
            )));
        }
        if metadata.mode & 0o005 != 0o005 {
            return Err(AppError::security_state_unavailable(format!(
                "{label} ancestor {} does not grant read/traverse access to the non-root service (mode {:04o}); root-only 0700 is refused",
                ancestor.display(),
                metadata.mode & 0o777
            )));
        }
        require_safe_acl(facts, ancestor, label)?;
    }
    Ok(())
}

fn validate_root_owned_file(
    facts: &dyn MacosServiceFacts,
    path: &Path,
    label: &str,
) -> AppResult<()> {
    let metadata = require_entry(facts, path, label)?;
    if metadata.is_symlink {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} is a symlink; refusing to follow it",
            path.display()
        )));
    }
    if !metadata.is_regular_file {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} is not a regular file",
            path.display()
        )));
    }
    if metadata.uid != 0 {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} is owned by uid:gid {}:{}, not root",
            path.display(),
            metadata.uid,
            metadata.gid
        )));
    }
    if metadata.nlink != 1 {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} has link count {}, not 1",
            path.display(),
            metadata.nlink
        )));
    }
    if metadata.mode & 0o022 != 0 {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} is group- or world-writable (mode {:04o})",
            path.display(),
            metadata.mode & 0o777
        )));
    }
    if metadata.mode & 0o004 == 0 {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} does not grant read access to the non-root service (mode {:04o}); root-only 0600 is refused",
            path.display(),
            metadata.mode & 0o777
        )));
    }
    require_safe_acl(facts, path, label)
}

fn validate_service_directory(
    facts: &dyn MacosServiceFacts,
    path: &Path,
    service_uid: u32,
    owner_only: bool,
    label: &str,
) -> AppResult<()> {
    let metadata = require_entry(facts, path, label)?;
    if metadata.is_symlink {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} is a symlink; refusing to follow it",
            path.display()
        )));
    }
    if !metadata.is_directory {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} is not a directory",
            path.display()
        )));
    }
    if metadata.uid != service_uid {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} is owned by uid:gid {}:{}, not by the {SERVICE_ACCOUNT} service account",
            path.display(),
            metadata.uid,
            metadata.gid
        )));
    }
    if metadata.mode & 0o022 != 0 {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} is group- or world-writable (mode {:04o})",
            path.display(),
            metadata.mode & 0o777
        )));
    }
    if owner_only {
        if metadata.mode & 0o077 != 0 {
            return Err(AppError::security_state_unavailable(format!(
                "{label} {} is not owner-private (expected 0700-class, mode {:04o})",
                path.display(),
                metadata.mode & 0o777
            )));
        }
        if metadata.mode & 0o700 != 0o700 {
            return Err(AppError::security_state_unavailable(format!(
                "{label} {} does not grant owner read/write/traverse access (expected 0700-class, mode {:04o})",
                path.display(),
                metadata.mode & 0o777
            )));
        }
    } else if metadata.mode & 0o500 != 0o500 {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} does not grant owner read/traverse access (mode {:04o})",
            path.display(),
            metadata.mode & 0o777
        )));
    }
    require_safe_acl(facts, path, label)
}

fn validate_service_private_file(
    facts: &dyn MacosServiceFacts,
    path: &Path,
    service_uid: u32,
    label: &str,
) -> AppResult<()> {
    let metadata = require_entry(facts, path, label)?;
    if metadata.is_symlink {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} is a symlink; refusing to follow it",
            path.display()
        )));
    }
    if !metadata.is_regular_file {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} is not a regular file",
            path.display()
        )));
    }
    if metadata.uid != service_uid {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} is owned by uid:gid {}:{}, not by the {SERVICE_ACCOUNT} service account",
            path.display(),
            metadata.uid,
            metadata.gid
        )));
    }
    if metadata.nlink != 1 {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} has link count {}, not 1",
            path.display(),
            metadata.nlink
        )));
    }
    if metadata.mode & 0o077 != 0 {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} is not owner-private (expected 0600-class, mode {:04o})",
            path.display(),
            metadata.mode & 0o777
        )));
    }
    if metadata.mode & 0o400 == 0 {
        return Err(AppError::security_state_unavailable(format!(
            "{label} {} does not grant owner read access (mode {:04o})",
            path.display(),
            metadata.mode & 0o777
        )));
    }
    require_safe_acl(facts, path, label)
}

fn require_entry(
    facts: &dyn MacosServiceFacts,
    path: &Path,
    label: &str,
) -> AppResult<ServicePathMetadata> {
    match facts.lstat(path) {
        Ok(Some(metadata)) => Ok(metadata),
        Ok(None) => Err(AppError::security_state_unavailable(format!(
            "{label} {} is absent; refusing to start from unverified state",
            path.display()
        ))),
        Err(error) => Err(AppError::security_state_unavailable(format!(
            "cannot inspect {label} {}: {}",
            path.display(),
            bounded_detail(&error)
        ))),
    }
}

fn require_safe_acl(facts: &dyn MacosServiceFacts, path: &Path, label: &str) -> AppResult<()> {
    match facts.extended_acl_is_safe(path) {
        Ok(true) => Ok(()),
        Ok(false) => Err(AppError::security_state_unavailable(format!(
            "{label} {} carries an extended ACL with an ALLOW entry; refusing to trust it",
            path.display()
        ))),
        Err(error) => Err(AppError::security_state_unavailable(format!(
            "cannot inspect the extended ACL for {label} {}: {}",
            path.display(),
            bounded_detail(&error)
        ))),
    }
}

fn bounded_detail(detail: &str) -> String {
    const MAX_DETAIL_CHARS: usize = 160;
    let mut bounded = String::new();
    for ch in detail.chars().take(MAX_DETAIL_CHARS) {
        bounded.push(if ch.is_control() { ' ' } else { ch });
    }
    bounded
}

/// JSON value that rejects duplicate object keys at every nesting depth.
///
/// `serde_json` otherwise keeps the last duplicate, which would let a reviewed
/// document disagree with the effective value. Duplicate keys are refused
/// before the typed configuration is built.
struct StrictJson(serde_json::Value);

impl StrictJson {
    fn into_value(self) -> serde_json::Value {
        self.0
    }
}

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictJson(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictJson(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictJson(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| serde::de::Error::custom("non-finite JSON number"))?;
        Ok(StrictJson(serde_json::Value::Number(number)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictJson(serde_json::Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictJson(serde_json::Value::String(value)))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictJson(serde_json::Value::Null))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictJson(serde_json::Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJson>()? {
            values.push(value.into_value());
        }
        Ok(StrictJson(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(serde::de::Error::custom(
                    "duplicate object key in service configuration",
                ));
            }
            let value = map.next_value::<StrictJson>()?;
            object.insert(key, value.into_value());
        }
        Ok(StrictJson(serde_json::Value::Object(object)))
    }
}

/// Fixed macOS service entry. It fails closed at the identity/ownership gate
/// before reading configuration, opening the store, or binding a listener
/// unless a verified root-owned install receipt proves this installer created
/// the exact service identity.
#[cfg(target_os = "macos")]
pub fn run() -> AppResult<()> {
    let facts = MacosSystemServiceFacts::new();
    // The durable receipt is the only accepted product-ownership evidence.
    // Absence fails as before; a present but invalid receipt fails closed.
    let ownership_verified = crate::installer::macos_apply::verify_runtime_receipt()?;
    authorize_service_identity_with_ownership(&facts, ownership_verified)?;
    // Match the existing Linux service contract (`UMask=0077`) so the SQLite
    // database and WAL/SHM sidecars are private even if the eventual launchd
    // plist omits its own umask key.
    set_private_process_umask();
    let config_bytes = system::read_root_owned_config()?;
    let plan = plan_reviewed_configuration(&facts, &config_bytes)?;

    tracing::info!(
        account = SERVICE_ACCOUNT,
        bind = %plan.bind_address,
        "macOS service configuration verified (loopback development router; not enrollment readiness)"
    );
    // Loopback keeps `tls::serve_blocking` on `crate::app`, the existing local
    // development/bootstrap router; it does not select the v2-only network
    // router or establish enrollment/production readiness.
    crate::tls::run_serve_tls_with_network_and_name(
        &plan.database_path,
        &plan.bind_address,
        &plan.certificate_path,
        &plan.private_key_path,
        false,
        Some(LOOPBACK_TLS_SERVER_NAME),
    )
}

/// Tighten the process file-creation mask to owner-only before the database or
/// any other service-owned file can be created.
#[cfg(target_os = "macos")]
fn set_private_process_umask() {
    // SAFETY: umask has no failure mode and only changes this process's
    // file-creation mask.
    let previous = unsafe { libc::umask(0o077) };
    if previous & 0o077 != 0 {
        tracing::info!(
            previous_umask = format!("{:04o}", previous & 0o777),
            "tightened the macOS service process umask to 0077"
        );
    }
}

/// On every non-macOS host the fixed service verb fails closed before reading
/// any path. The pure policy seam remains testable on other hosts.
#[cfg(not(target_os = "macos"))]
pub fn run() -> AppResult<()> {
    Err(AppError::not_implemented(
        "macOS service configuration and launch are available only on macOS",
    ))
}

// ---------------------------------------------------------------------------
// Production macOS facts and configuration reader
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub struct MacosSystemServiceFacts;

#[cfg(target_os = "macos")]
impl MacosSystemServiceFacts {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl Default for MacosSystemServiceFacts {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
impl MacosServiceFacts for MacosSystemServiceFacts {
    fn effective_uid(&self) -> Result<u32, String> {
        // SAFETY: geteuid has no preconditions and cannot fail.
        Ok(unsafe { libc::geteuid() })
    }

    fn real_uid(&self) -> Result<u32, String> {
        // SAFETY: getuid has no preconditions and cannot fail.
        Ok(unsafe { libc::getuid() })
    }

    fn account_name_for_uid(&self, uid: u32) -> Result<Option<String>, String> {
        let mut record: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buffer = [0u8; 4096];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: the record and buffer are valid for the call, and `result`
        // points to a local pointer the implementation may set.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut record,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if rc != 0 {
            return Err(format!("getpwuid_r failed with error {rc}"));
        }
        if result.is_null() {
            return Ok(None);
        }
        if record.pw_name.is_null() {
            return Err("the local account record has no name".to_string());
        }
        // SAFETY: a non-null `pw_name` from a successful getpwuid_r points to
        // a NUL-terminated string valid until the next lookup for this thread.
        let name = unsafe { std::ffi::CStr::from_ptr(record.pw_name) };
        let name = name
            .to_str()
            .map_err(|_| "the local account name is not valid UTF-8".to_string())?;
        Ok(Some(name.to_string()))
    }

    fn service_identity_decision(&self) -> ServiceIdentityDecision {
        crate::installer::macos_identity::observe_local_service_identity()
    }

    fn lstat(&self, path: &Path) -> Result<Option<ServicePathMetadata>, String> {
        use std::os::unix::fs::MetadataExt;

        match std::fs::symlink_metadata(path) {
            Ok(metadata) => Ok(Some(ServicePathMetadata {
                is_symlink: metadata.file_type().is_symlink(),
                is_directory: metadata.is_dir(),
                is_regular_file: metadata.is_file(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode(),
                nlink: metadata.nlink(),
            })),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("inspect '{}': {error}", path.display())),
        }
    }

    fn extended_acl_is_safe(&self, path: &Path) -> Result<bool, String> {
        use std::os::unix::ffi::OsStrExt;

        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "ACL path contains a NUL byte".to_string())?;
        // SAFETY: `c_path` is a valid NUL-terminated path, and the returned fd
        // is closed below on every path.
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK
                    | libc::O_NOCTTY,
            )
        };
        if fd < 0 {
            return Err(format!(
                "open '{}' for the extended ACL query: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let status = crate::private_file::query_extended_acl(fd);
        // SAFETY: `fd` was opened above and is not used after this close.
        unsafe { libc::close(fd) };
        match status {
            Ok(crate::private_file::AclStatus::Absent)
            | Ok(crate::private_file::AclStatus::DenyOnly) => Ok(true),
            Ok(crate::private_file::AclStatus::AllowPresent) => Ok(false),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[cfg(target_os = "macos")]
mod system {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path};

    use super::{
        bounded_detail, AppError, AppResult, MAX_SERVICE_CONFIG_BYTES, SERVICE_CONFIG_PATH,
    };

    pub(super) fn read_root_owned_config() -> AppResult<Vec<u8>> {
        read_root_owned_config_at(Path::new(SERVICE_CONFIG_PATH))
    }

    /// Read a bounded root-owned regular file through a held descriptor after
    /// walking every ancestor without following a symlink. The final file and
    /// all ancestors must be root-owned, not group/world-writable, and have no
    /// extended ACL ALLOW entry. The content is not a credential; it is still
    /// never echoed in diagnostics.
    pub(super) fn read_root_owned_config_at(path: &Path) -> AppResult<Vec<u8>> {
        if !path.is_absolute() {
            return Err(AppError::internal(
                "the service configuration path must be absolute",
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            AppError::internal("the service configuration path has no parent directory")
        })?;
        let file_name = path
            .file_name()
            .ok_or_else(|| AppError::internal("the service configuration path has no file name"))?;

        let directory = open_root_owned_directory(parent)?;
        let c_name = std::ffi::CString::new(file_name.as_bytes()).map_err(|_| {
            AppError::internal("the service configuration file name contains a NUL byte")
        })?;
        // SAFETY: `directory` is an open directory fd and `c_name` is a valid
        // single component. O_NOFOLLOW keeps a symlink from being followed.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK
                    | libc::O_NOCTTY,
            )
        };
        if fd < 0 {
            return Err(AppError::security_state_unavailable(format!(
                "cannot open the fixed service configuration file: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `fd` is a newly opened descriptor owned by this function.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };

        let metadata = file.metadata().map_err(|error| {
            AppError::security_state_unavailable(format!(
                "cannot inspect the fixed service configuration file: {}",
                bounded_detail(&error.to_string())
            ))
        })?;
        if !metadata.is_file() {
            return Err(AppError::security_state_unavailable(
                "the fixed service configuration path is not a regular file",
            ));
        }
        if metadata.uid() != 0 {
            return Err(AppError::security_state_unavailable(
                "the fixed service configuration file is not owned by root",
            ));
        }
        if metadata.nlink() != 1 {
            return Err(AppError::security_state_unavailable(
                "the fixed service configuration file does not have exactly one link",
            ));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(AppError::security_state_unavailable(
                "the fixed service configuration file is group- or world-writable",
            ));
        }
        if metadata.mode() & 0o004 == 0 {
            return Err(AppError::security_state_unavailable(
                "the fixed service configuration file does not grant read access to the non-root service; root-only 0600 is refused",
            ));
        }
        match crate::private_file::query_extended_acl(file.as_raw_fd()) {
            Ok(crate::private_file::AclStatus::Absent)
            | Ok(crate::private_file::AclStatus::DenyOnly) => {}
            Ok(crate::private_file::AclStatus::AllowPresent) => {
                return Err(AppError::security_state_unavailable(
                    "the fixed service configuration file carries an extended ACL with an ALLOW entry",
                ))
            }
            Err(error) => {
                return Err(AppError::security_state_unavailable(format!(
                    "cannot inspect the extended ACL for the fixed service configuration file: {}",
                    bounded_detail(&error.to_string())
                )))
            }
        }
        if metadata.len() > MAX_SERVICE_CONFIG_BYTES as u64 {
            return Err(AppError::bad_request(format!(
                "service configuration exceeds {MAX_SERVICE_CONFIG_BYTES} bytes"
            )));
        }

        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        let mut limited = file.take((MAX_SERVICE_CONFIG_BYTES as u64) + 1);
        limited.read_to_end(&mut bytes).map_err(|error| {
            AppError::security_state_unavailable(format!(
                "cannot read the fixed service configuration file: {}",
                bounded_detail(&error.to_string())
            ))
        })?;
        if bytes.len() > MAX_SERVICE_CONFIG_BYTES {
            return Err(AppError::bad_request(format!(
                "service configuration exceeds {MAX_SERVICE_CONFIG_BYTES} bytes"
            )));
        }
        if bytes.is_empty() {
            return Err(AppError::bad_request("service configuration is empty"));
        }
        Ok(bytes)
    }

    /// Walk from `/` to `path` with no symlink following. Each component must
    /// be a real directory owned by root, not group/world-writable, with no
    /// ACL ALLOW entry.
    fn open_root_owned_directory(path: &Path) -> AppResult<OwnedFd> {
        // SAFETY: `c"/"` is a valid NUL-terminated path.
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(AppError::security_state_unavailable(format!(
                "cannot open / while verifying the service configuration path: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `fd` is a newly opened descriptor owned by this function.
        let mut current = unsafe { OwnedFd::from_raw_fd(fd) };
        // Validate the traversal root itself before descending.
        validate_root_owned_directory(&current)?;

        for component in path.components() {
            let name = match component {
                Component::RootDir => continue,
                Component::Normal(name) => name,
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(AppError::security_state_unavailable(
                        "the fixed service configuration path contains a non-normal component",
                    ))
                }
            };
            let c_name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
                AppError::security_state_unavailable(
                    "a service configuration path component contains a NUL byte",
                )
            })?;
            // SAFETY: `current` is an open directory fd and `c_name` is one
            // valid component. O_NOFOLLOW refuses a symlink component.
            let next = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if next < 0 {
                return Err(AppError::security_state_unavailable(format!(
                    "cannot open a service configuration directory component without following links: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: `next` is a newly opened descriptor owned by this function.
            let next = unsafe { OwnedFd::from_raw_fd(next) };
            validate_root_owned_directory(&next)?;
            current = next;
        }
        Ok(current)
    }

    fn validate_root_owned_directory(directory: &OwnedFd) -> AppResult<()> {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `directory` is an open fd and `stat` is a valid output buffer.
        if unsafe { libc::fstat(directory.as_raw_fd(), &mut stat) } != 0 {
            return Err(AppError::security_state_unavailable(format!(
                "cannot inspect a service configuration directory: {}",
                std::io::Error::last_os_error()
            )));
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(AppError::security_state_unavailable(
                "a service configuration ancestor is not a directory",
            ));
        }
        if stat.st_uid != 0 {
            return Err(AppError::security_state_unavailable(
                "a service configuration ancestor is not owned by root",
            ));
        }
        if stat.st_mode & 0o022 != 0 {
            return Err(AppError::security_state_unavailable(
                "a service configuration ancestor is group- or world-writable",
            ));
        }
        if stat.st_mode & 0o005 != 0o005 {
            return Err(AppError::security_state_unavailable(
                "a service configuration ancestor does not grant read/traverse access to the non-root service; root-only 0700 is refused",
            ));
        }
        match crate::private_file::query_extended_acl(directory.as_raw_fd()) {
            Ok(crate::private_file::AclStatus::Absent)
            | Ok(crate::private_file::AclStatus::DenyOnly) => Ok(()),
            Ok(crate::private_file::AclStatus::AllowPresent) => {
                Err(AppError::security_state_unavailable(
                    "a service configuration ancestor carries an extended ACL with an ALLOW entry",
                ))
            }
            Err(error) => Err(AppError::security_state_unavailable(format!(
                "cannot inspect the extended ACL for a service configuration ancestor: {}",
                bounded_detail(&error.to_string())
            ))),
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn system_facts_resolve_the_current_identity() {
        let facts = MacosSystemServiceFacts::new();
        let effective_uid = facts.effective_uid().expect("effective uid");
        assert_eq!(facts.real_uid().expect("real uid"), effective_uid);
        let account = facts
            .account_name_for_uid(effective_uid)
            .expect("account lookup");
        assert!(
            account.is_some_and(|name| !name.is_empty()),
            "the current uid must resolve to a non-empty local account"
        );
    }

    #[test]
    fn system_facts_observe_a_disposable_directory_without_mutation() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().canonicalize().expect("canonicalize");
        let facts = MacosSystemServiceFacts::new();
        let metadata = facts
            .lstat(&path)
            .expect("lstat")
            .expect("the fixture directory exists");
        assert!(metadata.is_directory);
        assert!(!metadata.is_symlink);
        assert!(facts
            .extended_acl_is_safe(&path)
            .expect("ACL query on a disposable directory"));
    }

    #[test]
    fn system_configuration_reader_rejects_non_root_owned_file_without_mutation() {
        let directory = tempfile::tempdir().expect("tempdir");
        let directory = directory.path().canonicalize().expect("canonicalize");
        let path = directory.join("service.json");
        std::fs::write(&path, b"{}").expect("write fixture");
        let error = system::read_root_owned_config_at(&path).expect_err("must refuse");
        assert_eq!(
            error.code(),
            crate::error::ErrorCode::SecurityStateUnavailable
        );
        assert_eq!(std::fs::read(&path).expect("reread fixture"), b"{}");
    }
}
