//! Read-only macOS launchd preflight adapter.
//!
//! This module deliberately defines **no** wire contract. It observes the local
//! Mac and emits the existing installer v2 types:
//! [`lifecycle_v2::PreflightResult`] wrapping [`models::PreflightChecks`].
//!
//! Ownership values come from the Manager's current
//! `LocalHostingOwnershipPlan.current` and the fixed product layout:
//!
//! - product root `/Library/Application Support/Helicoid`;
//! - data path `/Library/Application Support/Helicoid/Data`;
//! - executable `/Library/Application Support/Helicoid/bin/hs-server`;
//! - configuration `/Library/Application Support/Helicoid/Configuration/service.json`;
//! - TLS material under `/Library/Application Support/Helicoid/TLS`;
//! - label `com.helicoid.server`;
//! - plist `/Library/LaunchDaemons/com.helicoid.server.plist`.
//!
//! The authority port is supplied by the reviewed v2 configuration; the
//! Manager default is 8920. The backup destination is a caller-selected v2
//! configuration value, not a product-owned constant.
//!
//! What this module does:
//!
//! - reads fixed facts with bounded, shell-free commands;
//! - maps them into `v2::PreflightResult` / `models::PreflightChecks`;
//! - exposes the fixed reviewed paths used by the read-only plan builder in
//!   [`super::machine::plan_v2_macos`];
//! - reports pending lifecycle gaps as failed checks or an unavailable
//!   capability document.
//!
//! What this module does not do:
//!
//! - install, apply, cancel, remove, or load a launchd job;
//! - create files, directories, accounts, or plists;
//! - claim service, bootstrap, enrollment, deployment, or installed readiness;
//! - accept a path based on mode bits alone. Any existing product, data,
//!   plist, or caller-selected backup path is a conflict regardless of its
//!   ACLs; no path is adopted or claimed as product-owned.
//!
//! A read-only review plan may be generated from this preflight and a verified
//! package by [`super::machine::plan_v2_macos`]. That plan is a review artifact
//! only: it does not create the `_helicoid` account or group, write a plist, or
//! apply changes. The separate [`super::macos_apply`] module owns the guarded
//! apply; the development-only `macos-dev-install` feature enables its
//! build-pinned install path and capability advertisement. A fresh-install
//! plan requires both the account and group to be absent; an existing group
//! with an absent account is not a fresh identity.
//!
//! Every existing ancestor of every reviewed path must be a non-symlink
//! directory owned by uid 0 with no group- or world-write permission and no
//! extended ACL ALLOW entry. ACL absence and deny-only ACLs are accepted;
//! an ACL query failure is unverified and fails the check. An absent ancestor
//! or an unreadable path is also unverified. The one exception is the reviewed
//! product root when checking the data path: it is checked separately and
//! created before the data directory. Symlink ancestors are refused with a
//! diagnostic and are never resolved. On a default macOS host `/tmp` and `/var`
//! are commonly symlinks to `/private/tmp` and `/private/var`; resolving to
//! `/private/...` does not make a group/world-writable directory acceptable.
//! Use another reviewed, root-owned directory rather than weakening the
//! symlink or write-permission checks. Caller-selected backup components must be
//! ASCII; non-ASCII names are refused conservatively to avoid macOS filesystem
//! normalization aliasing.
//!
//! Loopback HTTP is development-only. `PreflightResult::ok` means only that
//! these host checks passed; it never means enrollment or deployment readiness.
//!
//! Port observations are authorization-sensitive. A non-elevated preflight
//! cannot inspect system-owned listeners: it reports `ok: false`,
//! `occupied: false`, and a `query error (unverified)` annotation. That is an
//! unverified result, never evidence that the port is free; an authorized
//! observation (or explicit authorization for the check) is required before
//! treating the port as available.
//!
//! The generic `machine::preflight_v2` entry point remains Linux-only. The
//! macOS entry point, `machine::preflight_v2_macos`, delegates here and returns
//! this module's narrowed capability document. The separate, read-only
//! `machine::plan_v2_macos` entry point re-runs this preflight, derives the
//! frozen package target from the observed architecture, refuses an unverified
//! or non-fresh service identity, and only then verifies the signed package.
//! Apply, status, cancellation, removal, account creation, and readiness still
//! require lifecycle work outside this read-only adapter. The tests prove that
//! boundary instead of claiming integration.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use crate::error::{AppError, AppResult};

use super::lifecycle_v2 as v2;
use super::models::{
    CheckResult, ExistingInstallCheck, PathCheck, PathsCheck, PortConflict, PortListener,
    PortsCheck, PreflightChecks, PreflightResult as HostPreflightResult, PrivilegesCheck,
    ServicesCheck, StorageCheck,
};

/// Manager-owned product root from `LocalHostingOwnershipPlan.current`.
pub const PRODUCT_ROOT_PATH: &str = "/Library/Application Support/Helicoid";
/// Manager-owned data path from `LocalHostingOwnershipPlan.current`.
pub const DATA_PATH: &str = "/Library/Application Support/Helicoid/Data";
/// Manager-owned launchd label from `LocalHostingOwnershipPlan.current`.
pub const LAUNCHD_LABEL: &str = "com.helicoid.server";
/// Manager-owned LaunchDaemon plist path from `LocalHostingOwnershipPlan.current`.
pub const LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/com.helicoid.server.plist";
/// Root-owned executable directory beneath the product root.
pub const EXECUTABLE_DIRECTORY: &str = "/Library/Application Support/Helicoid/bin";
/// Fixed installed `hs-server` executable path used by the reviewed plan.
pub const EXECUTABLE_PATH: &str = "/Library/Application Support/Helicoid/bin/hs-server";
/// Root-owned configuration directory reviewed by the service runtime.
pub const CONFIGURATION_DIRECTORY: &str = "/Library/Application Support/Helicoid/Configuration";
/// Fixed service configuration document reviewed by the service runtime.
pub const CONFIGURATION_PATH: &str =
    "/Library/Application Support/Helicoid/Configuration/service.json";
/// Fixed TLS directory owned by the dedicated service account.
pub const TLS_DIRECTORY: &str = "/Library/Application Support/Helicoid/TLS";
/// Fixed certificate-chain path reviewed by the service runtime.
pub const TLS_CERTIFICATE_PATH: &str = "/Library/Application Support/Helicoid/TLS/fullchain.pem";
/// Fixed private-key path reviewed by the service runtime.
pub const TLS_PRIVATE_KEY_PATH: &str = "/Library/Application Support/Helicoid/TLS/private-key.pem";
/// Operator-provided TLS source directory for macOS apply.
pub const TLS_SOURCE_DIRECTORY: &str = "/etc/helicoid/tls";
/// Operator-provided certificate-chain source for macOS apply.
pub const TLS_SOURCE_CERTIFICATE_PATH: &str = "/etc/helicoid/tls/fullchain.pem";
/// Operator-provided private-key source for macOS apply.
pub const TLS_SOURCE_PRIVATE_KEY_PATH: &str = "/etc/helicoid/tls/private-key.pem";
/// Manager default authority port. The actual port comes from the v2 request.
pub const DEFAULT_AUTHORITY_PORT: u16 = 8920;

/// Manager disk-space floor (2 GiB) used by local host checks.
pub const MIN_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

const MAX_OBSERVATION_BYTES: usize = 64 * 1024;
const MAX_OBSERVATION_LINES: usize = 256;

/// Closed set of read-only observations. Each maps to one fixed absolute argv;
/// the only variable is the caller-selected TCP port, which is a separate argv
/// element and is never concatenated into a shell command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LaunchdQuery {
    EffectiveUid,
    OperatingSystemVersion,
    LocalArchitecture,
    LaunchdJobPresence,
    TcpPortListeners { port: u16 },
}

impl LaunchdQuery {
    pub fn name(self) -> String {
        match self {
            LaunchdQuery::EffectiveUid => "effective_uid".to_string(),
            LaunchdQuery::OperatingSystemVersion => "operating_system_version".to_string(),
            LaunchdQuery::LocalArchitecture => "local_architecture".to_string(),
            LaunchdQuery::LaunchdJobPresence => "launchd_job_presence".to_string(),
            LaunchdQuery::TcpPortListeners { port } => format!("tcp_port_listeners:{port}"),
        }
    }

    /// Fixed argv for this observation. The first element is absolute; the
    /// remainder are fixed literals plus the validated numeric port.
    pub fn reviewed_argv(self) -> Vec<String> {
        match self {
            LaunchdQuery::EffectiveUid => vec!["/usr/bin/id".to_string(), "-u".to_string()],
            LaunchdQuery::OperatingSystemVersion => {
                vec![
                    "/usr/bin/sw_vers".to_string(),
                    "-productVersion".to_string(),
                ]
            }
            LaunchdQuery::LocalArchitecture => {
                vec!["/usr/bin/uname".to_string(), "-m".to_string()]
            }
            LaunchdQuery::LaunchdJobPresence => vec![
                "/bin/launchctl".to_string(),
                "print".to_string(),
                format!("system/{LAUNCHD_LABEL}"),
            ],
            LaunchdQuery::TcpPortListeners { port } => vec![
                "/usr/sbin/lsof".to_string(),
                "-nP".to_string(),
                format!("-iTCP:{port}"),
                "-sTCP:LISTEN".to_string(),
                "-Fpc".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandObservation {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandObservation {
    pub fn success(stdout: impl Into<String>) -> Self {
        Self {
            exit_code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    pub fn failure(exit_code: i32, stderr: impl Into<String>) -> Self {
        Self {
            exit_code,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

/// Metadata used to reject unsafe path ancestors. Extended ACLs are queried
/// separately; an existing reviewed path remains a conflict regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathMetadata {
    pub is_symlink: bool,
    pub is_directory: bool,
    pub uid: u32,
    pub gid: u32,
    /// Raw `st_mode`, including file-type bits. Permission checks mask it.
    pub mode: u32,
}

/// Injectable read-only host seam. Tests use disposable fixtures; production
/// uses [`MacosSystemObserver`] on macOS.
pub trait MacosLaunchdObserver: Send + Sync {
    fn observe(&self, query: LaunchdQuery) -> Result<CommandObservation, String>;
    fn lstat(&self, path: &Path) -> Result<Option<PathMetadata>, String>;
    /// True only when the path has no extended ACL or only DENY entries.
    /// Any ALLOW entry, unsupported filesystem, or query error must be
    /// returned as an error or `false`; mode bits alone are not sufficient.
    fn extended_acl_is_safe(&self, path: &Path) -> Result<bool, String>;
    /// Total and available bytes for the nearest existing ancestor.
    fn storage(&self, path: &Path) -> Result<(u64, u64), String>;
}

fn validate_observation(observation: &CommandObservation) -> Result<(), String> {
    for (stream, value) in [
        ("stdout", &observation.stdout),
        ("stderr", &observation.stderr),
    ] {
        if value.len() > MAX_OBSERVATION_BYTES {
            return Err(format!(
                "{stream} exceeds the {MAX_OBSERVATION_BYTES}-byte observation bound"
            ));
        }
        if value.lines().count() > MAX_OBSERVATION_LINES {
            return Err(format!(
                "{stream} exceeds the {MAX_OBSERVATION_LINES}-line observation bound"
            ));
        }
        if value.as_bytes().contains(&0) {
            return Err(format!("{stream} contains a NUL byte"));
        }
    }
    Ok(())
}

fn first_line(value: &str) -> String {
    value
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .take(160)
        .collect()
}

fn parse_u32_field(value: &str, field: &str) -> Result<u32, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{field} observation was empty"));
    }
    if value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{field} observation was not a decimal integer"));
    }
    value
        .parse::<u32>()
        .map_err(|_| format!("{field} observation was outside the u32 range"))
}

fn require_success(observation: &CommandObservation, field: &str) -> Result<(), String> {
    validate_observation(observation)?;
    if observation.exit_code != 0 {
        return Err(format!(
            "{field} observation failed with exit {}: {}",
            observation.exit_code,
            first_line(&observation.stderr)
        ));
    }
    Ok(())
}

pub fn parse_effective_uid(observation: &CommandObservation) -> Result<u32, String> {
    require_success(observation, "effective uid")?;
    parse_u32_field(&observation.stdout, "effective uid")
}

/// Strict macOS product version such as `15.6.1` or `26.0`.
pub fn parse_operating_system_version(observation: &CommandObservation) -> Result<String, String> {
    require_success(observation, "macOS version")?;
    let value = observation.stdout.trim();
    if value.is_empty() || value.len() > 32 || !value.is_ascii() || value.lines().count() != 1 {
        return Err("macOS version observation was malformed".to_string());
    }
    let components: Vec<&str> = value.split('.').collect();
    if !(2..=3).contains(&components.len())
        || components.iter().any(|component| {
            component.is_empty()
                || component.len() > 4
                || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err("macOS version observation was not major.minor[.patch]".to_string());
    }
    Ok(value.to_string())
}

pub fn macos_major_version(version: &str) -> Option<u32> {
    version.split('.').next()?.parse().ok()
}

pub fn parse_local_architecture(observation: &CommandObservation) -> Result<String, String> {
    require_success(observation, "local architecture")?;
    let value = observation.stdout.trim();
    if value.is_empty()
        || value.len() > 32
        || value.lines().count() != 1
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("local architecture observation was malformed".to_string());
    }
    Ok(value.to_string())
}

/// `launchctl print` succeeds when the job is loaded. A nonzero exit is only
/// "not loaded" with launchd's explicit not-found diagnostic; anything else is
/// an unknown state and must not be treated as free.
///
/// The observation bound is checked before the exit-0 fast path. Oversized or
/// excessively long successful output is rejected rather than accepted as a
/// loaded job from an unbounded observation.
pub fn parse_launchd_job_presence(observation: &CommandObservation) -> Result<bool, String> {
    validate_observation(observation)?;
    if observation.exit_code == 0 {
        return Ok(true);
    }
    let diagnostic = format!("{}\n{}", observation.stdout, observation.stderr).to_ascii_lowercase();
    if diagnostic.contains("could not find service") || diagnostic.contains("could not find domain")
    {
        return Ok(false);
    }
    Err(format!(
        "launchd job state is unavailable (exit {}): {}",
        observation.exit_code,
        first_line(&observation.stderr)
    ))
}

/// `lsof` exit 1 means "no matching listeners" only when both streams are
/// silent. Any diagnostic makes the port state unknown; it is never free.
pub fn parse_tcp_port_listeners(observation: &CommandObservation) -> Result<Vec<String>, String> {
    validate_observation(observation)?;
    match observation.exit_code {
        1 => {
            if observation.stdout.trim().is_empty() && observation.stderr.trim().is_empty() {
                return Ok(Vec::new());
            }
            return Err(format!(
                "authority port state is unavailable (exit 1): {}",
                first_line(&observation.stderr)
            ));
        }
        0 => {}
        code => {
            return Err(format!(
                "authority port state is unavailable (exit {code}): {}",
                first_line(&observation.stderr)
            ))
        }
    }

    let mut listeners = Vec::new();
    let mut current_pid: Option<u32> = None;
    let mut current_command: Option<String> = None;

    fn flush_listener(pid: Option<u32>, command: Option<String>, out: &mut Vec<String>) {
        if let Some(pid) = pid {
            let name = command.unwrap_or_else(|| "unknown".to_string());
            out.push(format!("{name} (pid {pid})"));
        }
    }

    for raw in observation.stdout.lines() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let mut characters = line.chars();
        let Some(tag) = characters.next() else {
            continue;
        };
        let value = characters.as_str();
        match tag {
            'p' => {
                flush_listener(current_pid.take(), current_command.take(), &mut listeners);
                current_pid = Some(parse_u32_field(value, "lsof process id")?);
            }
            'c' => {
                if current_pid.is_none() {
                    return Err("lsof command record appeared before a process record".to_string());
                }
                if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
                    return Err("lsof command record was empty or malformed".to_string());
                }
                current_command = Some(value.to_string());
            }
            'f' => {
                // Real lsof with `-Fpc` can include file-descriptor records.
                // They do not identify the process and are safe to ignore,
                // but a descriptor without a process is malformed.
                if current_pid.is_none() {
                    return Err("lsof file record appeared before a process record".to_string());
                }
            }
            _ => return Err("lsof returned an unexpected field".to_string()),
        }
    }
    flush_listener(current_pid, current_command, &mut listeners);

    if listeners.is_empty() {
        return Err("lsof reported a listener but no process records".to_string());
    }
    Ok(listeners)
}

fn query(
    observer: &dyn MacosLaunchdObserver,
    query: LaunchdQuery,
) -> Result<CommandObservation, String> {
    observer
        .observe(query)
        .map_err(|error| format!("{} observation failed: {error}", query.name()))
}

struct ObservedHost {
    effective_uid: u32,
    os_version: String,
    architecture: String,
    launchd_job_loaded: bool,
}

fn observe_host(observer: &dyn MacosLaunchdObserver) -> Result<ObservedHost, String> {
    let effective_uid = parse_effective_uid(&query(observer, LaunchdQuery::EffectiveUid)?)?;
    let os_version =
        parse_operating_system_version(&query(observer, LaunchdQuery::OperatingSystemVersion)?)?;
    let architecture =
        parse_local_architecture(&query(observer, LaunchdQuery::LocalArchitecture)?)?;
    let launchd_job_loaded =
        parse_launchd_job_presence(&query(observer, LaunchdQuery::LaunchdJobPresence)?)?;
    Ok(ObservedHost {
        effective_uid,
        os_version,
        architecture,
        launchd_job_loaded,
    })
}

fn validate_contract_version(version: u32) -> AppResult<()> {
    if version != v2::CONTRACT_VERSION {
        return Err(AppError::bad_request(format!(
            "unsupported installer preflight contract_version: {version} (expected {})",
            v2::CONTRACT_VERSION
        )));
    }
    Ok(())
}

fn validate_normalized_absolute_path(path: &str, label: &str) -> AppResult<()> {
    if path.is_empty()
        || path.len() > 512
        || !path.starts_with('/')
        || path.ends_with('/')
        || path.contains("//")
        || path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
        || path
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(AppError::bad_request(format!(
            "{label} directory must be a normalized absolute path"
        )));
    }
    Ok(())
}

fn component_eq_case_insensitive(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
        || left.to_lowercase() == right.to_lowercase()
        || left.to_uppercase() == right.to_uppercase()
}

fn path_components_case_insensitive(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

/// Conservative component-wise overlap test for the default case-insensitive
/// macOS filesystem. A path overlap is refused if either path is a prefix of
/// the other after simple Unicode case folding. This may refuse a path that a
/// case-sensitive volume would allow; that is intentional.
fn paths_overlap_case_insensitive(left: &Path, right: &Path) -> bool {
    let left = path_components_case_insensitive(left);
    let right = path_components_case_insensitive(right);
    if left.is_empty() || right.is_empty() {
        return false;
    }
    let common = left.len().min(right.len());
    left.iter()
        .take(common)
        .zip(right.iter())
        .all(|(left, right)| component_eq_case_insensitive(left, right))
}

pub(crate) fn validate_macos_configuration(
    configuration: &v2::DeploymentConfiguration,
) -> AppResult<()> {
    if configuration.deployment_kind != v2::DeploymentKind::MacosLaunchd {
        return Err(AppError::not_implemented(
            "this adapter observes only the macOS launchd deployment",
        ));
    }
    if configuration.network.scope != v2::NetworkScope::LoopbackDevelopment {
        return Err(AppError::not_implemented(
            "only the loopback development network scope is supported by this read-only adapter",
        ));
    }
    if configuration.network.bind_address.is_some()
        || configuration.network.client_hostname.is_some()
    {
        return Err(AppError::bad_request(
            "loopback development must not carry bind_address or client_hostname",
        ));
    }
    if !(1024..=u16::MAX).contains(&configuration.network.authority_port) {
        return Err(AppError::bad_request(
            "authority_port must be an unprivileged port",
        ));
    }
    if configuration.storage.data_directory != DATA_PATH {
        return Err(AppError::bad_request(format!(
            "data_directory must be the Manager-owned path {DATA_PATH}"
        )));
    }
    validate_normalized_absolute_path(&configuration.storage.backup_directory, "backup")?;
    if !configuration.storage.backup_directory.is_ascii() {
        return Err(AppError::bad_request(
            "backup directory must use ASCII components; non-ASCII names are refused conservatively to avoid macOS filesystem normalization aliasing",
        ));
    }
    let backup = Path::new(&configuration.storage.backup_directory);
    let product_root = Path::new(PRODUCT_ROOT_PATH);
    let data = Path::new(DATA_PATH);
    let plist = Path::new(LAUNCHD_PLIST_PATH);
    let plist_parent = plist
        .parent()
        .ok_or_else(|| AppError::internal("launchd plist path has no parent"))?;
    if paths_overlap_case_insensitive(backup, product_root)
        || paths_overlap_case_insensitive(backup, data)
        || paths_overlap_case_insensitive(backup, plist)
        || paths_overlap_case_insensitive(backup, plist_parent)
    {
        return Err(AppError::bad_request(
            "backup directory must not overlap or contain the product, data, plist, or LaunchDaemons paths (case-insensitive comparison)",
        ));
    }
    Ok(())
}

fn check_os(version: &str) -> CheckResult {
    let ok = macos_major_version(version).is_some_and(|major| major >= 15);
    CheckResult {
        ok,
        value: "macos".to_string(),
        version: Some(version.to_string()),
        reason: (!ok).then(|| format!("macOS {version} is unsupported; require macOS 15 or newer")),
    }
}

fn check_arch(architecture: &str) -> CheckResult {
    let ok = matches!(architecture, "arm64" | "x86_64");
    CheckResult {
        ok,
        value: architecture.to_string(),
        version: None,
        reason: (!ok)
            .then(|| format!("unsupported architecture '{architecture}'; require arm64 or x86_64")),
    }
}

fn check_privileges(effective_uid: u32) -> PrivilegesCheck {
    PrivilegesCheck {
        ok: effective_uid == 0,
        is_root: effective_uid == 0,
        reason: (effective_uid != 0).then(|| {
            "macOS installer preflight must run with root authorization (euid 0); administrator-group access alone is not sufficient".to_string()
        }),
    }
}

fn check_storage(observer: &dyn MacosLaunchdObserver, data_path: &str) -> StorageCheck {
    match observer.storage(Path::new(data_path)) {
        Ok((total, available)) => {
            let ok = available >= MIN_FREE_BYTES;
            StorageCheck {
                ok,
                total_bytes: total,
                available_bytes: available,
                min_required_bytes: MIN_FREE_BYTES,
                reason: (!ok).then(|| {
                    format!(
                        "insufficient storage: {available} bytes available, {MIN_FREE_BYTES} required"
                    )
                }),
            }
        }
        Err(error) => StorageCheck {
            ok: false,
            total_bytes: 0,
            available_bytes: 0,
            min_required_bytes: MIN_FREE_BYTES,
            reason: Some(format!("cannot query storage: {error}")),
        },
    }
}

fn inspect_ancestors(
    observer: &dyn MacosLaunchdObserver,
    path: &Path,
    allowed_absent: Option<&Path>,
) -> Option<String> {
    for ancestor in path.ancestors().skip(1) {
        match observer.lstat(ancestor) {
            // The product root is reviewed separately and is created before
            // its data directory, so its absence is not an unverified parent.
            Ok(None) if Some(ancestor) == allowed_absent => {}
            Ok(None) => {
                return Some(format!(
                    "path ancestor {} does not exist; refusing to treat an unverified path as clean",
                    ancestor.display()
                ));
            }
            Ok(Some(metadata)) if metadata.is_symlink => {
                return Some(format!(
                    "path ancestor {} is a symlink; refusing to follow it",
                    ancestor.display()
                ));
            }
            Ok(Some(metadata)) if !metadata.is_directory => {
                return Some(format!(
                    "path ancestor {} is not a directory",
                    ancestor.display()
                ));
            }
            Ok(Some(metadata)) if metadata.uid != 0 => {
                return Some(format!(
                    "path ancestor {} is owned by uid:gid {}:{}, not root",
                    ancestor.display(),
                    metadata.uid,
                    metadata.gid
                ));
            }
            Ok(Some(metadata)) if metadata.mode & 0o022 != 0 => {
                return Some(format!(
                    "path ancestor {} is group- or world-writable (mode {:04o}); refusing to trust it",
                    ancestor.display(),
                    metadata.mode & 0o777
                ));
            }
            Ok(Some(_)) => match observer.extended_acl_is_safe(ancestor) {
                Ok(true) => {}
                Ok(false) => {
                    return Some(format!(
                        "path ancestor {} carries an extended ACL with an ALLOW entry; refusing to trust it",
                        ancestor.display()
                    ));
                }
                Err(error) => {
                    return Some(format!(
                        "cannot inspect extended ACL for path ancestor {}: {error}; refusing to trust it",
                        ancestor.display()
                    ));
                }
            },
            Err(error) => {
                return Some(format!(
                    "cannot inspect path ancestor {}: {error}",
                    ancestor.display()
                ));
            }
        }
    }
    None
}

fn check_paths(
    observer: &dyn MacosLaunchdObserver,
    configuration: &v2::DeploymentConfiguration,
) -> PathsCheck {
    let mut checked: Vec<PathCheck> = Vec::new();
    for path in [
        PRODUCT_ROOT_PATH,
        DATA_PATH,
        LAUNCHD_PLIST_PATH,
        configuration.storage.backup_directory.as_str(),
    ] {
        if checked.iter().any(|check| check.path == path) {
            continue;
        }
        let allowed_absent = (path == DATA_PATH).then(|| Path::new(PRODUCT_ROOT_PATH));
        if let Some(reason) = inspect_ancestors(observer, Path::new(path), allowed_absent) {
            checked.push(PathCheck {
                path: path.to_string(),
                exists: false,
                owned_by_us: false,
                reason: Some(reason),
            });
            continue;
        }
        let check = match observer.lstat(Path::new(path)) {
            Ok(None) => PathCheck {
                path: path.to_string(),
                exists: false,
                owned_by_us: false,
                reason: None,
            },
            Ok(Some(metadata)) if metadata.is_symlink => PathCheck {
                path: path.to_string(),
                exists: true,
                owned_by_us: false,
                reason: Some("path is a symlink".to_string()),
            },
            Ok(Some(_)) => PathCheck {
                path: path.to_string(),
                exists: true,
                owned_by_us: false,
                reason: Some(
                    "path already exists; a fresh install refuses to adopt it and macOS ACLs were not inspected"
                        .to_string(),
                ),
            },
            Err(error) => PathCheck {
                path: path.to_string(),
                exists: false,
                owned_by_us: false,
                reason: Some(format!("cannot inspect path: {error}")),
            },
        };
        checked.push(check);
    }

    let ok = checked
        .iter()
        .all(|check| !check.exists && check.reason.is_none());
    PathsCheck { ok, checked }
}

fn check_services(launchd_job_loaded: bool, paths: &PathsCheck) -> ServicesCheck {
    let mut conflicts = Vec::new();
    if launchd_job_loaded {
        conflicts.push(format!("launchd job {LAUNCHD_LABEL} is already loaded"));
    }
    let plist_conflict = paths
        .checked
        .iter()
        .find(|check| check.path == LAUNCHD_PLIST_PATH)
        .is_some_and(|check| check.exists || check.reason.is_some());
    if plist_conflict {
        conflicts.push(format!(
            "launchd plist {LAUNCHD_PLIST_PATH} is present or uninspectable"
        ));
    }
    ServicesCheck {
        ok: conflicts.is_empty(),
        existing_units: if conflicts.is_empty() {
            Vec::new()
        } else {
            vec![LAUNCHD_LABEL.to_string()]
        },
        conflicts,
    }
}

/// Check the selected TCP authority port.
///
/// Non-root callers cannot see system-owned listeners, so the result is marked
/// unverified and `ok: false`; it must never be interpreted as a free port.
fn check_ports(observer: &dyn MacosLaunchdObserver, port: u16, effective_uid: u32) -> PortsCheck {
    if effective_uid != 0 {
        return ports_query_error(
            port,
            "administrator access is required to inspect system-owned listeners",
        );
    }

    let observation = match observer.observe(LaunchdQuery::TcpPortListeners { port }) {
        Ok(observation) => observation,
        Err(error) => return ports_query_error(port, &error.to_string()),
    };
    let processes = match parse_tcp_port_listeners(&observation) {
        Ok(processes) => processes,
        Err(error) => return ports_query_error(port, &error),
    };

    if processes.is_empty() {
        return PortsCheck {
            ok: true,
            listeners: vec![PortListener {
                port,
                protocol: "tcp".to_string(),
                occupied: false,
                process: None,
            }],
            conflicts: Vec::new(),
        };
    }

    let conflicts: Vec<PortConflict> = processes
        .iter()
        .map(|process| PortConflict {
            port,
            protocol: "tcp".to_string(),
            process: process.clone(),
        })
        .collect();
    let listeners = processes
        .into_iter()
        .map(|process| PortListener {
            port,
            protocol: "tcp".to_string(),
            occupied: true,
            process: Some(process),
        })
        .collect();
    PortsCheck {
        ok: false,
        listeners,
        conflicts,
    }
}

fn ports_query_error(port: u16, detail: &str) -> PortsCheck {
    PortsCheck {
        ok: false,
        listeners: vec![PortListener {
            port,
            protocol: "tcp".to_string(),
            // No listener was observed. `ok: false` carries the failure; the
            // listener must not fabricate an occupation claim.
            occupied: false,
            process: Some(format!("query error (unverified): {detail}")),
        }],
        conflicts: Vec::new(),
    }
}

fn check_existing_install(paths: &PathsCheck, launchd_job_loaded: bool) -> ExistingInstallCheck {
    let detected = launchd_job_loaded
        || paths.checked.iter().any(|check| {
            (check.exists || check.reason.is_some())
                && matches!(
                    check.path.as_str(),
                    PRODUCT_ROOT_PATH | DATA_PATH | LAUNCHD_PLIST_PATH
                )
        });
    ExistingInstallCheck {
        detected,
        version: None,
        state: detected.then(|| "existing product resources detected".to_string()),
    }
}

/// Capability document derived from the existing v2 report, narrowed to what
/// this adapter actually provides. Install is limited to a fresh fixed-path
/// identity and never claims service readiness or enrollment.
pub fn capabilities_v2() -> v2::LifecycleCapabilities {
    let mut reasons_unavailable = BTreeMap::new();
    #[cfg(feature = "macos-dev-install")]
    let macos_reason = "macOS install is enabled only by the development-only macos-dev-install compile feature with a build-pinned CI key; production signing/notarization, installed production acceptance, updates, backup, restore, and removal remain unavailable";
    #[cfg(not(feature = "macos-dev-install"))]
    let macos_reason = "macOS install capability is gated off: no independently trusted release root and no installed-service acceptance exist; plan review remains available, and readiness, enrollment, updates, backup, restore, and removal are not implemented";
    reasons_unavailable.insert("macos_launchd".to_string(), macos_reason.to_string());
    reasons_unavailable.insert(
        "enrollment_readiness".to_string(),
        "loopback HTTPS is development-only; apply bootstraps launchd and verifies loopback TLS health but does not establish enrollment or deployment readiness"
            .to_string(),
    );

    #[cfg(feature = "macos-dev-install")]
    let supported_actions = vec![
        v2::LifecycleAction::Preflight,
        v2::LifecycleAction::Plan,
        v2::LifecycleAction::Install,
        v2::LifecycleAction::Cancel,
        v2::LifecycleAction::Inspect,
    ];
    #[cfg(not(feature = "macos-dev-install"))]
    let supported_actions = vec![v2::LifecycleAction::Preflight, v2::LifecycleAction::Plan];

    v2::LifecycleCapabilities {
        contract_version: v2::CONTRACT_VERSION,
        supported_deployment_kinds: vec![v2::DeploymentKind::MacosLaunchd],
        supported_network_scopes: vec![v2::NetworkScope::LoopbackDevelopment],
        supported_actions,
        custom_storage_directories: false,
        durable_operation_journal: cfg!(feature = "macos-dev-install"),
        cancellation: cfg!(feature = "macos-dev-install"),
        online_update: false,
        backup_and_restore: false,
        public_edge_integration: false,
        reasons_unavailable,
    }
}

/// Read-only macOS host preflight that emits the existing installer v2
/// contract. It does not generate a plan by itself, install anything, or claim
/// readiness.
///
/// The v2 lifecycle entry point (`machine::preflight_v2`) still rejects macOS;
/// this function is called by `machine::preflight_v2_macos` and by the separate
/// read-only `machine::plan_v2_macos` re-observation path. The tests prove that
/// boundary explicitly.
pub fn preflight_v2(
    observer: &dyn MacosLaunchdObserver,
    input: &v2::PreflightInput,
) -> AppResult<v2::PreflightResult> {
    validate_contract_version(input.contract_version)?;
    validate_macos_configuration(&input.configuration)?;

    let observed = observe_host(observer).map_err(|error| {
        AppError::security_state_unavailable(format!(
            "cannot verify macOS launchd host state: {error}"
        ))
    })?;

    let paths = check_paths(observer, &input.configuration);
    let ports = check_ports(
        observer,
        input.configuration.network.authority_port,
        observed.effective_uid,
    );
    let storage = check_storage(observer, &input.configuration.storage.data_directory);
    let services = check_services(observed.launchd_job_loaded, &paths);
    let existing_install = check_existing_install(&paths, observed.launchd_job_loaded);

    let checks = PreflightChecks {
        os: check_os(&observed.os_version),
        arch: check_arch(&observed.architecture),
        privileges: check_privileges(observed.effective_uid),
        storage,
        ports,
        paths,
        services,
        existing_install,
    };
    let ok = checks.os.ok
        && checks.arch.ok
        && checks.privileges.ok
        && checks.storage.ok
        && checks.ports.ok
        && checks.paths.ok
        && checks.services.ok
        && !checks.existing_install.detected;

    Ok(v2::PreflightResult {
        contract_version: v2::CONTRACT_VERSION,
        configuration: input.configuration.clone(),
        ok,
        host_checks: HostPreflightResult {
            contract_version: super::models::CONTRACT_VERSION,
            ok,
            checks,
        },
        tls_certificate_sha256: None,
        tls_subject_name_verified: false,
        docker_compose_runtime: None,
        capabilities: capabilities_v2(),
    })
}

// ---------------------------------------------------------------------------
// Production macOS observer (read-only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub struct MacosSystemObserver;

#[cfg(target_os = "macos")]
impl MacosSystemObserver {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl Default for MacosSystemObserver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
const COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(target_os = "macos")]
const MAX_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;

#[cfg(target_os = "macos")]
fn read_capped(mut pipe: impl std::io::Read) -> Result<(Vec<u8>, bool), String> {
    let mut captured = Vec::new();
    let mut total = 0usize;
    let mut chunk = [0u8; 8192];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                total = total.saturating_add(read);
                if captured.len() < MAX_COMMAND_OUTPUT_BYTES {
                    let room = MAX_COMMAND_OUTPUT_BYTES - captured.len();
                    captured.extend_from_slice(&chunk[..read.min(room)]);
                }
            }
            // A partial read is not a successful observation. Returning the
            // bytes captured so far could let a truncated id/os/launchctl
            // result look like a valid short result.
            Err(error) => return Err(format!("read command output: {error}")),
        }
    }
    Ok((captured, total > MAX_COMMAND_OUTPUT_BYTES))
}

#[cfg(target_os = "macos")]
fn run_bounded_command(argv: &[String]) -> Result<CommandObservation, String> {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    if argv.is_empty() || argv.len() > 8 {
        return Err("reviewed command has an invalid argument count".to_string());
    }
    if !argv[0].starts_with('/') || argv.iter().any(|argument| argument.contains('\0')) {
        return Err("reviewed command must use an absolute program path".to_string());
    }

    let mut command = Command::new(&argv[0]);
    if argv.len() > 1 {
        command.args(&argv[1..]);
    }
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn '{}': {error}", argv[0]))?;

    let stdout_pipe = match child.stdout.take() {
        Some(pipe) => pipe,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("stdout pipe unavailable".to_string());
        }
    };
    let stderr_pipe = match child.stderr.take() {
        Some(pipe) => pipe,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("stderr pipe unavailable".to_string());
        }
    };
    let stdout_thread = std::thread::spawn(move || read_capped(stdout_pipe));
    let stderr_thread = std::thread::spawn(move || read_capped(stderr_pipe));

    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "command '{}' timed out after {}s",
                        argv[0],
                        COMMAND_TIMEOUT.as_secs()
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("wait for '{}': {error}", argv[0]));
            }
        }
    };

    let (stdout, stdout_overflow) = stdout_thread
        .join()
        .map_err(|_| "stdout reader panicked".to_string())?
        .map_err(|error| format!("stdout reader failed: {error}"))?;
    let (stderr, stderr_overflow) = stderr_thread
        .join()
        .map_err(|_| "stderr reader panicked".to_string())?
        .map_err(|error| format!("stderr reader failed: {error}"))?;

    if stdout_overflow || stderr_overflow {
        return Err(format!(
            "command '{}' exceeded the {MAX_COMMAND_OUTPUT_BYTES}-byte output bound",
            argv[0]
        ));
    }

    let exit_code = status
        .code()
        .ok_or_else(|| format!("command '{}' ended without an exit code", argv[0]))?;
    let stdout = String::from_utf8(stdout)
        .map_err(|_| format!("command '{}' produced non-UTF-8 stdout", argv[0]))?;
    let stderr = String::from_utf8(stderr)
        .map_err(|_| format!("command '{}' produced non-UTF-8 stderr", argv[0]))?;

    Ok(CommandObservation {
        exit_code,
        stdout,
        stderr,
    })
}

#[cfg(target_os = "macos")]
impl MacosLaunchdObserver for MacosSystemObserver {
    fn observe(&self, query: LaunchdQuery) -> Result<CommandObservation, String> {
        run_bounded_command(&query.reviewed_argv())
    }

    fn lstat(&self, path: &Path) -> Result<Option<PathMetadata>, String> {
        use std::os::unix::fs::MetadataExt;

        match std::fs::symlink_metadata(path) {
            Ok(metadata) => Ok(Some(PathMetadata {
                is_symlink: metadata.file_type().is_symlink(),
                is_directory: metadata.is_dir(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode(),
            })),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("inspect '{}': {error}", path.display())),
        }
    }

    fn extended_acl_is_safe(&self, path: &Path) -> Result<bool, String> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| {
                format!(
                    "open '{}' as a directory without following links: {error}",
                    path.display()
                )
            })?;
        let status = crate::private_file::query_extended_acl(directory.as_raw_fd())
            .map_err(|error| error.to_string())?;
        Ok(matches!(
            status,
            crate::private_file::AclStatus::Absent | crate::private_file::AclStatus::DenyOnly
        ))
    }

    fn storage(&self, path: &Path) -> Result<(u64, u64), String> {
        use std::ffi::CString;

        let existing = path
            .ancestors()
            .find(|candidate| candidate.is_dir())
            .ok_or_else(|| {
                format!(
                    "no existing directory for storage path '{}'",
                    path.display()
                )
            })?;
        let c_path = CString::new(existing.to_string_lossy().as_bytes())
            .map_err(|_| "storage path contains a NUL byte".to_string())?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `statvfs` writes into the zeroed struct and `c_path` is a
        // valid NUL-terminated path for the duration of the call.
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if rc != 0 {
            return Err(format!("statvfs failed for '{}': {rc}", existing.display()));
        }
        let block_size = if stat.f_frsize > 0 {
            stat.f_frsize as u128
        } else {
            stat.f_bsize as u128
        };
        let total = block_size
            .saturating_mul(stat.f_blocks as u128)
            .min(u64::MAX as u128) as u64;
        let available = block_size
            .saturating_mul(stat.f_bavail as u128)
            .min(u64::MAX as u128) as u64;
        Ok((total, available))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    struct FailingReader;

    impl std::io::Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected read failure"))
        }
    }

    #[test]
    fn command_output_read_error_is_not_truncated_success() {
        assert!(read_capped(FailingReader).is_err());
    }

    #[test]
    fn reviewed_commands_do_not_inherit_the_parent_environment() {
        let variable = "HELICOID_LAUNCHD_TEST_INHERITED";
        std::env::set_var(variable, "must-not-leak");
        let observation = run_bounded_command(&["/usr/bin/env".to_string()])
            .expect("read-only environment observation");
        std::env::remove_var(variable);

        assert!(!observation.stdout.contains(variable));
        assert!(observation.stdout.contains("LC_ALL=C"));
        assert!(observation.stdout.contains("LANG=C"));
        assert!(observation
            .stdout
            .contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin"));
    }
}
