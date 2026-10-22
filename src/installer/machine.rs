//! Installer state machine: preflight, plan, apply, inspect, resume, remove.
//!
//! Phase journal committed atomically. Retries idempotent. Interrupted apply
//! inspect/resume rechecks actual ownership. Cancellation/rollback tracks what
//! was actually created; never deletes previous data or global files.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};

use super::adapter::{CommandAdapter, LifecycleLockError, LifecycleOperationLock};
use super::lifecycle_v2 as v2;
use super::manifest;
use super::models::*;
use crate::error::{AppError, AppResult};

/// Minimum storage required (1 GiB).
const MIN_STORAGE_BYTES: u64 = 1024 * 1024 * 1024;

/// The installed development service binds to loopback HTTP on 8787.
/// No network-facing firewall exception is installed by this foundation.
const REQUIRED_PORTS: &[(u16, &str)] = &[(8787, "tcp")];

/// Ports that are allowed to be occupied (not ours).
const ALLOWED_OCCUPIED_PORTS: &[(u16, &str)] = &[(80, "tcp"), (443, "tcp")];

/// Namespaced paths.
const BASE_DIR: &str = "/opt/helicoid";
const DATA_DIR: &str = "/var/lib/helicoid";
const DATA_SUBDIR: &str = "/var/lib/helicoid/data";
const BACKUP_DIR: &str = "/var/lib/helicoid/backups";
const BACKUP_ROOT: &str = "/var/backups/helicoid";
const COMPOSE_MANAGER_IDENTITY_DIR: &str = "/var/lib/helicoid/.local/state/helicoid";
const CONFIG_DIR: &str = "/etc/helicoid";
const COMPOSE_DIR: &str = "/opt/helicoid/compose";
const TLS_CERTIFICATE_PATH: &str = "/etc/ssl/helicoid/fullchain.pem";
const TLS_PRIVATE_KEY_PATH: &str = "/etc/ssl/helicoid/private-key.pem";
const SERVICE_USER: &str = "hs-server";
const CONTAINER_OWNER: &str = "10001:10001";
const UNIT_NAME: &str = "hs-server.service";
const BACKUP_SERVICE_UNIT: &str = "hs-server-backup.service";
const BACKUP_TIMER_UNIT: &str = "hs-server-backup.timer";
const BACKUP_CONTROL_SOCKET_UNIT: &str = "hs-server-backup-control.socket";
const BACKUP_CONTROL_SERVICE_UNIT: &str = "hs-server-backup-control@.service";
const BACKUP_CONTROL_SOCKET_PATH: &str = "/run/helicoid-backup-control/backup-control.sock";
const COMPOSE_LOG_OUTPUT_LIMIT: usize = 256 * 1024;
const COMPOSE_LOG_COMMAND_TIMEOUT_SECS: u64 = 5;
pub const BACKUP_CREDENTIAL_PATH: &str = "/etc/helicoid/backup-passphrase.cred";
pub const COMPOSE_BACKUP_CREDENTIAL_PATH: &str = "/opt/helicoid/.installer/backup-passphrase.cred";
const COMPOSE_ARTIFACT_PATHS: &[&str] = &[
    "artifacts/compose/server-image.tar",
    "artifacts/compose/compose.yaml",
    "artifacts/compose/image-ref",
    "artifacts/compose/image-id",
    "artifacts/compose/.env.example",
    "artifacts/compose/tls/readme.md",
];

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

/// Run read-only preflight checks against the target host.
pub fn preflight(
    adapter: &dyn CommandAdapter,
    input: &PreflightInput,
) -> AppResult<PreflightResult> {
    if input.contract_version != CONTRACT_VERSION {
        return Err(AppError::bad_request(format!(
            "unsupported contract_version: {} (expected {})",
            input.contract_version, CONTRACT_VERSION
        )));
    }
    let checks = PreflightChecks {
        os: check_os(adapter)?,
        arch: check_arch(adapter)?,
        privileges: check_privileges(adapter)?,
        storage: check_storage(adapter)?,
        ports: check_ports(adapter)?,
        paths: check_paths(adapter)?,
        services: check_services(adapter)?,
        existing_install: check_existing_install(adapter)?,
    };

    let ok = checks.os.ok
        && checks.arch.ok
        && checks.privileges.ok
        && checks.storage.ok
        && checks.ports.ok
        && checks.paths.ok
        && checks.services.ok
        && !checks.existing_install.detected;

    if !checks.existing_install.detected {
        // Not an error if no existing install.
    }

    Ok(PreflightResult {
        contract_version: CONTRACT_VERSION,
        ok,
        checks,
    })
}

fn check_os(adapter: &dyn CommandAdapter) -> AppResult<CheckResult> {
    match adapter.query_os() {
        Ok((name, version)) => {
            let ok = name.eq_ignore_ascii_case("ubuntu")
                && matches!(version.as_str(), "24.04" | "26.04");
            let reason = if !ok {
                Some(format!(
                    "unsupported OS: {name} {version} (require Ubuntu 24.04 or 26.04)"
                ))
            } else {
                None
            };
            Ok(CheckResult {
                ok,
                value: name,
                version: Some(version),
                reason,
            })
        }
        Err(e) => Ok(CheckResult {
            ok: false,
            value: "unknown".into(),
            version: None,
            reason: Some(format!("cannot query OS: {e}")),
        }),
    }
}

fn check_arch(adapter: &dyn CommandAdapter) -> AppResult<CheckResult> {
    match adapter.query_arch() {
        Ok(arch) => {
            let ok = arch == "x86_64";
            let reason = if !ok {
                Some(format!("unsupported architecture: {arch} (require x86_64)"))
            } else {
                None
            };
            Ok(CheckResult {
                ok,
                value: arch,
                version: None,
                reason,
            })
        }
        Err(e) => Ok(CheckResult {
            ok: false,
            value: "unknown".into(),
            version: None,
            reason: Some(format!("cannot query architecture: {e}")),
        }),
    }
}

fn check_privileges(adapter: &dyn CommandAdapter) -> AppResult<PrivilegesCheck> {
    match adapter.query_is_root() {
        Ok(is_root) => {
            let reason = if !is_root {
                Some("installer must run as root".into())
            } else {
                None
            };
            Ok(PrivilegesCheck {
                ok: is_root,
                is_root,
                reason,
            })
        }
        Err(e) => Ok(PrivilegesCheck {
            ok: false,
            is_root: false,
            reason: Some(format!("cannot query privileges: {e}")),
        }),
    }
}

fn check_storage(adapter: &dyn CommandAdapter) -> AppResult<StorageCheck> {
    check_storage_at(adapter, Path::new(DATA_DIR))
}

fn check_storage_at(adapter: &dyn CommandAdapter, path: &Path) -> AppResult<StorageCheck> {
    match adapter.query_storage(path) {
        Ok((total, available)) => {
            let ok = available >= MIN_STORAGE_BYTES;
            let reason = if !ok {
                Some(format!(
                    "insufficient storage: {available} bytes available, {MIN_STORAGE_BYTES} required"
                ))
            } else {
                None
            };
            Ok(StorageCheck {
                ok,
                total_bytes: total,
                available_bytes: available,
                min_required_bytes: MIN_STORAGE_BYTES,
                reason,
            })
        }
        Err(e) => Ok(StorageCheck {
            ok: false,
            total_bytes: 0,
            available_bytes: 0,
            min_required_bytes: MIN_STORAGE_BYTES,
            reason: Some(format!("cannot query storage: {e}")),
        }),
    }
}

fn check_ports(adapter: &dyn CommandAdapter) -> AppResult<PortsCheck> {
    let mut listeners = Vec::new();
    let mut conflicts = Vec::new();
    let mut ok = true;

    // Check our required ports.
    for &(port, protocol) in REQUIRED_PORTS {
        match adapter.query_port_listener(port, protocol) {
            Ok(Some(process)) => {
                ok = false;
                conflicts.push(PortConflict {
                    port,
                    protocol: protocol.to_string(),
                    process,
                });
                listeners.push(PortListener {
                    port,
                    protocol: protocol.to_string(),
                    occupied: true,
                    process: Some(conflicts.last().unwrap().process.clone()),
                });
            }
            Ok(None) => {
                listeners.push(PortListener {
                    port,
                    protocol: protocol.to_string(),
                    occupied: false,
                    process: None,
                });
            }
            Err(e) => {
                ok = false;
                listeners.push(PortListener {
                    port,
                    protocol: protocol.to_string(),
                    occupied: true,
                    process: Some(format!("query error: {e}")),
                });
            }
        }
    }

    // Also report allowed occupied ports (informational).
    for &(port, protocol) in ALLOWED_OCCUPIED_PORTS {
        if let Ok(Some(process)) = adapter.query_port_listener(port, protocol) {
            listeners.push(PortListener {
                port,
                protocol: protocol.to_string(),
                occupied: true,
                process: Some(process),
            });
        }
    }

    Ok(PortsCheck {
        ok,
        listeners,
        conflicts,
    })
}

fn check_paths(adapter: &dyn CommandAdapter) -> AppResult<PathsCheck> {
    let paths_to_check = [BASE_DIR, DATA_DIR, CONFIG_DIR];
    let mut checked = Vec::new();
    let mut ok = true;

    for path_str in &paths_to_check {
        let path = Path::new(path_str);
        if !adapter.path_exists(path) {
            checked.push(PathCheck {
                path: path_str.to_string(),
                exists: false,
                owned_by_us: false,
                reason: None,
            });
            continue;
        }

        // Existing path: the ownership/symlink query must succeed, and a
        // symlink or foreign path is a hard conflict. Unknown is not free.
        match adapter.symlink_metadata(path) {
            Ok(meta) if meta.is_symlink => {
                ok = false;
                checked.push(PathCheck {
                    path: path_str.to_string(),
                    exists: true,
                    owned_by_us: false,
                    reason: Some("path is a symlink".into()),
                });
            }
            Ok(_) => {
                // Present non-symlink path: not ours to claim in a clean install.
                ok = false;
                checked.push(PathCheck {
                    path: path_str.to_string(),
                    exists: true,
                    owned_by_us: false,
                    reason: Some("path already exists".into()),
                });
            }
            Err(e) => {
                ok = false;
                checked.push(PathCheck {
                    path: path_str.to_string(),
                    exists: true,
                    owned_by_us: false,
                    reason: Some(format!("cannot query path metadata: {e}")),
                });
            }
        }
    }

    Ok(PathsCheck { ok, checked })
}

fn check_services(adapter: &dyn CommandAdapter) -> AppResult<ServicesCheck> {
    let mut existing_units = Vec::new();
    let mut conflicts = Vec::new();

    for unit in [
        UNIT_NAME,
        BACKUP_SERVICE_UNIT,
        BACKUP_TIMER_UNIT,
        BACKUP_CONTROL_SOCKET_UNIT,
        BACKUP_CONTROL_SERVICE_UNIT,
    ] {
        match adapter.query_unit_exists(unit) {
            Ok(true) => {
                existing_units.push(unit.to_string());
                conflicts.push(format!("unit {unit} already exists"));
            }
            Ok(false) => {}
            Err(e) => {
                return Err(AppError::internal(format!(
                    "cannot query service '{unit}': {e}"
                )));
            }
        }
    }

    Ok(ServicesCheck {
        ok: conflicts.is_empty(),
        existing_units,
        conflicts,
    })
}

fn acquire_lifecycle_operation_lock(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
) -> AppResult<Box<dyn LifecycleOperationLock>> {
    adapter
        .acquire_lifecycle_operation_lock(state_dir)
        .map_err(|error| match error {
            LifecycleLockError::Busy => AppError::conflict(
                "another installer lifecycle operation is already in progress",
                None,
            ),
            LifecycleLockError::Unavailable(error) => {
                AppError::internal(format!("cannot acquire installer lifecycle lock: {error}"))
            }
        })
}

fn check_existing_install(adapter: &dyn CommandAdapter) -> AppResult<ExistingInstallCheck> {
    // Check if there's an existing installation by looking for state directory.
    let state_file = Path::new("/opt/helicoid/.installer/journal.json");
    if adapter.path_exists(state_file) {
        return Ok(ExistingInstallCheck {
            detected: true,
            version: None,
            state: Some("previous installation detected".into()),
        });
    }
    Ok(ExistingInstallCheck {
        detected: false,
        version: None,
        state: None,
    })
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// Generate an installation plan from preflight results and package.
pub fn plan(
    adapter: &dyn CommandAdapter,
    input: &PlanInput,
    verifying_key_bytes: Option<&[u8; 32]>,
) -> AppResult<PlanResult> {
    plan_requiring_artifacts(adapter, input, verifying_key_bytes, &[])
}

fn plan_requiring_artifacts(
    adapter: &dyn CommandAdapter,
    input: &PlanInput,
    verifying_key_bytes: Option<&[u8; 32]>,
    required_artifacts: &[&str],
) -> AppResult<PlanResult> {
    if input.contract_version != CONTRACT_VERSION {
        return Err(AppError::bad_request(format!(
            "unsupported contract_version: {} (expected {})",
            input.contract_version, CONTRACT_VERSION
        )));
    }

    // Verify preflight is ok.
    if !input.preflight.ok {
        return Ok(PlanResult {
            contract_version: CONTRACT_VERSION,
            ok: false,
            manifest_verified: false,
            plan: None,
            warnings: vec![],
            error: Some("preflight checks failed; cannot generate plan".into()),
        });
    }

    // Verify package manifest if verifying key is provided.
    let product;
    let version;

    if let Some(key) = verifying_key_bytes {
        match manifest::verify_manifest(adapter, Path::new(&input.package_dir), key) {
            Ok(m) => {
                if required_artifacts.iter().any(|required| {
                    !m.artifacts
                        .iter()
                        .any(|artifact| artifact.path == *required)
                }) {
                    return Ok(PlanResult {
                        contract_version: CONTRACT_VERSION,
                        ok: false,
                        manifest_verified: true,
                        plan: None,
                        warnings: vec![],
                        error: Some(
                            "signed package is missing artifacts required by this deployment kind"
                                .into(),
                        ),
                    });
                }
                product = m.product;
                version = m.version;
            }
            Err(e) => {
                return Ok(PlanResult {
                    contract_version: CONTRACT_VERSION,
                    ok: false,
                    manifest_verified: false,
                    plan: None,
                    warnings: vec![],
                    error: Some(format!("manifest verification failed: {e}")),
                });
            }
        }
    } else {
        // No verifying key provided — cannot verify manifest.
        return Ok(PlanResult {
            contract_version: CONTRACT_VERSION,
            ok: false,
            manifest_verified: false,
            plan: None,
            warnings: vec![],
            error: Some("no verifying key provided (--verify-key)".into()),
        });
    }

    let mut install_plan = generate_canonical_plan(&product, &version);
    install_plan.review_digest = compute_plan_digest(&install_plan);

    Ok(PlanResult {
        contract_version: CONTRACT_VERSION,
        ok: true,
        manifest_verified: true,
        plan: Some(install_plan),
        warnings: vec![],
        error: None,
    })
}

/// Current capability report for the v2 lifecycle contract.
pub fn lifecycle_capabilities_v2() -> v2::LifecycleCapabilities {
    use v2::{DeploymentKind, LifecycleAction, NetworkScope};

    let on_linux = cfg!(target_os = "linux");
    let mut reasons_unavailable = BTreeMap::new();
    reasons_unavailable.insert(
        "macos_launchd".to_string(),
        "the launchd host adapter is not implemented in this server package".to_string(),
    );
    reasons_unavailable.insert(
        "windows_service".to_string(),
        "the Windows hosting adapter is not implemented in this server package".to_string(),
    );
    reasons_unavailable.insert(
        "public_edge".to_string(),
        "the organization-owned WebRTC edge is a separate deployment and is not provisioned here"
            .to_string(),
    );
    reasons_unavailable.insert(
        "cancellation".to_string(),
        "the installer journals resumable phases but has no safe cancellation operation"
            .to_string(),
    );
    reasons_unavailable.insert(
        "online_update".to_string(),
        "signed service updates, persistent downgrade protection, schema compatibility review, and health-gated binary rollback are not implemented".to_string(),
    );
    reasons_unavailable.insert(
        "backup_and_restore".to_string(),
        "encrypted database archives and restore-to-new-file exist separately; lifecycle-managed deployment restore and authority reconciliation are not implemented".to_string(),
    );
    reasons_unavailable.insert(
        "cutover".to_string(),
        "two-host coordination and independent proof that the predecessor is fenced are not implemented".to_string(),
    );
    // Keep the original aggregate key for older Manager and TUI clients.
    reasons_unavailable.insert(
        "online_update_backup_restore".to_string(),
        "online update and deployment restore/cutover are not implemented; scheduled encrypted database backups are available for Linux systemd and Compose deployments".to_string(),
    );

    v2::LifecycleCapabilities {
        contract_version: v2::CONTRACT_VERSION,
        supported_deployment_kinds: if on_linux {
            vec![DeploymentKind::LinuxSystemd, DeploymentKind::LinuxCompose]
        } else {
            vec![]
        },
        supported_network_scopes: if on_linux {
            vec![
                NetworkScope::LoopbackDevelopment,
                NetworkScope::Lan,
                NetworkScope::PrivateDns,
            ]
        } else {
            vec![NetworkScope::LoopbackDevelopment]
        },
        supported_actions: vec![
            LifecycleAction::Preflight,
            LifecycleAction::Plan,
            LifecycleAction::Install,
            LifecycleAction::Resume,
            LifecycleAction::Inspect,
            LifecycleAction::Remove,
        ],
        custom_storage_directories: true,
        durable_operation_journal: true,
        cancellation: false,
        online_update: false,
        backup_and_restore: false,
        public_edge_integration: false,
        reasons_unavailable,
    }
}

/// Read-only local-host preflight with the v2 deployment configuration attached.
pub fn preflight_v2(
    adapter: &dyn CommandAdapter,
    input: &v2::PreflightInput,
) -> AppResult<v2::PreflightResult> {
    if input.contract_version != v2::CONTRACT_VERSION {
        return Err(AppError::bad_request(format!(
            "unsupported lifecycle contract_version: {} (expected {})",
            input.contract_version,
            v2::CONTRACT_VERSION
        )));
    }
    validate_v2_configuration(&input.configuration)?;
    validate_storage_directories(adapter, &input.configuration)?;
    let mut host_checks = preflight(
        adapter,
        &super::models::PreflightInput {
            contract_version: CONTRACT_VERSION,
            target: PreflightTarget {
                host: "localhost".to_string(),
                port: 22,
            },
        },
    )?;
    let tls_certificate_sha256 = validate_network_tls_configuration(adapter, &input.configuration)?;
    let tls_subject_name_verified = tls_certificate_sha256.is_some();
    if input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose {
        // The host-level 8787 probe belongs to the systemd loopback service.
        // Compose publishes its reviewed authority port instead.
        host_checks.checks.ports = PortsCheck {
            ok: true,
            listeners: vec![],
            conflicts: vec![],
        };
    }
    if matches!(
        input.configuration.network.scope,
        v2::NetworkScope::Lan | v2::NetworkScope::PrivateDns
    ) || input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose
    {
        let port = input.configuration.network.authority_port;
        match adapter.query_port_listener(port, "tcp") {
            Ok(Some(process)) => {
                host_checks.checks.ports.ok = false;
                host_checks.checks.ports.conflicts.push(PortConflict {
                    port,
                    protocol: "tcp".to_string(),
                    process: process.clone(),
                });
                host_checks.checks.ports.listeners.push(PortListener {
                    port,
                    protocol: "tcp".to_string(),
                    occupied: true,
                    process: Some(process),
                });
            }
            Ok(None) => host_checks.checks.ports.listeners.push(PortListener {
                port,
                protocol: "tcp".to_string(),
                occupied: false,
                process: None,
            }),
            Err(error) => {
                host_checks.checks.ports.ok = false;
                host_checks.checks.ports.listeners.push(PortListener {
                    port,
                    protocol: "tcp".to_string(),
                    occupied: true,
                    process: Some(format!("query error: {error}")),
                });
            }
        }
    }
    let backup_root =
        if Path::new(&input.configuration.storage.backup_directory).starts_with(BACKUP_DIR) {
            BACKUP_DIR
        } else {
            BACKUP_ROOT
        };
    let backup_root_check = check_path_is_free(adapter, backup_root);
    host_checks.checks.paths.ok &= backup_root_check.reason.is_none();
    host_checks.checks.paths.checked.push(backup_root_check);
    host_checks.checks.storage = check_storage_at(
        adapter,
        Path::new(&input.configuration.storage.data_directory),
    )?;
    let docker_compose_runtime =
        if input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose {
            Some(check_docker_compose_runtime(adapter))
        } else {
            None
        };
    host_checks.ok = preflight_checks_ok(&host_checks.checks)
        && docker_compose_runtime
            .as_ref()
            .is_none_or(|runtime| runtime.available);
    Ok(v2::PreflightResult {
        contract_version: v2::CONTRACT_VERSION,
        configuration: input.configuration.clone(),
        ok: host_checks.ok,
        host_checks,
        tls_certificate_sha256,
        tls_subject_name_verified,
        docker_compose_runtime,
        capabilities: lifecycle_capabilities_v2(),
    })
}

fn check_docker_compose_runtime(adapter: &dyn CommandAdapter) -> v2::DockerComposeRuntimeCheck {
    match adapter.query_docker_compose_runtime() {
        Ok(Some(runtime)) => {
            let compose_supported = parse_compose_version(&runtime.compose_version)
                .is_some_and(|version| version >= (2, 17, 0));
            v2::DockerComposeRuntimeCheck {
                available: compose_supported,
                docker_server_version: Some(runtime.docker_server_version),
                compose_version: Some(runtime.compose_version.clone()),
                reason: (!compose_supported).then(|| {
                    format!(
                        "Docker Compose {} is unsupported or malformed (require version 2.17.0 or newer)",
                        runtime.compose_version
                    )
                }),
            }
        }
        Ok(None) => v2::DockerComposeRuntimeCheck {
            available: false,
            docker_server_version: None,
            compose_version: None,
            reason: Some(
                "Docker Engine and the Docker Compose plugin must be installed and the daemon must be reachable".into(),
            ),
        },
        Err(error) => v2::DockerComposeRuntimeCheck {
            available: false,
            docker_server_version: None,
            compose_version: None,
            reason: Some(format!("cannot verify Docker Compose runtime: {error}")),
        },
    }
}

fn parse_compose_version(value: &str) -> Option<(u64, u64, u64)> {
    let numeric = value.strip_prefix('v').unwrap_or(value);
    let mut components = numeric.split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next()?.parse().ok()?;
    let patch = components.next()?.parse().ok()?;
    if components.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn check_path_is_free(adapter: &dyn CommandAdapter, path: &str) -> PathCheck {
    match adapter.symlink_metadata(Path::new(path)) {
        Ok(metadata) if metadata.is_symlink => PathCheck {
            path: path.to_string(),
            exists: true,
            owned_by_us: false,
            reason: Some("path is a symlink".into()),
        },
        Ok(_) => PathCheck {
            path: path.to_string(),
            exists: true,
            owned_by_us: false,
            reason: Some("path already exists".into()),
        },
        Err(error) if is_missing_path_error(&error) => PathCheck {
            path: path.to_string(),
            exists: false,
            owned_by_us: false,
            reason: None,
        },
        Err(error) => PathCheck {
            path: path.to_string(),
            exists: true,
            owned_by_us: false,
            reason: Some(format!("cannot query path metadata: {error}")),
        },
    }
}

fn preflight_checks_ok(checks: &PreflightChecks) -> bool {
    checks.os.ok
        && checks.arch.ok
        && checks.privileges.ok
        && checks.storage.ok
        && checks.ports.ok
        && checks.paths.ok
        && checks.services.ok
        && !checks.existing_install.detected
}

fn validate_v2_configuration(configuration: &v2::DeploymentConfiguration) -> AppResult<()> {
    use v2::{DeploymentKind, NetworkScope};

    if !matches!(
        configuration.deployment_kind,
        DeploymentKind::LinuxSystemd | DeploymentKind::LinuxCompose
    ) {
        return Err(AppError::not_implemented(
            "this installer supports only Linux systemd and Docker Compose deployment configurations",
        ));
    }
    match configuration.network.scope {
        NetworkScope::LoopbackDevelopment
            if configuration.network.authority_port == 8787
                && configuration.network.bind_address.is_none()
                && configuration.network.client_hostname.is_none() => {}
        NetworkScope::Lan | NetworkScope::PrivateDns if cfg!(target_os = "linux") => {
            if !(1024..=u16::MAX).contains(&configuration.network.authority_port)
                || configuration.network.authority_port == 8787
            {
                return Err(AppError::bad_request(
                    "LAN and private DNS authority_port must be an unprivileged port other than 8787",
                ));
            }
            let address = configuration
                .network
                .bind_address
                .as_deref()
                .ok_or_else(|| {
                    AppError::bad_request("LAN and private DNS bind_address is required")
                })?;
            let ip: IpAddr = address.parse().map_err(|_| {
                AppError::bad_request(
                    "LAN and private DNS bind_address must be a literal private IP address",
                )
            })?;
            if !is_private_lan_address(ip) {
                return Err(AppError::bad_request(
                    "LAN and private DNS bind_address must be an RFC1918 IPv4 or unique-local IPv6 address",
                ));
            }
            if configuration.network.scope == NetworkScope::PrivateDns
                && configuration.network.client_hostname.is_none()
            {
                return Err(AppError::bad_request(
                    "private DNS client_hostname is required",
                ));
            }
            if let Some(hostname) = configuration.network.client_hostname.as_deref() {
                if !is_valid_client_hostname(hostname) {
                    return Err(AppError::bad_request(
                        "LAN and private DNS client_hostname must be a DNS hostname, not an IP address or localhost name",
                    ));
                }
            }
        }
        NetworkScope::Lan | NetworkScope::PrivateDns => {
            return Err(AppError::not_implemented(
                "LAN and private DNS deployment is supported only on Linux",
            ));
        }
        NetworkScope::PublicEdge => {
            return Err(AppError::not_implemented(
                "public-edge network scope is not implemented",
            ));
        }
        _ => {
            return Err(AppError::bad_request(
                "loopback development scope requires port 8787 and no bind_address or client_hostname",
            ));
        }
    }
    validate_storage_path(
        &configuration.storage.data_directory,
        &[DATA_SUBDIR],
        "data",
    )?;
    validate_storage_path(
        &configuration.storage.backup_directory,
        &[BACKUP_DIR, BACKUP_ROOT],
        "backup",
    )?;
    let data = Path::new(&configuration.storage.data_directory);
    let backup = Path::new(&configuration.storage.backup_directory);
    if data == backup || data.starts_with(backup) || backup.starts_with(data) {
        return Err(AppError::bad_request(
            "data and backup directories must be separate and must not contain one another",
        ));
    }
    Ok(())
}

fn is_private_lan_address(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => address.segments()[0] & 0xfe00 == 0xfc00,
    }
}

fn is_valid_client_hostname(hostname: &str) -> bool {
    if hostname.is_empty()
        || hostname.len() > 253
        || !hostname.is_ascii()
        || hostname.parse::<IpAddr>().is_ok()
    {
        return false;
    }
    let lowercase = hostname.to_ascii_lowercase();
    if lowercase == "localhost" || lowercase.ends_with(".localhost") {
        return false;
    }
    if !hostname.bytes().any(|byte| byte.is_ascii_alphabetic()) {
        return false;
    }
    hostname.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    })
}

/// Validate a configured private listener address is present on this host, and
/// validate the exact TLS inputs before a plan can be reviewed or applied.
/// The temporary port-zero bind is immediately dropped and does not reserve
/// or change the configured listener port.
fn validate_network_tls_configuration(
    adapter: &dyn CommandAdapter,
    configuration: &v2::DeploymentConfiguration,
) -> AppResult<Option<String>> {
    let compose = configuration.deployment_kind == v2::DeploymentKind::LinuxCompose;
    let externally_reachable = matches!(
        configuration.network.scope,
        v2::NetworkScope::Lan | v2::NetworkScope::PrivateDns
    );
    if !externally_reachable && !compose {
        return Ok(None);
    }
    let expected_server_name = if externally_reachable {
        let address = configuration
            .network
            .bind_address
            .as_deref()
            .ok_or_else(|| AppError::bad_request("LAN and private DNS bind_address is required"))?;
        let ip: IpAddr = address.parse().map_err(|_| {
            AppError::bad_request(
                "LAN and private DNS bind_address must be a literal private IP address",
            )
        })?;
        let probe = TcpListener::bind(SocketAddr::new(ip, 0)).map_err(|error| {
            AppError::bad_request(format!(
                "configured private bind_address {ip} is not available on this host: {error}"
            ))
        })?;
        drop(probe);
        configuration
            .network
            .client_hostname
            .as_deref()
            .unwrap_or(address)
    } else {
        "localhost"
    };
    let bind = if compose {
        "0.0.0.0:8920".to_string()
    } else {
        let address = configuration
            .network
            .bind_address
            .as_deref()
            .ok_or_else(|| AppError::bad_request("LAN and private DNS bind_address is required"))?;
        let ip: IpAddr = address.parse().map_err(|_| {
            AppError::bad_request(
                "LAN and private DNS bind_address must be a literal private IP address",
            )
        })?;
        SocketAddr::new(ip, configuration.network.authority_port).to_string()
    };
    let digest = adapter
        .validate_tls_inputs(
            &bind,
            Path::new(TLS_CERTIFICATE_PATH),
            Path::new(TLS_PRIVATE_KEY_PATH),
            expected_server_name,
        )
        .map_err(|error| AppError::bad_request(format!("TLS configuration is invalid: {error}")))?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::internal(
            "TLS validation returned an invalid certificate digest",
        ));
    }
    Ok(Some(digest.to_ascii_lowercase()))
}

fn validate_storage_path(path: &str, roots: &[&str], label: &str) -> AppResult<()> {
    const MAX_STORAGE_PATH_BYTES: usize = 512;
    if path.len() > MAX_STORAGE_PATH_BYTES
        || !path.starts_with('/')
        || path.ends_with('/')
        || path.contains("//")
        || path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
        || path.split('/').skip(1).any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        || !roots
            .iter()
            .any(|root| path == *root || Path::new(path).starts_with(root))
    {
        return Err(AppError::bad_request(format!(
            "{label} directory must be a normalized path within a Helicoid-owned storage root"
        )));
    }
    Ok(())
}

fn same_configuration_ignoring_removal_policy(
    stored: &v2::DeploymentConfiguration,
    requested: &v2::DeploymentConfiguration,
) -> bool {
    let mut stored = stored.clone();
    stored.storage.preserve_data_on_remove = requested.storage.preserve_data_on_remove;
    stored == *requested
}

fn validate_storage_directories(
    adapter: &dyn CommandAdapter,
    configuration: &v2::DeploymentConfiguration,
) -> AppResult<()> {
    for (label, path) in [
        ("data", configuration.storage.data_directory.as_str()),
        ("backup", configuration.storage.backup_directory.as_str()),
    ] {
        let mut current = PathBuf::new();
        for component in Path::new(path).components() {
            current.push(component);
            match adapter.symlink_metadata(&current) {
                Ok(metadata) if metadata.is_symlink => {
                    return Err(AppError::forbidden(format!(
                        "{label} directory path contains a symlink at {}",
                        current.display()
                    )));
                }
                Ok(metadata) if !metadata.is_dir => {
                    return Err(AppError::conflict(
                        format!(
                            "{label} directory path contains a non-directory at {}",
                            current.display()
                        ),
                        None,
                    ));
                }
                Ok(_) => {}
                Err(error) if is_missing_path_error(&error) => {}
                Err(error) => {
                    return Err(AppError::internal(format!(
                        "cannot inspect {label} directory path {}: {error}",
                        current.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

fn is_missing_path_error(error: &str) -> bool {
    error.starts_with("file not found:")
        || error.starts_with("path not found:")
        || error.contains("No such file or directory")
}

/// Bind the v2 review to the observed host preflight, exact generated
/// resources, and deployment configuration. It is not a signature or an
/// authorization token.
pub fn compute_reviewed_plan_digest_v2(
    configuration: &v2::DeploymentConfiguration,
    preflight: &v2::PreflightResult,
    plan: &InstallPlan,
) -> AppResult<String> {
    #[derive(serde::Serialize)]
    struct Review<'a> {
        contract_version: u32,
        configuration: &'a v2::DeploymentConfiguration,
        host_preflight: &'a super::models::PreflightResult,
        tls_certificate_sha256: &'a Option<String>,
        tls_subject_name_verified: bool,
        docker_compose_runtime: &'a Option<v2::DockerComposeRuntimeCheck>,
        installer_plan_digest: &'a str,
    }

    let canonical = Review {
        contract_version: v2::CONTRACT_VERSION,
        configuration,
        host_preflight: &preflight.host_checks,
        tls_certificate_sha256: &preflight.tls_certificate_sha256,
        tls_subject_name_verified: preflight.tls_subject_name_verified,
        docker_compose_runtime: &preflight.docker_compose_runtime,
        installer_plan_digest: &plan.review_digest,
    };
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AppError::internal(format!("serialize v2 review: {error}")))?;
    Ok(manifest::sha256_hex(&bytes))
}

/// Generate a v2 plan while keeping resource generation and package
/// verification in the existing installer domain implementation.
pub fn plan_v2(
    adapter: &dyn CommandAdapter,
    input: &v2::PlanInput,
    verifying_key_bytes: Option<&[u8; 32]>,
) -> AppResult<v2::PlanResult> {
    if input.contract_version != v2::CONTRACT_VERSION {
        return Err(AppError::bad_request(format!(
            "unsupported lifecycle contract_version: {} (expected {})",
            input.contract_version,
            v2::CONTRACT_VERSION
        )));
    }
    validate_v2_configuration(&input.configuration)?;
    validate_storage_directories(adapter, &input.configuration)?;
    if input.preflight.contract_version != v2::CONTRACT_VERSION
        || input.preflight.host_checks.contract_version != CONTRACT_VERSION
        || input.preflight.configuration != input.configuration
        || input.preflight.ok != input.preflight.host_checks.ok
        || (input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose
            && !input
                .preflight
                .docker_compose_runtime
                .as_ref()
                .is_some_and(|runtime| runtime.available))
    {
        return Err(AppError::bad_request(format!(
            "unsupported nested preflight contract version; expected lifecycle v{} wrapping host v{}",
            v2::CONTRACT_VERSION,
            CONTRACT_VERSION
        )));
    }
    let current_tls_certificate_sha256 =
        validate_network_tls_configuration(adapter, &input.configuration)?;
    if input.preflight.tls_certificate_sha256 != current_tls_certificate_sha256
        || input.preflight.tls_subject_name_verified != current_tls_certificate_sha256.is_some()
    {
        return Err(AppError::conflict(
            "TLS certificate or subject-name verification changed after preflight; generate a new plan",
            None,
        ));
    }

    let legacy_input = super::models::PlanInput {
        contract_version: CONTRACT_VERSION,
        preflight: input.preflight.host_checks.clone(),
        package_dir: input.package_dir.clone(),
    };
    let required_artifacts =
        if input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose {
            COMPOSE_ARTIFACT_PATHS
        } else {
            &[]
        };
    let generated = plan_requiring_artifacts(
        adapter,
        &legacy_input,
        verifying_key_bytes,
        required_artifacts,
    )?;
    let configured_plan = generated
        .plan
        .as_ref()
        .map(|plan| generate_canonical_plan_v2(&plan.product, &plan.version, &input.configuration));
    let digest = match configured_plan.as_ref() {
        Some(plan) => Some(compute_reviewed_plan_digest_v2(
            &input.configuration,
            &input.preflight,
            plan,
        )?),
        None => None,
    };

    let mut warnings = generated.warnings;
    if input.configuration.network.scope == v2::NetworkScope::PrivateDns {
        let hostname = input
            .configuration
            .network
            .client_hostname
            .as_deref()
            .expect("validated private DNS configuration has a hostname");
        let address = input
            .configuration
            .network
            .bind_address
            .as_deref()
            .expect("validated private DNS configuration has a bind address");
        let port = input.configuration.network.authority_port;
        warnings.push(
            format!(
                "Private DNS integration: create an internal A/AAAA record {hostname} -> {address}; allow TCP {port} only from approved Manager networks; if using a proxy, forward HTTPS to {address}:{port} with certificate validation and the hostname preserved. Install a trusted certificate with the {hostname} DNS SAN. DNS, firewall, proxy, CA trust, and certificate renewal are operator-managed."
            ),
        );
    }
    Ok(v2::PlanResult {
        contract_version: v2::CONTRACT_VERSION,
        ok: generated.ok,
        configuration: input.configuration.clone(),
        plan: configured_plan,
        reviewed_plan_digest: digest,
        capabilities: lifecycle_capabilities_v2(),
        warnings,
        error: generated.error,
    })
}

fn operation_record_path(state_dir: &Path) -> PathBuf {
    state_dir.join("operation-v2.json")
}

/// Return the durable deployment configuration recorded by the v2 lifecycle
/// operation. This is read-only so local management tools can safely discover
/// custom storage paths before requesting status or removal.
pub fn stored_configuration_v2(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
) -> AppResult<Option<v2::DeploymentConfiguration>> {
    validate_v2_removal_state_dir(adapter, state_dir)?;
    let record_path = operation_record_path(state_dir);
    if !path_present(adapter, &record_path) {
        return Ok(None);
    }

    let metadata = adapter.symlink_metadata(&record_path).map_err(|error| {
        AppError::internal(format!(
            "inspect installer operation record {}: {error}",
            record_path.display()
        ))
    })?;
    if metadata.is_symlink || metadata.is_dir {
        return Err(AppError::forbidden(
            "refusing to read a symlink or directory as the installer operation record",
        ));
    }
    let bytes = adapter
        .read_file(&record_path)
        .map_err(|error| AppError::internal(format!("read installer operation record: {error}")))?;
    let record: v2::OperationRecord = serde_json::from_slice(&bytes).map_err(|error| {
        AppError::internal(format!("corrupt installer operation record: {error}"))
    })?;
    if record.contract_version != v2::CONTRACT_VERSION
        || uuid::Uuid::parse_str(&record.operation_id).is_err()
    {
        return Err(AppError::conflict(
            "installer operation record has an unsupported identity or contract version",
            None,
        ));
    }
    validate_v2_configuration(&record.configuration)?;
    Ok(Some(record.configuration))
}

/// Return the product-owned credential path for the installed deployment.
pub fn backup_credential_path_v2(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
) -> AppResult<PathBuf> {
    let configuration = stored_configuration_v2(adapter, state_dir)?.ok_or_else(|| {
        AppError::conflict(
            "scheduled backups require a completed server installation",
            None,
        )
    })?;
    let path = match configuration.deployment_kind {
        v2::DeploymentKind::LinuxSystemd => BACKUP_CREDENTIAL_PATH,
        v2::DeploymentKind::LinuxCompose => COMPOSE_BACKUP_CREDENTIAL_PATH,
        _ => {
            return Err(AppError::not_implemented(
                "scheduled backups require a supported Linux deployment",
            ));
        }
    };
    Ok(PathBuf::from(path))
}

/// Load a completed Linux installation and prove ownership of its backup
/// units before changing the backup timer.
fn load_owned_backup_schedule(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
) -> AppResult<(v2::DeploymentConfiguration, PathBuf, Journal, String)> {
    if !adapter
        .query_is_root()
        .map_err(|error| AppError::internal(format!("check host privileges: {error}")))?
    {
        return Err(AppError::forbidden(
            "managing scheduled backups requires a root terminal",
        ));
    }
    let configuration = stored_configuration_v2(adapter, state_dir)?.ok_or_else(|| {
        AppError::conflict(
            "scheduled backups require a completed server installation",
            None,
        )
    })?;
    validate_v2_configuration(&configuration)?;
    if !matches!(
        configuration.deployment_kind,
        v2::DeploymentKind::LinuxSystemd | v2::DeploymentKind::LinuxCompose
    ) {
        return Err(AppError::not_implemented(
            "scheduled backups require a supported Linux deployment",
        ));
    }

    let record_path = operation_record_path(state_dir);
    let record_bytes = adapter
        .read_file(&record_path)
        .map_err(|error| AppError::internal(format!("read installer operation record: {error}")))?;
    let record: v2::OperationRecord = serde_json::from_slice(&record_bytes).map_err(|error| {
        AppError::internal(format!("corrupt installer operation record: {error}"))
    })?;
    if record.contract_version != v2::CONTRACT_VERSION
        || record.action != v2::LifecycleAction::Install
        || record.configuration != configuration
        || !record
            .outcome
            .as_ref()
            .is_some_and(|outcome| outcome.state == v2::OperationState::Completed)
    {
        return Err(AppError::conflict(
            "scheduled backups require the matching completed installation record",
            None,
        ));
    }

    let journal_path = state_dir.join("journal.json");
    let journal_bytes = adapter.read_file(&journal_path).map_err(|error| {
        AppError::internal(format!("read installer ownership journal: {error}"))
    })?;
    let journal: Journal = serde_json::from_slice(&journal_bytes)
        .map_err(|error| AppError::internal(format!("corrupt installer journal: {error}")))?;
    if journal.current_phase != "completed"
        || (configuration.deployment_kind == v2::DeploymentKind::LinuxSystemd
            && !journal
                .resources_created
                .units
                .contains(&UNIT_NAME.to_string()))
        || !journal
            .resources_created
            .units
            .contains(&BACKUP_SERVICE_UNIT.to_string())
        || !journal
            .resources_created
            .units
            .contains(&BACKUP_TIMER_UNIT.to_string())
        || (configuration.deployment_kind == v2::DeploymentKind::LinuxCompose
            && (!journal
                .resources_created
                .units
                .contains(&BACKUP_CONTROL_SOCKET_UNIT.to_string())
                || !journal
                    .resources_created
                    .units
                    .contains(&BACKUP_CONTROL_SERVICE_UNIT.to_string())))
    {
        return Err(AppError::conflict(
            "the installation journal does not own the complete backup timer resources",
            None,
        ));
    }
    let mut required_units = vec![BACKUP_SERVICE_UNIT, BACKUP_TIMER_UNIT];
    if configuration.deployment_kind == v2::DeploymentKind::LinuxSystemd {
        required_units.push(UNIT_NAME);
    } else {
        required_units.extend([BACKUP_CONTROL_SOCKET_UNIT, BACKUP_CONTROL_SERVICE_UNIT]);
    }
    for unit in required_units {
        match adapter.query_unit_exists(unit) {
            Ok(true) => {}
            Ok(false) => {
                return Err(AppError::conflict(
                    "an installer-owned backup unit is missing; repair the installation first",
                    None,
                ));
            }
            Err(error) => {
                return Err(AppError::internal(format!("inspect backup unit: {error}")));
            }
        }
        if matches!(
            unit,
            BACKUP_SERVICE_UNIT
                | BACKUP_TIMER_UNIT
                | BACKUP_CONTROL_SOCKET_UNIT
                | BACKUP_CONTROL_SERVICE_UNIT
        ) {
            let expected = expected_backup_unit_content(unit, &configuration);
            let path = PathBuf::from(format!("/etc/systemd/system/{unit}"));
            let installed = adapter.read_file(&path).map_err(|error| {
                AppError::internal(format!("read installer-owned backup unit: {error}"))
            })?;
            if installed != expected.as_bytes() {
                return Err(AppError::conflict(
                    format!("installer-owned backup unit '{unit}' was modified"),
                    None,
                ));
            }
        }
    }
    Ok((configuration, journal_path, journal, record.operation_id))
}

fn expected_backup_unit_content(unit: &str, configuration: &v2::DeploymentConfiguration) -> String {
    generate_unit_content(
        SERVICE_USER,
        &UnitSpec {
            name: unit.to_string(),
            action: "install".to_string(),
            enabled: unit == BACKUP_CONTROL_SOCKET_UNIT,
            restart_policy: "no".to_string(),
        },
        &configuration.storage.data_directory,
        &configuration.storage.backup_directory,
        Some(&configuration.network),
        Some(configuration.deployment_kind),
    )
}

/// Provision the systemd-encrypted backup credential and enable the timer for
/// an installed Linux systemd or Compose deployment. Plaintext is accepted only in
/// memory from the local terminal and never enters the operation journal.
pub fn enable_backup_schedule_v2(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
    passphrase: Option<&[u8]>,
) -> AppResult<()> {
    let _operation_lock = acquire_lifecycle_operation_lock(adapter, state_dir)?;
    let (_configuration, journal_path, mut journal, _operation_id) =
        load_owned_backup_schedule(adapter, state_dir)?;
    let supports_encrypted_credentials =
        adapter.supports_encrypted_credentials().map_err(|error| {
            AppError::internal(format!("check systemd credential support: {error}"))
        })?;
    if !supports_encrypted_credentials {
        return Err(AppError::not_implemented(
            "scheduled backups require systemd 250 or newer for encrypted unit credentials",
        ));
    }

    let credential_path = backup_credential_path_v2(adapter, state_dir)?;
    let credential_identity = credential_path.to_string_lossy().into_owned();
    if adapter.path_exists(&credential_path) || adapter.symlink_metadata(&credential_path).is_ok() {
        if !journal
            .resources_created
            .files
            .iter()
            .any(|path| path == &credential_identity)
            || !is_resource_completed(&journal, "file", &credential_identity)
        {
            return Err(AppError::conflict(
                "an unjournaled backup credential occupies the product path; refusing to replace it",
                None,
            ));
        }
    } else {
        let passphrase = passphrase.ok_or_else(|| {
            AppError::bad_request("a backup passphrase is required to configure scheduled backups")
        })?;
        if !(16..=4096).contains(&passphrase.len())
            || passphrase.contains(&b'\n')
            || passphrase.contains(&b'\r')
        {
            return Err(AppError::bad_request(
                "backup passphrase must contain 16 to 4096 bytes on one line",
            ));
        }
        let encrypted = adapter
            .encrypt_backup_credential(passphrase)
            .map_err(|error| {
                AppError::unprocessable(format!("encrypt backup credential: {error}"))
            })?;
        if encrypted.is_empty() || encrypted.len() > 64 * 1024 {
            return Err(AppError::unprocessable(
                "systemd returned an invalid encrypted backup credential",
            ));
        }
        reject_symlink_parents(adapter, &credential_identity)?;
        record_resource_intent(
            adapter,
            &journal_path,
            &mut journal,
            "file",
            &credential_identity,
        )?;
        if let Err(error) = adapter.write_new_private_file(&credential_path, &encrypted) {
            let message = "could not persist the encrypted backup credential";
            let _ = record_resource_failed(
                adapter,
                &journal_path,
                &mut journal,
                "file",
                &credential_identity,
                message,
            );
            return Err(AppError::internal(format!("{message}: {error}")));
        }
        if !journal
            .resources_created
            .files
            .iter()
            .any(|path| path == &credential_identity)
        {
            journal
                .resources_created
                .files
                .push(credential_identity.clone());
            save_journal(adapter, &journal_path, &journal)?;
        }
        record_resource_completed(
            adapter,
            &journal_path,
            &mut journal,
            "file",
            &credential_identity,
        )?;
    }

    adapter
        .verify_backup_credential_file(&credential_path)
        .map_err(|error| {
            AppError::conflict(format!("verify encrypted backup credential: {error}"), None)
        })?;

    adapter
        .systemd_daemon_reload()
        .map_err(|error| AppError::internal(format!("reload backup timer units: {error}")))?;
    record_resource_intent(
        adapter,
        &journal_path,
        &mut journal,
        "backup_schedule",
        BACKUP_TIMER_UNIT,
    )?;
    if let Err(error) = adapter
        .enable_unit(BACKUP_TIMER_UNIT)
        .and_then(|()| adapter.start_unit(BACKUP_TIMER_UNIT))
    {
        let message = "could not enable and start the backup timer";
        let _ = record_resource_failed(
            adapter,
            &journal_path,
            &mut journal,
            "backup_schedule",
            BACKUP_TIMER_UNIT,
            message,
        );
        return Err(AppError::internal(format!("{message}: {error}")));
    }
    record_resource_completed(
        adapter,
        &journal_path,
        &mut journal,
        "backup_schedule",
        BACKUP_TIMER_UNIT,
    )
}

/// Stop and disable the owned backup timer while keeping its encrypted
/// credential and existing archives intact.
pub fn disable_backup_schedule_v2(adapter: &dyn CommandAdapter, state_dir: &Path) -> AppResult<()> {
    let _operation_lock = acquire_lifecycle_operation_lock(adapter, state_dir)?;
    let (_configuration, journal_path, mut journal, _operation_id) =
        load_owned_backup_schedule(adapter, state_dir)?;
    record_resource_intent(
        adapter,
        &journal_path,
        &mut journal,
        "backup_schedule",
        BACKUP_TIMER_UNIT,
    )?;
    if let Err(error) = adapter
        .stop_unit(BACKUP_TIMER_UNIT)
        .and_then(|()| adapter.disable_unit(BACKUP_TIMER_UNIT))
    {
        let message = "could not stop and disable the backup timer";
        let _ = record_resource_failed(
            adapter,
            &journal_path,
            &mut journal,
            "backup_schedule",
            BACKUP_TIMER_UNIT,
            message,
        );
        return Err(AppError::internal(format!("{message}: {error}")));
    }
    record_resource_completed(
        adapter,
        &journal_path,
        &mut journal,
        "backup_schedule",
        BACKUP_TIMER_UNIT,
    )
}

/// Run one scheduled backup for an installed Compose deployment. The host
/// systemd service passes its encrypted credential through stdin to the
/// verified, running product container.
pub fn create_scheduled_compose_backup_v2(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
    passphrase: &[u8],
) -> AppResult<()> {
    let _operation_lock = acquire_lifecycle_operation_lock(adapter, state_dir)?;
    let (configuration, _journal_path, _journal, operation_id) =
        load_owned_backup_schedule(adapter, state_dir)?;
    if configuration.deployment_kind != v2::DeploymentKind::LinuxCompose {
        return Err(AppError::bad_request(
            "Compose scheduled backup runner requires a Linux Compose installation",
        ));
    }
    if !(16..=4096).contains(&passphrase.len())
        || passphrase.contains(&b'\n')
        || passphrase.contains(&b'\r')
    {
        return Err(AppError::bad_request(
            "backup credential must contain 16 to 4096 bytes on one line",
        ));
    }
    let container_id = compose_owned_running_container(adapter, &operation_id)?
        .ok_or_else(|| AppError::conflict("the owned Compose server is not running", None))?;
    let args = compose_scheduled_backup_args(
        &container_id,
        &configuration.storage.data_directory,
        &configuration.storage.backup_directory,
    )?;
    let (_, _, code) = adapter
        .docker_command_with_input(&args, passphrase)
        .map_err(|_| AppError::internal("could not start the encrypted Compose backup"))?;
    if code != 0 {
        return Err(AppError::internal(format!(
            "encrypted Compose backup failed (exit {code})"
        )));
    }
    Ok(())
}

fn compose_scheduled_backup_args(
    container_id: &str,
    data_directory: &str,
    backup_directory: &str,
) -> AppResult<Vec<String>> {
    if !is_valid_container_id(container_id)
        || !Path::new(data_directory).is_absolute()
        || !Path::new(backup_directory).is_absolute()
    {
        return Err(AppError::unprocessable(
            "verified Compose backup paths or container identity are invalid",
        ));
    }
    Ok(vec![
        "exec".to_string(),
        "--interactive".to_string(),
        container_id.to_string(),
        "hs-server".to_string(),
        "--data".to_string(),
        Path::new(data_directory)
            .join("hs-server.db")
            .to_string_lossy()
            .into_owned(),
        "backup".to_string(),
        "scheduled-stdin-create".to_string(),
        "--directory".to_string(),
        backup_directory.to_string(),
    ])
}

/// Read a bounded recent-log window from the journal-owned Compose container.
/// The caller must be the root-owned host control service; no caller-provided
/// Docker arguments, project names, or container identifiers are accepted.
pub fn recent_compose_service_logs_v2(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
) -> AppResult<Vec<u8>> {
    let _operation_lock = acquire_lifecycle_operation_lock(adapter, state_dir)?;
    let (configuration, _journal_path, _journal, operation_id) =
        load_owned_backup_schedule(adapter, state_dir)?;
    if configuration.deployment_kind != v2::DeploymentKind::LinuxCompose {
        return Err(AppError::bad_request(
            "Compose service logs require a Linux Compose installation",
        ));
    }

    let container_id = compose_owned_running_container_for_logs(adapter, &operation_id)?;
    let args = vec![
        "logs".to_string(),
        "--since=15m".to_string(),
        "--tail=100".to_string(),
        "--timestamps".to_string(),
        container_id,
    ];
    let raw_logs = run_bounded_compose_log_command(adapter, &args, "read Compose service logs")?;
    sanitize_compose_service_logs(&raw_logs)
}

#[derive(serde::Serialize)]
struct ComposeLogEventMetadata {
    timestamp: String,
    event: String,
}

#[derive(serde::Serialize)]
struct ComposeLogMetadata {
    events: Vec<ComposeLogEventMetadata>,
    omitted_count: usize,
}

fn sanitize_compose_service_logs(raw_logs: &[u8]) -> AppResult<Vec<u8>> {
    let text = std::str::from_utf8(raw_logs)
        .map_err(|_| AppError::unprocessable("Compose service log output is not UTF-8"))?;
    let mut metadata = ComposeLogMetadata {
        events: Vec::new(),
        omitted_count: 0,
    };
    for (index, line) in text.lines().enumerate() {
        if index >= 100 {
            return Err(AppError::unprocessable(
                "Compose service log output exceeded its record limit",
            ));
        }
        let Some((timestamp, message)) = line.split_once(' ') else {
            metadata.omitted_count += 1;
            continue;
        };
        if !is_bounded_log_timestamp(timestamp) {
            metadata.omitted_count += 1;
            continue;
        }
        let Some(event) = compose_service_event_code(message) else {
            metadata.omitted_count += 1;
            continue;
        };
        metadata.events.push(ComposeLogEventMetadata {
            timestamp: timestamp.to_string(),
            event: event.to_string(),
        });
    }
    serde_json::to_vec(&metadata)
        .map_err(|_| AppError::internal("encode sanitized Compose service log metadata"))
}

fn is_bounded_log_timestamp(timestamp: &str) -> bool {
    (20..=40).contains(&timestamp.len())
        && timestamp.bytes().all(|byte| {
            byte.is_ascii_digit() || matches!(byte, b'T' | b':' | b'.' | b'Z' | b'+' | b'-')
        })
}

fn compose_service_event_code(message: &str) -> Option<&'static str> {
    let mut message = message.trim_start();
    if let Some((timestamp, rest)) = message.split_once(' ') {
        if is_bounded_log_timestamp(timestamp) {
            message = rest.trim_start();
        }
    }
    if let Some((level, rest)) = message.split_once(' ') {
        if matches!(level, "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR") {
            message = rest.trim_start();
        }
    }

    const EVENTS: &[(&str, &str)] = &[
        ("hs-server listening over HTTPS", "server_listening_https"),
        (
            "hs-server listening (HTTP, development foundation)",
            "server_listening_development_http",
        ),
        ("shutdown requested", "server_shutdown_requested"),
        (
            "corrupt operator_mfa_policy; denying authority",
            "operator_mfa_policy_corrupt",
        ),
        (
            "security_policy row missing; denying authority",
            "security_policy_missing",
        ),
        (
            "failed to hydrate durable security state; failing closed",
            "security_state_hydration_failed",
        ),
        (
            "latched Security State Unavailable",
            "security_state_unavailable",
        ),
        (
            "required storage operation failed",
            "required_storage_operation_failed",
        ),
        (
            "required storage lock/internal failure",
            "required_storage_lock_failed",
        ),
        (
            "file-job expiry maintenance failed",
            "file_job_expiry_maintenance_failed",
        ),
        (
            "file-request deadline maintenance failed",
            "file_request_deadline_maintenance_failed",
        ),
        ("storage operation failed", "storage_operation_failed"),
        ("password hashing failed", "password_hashing_failed"),
        ("secure randomness failed", "secure_randomness_failed"),
    ];
    EVENTS.iter().find_map(|(static_message, code)| {
        let quoted_message = format!("{static_message:?}");
        (has_log_message_prefix(message, static_message)
            || has_log_message_prefix(message, &quoted_message))
        .then_some(*code)
    })
}

fn has_log_message_prefix(message: &str, prefix: &str) -> bool {
    message == prefix
        || message
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with(' ') || suffix.starts_with('\t'))
}

fn compose_owned_running_container_for_logs(
    adapter: &dyn CommandAdapter,
    operation_id: &str,
) -> AppResult<String> {
    let project_name = compose_project_name(operation_id)?;
    let args = vec![
        "ps".to_string(),
        "--filter".to_string(),
        format!("label=com.docker.compose.project={project_name}"),
        "--filter".to_string(),
        "label=com.docker.compose.service=server".to_string(),
        "--filter".to_string(),
        "label=com.helicoid.managed=true".to_string(),
        "--filter".to_string(),
        format!("label=com.helicoid.operation-id={operation_id}"),
        "--format".to_string(),
        "{{.ID}}".to_string(),
    ];
    let output = run_bounded_compose_log_command(adapter, &args, "inspect owned Compose service")?;
    let output = std::str::from_utf8(&output)
        .map_err(|_| AppError::internal("Docker returned an invalid Compose service identity"))?;
    let ids: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if ids.len() != 1 || !is_valid_container_id(ids[0]) {
        return Err(AppError::conflict(
            "the journaled Compose server is not uniquely running",
            None,
        ));
    }
    let container_id = ids[0].to_ascii_lowercase();

    let labels = run_bounded_compose_log_command(
        adapter,
        &[
            "inspect".to_string(),
            "--format={{json .Config.Labels}}".to_string(),
            container_id.clone(),
        ],
        "verify Compose service ownership",
    )?;
    let labels: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&labels)
        .map_err(|_| AppError::internal("Docker returned invalid Compose ownership metadata"))?;
    let label = |key: &str| labels.get(key).and_then(serde_json::Value::as_str);
    if label("com.docker.compose.project") != Some(project_name.as_str())
        || label("com.docker.compose.service") != Some("server")
        || label("com.helicoid.managed") != Some("true")
        || label("com.helicoid.operation-id") != Some(operation_id)
    {
        return Err(AppError::conflict(
            "Compose container labels do not match the journaled Helicoid project",
            None,
        ));
    }

    let expected_image_id = read_compose_package_value(
        adapter,
        &Path::new(COMPOSE_DIR).join("image-id"),
        "image ID",
    )?;
    let image_id = run_bounded_compose_log_command(
        adapter,
        &[
            "inspect".to_string(),
            "--format={{.Image}}".to_string(),
            container_id.clone(),
        ],
        "verify Compose service image",
    )?;
    if std::str::from_utf8(&image_id).map(str::trim).ok() != Some(expected_image_id.as_str()) {
        return Err(AppError::conflict(
            "Compose container does not use the journaled signed image",
            None,
        ));
    }

    let state = run_bounded_compose_log_command(
        adapter,
        &[
            "inspect".to_string(),
            "--format={{.State.Status}}".to_string(),
            container_id.clone(),
        ],
        "verify Compose service state",
    )?;
    if std::str::from_utf8(&state).map(str::trim).ok() != Some("running") {
        return Err(AppError::conflict(
            "the journaled Compose server is not running",
            None,
        ));
    }
    Ok(container_id)
}

fn run_bounded_compose_log_command(
    adapter: &dyn CommandAdapter,
    args: &[String],
    action: &str,
) -> AppResult<Vec<u8>> {
    let (stdout, _stderr, code) = adapter
        .docker_command_with_timeout(args, COMPOSE_LOG_COMMAND_TIMEOUT_SECS)
        .map_err(|_| AppError::internal(format!("{action} is unavailable")))?;
    if code != 0 {
        return Err(AppError::internal(format!("{action} failed")));
    }
    if stdout.len() >= COMPOSE_LOG_OUTPUT_LIMIT {
        return Err(AppError::unprocessable(format!(
            "{action} exceeded its output limit"
        )));
    }
    Ok(stdout)
}

fn persist_operation_record(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
    record: &v2::OperationRecord,
) -> AppResult<()> {
    let bytes = serde_json::to_vec_pretty(record)
        .map_err(|error| AppError::internal(format!("serialize operation record: {error}")))?;
    adapter
        .write_file(&operation_record_path(state_dir), &bytes)
        .map_err(|error| AppError::internal(format!("persist operation record: {error}")))
}

fn load_or_create_operation_record(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
    configuration: &v2::DeploymentConfiguration,
    reviewed_plan_digest: &str,
) -> AppResult<v2::OperationRecord> {
    let path = operation_record_path(state_dir);
    if adapter.path_exists(&path) {
        let bytes = adapter.read_file(&path).map_err(|error| {
            AppError::internal(format!("cannot read operation record: {error}"))
        })?;
        let record: v2::OperationRecord = serde_json::from_slice(&bytes)
            .map_err(|error| AppError::internal(format!("corrupt operation record: {error}")))?;
        if record.contract_version != v2::CONTRACT_VERSION
            || record.configuration != *configuration
            || record.reviewed_plan_digest != reviewed_plan_digest
            || uuid::Uuid::parse_str(&record.operation_id).is_err()
        {
            return Err(AppError::conflict(
                "the durable operation record belongs to a different reviewed plan or configuration",
                None,
            ));
        }
        return Ok(record);
    }

    let record = v2::OperationRecord {
        contract_version: v2::CONTRACT_VERSION,
        operation_id: uuid::Uuid::new_v4().to_string(),
        action: v2::LifecycleAction::Install,
        resource_operation_id: None,
        reviewed_plan_digest: reviewed_plan_digest.to_string(),
        configuration: configuration.clone(),
        created_at: adapter.now_iso8601(),
        outcome: None,
    };
    persist_operation_record(adapter, state_dir, &record)?;
    Ok(record)
}

/// Start or resume the current v2 install operation. The existing installer
/// verifies the package and canonical resource plan again before any effect.
pub fn apply_v2(
    adapter: &dyn CommandAdapter,
    input: &v2::ApplyInput,
    state_dir: &Path,
) -> AppResult<v2::OperationStatus> {
    run_v2_operation(adapter, input, state_dir, false)
}

/// Resume only an already journaled operation with the same reviewed request.
pub fn resume_v2(
    adapter: &dyn CommandAdapter,
    input: &v2::ApplyInput,
    state_dir: &Path,
) -> AppResult<v2::OperationStatus> {
    run_v2_operation(adapter, input, state_dir, true)
}

/// Remove the journaled Linux installation through the v2 lifecycle contract.
/// The durable operation record is written before host effects and retained
/// after completion so status can distinguish removal from an absent install.
pub fn remove_v2(
    adapter: &dyn CommandAdapter,
    input: &v2::RemoveInput,
    state_dir: &Path,
) -> AppResult<v2::OperationStatus> {
    if input.contract_version != v2::CONTRACT_VERSION {
        return Err(AppError::bad_request(format!(
            "unsupported lifecycle contract_version: {} (expected {})",
            input.contract_version,
            v2::CONTRACT_VERSION
        )));
    }
    validate_v2_configuration(&input.configuration)?;
    if !input.confirm {
        return Err(AppError::bad_request("remove requires confirm: true"));
    }
    let _operation_lock = acquire_lifecycle_operation_lock(adapter, state_dir)?;
    validate_v2_removal_state_dir(adapter, state_dir)?;

    let journal_path = state_dir.join("journal.json");
    let record_path = operation_record_path(state_dir);
    let existing_record = if adapter.path_exists(&record_path) {
        let bytes = adapter.read_file(&record_path).map_err(|error| {
            AppError::internal(format!("cannot read operation record: {error}"))
        })?;
        let record: v2::OperationRecord = serde_json::from_slice(&bytes)
            .map_err(|error| AppError::internal(format!("corrupt operation record: {error}")))?;
        if record.contract_version != v2::CONTRACT_VERSION
            || !same_configuration_ignoring_removal_policy(
                &record.configuration,
                &input.configuration,
            )
            || uuid::Uuid::parse_str(&record.operation_id).is_err()
        {
            return Err(AppError::conflict(
                "operation record does not match the requested deployment configuration",
                None,
            ));
        }
        Some(record)
    } else {
        None
    };

    if existing_record.is_none()
        && (input.configuration.storage.data_directory != DATA_SUBDIR
            || input.configuration.storage.backup_directory != BACKUP_DIR)
    {
        return Err(AppError::conflict(
            "custom storage removal requires the durable install configuration record",
            None,
        ));
    }

    if !adapter.path_exists(&journal_path) {
        let Some(mut record) = existing_record else {
            return operation_status_v2(
                adapter,
                &v2::StatusInput {
                    contract_version: v2::CONTRACT_VERSION,
                    configuration: input.configuration.clone(),
                },
                state_dir,
            );
        };
        if record.action != v2::LifecycleAction::Remove {
            return Err(AppError::conflict(
                "the ownership journal is missing; refusing to infer removal from an install record",
                None,
            ));
        }
        let removal_journal_present = input.configuration.deployment_kind
            == v2::DeploymentKind::LinuxCompose
            && path_present(adapter, &state_dir.join("removal-v2.json"));
        let compose_removal_complete = if removal_journal_present {
            compose_removal_journal_complete(adapter, state_dir, &record)?
        } else {
            false
        };
        let resources_remain =
            if input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose {
                match record.resource_operation_id.as_deref() {
                    Some(operation_id) => compose_resources_remain(adapter, operation_id)?.1,
                    None => true,
                }
            } else {
                owned_service_resources_remain(adapter)?
            };
        if let Some(outcome) = &record.outcome {
            if outcome.state == v2::OperationState::Completed {
                if resources_remain
                    || (removal_journal_present && !compose_removal_complete)
                    || (input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose
                        && !compose_removal_files_are_gone(adapter, &input.configuration)?)
                {
                    return Err(AppError::conflict(
                        "removal is recorded complete but its journal or owned service resources remain; inspect the host manually",
                        None,
                    ));
                }
                if removal_journal_present {
                    adapter
                        .remove_file(&state_dir.join("removal-v2.json"))
                        .map_err(|error| {
                            AppError::internal(format!(
                                "remove completed Compose removal journal: {error}"
                            ))
                        })?;
                }
                return operation_status_v2(
                    adapter,
                    &v2::StatusInput {
                        contract_version: v2::CONTRACT_VERSION,
                        configuration: input.configuration.clone(),
                    },
                    state_dir,
                );
            }
        }
        if resources_remain
            || (input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose
                && (!removal_journal_present
                    || !compose_removal_complete
                    || !compose_removal_files_are_gone(adapter, &input.configuration)?))
            || (input.configuration.deployment_kind != v2::DeploymentKind::LinuxCompose
                && removal_journal_present)
        {
            return Err(AppError::conflict(
                "the ownership journal is missing while its removal journal or Helicoid service resources remain; refusing automatic removal",
                None,
            ));
        }
        record.outcome = Some(v2::OperationOutcome {
            state: v2::OperationState::Completed,
            result: v2::OperationResult {
                code: "removed".to_string(),
                summary: if input.configuration.storage.preserve_data_on_remove {
                    format!(
                        "The installed service was removed. Data and backups remain at {} and {}.",
                        input.configuration.storage.data_directory,
                        input.configuration.storage.backup_directory
                    )
                } else {
                    "The installed service and its configured data and backups were removed."
                        .to_string()
                },
                errors: vec![],
                warnings: vec![],
            },
        });
        persist_operation_record(adapter, state_dir, &record)?;
        if removal_journal_present {
            adapter
                .remove_file(&state_dir.join("removal-v2.json"))
                .map_err(|error| {
                    AppError::internal(format!("remove completed Compose removal journal: {error}"))
                })?;
        }
        return operation_status_v2(
            adapter,
            &v2::StatusInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: input.configuration.clone(),
            },
            state_dir,
        );
    }

    let journal_bytes = adapter
        .read_file(&journal_path)
        .map_err(|error| AppError::internal(format!("cannot read installer journal: {error}")))?;
    let _: Journal = serde_json::from_slice(&journal_bytes)
        .map_err(|error| AppError::internal(format!("corrupt installer journal: {error}")))?;
    let digest_input = serde_json::to_vec(&(
        v2::CONTRACT_VERSION,
        "remove",
        &input.configuration,
        manifest::sha256_hex(&journal_bytes),
    ))
    .map_err(|error| AppError::internal(format!("serialize remove review: {error}")))?;
    let reviewed_digest = manifest::sha256_hex(&digest_input);

    let mut record = match existing_record {
        Some(record) if record.action == v2::LifecycleAction::Remove => {
            if record.reviewed_plan_digest != reviewed_digest {
                return Err(AppError::conflict(
                    "the removal journal changed after the v2 removal operation was reviewed",
                    None,
                ));
            }
            record
        }
        Some(record) if record.action != v2::LifecycleAction::Install => {
            return Err(AppError::conflict(
                "another lifecycle operation is recorded; inspect or finish it before removal",
                None,
            ));
        }
        Some(record) if record.action == v2::LifecycleAction::Install => v2::OperationRecord {
            contract_version: v2::CONTRACT_VERSION,
            operation_id: uuid::Uuid::new_v4().to_string(),
            action: v2::LifecycleAction::Remove,
            resource_operation_id: Some(record.operation_id),
            reviewed_plan_digest: reviewed_digest,
            configuration: input.configuration.clone(),
            created_at: adapter.now_iso8601(),
            outcome: None,
        },
        _ => v2::OperationRecord {
            contract_version: v2::CONTRACT_VERSION,
            operation_id: uuid::Uuid::new_v4().to_string(),
            action: v2::LifecycleAction::Remove,
            resource_operation_id: None,
            reviewed_plan_digest: reviewed_digest,
            configuration: input.configuration.clone(),
            created_at: adapter.now_iso8601(),
            outcome: None,
        },
    };
    record.action = v2::LifecycleAction::Remove;
    record.outcome = None;
    persist_operation_record(adapter, state_dir, &record)?;

    let removal_input = RemoveInput {
        contract_version: CONTRACT_VERSION,
        state_dir: state_dir.to_string_lossy().into_owned(),
        delete_data: !input.configuration.storage.preserve_data_on_remove,
        confirm: input.confirm,
    };
    let removal = if input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose {
        let compose_errors = remove_compose_resources(adapter, state_dir, &record)?;
        if compose_errors.is_empty() {
            remove_with_storage(
                adapter,
                &removal_input,
                &input.configuration.storage.data_directory,
                &input.configuration.storage.backup_directory,
            )?
        } else {
            RemoveResult {
                contract_version: CONTRACT_VERSION,
                ok: false,
                removed: vec![],
                data_preserved: true,
                data_dir: Some(input.configuration.storage.data_directory.clone()),
                backup_dir: Some(input.configuration.storage.backup_directory.clone()),
                errors: compose_errors,
            }
        }
    } else {
        remove_with_storage(
            adapter,
            &removal_input,
            &input.configuration.storage.data_directory,
            &input.configuration.storage.backup_directory,
        )?
    };
    let state = if removal.ok {
        v2::OperationState::Completed
    } else {
        v2::OperationState::AttentionRequired
    };
    let result = v2::OperationResult {
        code: if removal.ok {
            "removed".to_string()
        } else {
            "remove_failed".to_string()
        },
        summary: if !removal.ok {
            "Removal is incomplete; owned service resources or data may remain. Review the errors and retry while the ownership journal is available.".to_string()
        } else if removal.data_preserved {
            format!(
                "The installed service was removed. Data and backups remain at {} and {}.",
                input.configuration.storage.data_directory,
                input.configuration.storage.backup_directory
            )
        } else {
            "The installed service and its configured data and backups were removed.".to_string()
        },
        errors: removal.errors,
        warnings: vec![],
    };
    record.outcome = Some(v2::OperationOutcome { state, result });
    persist_operation_record(adapter, state_dir, &record)?;
    if removal.ok && input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose {
        let removal_journal = state_dir.join("removal-v2.json");
        if path_present(adapter, &removal_journal) {
            adapter.remove_file(&removal_journal).map_err(|error| {
                AppError::internal(format!("remove completed Compose removal journal: {error}"))
            })?;
        }
    }
    operation_status_v2(
        adapter,
        &v2::StatusInput {
            contract_version: v2::CONTRACT_VERSION,
            configuration: input.configuration.clone(),
        },
        state_dir,
    )
}

fn validate_v2_removal_state_dir(adapter: &dyn CommandAdapter, state_dir: &Path) -> AppResult<()> {
    const PRODUCT_STATE_DIR: &str = "/opt/helicoid/.installer";
    if state_dir != Path::new(PRODUCT_STATE_DIR) {
        return Err(AppError::not_implemented(
            "v2 removal is limited to /opt/helicoid/.installer",
        ));
    }
    for name in [
        "journal.json",
        "operation-v2.json",
        "installed.json",
        "removal-v2.json",
    ] {
        let path = state_dir.join(name);
        let path_text = path
            .to_str()
            .ok_or_else(|| AppError::bad_request("installer state path is not valid UTF-8"))?;
        reject_symlink_parents(adapter, path_text)?;
        if path_present(adapter, &path) {
            let metadata = adapter.symlink_metadata(&path).map_err(|error| {
                AppError::internal(format!(
                    "inspect installer state file {}: {error}",
                    path.display()
                ))
            })?;
            if metadata.is_symlink || metadata.is_dir {
                return Err(AppError::forbidden(format!(
                    "refusing to operate on symlink or directory at installer state path {}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

fn owned_service_resources_remain(adapter: &dyn CommandAdapter) -> AppResult<bool> {
    let unit_exists = adapter
        .query_unit_exists(UNIT_NAME)
        .map_err(|error| AppError::internal(format!("inspect service unit: {error}")))?;
    let user_exists = adapter
        .query_user_exists(SERVICE_USER)
        .map_err(|error| AppError::internal(format!("inspect service user: {error}")))?;
    let binary_path = PathBuf::from(format!("{BASE_DIR}/bin/hs-server"));
    let unit_path = PathBuf::from(format!("/etc/systemd/system/{UNIT_NAME}"));
    Ok(unit_exists
        || user_exists
        || path_present(adapter, &binary_path)
        || path_present(adapter, &unit_path))
}

fn run_v2_operation(
    adapter: &dyn CommandAdapter,
    input: &v2::ApplyInput,
    state_dir: &Path,
    resume_only: bool,
) -> AppResult<v2::OperationStatus> {
    if input.contract_version != v2::CONTRACT_VERSION {
        return Err(AppError::bad_request(format!(
            "unsupported lifecycle contract_version: {} (expected {})",
            input.contract_version,
            v2::CONTRACT_VERSION
        )));
    }
    let _operation_lock = acquire_lifecycle_operation_lock(adapter, state_dir)?;
    validate_v2_configuration(&input.configuration)?;
    if input.preflight.contract_version != v2::CONTRACT_VERSION
        || input.preflight.host_checks.contract_version != CONTRACT_VERSION
        || input.preflight.configuration != input.configuration
        || (input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose
            && !input
                .preflight
                .docker_compose_runtime
                .as_ref()
                .is_some_and(|runtime| runtime.available))
    {
        return Err(AppError::bad_request(format!(
            "preflight configuration or contract version does not match the reviewed v2 request (host v{})",
            CONTRACT_VERSION
        )));
    }
    if !input.preflight.ok || !input.preflight.host_checks.ok {
        return Err(AppError::bad_request(
            "preflight checks failed; cannot apply the reviewed plan",
        ));
    }
    if !input.confirm {
        return Err(AppError::bad_request("install requires confirm: true"));
    }
    let expected_digest =
        compute_reviewed_plan_digest_v2(&input.configuration, &input.preflight, &input.plan)?;
    if input.reviewed_plan_digest != expected_digest {
        return Err(AppError::forbidden(
            "reviewed_plan_digest does not match the reviewed configuration and resource plan",
        ));
    }
    let current_tls_certificate_sha256 =
        validate_network_tls_configuration(adapter, &input.configuration)?;
    if input.preflight.tls_certificate_sha256 != current_tls_certificate_sha256
        || input.preflight.tls_subject_name_verified != current_tls_certificate_sha256.is_some()
    {
        return Err(AppError::conflict(
            "TLS certificate or subject-name verification changed after plan review; generate a new plan",
            None,
        ));
    }

    if resume_only
        && (!adapter.path_exists(&state_dir.join("journal.json"))
            || !adapter.path_exists(&operation_record_path(state_dir)))
    {
        return Err(AppError::conflict(
            "resume requires an existing v2 operation record and phase journal",
            None,
        ));
    }
    if !resume_only {
        if adapter.path_exists(&state_dir.join("journal.json")) {
            return Err(AppError::conflict(
                "an installer journal already exists; continue it with resume-v2",
                None,
            ));
        }
        let current_preflight = preflight_v2(
            adapter,
            &v2::PreflightInput {
                contract_version: v2::CONTRACT_VERSION,
                configuration: input.configuration.clone(),
            },
        )?;
        if !current_preflight.ok {
            return Err(AppError::conflict(
                "host preflight has changed or no longer passes; review a fresh plan before applying",
                None,
            ));
        }
        let reviewed = serde_json::to_vec(&input.preflight.host_checks).map_err(|error| {
            AppError::internal(format!("serialize reviewed preflight: {error}"))
        })?;
        let current = serde_json::to_vec(&current_preflight.host_checks)
            .map_err(|error| AppError::internal(format!("serialize current preflight: {error}")))?;
        if reviewed != current {
            return Err(AppError::conflict(
                "host preflight differs from the reviewed result; generate a new plan",
                None,
            ));
        }
        if input.preflight.tls_certificate_sha256 != current_preflight.tls_certificate_sha256
            || input.preflight.tls_subject_name_verified
                != current_preflight.tls_subject_name_verified
        {
            return Err(AppError::conflict(
                "TLS certificate or subject-name verification changed after plan review; generate a new plan",
                None,
            ));
        }
        if input.preflight.docker_compose_runtime != current_preflight.docker_compose_runtime {
            return Err(AppError::conflict(
                "Docker Engine or Compose runtime changed after plan review; generate a new plan",
                None,
            ));
        }
    } else if input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose {
        let current_runtime = check_docker_compose_runtime(adapter);
        if !current_runtime.available
            || input.preflight.docker_compose_runtime.as_ref() != Some(&current_runtime)
        {
            return Err(AppError::conflict(
                "Docker Engine or Compose runtime changed or is unavailable; resolve it before resuming",
                None,
            ));
        }
    }

    let record = load_or_create_operation_record(
        adapter,
        state_dir,
        &input.configuration,
        &input.reviewed_plan_digest,
    )?;
    let legacy_input = super::models::ApplyInput {
        contract_version: CONTRACT_VERSION,
        plan: input.plan.clone(),
        preflight: input.preflight.host_checks.clone(),
        confirm: input.confirm,
        package_dir: Some(input.package_dir.clone()),
        verify_key: Some(input.verify_key.clone()),
    };
    let _ = apply_internal(
        adapter,
        &legacy_input,
        state_dir,
        Some(&input.configuration),
        Some(&record.operation_id),
    )?;
    operation_status_v2(
        adapter,
        &v2::StatusInput {
            contract_version: v2::CONTRACT_VERSION,
            configuration: record.configuration,
        },
        state_dir,
    )
}

/// Read the durable v2 operation record and phase journal without host effects.
pub fn operation_status_v2(
    adapter: &dyn CommandAdapter,
    input: &v2::StatusInput,
    state_dir: &Path,
) -> AppResult<v2::OperationStatus> {
    use v2::{OperationResult, OperationState};

    if input.contract_version != v2::CONTRACT_VERSION {
        return Err(AppError::bad_request(format!(
            "unsupported lifecycle contract_version: {} (expected {})",
            input.contract_version,
            v2::CONTRACT_VERSION
        )));
    }
    validate_v2_configuration(&input.configuration)?;
    if input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose {
        return compose_operation_status(adapter, input, state_dir);
    }

    let journal_path = state_dir.join("journal.json");
    let record_path = operation_record_path(state_dir);
    if !adapter.path_exists(&journal_path) {
        let record = if adapter.path_exists(&record_path) {
            let bytes = adapter.read_file(&record_path).map_err(|error| {
                AppError::internal(format!("cannot read operation record: {error}"))
            })?;
            Some(
                serde_json::from_slice::<v2::OperationRecord>(&bytes).map_err(|error| {
                    AppError::internal(format!("corrupt operation record: {error}"))
                })?,
            )
        } else {
            None
        };
        if record.as_ref().is_some_and(|record| {
            record.contract_version != v2::CONTRACT_VERSION
                || (record.action == v2::LifecycleAction::Remove
                    && !same_configuration_ignoring_removal_policy(
                        &record.configuration,
                        &input.configuration,
                    ))
                || (record.action != v2::LifecycleAction::Remove
                    && record.configuration != input.configuration)
                || uuid::Uuid::parse_str(&record.operation_id).is_err()
        }) {
            return Err(AppError::unprocessable(
                "operation record does not match the requested deployment configuration",
            ));
        }
        if let Some(record) = record {
            if record.action == v2::LifecycleAction::Remove {
                return remove_operation_status(adapter, input, record, false);
            }
            return Ok(v2::OperationStatus {
                contract_version: v2::CONTRACT_VERSION,
                configuration: input.configuration.clone(),
                operation_id: Some(record.operation_id),
                action: Some(record.action),
                state: OperationState::AttentionRequired,
                reviewed_plan_digest: Some(record.reviewed_plan_digest),
                current_phase: None,
                phases: BTreeMap::new(),
                cancellation_available: false,
                resume_available: false,
                service_installed: false,
                bootstrap_ready: false,
                server_ready_for_enrollment: false,
                result: OperationResult {
                    code: "journal_missing".to_string(),
                    summary: "An operation identity exists, but no phase journal is available; its result cannot be confirmed.".to_string(),
                    errors: vec![],
                    warnings: vec![],
                },
            });
        }
        return Ok(v2::OperationStatus {
            contract_version: v2::CONTRACT_VERSION,
            configuration: input.configuration.clone(),
            operation_id: None,
            action: None,
            state: OperationState::NotInstalled,
            reviewed_plan_digest: None,
            current_phase: None,
            phases: BTreeMap::new(),
            cancellation_available: false,
            resume_available: false,
            service_installed: false,
            bootstrap_ready: false,
            server_ready_for_enrollment: false,
            result: OperationResult {
                code: "not_installed".to_string(),
                summary: "No installer journal is present.".to_string(),
                errors: vec![],
                warnings: vec![],
            },
        });
    }

    let bytes = adapter
        .read_file(&journal_path)
        .map_err(|error| AppError::internal(format!("cannot read installer journal: {error}")))?;
    let journal: Journal = serde_json::from_slice(&bytes)
        .map_err(|error| AppError::internal(format!("corrupt installer journal: {error}")))?;
    let record = if adapter.path_exists(&record_path) {
        let bytes = adapter.read_file(&record_path).map_err(|error| {
            AppError::internal(format!("cannot read operation record: {error}"))
        })?;
        Some(
            serde_json::from_slice::<v2::OperationRecord>(&bytes).map_err(|error| {
                AppError::internal(format!("corrupt operation record: {error}"))
            })?,
        )
    } else {
        None
    };
    if let Some(record) = &record {
        if record.contract_version != v2::CONTRACT_VERSION
            || (record.action == v2::LifecycleAction::Remove
                && !same_configuration_ignoring_removal_policy(
                    &record.configuration,
                    &input.configuration,
                ))
            || (record.action != v2::LifecycleAction::Remove
                && record.configuration != input.configuration)
            || uuid::Uuid::parse_str(&record.operation_id).is_err()
        {
            return Err(AppError::unprocessable(
                "operation record does not match the requested deployment configuration",
            ));
        }
        if record.action == v2::LifecycleAction::Remove {
            return remove_operation_status(adapter, input, record.clone(), true);
        }
    }

    let phases: BTreeMap<String, PhaseStatus> = journal
        .phases
        .iter()
        .map(|(name, entry)| (name.clone(), entry.status))
        .collect();
    let completed = phases.get("completed") == Some(&PhaseStatus::Completed);
    let failed = phases.values().any(|status| *status == PhaseStatus::Failed);
    let interrupted = phases
        .values()
        .any(|status| *status == PhaseStatus::InProgress);
    let installed = journal
        .phases
        .get("units")
        .is_some_and(|entry| entry.status == PhaseStatus::Completed);
    let state = if completed {
        OperationState::Completed
    } else if failed {
        OperationState::AttentionRequired
    } else {
        OperationState::InProgress
    };
    let errors = journal
        .phases
        .values()
        .filter_map(|entry| entry.error.clone())
        .collect::<Vec<_>>();
    let (code, summary) = if completed {
        ("completed", "The service package was installed.")
    } else if failed {
        (
            "phase_failed",
            "An installer phase failed; review the result before resuming.",
        )
    } else if interrupted {
        (
            "interrupted",
            "The durable phase journal has an interrupted operation.",
        )
    } else {
        (
            "in_progress",
            "The durable phase journal records an incomplete operation.",
        )
    };

    Ok(v2::OperationStatus {
        contract_version: v2::CONTRACT_VERSION,
        configuration: input.configuration.clone(),
        operation_id: record.as_ref().map(|item| item.operation_id.clone()),
        action: record.as_ref().map(|item| item.action),
        state,
        reviewed_plan_digest: record
            .as_ref()
            .map(|item| item.reviewed_plan_digest.clone()),
        current_phase: Some(journal.current_phase),
        phases,
        cancellation_available: false,
        resume_available: !completed && record.is_some(),
        service_installed: installed,
        // The current unit starts loopback development HTTP and does not prove
        // authenticated bootstrap, so it cannot claim readiness for enrollment.
        bootstrap_ready: false,
        server_ready_for_enrollment: false,
        result: OperationResult {
            code: code.to_string(),
            summary: summary.to_string(),
            errors,
            warnings: vec![],
        },
    })
}

fn compose_operation_status(
    adapter: &dyn CommandAdapter,
    input: &v2::StatusInput,
    state_dir: &Path,
) -> AppResult<v2::OperationStatus> {
    use v2::{OperationResult, OperationState};

    validate_v2_removal_state_dir(adapter, state_dir)?;
    let journal_path = state_dir.join("journal.json");
    let record_path = operation_record_path(state_dir);
    if !adapter.path_exists(&journal_path) {
        let record = if path_present(adapter, &record_path) {
            let bytes = adapter.read_file(&record_path).map_err(|error| {
                AppError::internal(format!("cannot read operation record: {error}"))
            })?;
            Some(
                serde_json::from_slice::<v2::OperationRecord>(&bytes).map_err(|error| {
                    AppError::internal(format!("corrupt operation record: {error}"))
                })?,
            )
        } else {
            None
        };
        if let Some(record) = &record {
            if record.contract_version != v2::CONTRACT_VERSION
                || record.configuration != input.configuration
                || uuid::Uuid::parse_str(&record.operation_id).is_err()
            {
                return Err(AppError::unprocessable(
                    "operation record does not match the requested Compose configuration",
                ));
            }
            if record.action == v2::LifecycleAction::Remove {
                return remove_operation_status(adapter, input, record.clone(), false);
            }
            return Ok(v2::OperationStatus {
                contract_version: v2::CONTRACT_VERSION,
                configuration: input.configuration.clone(),
                operation_id: Some(record.operation_id.clone()),
                action: Some(record.action),
                state: OperationState::AttentionRequired,
                reviewed_plan_digest: Some(record.reviewed_plan_digest.clone()),
                current_phase: None,
                phases: BTreeMap::new(),
                cancellation_available: false,
                resume_available: false,
                service_installed: false,
                bootstrap_ready: false,
                server_ready_for_enrollment: false,
                result: OperationResult {
                    code: "journal_missing".to_string(),
                    summary:
                        "A Compose operation record exists, but its ownership journal is missing."
                            .to_string(),
                    errors: vec![],
                    warnings: vec![],
                },
            });
        }
        return Ok(v2::OperationStatus {
            contract_version: v2::CONTRACT_VERSION,
            configuration: input.configuration.clone(),
            operation_id: None,
            action: None,
            state: OperationState::NotInstalled,
            reviewed_plan_digest: None,
            current_phase: None,
            phases: BTreeMap::new(),
            cancellation_available: false,
            resume_available: false,
            service_installed: false,
            bootstrap_ready: false,
            server_ready_for_enrollment: false,
            result: OperationResult {
                code: "not_installed".to_string(),
                summary: "No Compose installer journal is present.".to_string(),
                errors: vec![],
                warnings: vec![],
            },
        });
    }

    let journal_bytes = adapter.read_file(&journal_path).map_err(|error| {
        AppError::internal(format!("cannot read Compose installer journal: {error}"))
    })?;
    let journal: Journal = serde_json::from_slice(&journal_bytes)
        .map_err(|error| AppError::internal(format!("corrupt Compose journal: {error}")))?;
    let record = if path_present(adapter, &record_path) {
        let bytes = adapter.read_file(&record_path).map_err(|error| {
            AppError::internal(format!("cannot read Compose operation record: {error}"))
        })?;
        Some(
            serde_json::from_slice::<v2::OperationRecord>(&bytes).map_err(|error| {
                AppError::internal(format!("corrupt Compose operation record: {error}"))
            })?,
        )
    } else {
        None
    };
    if let Some(record) = &record {
        if record.contract_version != v2::CONTRACT_VERSION
            || (record.action == v2::LifecycleAction::Remove
                && !same_configuration_ignoring_removal_policy(
                    &record.configuration,
                    &input.configuration,
                ))
            || (record.action != v2::LifecycleAction::Remove
                && record.configuration != input.configuration)
            || uuid::Uuid::parse_str(&record.operation_id).is_err()
        {
            return Err(AppError::unprocessable(
                "Compose operation record does not match the requested deployment configuration",
            ));
        }
        if record.action == v2::LifecycleAction::Remove {
            return remove_operation_status(adapter, input, record.clone(), true);
        }
    }

    let phases = journal
        .phases
        .iter()
        .map(|(name, entry)| (name.clone(), entry.status))
        .collect::<BTreeMap<_, _>>();
    let phase_completed = phases.get("completed") == Some(&PhaseStatus::Completed);
    let phase_failed = phases.values().any(|status| *status == PhaseStatus::Failed);
    let interrupted = phases
        .values()
        .any(|status| *status == PhaseStatus::InProgress);
    let mut errors = journal
        .phases
        .values()
        .filter_map(|entry| entry.error.clone())
        .collect::<Vec<_>>();
    let mut service_installed = false;
    let mut service_running = false;
    let mut health_state = String::new();
    let mut readiness_probe = None;
    let mut runtime_error = None;
    let mut readiness_warning = false;

    if phases.get("units") == Some(&PhaseStatus::Completed) {
        if let Some(record) = &record {
            let image_id_path = Path::new(COMPOSE_DIR).join("image-id");
            match read_compose_package_value(adapter, &image_id_path, "image ID") {
                Ok(image_id) => {
                    let project_name = compose_project_name(&record.operation_id)?;
                    match compose_project_containers(adapter, &project_name) {
                        Ok(containers) if containers.len() == 1 => {
                            match verify_compose_container(
                                adapter,
                                &containers[0],
                                &project_name,
                                &record.operation_id,
                                &image_id,
                            ) {
                                Ok(()) => {
                                    service_installed = true;
                                    match compose_container_state(adapter, &containers[0]) {
                                        Ok(state) if state == "running" => {
                                            service_running = true;
                                            match compose_container_health_state(
                                                adapter,
                                                &containers[0],
                                            ) {
                                                Ok(health) => health_state = health,
                                                Err(error) => {
                                                    runtime_error = Some(error.to_string())
                                                }
                                            }
                                            match compose_container_readiness(
                                                adapter,
                                                &containers[0],
                                            ) {
                                                Ok(readiness) => readiness_probe = Some(readiness),
                                                Err(_) => readiness_warning = true,
                                            }
                                        }
                                        Ok(state) => {
                                            runtime_error = Some(format!(
                                                "journaled Compose server is not running (state: {})",
                                                state
                                            ));
                                        }
                                        Err(error) => runtime_error = Some(error.to_string()),
                                    }
                                }
                                Err(error) => runtime_error = Some(error.to_string()),
                            }
                        }
                        Ok(_) => {
                            runtime_error = Some(
                                "journaled Compose project does not contain exactly one server container".to_string(),
                            );
                        }
                        Err(error) => runtime_error = Some(error.to_string()),
                    }
                }
                Err(error) => runtime_error = Some(error.to_string()),
            }
        } else {
            runtime_error = Some("Compose ownership journal has no operation record".to_string());
        }
    }

    if let Some(error) = runtime_error.as_ref() {
        errors.push(error.clone());
    }
    let state = if phase_completed && service_running {
        OperationState::Completed
    } else if phase_failed || (phase_completed && !service_running) {
        OperationState::AttentionRequired
    } else {
        OperationState::InProgress
    };
    let (bootstrap_ready, server_ready_for_enrollment) =
        compose_readiness_flags(&health_state, readiness_probe.as_ref());
    let (code, summary) = match state {
        OperationState::Completed if server_ready_for_enrollment => (
            "installed_and_healthy",
            "The journaled Compose server container is running and its healthcheck confirms bootstrap and enrollment readiness.",
        ),
        OperationState::Completed if bootstrap_ready => (
            "installed_bootstrap_ready",
            "The journaled Compose server container is running and ready for initial bootstrap; enrollment readiness is pending.",
        ),
        OperationState::Completed => (
            "installed",
            "The journaled Compose server container is running. Its healthcheck has not confirmed bootstrap and enrollment readiness.",
        ),
        OperationState::AttentionRequired => (
            "compose_reconciliation_required",
            "Compose resources do not match the completed journal or an install phase failed; inspect the reported errors before retrying.",
        ),
        _ if interrupted => (
            "interrupted",
            "The Compose ownership journal records an interrupted operation.",
        ),
        _ => (
            "in_progress",
            "The durable Compose journal records an incomplete operation.",
        ),
    };

    Ok(v2::OperationStatus {
        contract_version: v2::CONTRACT_VERSION,
        configuration: input.configuration.clone(),
        operation_id: record.as_ref().map(|record| record.operation_id.clone()),
        action: record.as_ref().map(|record| record.action),
        state,
        reviewed_plan_digest: record
            .as_ref()
            .map(|record| record.reviewed_plan_digest.clone()),
        current_phase: Some(journal.current_phase),
        phases,
        cancellation_available: false,
        resume_available: record.as_ref().is_some_and(|record| {
            record.action == v2::LifecycleAction::Install
                && (!phase_completed || phase_failed || interrupted || !service_running)
        }),
        service_installed,
        // Compose health succeeds only after bootstrap, so it confirms
        // enrollment readiness but cannot mean initial bootstrap is pending.
        bootstrap_ready,
        server_ready_for_enrollment,
        result: OperationResult {
            code: code.to_string(),
            summary: summary.to_string(),
            errors,
            warnings: if readiness_warning {
                vec![
                    "The verified Compose container did not return a valid local readiness probe."
                        .to_string(),
                ]
            } else {
                vec![]
            },
        },
    })
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ComposeRemovalJournal {
    contract_version: u32,
    operation_id: String,
    resource_operation_id: String,
    reviewed_plan_digest: String,
    resources: BTreeMap<String, ResourceStatus>,
}

fn compose_removal_journal_complete(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
    record: &v2::OperationRecord,
) -> AppResult<bool> {
    let path = state_dir.join("removal-v2.json");
    let metadata = adapter
        .symlink_metadata(&path)
        .map_err(|error| AppError::internal(format!("inspect Compose removal journal: {error}")))?;
    if metadata.is_symlink || metadata.is_dir || metadata.len == 0 || metadata.len > 1024 * 1024 {
        return Ok(false);
    }
    let bytes = adapter
        .read_file(&path)
        .map_err(|error| AppError::internal(format!("read Compose removal journal: {error}")))?;
    let journal: ComposeRemovalJournal = serde_json::from_slice(&bytes)
        .map_err(|error| AppError::internal(format!("corrupt Compose removal journal: {error}")))?;
    let Some(resource_operation_id) = record.resource_operation_id.as_deref() else {
        return Ok(false);
    };
    if journal.contract_version != v2::CONTRACT_VERSION
        || journal.operation_id != record.operation_id
        || journal.resource_operation_id != resource_operation_id
        || journal.reviewed_plan_digest != record.reviewed_plan_digest
        || journal
            .resources
            .values()
            .any(|status| *status != ResourceStatus::Completed)
    {
        return Ok(false);
    }
    if !record.configuration.storage.preserve_data_on_remove
        && journal
            .resources
            .get("manager_identity:/var/lib/helicoid/.local/state/helicoid")
            != Some(&ResourceStatus::Completed)
    {
        return Ok(false);
    }
    Ok(true)
}

fn compose_removal_files_are_gone(
    adapter: &dyn CommandAdapter,
    configuration: &v2::DeploymentConfiguration,
) -> AppResult<bool> {
    let mut paths = vec![Path::new(COMPOSE_DIR).to_path_buf()];
    if !configuration.storage.preserve_data_on_remove {
        paths.extend([
            PathBuf::from(&configuration.storage.data_directory),
            PathBuf::from(&configuration.storage.backup_directory),
            PathBuf::from(COMPOSE_MANAGER_IDENTITY_DIR),
        ]);
    }
    for path in paths {
        match adapter.symlink_metadata(&path) {
            Ok(_) => return Ok(false),
            Err(error) if is_missing_path_error(&error) => {}
            Err(error) => {
                return Err(AppError::internal(format!(
                    "inspect removed Compose path {}: {error}",
                    path.display()
                )))
            }
        }
    }
    Ok(true)
}

fn load_compose_removal_journal(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
    record: &v2::OperationRecord,
) -> AppResult<ComposeRemovalJournal> {
    let resource_operation_id = record.resource_operation_id.as_deref().ok_or_else(|| {
        AppError::conflict(
            "Compose removal record is missing the install resource identity",
            None,
        )
    })?;
    uuid::Uuid::parse_str(resource_operation_id)
        .map_err(|_| AppError::unprocessable("Compose install identity is invalid"))?;
    let path = state_dir.join("removal-v2.json");
    if path_present(adapter, &path) {
        let metadata = adapter.symlink_metadata(&path).map_err(|error| {
            AppError::internal(format!("inspect Compose removal journal: {error}"))
        })?;
        if metadata.is_symlink || metadata.is_dir || metadata.len == 0 || metadata.len > 1024 * 1024
        {
            return Err(AppError::forbidden(
                "Compose removal journal has an invalid file shape",
            ));
        }
        let bytes = adapter.read_file(&path).map_err(|error| {
            AppError::internal(format!("read Compose removal journal: {error}"))
        })?;
        let journal: ComposeRemovalJournal = serde_json::from_slice(&bytes).map_err(|error| {
            AppError::internal(format!("corrupt Compose removal journal: {error}"))
        })?;
        if journal.contract_version != v2::CONTRACT_VERSION
            || journal.operation_id != record.operation_id
            || journal.resource_operation_id != resource_operation_id
            || journal.reviewed_plan_digest != record.reviewed_plan_digest
        {
            return Err(AppError::conflict(
                "Compose removal journal belongs to another reviewed operation",
                None,
            ));
        }
        return Ok(journal);
    }

    let journal = ComposeRemovalJournal {
        contract_version: v2::CONTRACT_VERSION,
        operation_id: record.operation_id.clone(),
        resource_operation_id: resource_operation_id.to_string(),
        reviewed_plan_digest: record.reviewed_plan_digest.clone(),
        resources: BTreeMap::new(),
    };
    save_compose_removal_journal(adapter, state_dir, &journal)?;
    Ok(journal)
}

fn save_compose_removal_journal(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
    journal: &ComposeRemovalJournal,
) -> AppResult<()> {
    let bytes = serde_json::to_vec_pretty(journal).map_err(|error| {
        AppError::internal(format!("serialize Compose removal journal: {error}"))
    })?;
    adapter
        .write_file(&state_dir.join("removal-v2.json"), &bytes)
        .map_err(|error| AppError::internal(format!("save Compose removal journal: {error}")))
}

fn remove_compose_resources(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
    record: &v2::OperationRecord,
) -> AppResult<Vec<String>> {
    if record.action != v2::LifecycleAction::Remove {
        return Err(AppError::conflict(
            "Compose removal requires a durable remove operation record",
            None,
        ));
    }
    let install_journal_bytes = adapter
        .read_file(&state_dir.join("journal.json"))
        .map_err(|error| AppError::internal(format!("read Compose ownership journal: {error}")))?;
    let install_journal: Journal =
        serde_json::from_slice(&install_journal_bytes).map_err(|error| {
            AppError::internal(format!("corrupt Compose ownership journal: {error}"))
        })?;
    let mut removal_journal = load_compose_removal_journal(adapter, state_dir, record)?;
    let resource_operation_id = removal_journal.resource_operation_id.clone();
    let project_name = compose_project_name(&resource_operation_id)?;
    let expected_image_id = read_compose_package_value(
        adapter,
        &Path::new(COMPOSE_DIR).join("image-id"),
        "image ID",
    )?;
    let mut errors = Vec::new();

    let containers = match compose_project_containers(adapter, &project_name) {
        Ok(containers) => containers,
        Err(error) => return Ok(vec![error.to_string()]),
    };
    for container_id in containers {
        if let Err(error) = verify_compose_container(
            adapter,
            &container_id,
            &project_name,
            &resource_operation_id,
            &expected_image_id,
        ) {
            errors.push(error.to_string());
            continue;
        }
        let key = format!("container:{container_id}");
        if removal_journal.resources.get(&key) == Some(&ResourceStatus::Completed) {
            continue;
        }
        removal_journal
            .resources
            .insert(key.clone(), ResourceStatus::Intent);
        save_compose_removal_journal(adapter, state_dir, &removal_journal)?;
        let result = docker_command_output(
            adapter,
            &[
                "rm".to_string(),
                "--force".to_string(),
                container_id.clone(),
            ],
            "remove owned Compose container",
        );
        let still_present = compose_project_containers(adapter, &project_name)
            .map(|items| items.contains(&container_id))
            .unwrap_or(true);
        if still_present {
            errors.push(
                result
                    .err()
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| {
                        "Docker reported success but the owned Compose container remains"
                            .to_string()
                    }),
            );
            removal_journal
                .resources
                .insert(key, ResourceStatus::Failed);
            save_compose_removal_journal(adapter, state_dir, &removal_journal)?;
            continue;
        }
        removal_journal
            .resources
            .insert(key, ResourceStatus::Completed);
        save_compose_removal_journal(adapter, state_dir, &removal_journal)?;
    }

    let network_ids = match compose_project_networks(adapter, &project_name) {
        Ok(networks) => networks,
        Err(error) => {
            errors.push(error.to_string());
            vec![]
        }
    };
    for network_id in network_ids {
        if let Err(error) = verify_compose_network(adapter, &network_id, &project_name) {
            errors.push(error.to_string());
            continue;
        }
        let key = format!("network:{network_id}");
        if removal_journal.resources.get(&key) == Some(&ResourceStatus::Completed) {
            continue;
        }
        removal_journal
            .resources
            .insert(key.clone(), ResourceStatus::Intent);
        save_compose_removal_journal(adapter, state_dir, &removal_journal)?;
        let result = docker_command_output(
            adapter,
            &["network".to_string(), "rm".to_string(), network_id.clone()],
            "remove owned Compose network",
        );
        let still_present = compose_project_networks(adapter, &project_name)
            .map(|items| items.contains(&network_id))
            .unwrap_or(true);
        if still_present {
            errors.push(
                result
                    .err()
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| {
                        "Docker reported success but the owned Compose network remains".to_string()
                    }),
            );
            removal_journal
                .resources
                .insert(key, ResourceStatus::Failed);
            save_compose_removal_journal(adapter, state_dir, &removal_journal)?;
            continue;
        }
        removal_journal
            .resources
            .insert(key, ResourceStatus::Completed);
        save_compose_removal_journal(adapter, state_dir, &removal_journal)?;
    }

    let runtime_image_ref = format!(
        "localhost/helicoid-server:install-{}",
        uuid::Uuid::parse_str(&resource_operation_id)
            .map_err(|_| AppError::unprocessable("Compose operation identity is invalid"))?
            .simple()
    );
    let image_was_journaled = install_journal.resources.iter().any(|resource| {
        resource.resource_type == "compose_image_tag"
            && resource.identity == runtime_image_ref
            && matches!(
                resource.status,
                ResourceStatus::Intent | ResourceStatus::Completed
            )
    });
    if image_was_journaled {
        let key = format!("image:{runtime_image_ref}");
        if removal_journal.resources.get(&key) != Some(&ResourceStatus::Completed) {
            match inspect_docker_image_id(adapter, &runtime_image_ref)? {
                Some(image_id) if image_id != expected_image_id => {
                    errors.push(
                        "operation-specific Docker image tag changed; refusing to remove it".into(),
                    );
                }
                Some(_) => {
                    removal_journal
                        .resources
                        .insert(key.clone(), ResourceStatus::Intent);
                    save_compose_removal_journal(adapter, state_dir, &removal_journal)?;
                    let result = docker_command_output(
                        adapter,
                        &[
                            "image".to_string(),
                            "rm".to_string(),
                            runtime_image_ref.clone(),
                        ],
                        "remove operation-owned Compose image tag",
                    );
                    match inspect_docker_image_id(adapter, &runtime_image_ref)? {
                        None => {
                            removal_journal
                                .resources
                                .insert(key, ResourceStatus::Completed);
                            save_compose_removal_journal(adapter, state_dir, &removal_journal)?;
                        }
                        Some(_) => {
                            errors.push(
                                result
                                    .err()
                                    .map(|error| error.to_string())
                                    .unwrap_or_else(|| {
                                        "Docker reported success but the Compose image tag remains"
                                            .to_string()
                                    }),
                            );
                            removal_journal
                                .resources
                                .insert(key, ResourceStatus::Failed);
                            save_compose_removal_journal(adapter, state_dir, &removal_journal)?;
                        }
                    }
                }
                None => {
                    removal_journal
                        .resources
                        .insert(key, ResourceStatus::Completed);
                    save_compose_removal_journal(adapter, state_dir, &removal_journal)?;
                }
            }
        }
    }

    if errors.is_empty() && !record.configuration.storage.preserve_data_on_remove {
        if let Err(error) =
            remove_compose_manager_identity(adapter, state_dir, &mut removal_journal)
        {
            errors.push(error.to_string());
        }
    }

    // The package-scoped image tag is shared by content digest and may be used
    // by another installation, so removal drops only this operation's tag.
    let has_owned_project_objects = !compose_project_containers(adapter, &project_name)?.is_empty()
        || !compose_project_networks(adapter, &project_name)?.is_empty();
    if has_owned_project_objects {
        errors.push("owned Compose project resources remain after removal".into());
    }
    Ok(errors)
}

fn remove_compose_manager_identity(
    adapter: &dyn CommandAdapter,
    state_dir: &Path,
    journal: &mut ComposeRemovalJournal,
) -> AppResult<()> {
    const RESOURCE_KEY: &str = "manager_identity:/var/lib/helicoid/.local/state/helicoid";
    if journal.resources.get(RESOURCE_KEY) == Some(&ResourceStatus::Completed) {
        if path_present(adapter, Path::new(COMPOSE_MANAGER_IDENTITY_DIR)) {
            return Err(AppError::conflict(
                "Compose Manager identity path reappeared after its journaled removal; refusing to delete new data",
                None,
            ));
        }
        return Ok(());
    }
    let identity_path = Path::new(COMPOSE_MANAGER_IDENTITY_DIR);
    if path_present(adapter, identity_path) {
        reject_symlink_parents(adapter, COMPOSE_MANAGER_IDENTITY_DIR)?;
        let metadata = adapter.symlink_metadata(identity_path).map_err(|error| {
            AppError::internal(format!("inspect Compose Manager identity: {error}"))
        })?;
        if metadata.is_symlink || !metadata.is_dir {
            return Err(AppError::conflict(
                "Compose Manager identity path is not a real directory; refusing data removal",
                None,
            ));
        }
        journal
            .resources
            .insert(RESOURCE_KEY.to_string(), ResourceStatus::Intent);
        save_compose_removal_journal(adapter, state_dir, journal)?;
        if let Err(error) = adapter.remove_dir_all(identity_path) {
            journal
                .resources
                .insert(RESOURCE_KEY.to_string(), ResourceStatus::Failed);
            save_compose_removal_journal(adapter, state_dir, journal)?;
            return Err(AppError::internal(format!(
                "remove Compose Manager identity: {error}"
            )));
        }
    }
    journal
        .resources
        .insert(RESOURCE_KEY.to_string(), ResourceStatus::Completed);
    save_compose_removal_journal(adapter, state_dir, journal)?;
    Ok(())
}

fn compose_project_networks(
    adapter: &dyn CommandAdapter,
    project_name: &str,
) -> AppResult<Vec<String>> {
    let output = docker_command_output(
        adapter,
        &[
            "network".to_string(),
            "ls".to_string(),
            "--filter".to_string(),
            format!("label=com.docker.compose.project={project_name}"),
            "--format".to_string(),
            "{{.ID}}".to_string(),
        ],
        "inspect Compose project networks",
    )?;
    let mut ids = Vec::new();
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if !is_valid_container_id(line) {
            return Err(AppError::internal(
                "Docker returned an invalid Compose network identity",
            ));
        }
        ids.push(line.to_ascii_lowercase());
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn verify_compose_network(
    adapter: &dyn CommandAdapter,
    network_id: &str,
    project_name: &str,
) -> AppResult<()> {
    let labels = docker_command_output(
        adapter,
        &[
            "network".to_string(),
            "inspect".to_string(),
            "--format={{json .Labels}}".to_string(),
            network_id.to_string(),
        ],
        "inspect Compose network labels",
    )?;
    let labels: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&labels)
        .map_err(|_| AppError::internal("Docker returned invalid Compose network labels"))?;
    let label = |key: &str| labels.get(key).and_then(serde_json::Value::as_str);
    if label("com.docker.compose.project") != Some(project_name)
        || label("com.docker.compose.network") != Some("default")
    {
        return Err(AppError::conflict(
            "Compose network labels do not match the journaled Helicoid project",
            None,
        ));
    }
    Ok(())
}

fn remove_operation_status(
    adapter: &dyn CommandAdapter,
    input: &v2::StatusInput,
    record: v2::OperationRecord,
    journal_present: bool,
) -> AppResult<v2::OperationStatus> {
    let compose = input.configuration.deployment_kind == v2::DeploymentKind::LinuxCompose;
    let (installed, service_resources_remain, journal_pending) = if compose {
        let resource_operation_id = record.resource_operation_id.as_deref().ok_or_else(|| {
            AppError::conflict(
                "Compose removal record is missing the install resource identity",
                None,
            )
        })?;
        let (installed, resources_remain) =
            compose_resources_remain(adapter, resource_operation_id)?;
        (
            installed,
            resources_remain,
            path_present(
                adapter,
                Path::new("/opt/helicoid/.installer/removal-v2.json"),
            ),
        )
    } else {
        (
            adapter
                .query_unit_exists(UNIT_NAME)
                .map_err(|error| AppError::internal(format!("inspect service unit: {error}")))?,
            owned_service_resources_remain(adapter)?,
            journal_present,
        )
    };
    let recorded_outcome = record.outcome;
    let completed_outcome = recorded_outcome
        .as_ref()
        .is_some_and(|outcome| outcome.state == v2::OperationState::Completed);
    let state = if completed_outcome && !journal_pending && !service_resources_remain {
        v2::OperationState::Completed
    } else {
        v2::OperationState::AttentionRequired
    };
    let mut phases = BTreeMap::new();
    phases.insert(
        "remove".to_string(),
        if state == v2::OperationState::Completed {
            PhaseStatus::Completed
        } else if journal_pending {
            PhaseStatus::Failed
        } else {
            PhaseStatus::InProgress
        },
    );
    let result = match recorded_outcome {
        Some(outcome) if state == v2::OperationState::Completed => outcome.result,
        Some(outcome) => v2::OperationResult {
            code: if completed_outcome && (journal_pending || service_resources_remain) {
                "remove_journal_remains".to_string()
            } else {
                outcome.result.code
            },
            summary: if completed_outcome && (journal_pending || service_resources_remain) {
                "Removal was recorded complete, but its removal journal or owned service resources remain; inspect the host before retrying.".to_string()
            } else {
                outcome.result.summary
            },
            errors: if completed_outcome && (journal_pending || service_resources_remain) {
                vec!["owned service resources exist after recorded completion".to_string()]
            } else {
                outcome.result.errors
            },
            warnings: outcome.result.warnings,
        },
        None => v2::OperationResult {
            code: "remove_interrupted".to_string(),
            summary: if journal_pending {
                "Removal started but did not record an outcome. Review the host and rerun remove-v2 to continue from the owned-resource journal.".to_string()
            } else {
                "Removal may have completed before its final result was recorded. Rerun remove-v2 to verify and finalize the operation.".to_string()
            },
            errors: vec![],
            warnings: vec![],
        },
    };
    Ok(v2::OperationStatus {
        contract_version: v2::CONTRACT_VERSION,
        configuration: input.configuration.clone(),
        operation_id: Some(record.operation_id),
        action: Some(v2::LifecycleAction::Remove),
        state,
        reviewed_plan_digest: Some(record.reviewed_plan_digest),
        current_phase: Some("remove".to_string()),
        phases,
        cancellation_available: false,
        resume_available: state != v2::OperationState::Completed,
        service_installed: installed,
        bootstrap_ready: false,
        server_ready_for_enrollment: false,
        result,
    })
}

fn compose_resources_remain(
    adapter: &dyn CommandAdapter,
    operation_id: &str,
) -> AppResult<(bool, bool)> {
    let project_name = compose_project_name(operation_id)?;
    let containers = compose_project_containers(adapter, &project_name)?;
    for container in &containers {
        verify_compose_container_labels(adapter, container, &project_name, operation_id)?;
    }
    let networks = compose_project_networks(adapter, &project_name)?;
    for network in &networks {
        verify_compose_network(adapter, network, &project_name)?;
    }
    let runtime_ref = format!(
        "localhost/helicoid-server:install-{}",
        uuid::Uuid::parse_str(operation_id)
            .map_err(|_| AppError::unprocessable("Compose install identity is invalid"))?
            .simple()
    );
    let runtime_image_remains = inspect_docker_image_id(adapter, &runtime_ref)?.is_some();
    let service_remains = !containers.is_empty();
    Ok((
        service_remains,
        service_remains || !networks.is_empty() || runtime_image_remains,
    ))
}

/// Generate the canonical installation plan from product/version.
///
/// All resources (directories, files, units, firewall rules, listeners)
/// are fixed by the installer policy — the manifest only provides product
/// and version. The caller cannot request arbitrary destinations, users,
/// units, firewall rules, or system paths.
pub fn generate_canonical_plan(product: &str, version: &str) -> InstallPlan {
    InstallPlan {
        review_digest: String::new(),
        product: product.to_string(),
        version: version.to_string(),
        service_user: ServiceUserSpec {
            name: SERVICE_USER.to_string(),
            create: true,
        },
        directories: vec![
            DirectorySpec {
                path: BASE_DIR.to_string(),
                owner: "root".to_string(),
                mode: "0755".to_string(),
                create: true,
            },
            DirectorySpec {
                path: format!("{BASE_DIR}/bin"),
                owner: "root".to_string(),
                mode: "0755".to_string(),
                create: true,
            },
            DirectorySpec {
                path: DATA_DIR.to_string(),
                owner: "root".to_string(),
                mode: "0755".to_string(),
                create: true,
            },
            DirectorySpec {
                path: DATA_SUBDIR.to_string(),
                owner: SERVICE_USER.to_string(),
                mode: "0700".to_string(),
                create: true,
            },
            DirectorySpec {
                path: BACKUP_DIR.to_string(),
                owner: SERVICE_USER.to_string(),
                mode: "0700".to_string(),
                create: true,
            },
            DirectorySpec {
                path: CONFIG_DIR.to_string(),
                owner: "root".to_string(),
                mode: "0700".to_string(),
                create: true,
            },
        ],
        files: vec![
            FileSpec {
                source: "artifacts/hs-server".to_string(),
                destination: format!("{BASE_DIR}/bin/hs-server"),
                mode: "0755".to_string(),
            },
            FileSpec {
                source: "artifacts/helicoid-server".to_string(),
                destination: format!("{BASE_DIR}/bin/helicoid-server"),
                mode: "0755".to_string(),
            },
            FileSpec {
                source: "artifacts/hs-server.service".to_string(),
                destination: format!("/etc/systemd/system/{UNIT_NAME}"),
                mode: "0644".to_string(),
            },
        ],
        units: vec![UnitSpec {
            name: UNIT_NAME.to_string(),
            action: "install".to_string(),
            enabled: true,
            restart_policy: "on-failure".to_string(),
        }],
        firewall: vec![],
        listeners: vec![ListenerSpec {
            port: 8787,
            protocol: "tcp".to_string(),
            description: "loopback-only development authority".to_string(),
        }],
        migrations: MigrationSpec {
            schema_version: crate::db::SCHEMA_VERSION,
            backup_required: true,
        },
        not_implemented: vec![
            "LAN and public network exposure (service remains loopback-only)".into(),
            "Docker Compose deployment".into(),
            "Configurable data and backup directories".into(),
            "Durable cancellation, online update, backup, and restore operations".into(),
            "MFA enrollment".into(),
            "Remote control / screen observation".into(),
            "File jobs".into(),
            "Security recovery".into(),
        ],
    }
}

fn generate_canonical_plan_v2(
    product: &str,
    version: &str,
    configuration: &v2::DeploymentConfiguration,
) -> InstallPlan {
    if configuration.deployment_kind == v2::DeploymentKind::LinuxCompose {
        return generate_canonical_compose_plan(product, version, configuration);
    }

    let mut plan = generate_canonical_plan(product, version);
    plan.directories
        .retain(|directory| directory.path != DATA_SUBDIR && directory.path != BACKUP_DIR);
    plan.directories.extend(storage_directory_specs(
        &configuration.storage.data_directory,
    ));
    plan.directories.extend(storage_directory_specs(
        &configuration.storage.backup_directory,
    ));
    plan.directories
        .sort_by(|left, right| left.path.cmp(&right.path));
    plan.directories
        .dedup_by(|left, right| left.path == right.path);

    // The legacy package's unit artifact contains fixed paths. The v2 unit is
    // rendered from the reviewed storage configuration during apply instead.
    let unit_destination = format!("/etc/systemd/system/{UNIT_NAME}");
    plan.files
        .retain(|file| file.destination != unit_destination);
    plan.directories
        .iter_mut()
        .filter(|directory| {
            directory.path == BASE_DIR
                || directory.path == format!("{BASE_DIR}/bin")
                || directory.path == DATA_DIR
                || directory.path == CONFIG_DIR
        })
        .for_each(|directory| {
            directory.owner = "root".to_string();
        });
    plan.not_implemented
        .retain(|item| item != "Configurable data and backup directories");
    plan.units.extend([
        UnitSpec {
            name: BACKUP_SERVICE_UNIT.to_string(),
            action: "install".to_string(),
            enabled: false,
            restart_policy: "no".to_string(),
        },
        UnitSpec {
            name: BACKUP_TIMER_UNIT.to_string(),
            action: "install".to_string(),
            enabled: false,
            restart_policy: "no".to_string(),
        },
    ]);
    if matches!(
        configuration.network.scope,
        v2::NetworkScope::Lan | v2::NetworkScope::PrivateDns
    ) {
        let address = configuration
            .network
            .bind_address
            .as_deref()
            .expect("validated LAN or private DNS configuration has a bind address");
        let bind_address = address
            .parse::<IpAddr>()
            .map(|ip| SocketAddr::new(ip, configuration.network.authority_port).to_string())
            .expect("validated LAN or private DNS configuration has a literal IP address");
        plan.listeners.push(ListenerSpec {
            port: configuration.network.authority_port,
            protocol: "tcp".to_string(),
            description: format!(
                "{} HTTPS authority at {bind_address}; v2 routes only",
                if configuration.network.scope == v2::NetworkScope::PrivateDns {
                    "private DNS"
                } else {
                    "LAN"
                }
            ),
        });
        plan.not_implemented.retain(|item| {
            item != "LAN and public network exposure (service remains loopback-only)"
        });
    }
    plan.review_digest = compute_plan_digest(&plan);
    plan
}

fn generate_canonical_compose_plan(
    product: &str,
    version: &str,
    configuration: &v2::DeploymentConfiguration,
) -> InstallPlan {
    let mut plan = generate_canonical_plan(product, version);
    plan.service_user.create = false;
    plan.directories = vec![
        DirectorySpec {
            path: BASE_DIR.to_string(),
            owner: "root".to_string(),
            mode: "0755".to_string(),
            create: true,
        },
        DirectorySpec {
            path: format!("{BASE_DIR}/bin"),
            owner: "root".to_string(),
            mode: "0755".to_string(),
            create: true,
        },
        DirectorySpec {
            path: COMPOSE_DIR.to_string(),
            owner: "root".to_string(),
            mode: "0755".to_string(),
            create: true,
        },
        DirectorySpec {
            path: format!("{COMPOSE_DIR}/tls"),
            owner: "root".to_string(),
            mode: "0755".to_string(),
            create: true,
        },
        DirectorySpec {
            path: DATA_DIR.to_string(),
            owner: CONTAINER_OWNER.to_string(),
            mode: "0700".to_string(),
            create: true,
        },
    ];
    plan.directories.extend(storage_directory_specs(
        &configuration.storage.data_directory,
    ));
    plan.directories.extend(storage_directory_specs(
        &configuration.storage.backup_directory,
    ));
    for directory in &mut plan.directories {
        if [DATA_DIR, DATA_SUBDIR, BACKUP_DIR, BACKUP_ROOT].contains(&directory.path.as_str())
            || Path::new(&directory.path).starts_with(DATA_SUBDIR)
            || Path::new(&directory.path).starts_with(BACKUP_DIR)
            || Path::new(&directory.path).starts_with(BACKUP_ROOT)
        {
            directory.owner = CONTAINER_OWNER.to_string();
        }
    }
    plan.directories
        .sort_by(|left, right| left.path.cmp(&right.path));
    plan.directories
        .dedup_by(|left, right| left.path == right.path);

    plan.files = vec![
        FileSpec {
            source: "artifacts/hs-server".to_string(),
            destination: format!("{BASE_DIR}/bin/hs-server"),
            mode: "0755".to_string(),
        },
        FileSpec {
            source: "artifacts/compose/server-image.tar".to_string(),
            destination: format!("{COMPOSE_DIR}/server-image.tar"),
            mode: "0644".to_string(),
        },
        FileSpec {
            source: "artifacts/compose/compose.yaml".to_string(),
            destination: format!("{COMPOSE_DIR}/compose.yaml"),
            mode: "0644".to_string(),
        },
        FileSpec {
            source: "artifacts/compose/image-ref".to_string(),
            destination: format!("{COMPOSE_DIR}/image-ref"),
            mode: "0644".to_string(),
        },
        FileSpec {
            source: "artifacts/compose/image-id".to_string(),
            destination: format!("{COMPOSE_DIR}/image-id"),
            mode: "0644".to_string(),
        },
        FileSpec {
            source: "artifacts/compose/.env.example".to_string(),
            destination: format!("{COMPOSE_DIR}/.env.example"),
            mode: "0644".to_string(),
        },
        FileSpec {
            source: "artifacts/compose/tls/readme.md".to_string(),
            destination: format!("{COMPOSE_DIR}/tls/readme.md"),
            mode: "0644".to_string(),
        },
    ];
    plan.units = vec![
        UnitSpec {
            name: BACKUP_CONTROL_SERVICE_UNIT.to_string(),
            action: "install".to_string(),
            enabled: false,
            restart_policy: "no".to_string(),
        },
        UnitSpec {
            name: BACKUP_CONTROL_SOCKET_UNIT.to_string(),
            action: "install".to_string(),
            enabled: true,
            restart_policy: "no".to_string(),
        },
        UnitSpec {
            name: BACKUP_SERVICE_UNIT.to_string(),
            action: "install".to_string(),
            enabled: false,
            restart_policy: "no".to_string(),
        },
        UnitSpec {
            name: BACKUP_TIMER_UNIT.to_string(),
            action: "install".to_string(),
            enabled: false,
            restart_policy: "no".to_string(),
        },
    ];
    plan.firewall.clear();
    plan.listeners = vec![ListenerSpec {
        port: configuration.network.authority_port,
        protocol: "tcp".to_string(),
        description: match configuration.network.scope {
            v2::NetworkScope::Lan | v2::NetworkScope::PrivateDns => format!(
                "{} HTTPS authority at {}:{}; v2 routes only",
                if configuration.network.scope == v2::NetworkScope::PrivateDns {
                    "private DNS"
                } else {
                    "LAN"
                },
                configuration
                    .network
                    .bind_address
                    .as_deref()
                    .unwrap_or_default(),
                configuration.network.authority_port
            ),
            _ => format!(
                "loopback HTTPS authority on TCP {}",
                configuration.network.authority_port
            ),
        },
    }];
    plan.not_implemented = vec![
        "public-edge networking and external DNS/PKI automation".into(),
        "durable cancellation, online update, and deployment restore/cutover (encrypted database backups and optional systemd scheduling are available separately)".into(),
        "MFA enrollment in the desktop Manager".into(),
        "remote control and screen observation".into(),
        "file jobs".into(),
        "security recovery".into(),
    ];
    plan.review_digest = compute_plan_digest(&plan);
    plan
}

fn storage_directory_specs(path: &str) -> Vec<DirectorySpec> {
    let root = if Path::new(path).starts_with(DATA_SUBDIR) {
        DATA_SUBDIR
    } else if Path::new(path).starts_with(BACKUP_DIR) {
        BACKUP_DIR
    } else {
        BACKUP_ROOT
    };
    let mut specs = Vec::new();
    let mut current = PathBuf::from(root);
    let owner = SERVICE_USER.to_string();
    let mut add = |directory: &Path| {
        specs.push(DirectorySpec {
            path: directory.to_string_lossy().into_owned(),
            owner: owner.clone(),
            mode: "0700".to_string(),
            create: true,
        });
    };
    add(&current);
    if let Ok(relative) = Path::new(path).strip_prefix(root) {
        for component in relative.components() {
            current.push(component);
            add(&current);
        }
    }
    specs
}

/// Compute a deterministic review digest over the full canonical plan.
///
/// Hashes every field that determines the exact resource set (product, version,
/// service user, directories, files, units, firewall, listeners, migrations,
/// not_implemented). The `review_digest` field itself is excluded so the
/// digest is self-consistent.
pub fn compute_plan_digest(plan: &InstallPlan) -> String {
    use serde::Serialize;

    #[derive(Serialize)]
    struct PlanDigest<'a> {
        product: &'a str,
        version: &'a str,
        service_user: &'a ServiceUserSpec,
        directories: &'a [DirectorySpec],
        files: &'a [FileSpec],
        units: &'a [UnitSpec],
        firewall: &'a [FirewallRule],
        listeners: &'a [ListenerSpec],
        migrations: &'a MigrationSpec,
        not_implemented: &'a [String],
    }

    let canonical = PlanDigest {
        product: &plan.product,
        version: &plan.version,
        service_user: &plan.service_user,
        directories: &plan.directories,
        files: &plan.files,
        units: &plan.units,
        firewall: &plan.firewall,
        listeners: &plan.listeners,
        migrations: &plan.migrations,
        not_implemented: &plan.not_implemented,
    };

    let json = serde_json::to_string(&canonical).expect("plan digest serialization");
    manifest::sha256_hex(json.as_bytes())
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

/// Execute the installation plan with phase journal.
///
/// Bind apply to exact reviewed plan digest and current fresh preflight state.
/// Does not accept stale reviews after occupied port/path changes.
pub fn apply(
    adapter: &dyn CommandAdapter,
    input: &ApplyInput,
    state_dir: &Path,
) -> AppResult<ApplyResult> {
    let _operation_lock = acquire_lifecycle_operation_lock(adapter, state_dir)?;
    apply_internal(adapter, input, state_dir, None, None)
}

fn apply_internal(
    adapter: &dyn CommandAdapter,
    input: &ApplyInput,
    state_dir: &Path,
    configuration: Option<&v2::DeploymentConfiguration>,
    operation_id: Option<&str>,
) -> AppResult<ApplyResult> {
    if !input.confirm {
        return Err(AppError::bad_request("apply requires confirm: true"));
    }

    if !input.preflight.ok {
        return Err(AppError::bad_request("preflight is not ok; cannot apply"));
    }

    let plan = &input.plan;

    // Initialize or load journal.
    // Journal integrity is checked before verification to surface corruption
    // or plan mismatch errors independently of trust validation.
    let journal_path = state_dir.join("journal.json");
    let mut journal = if adapter.path_exists(&journal_path) {
        let bytes = adapter
            .read_file(&journal_path)
            .map_err(|e| AppError::internal(format!("cannot read journal: {e}")))?;
        serde_json::from_slice::<Journal>(&bytes)
            .map_err(|e| AppError::internal(format!("corrupt journal: {e}")))?
    } else {
        create_journal(adapter, &plan.review_digest)
    };

    // Verify journal matches this plan.
    if journal.plan_digest != plan.review_digest {
        return Err(AppError::conflict(
            "journal belongs to a different plan; cannot apply",
            None,
        ));
    }

    // Recheck required ports. An occupied port is ignored only after the
    // journal records the product's complete unit phase and that exact unit
    // still exists; no listener identity is inferred from procfs.
    // Query errors MUST deny apply — treating errors as "port free" is unsafe.
    let compose =
        configuration.is_some_and(|item| item.deployment_kind == v2::DeploymentKind::LinuxCompose);
    let phase_owns_service = journal
        .phases
        .get("units")
        .is_some_and(|phase| phase.status == PhaseStatus::Completed);
    let service_is_owned_and_active = if compose && phase_owns_service {
        compose_service_is_owned_and_running(
            adapter,
            operation_id.ok_or_else(|| {
                AppError::conflict("Compose journal has no durable operation identity", None)
            })?,
        )?
    } else if !compose
        && phase_owns_service
        && journal
            .resources_created
            .units
            .iter()
            .any(|unit| unit == UNIT_NAME)
    {
        adapter.query_unit_exists(UNIT_NAME).map_err(|error| {
            AppError::conflict(
                format!("cannot verify owned unit {UNIT_NAME}: {error}"),
                None,
            )
        })?
    } else {
        false
    };
    let mut required_ports = if compose {
        vec![]
    } else {
        REQUIRED_PORTS.to_vec()
    };
    if let Some(configuration) = configuration {
        if compose
            || matches!(
                configuration.network.scope,
                v2::NetworkScope::Lan | v2::NetworkScope::PrivateDns
            )
        {
            required_ports.push((configuration.network.authority_port, "tcp"));
        }
    }
    for &(port, protocol) in &required_ports {
        match adapter.query_port_listener(port, protocol) {
            Ok(Some(_)) if service_is_owned_and_active => {}
            Ok(Some(_)) => {
                return Err(AppError::conflict(
                    format!("port {port}/{protocol} is now occupied; preflight state has changed"),
                    None,
                ));
            }
            Ok(None) => {}
            Err(error) => {
                return Err(AppError::conflict(
                    format!("cannot verify port {port}/{protocol} availability: {error}"),
                    None,
                ));
            }
        }
    }

    // Verification is mandatory for apply: require a package verify key.
    let key_hex = input.verify_key.as_ref().ok_or_else(|| {
        AppError::forbidden("apply requires a package verification key (verify_key)")
    })?;
    let pkg_dir = input.package_dir.as_ref().ok_or_else(|| {
        AppError::bad_request("apply requires package_dir when verify_key is provided")
    })?;

    // Independently re-verify the signed package.
    // This catches tampering between plan review and apply.
    let key_bytes = hex_decode_32(key_hex)?;
    let verified_manifest = manifest::verify_manifest(adapter, Path::new(pkg_dir), &key_bytes)?;

    // Regenerate the canonical plan from the verified manifest + fixed policy.
    // The manifest provides product/version; all resources are installer-policy
    // constants. The caller cannot modify destinations, users, units, firewall
    // rules, or system paths.
    let canonical_plan = match configuration {
        Some(configuration) => {
            validate_v2_configuration(configuration)?;
            validate_storage_directories(adapter, configuration)?;
            generate_canonical_plan_v2(
                &verified_manifest.product,
                &verified_manifest.version,
                configuration,
            )
        }
        None => {
            let mut plan =
                generate_canonical_plan(&verified_manifest.product, &verified_manifest.version);
            plan.review_digest = compute_plan_digest(&plan);
            plan
        }
    };

    // Compare the caller's review digest against the independently computed one.
    // A caller who modified any plan field (destinations, modes, units, etc.)
    // and recomputed the digest will be caught here.
    let submitted_plan = serde_json::to_vec(plan)
        .map_err(|error| AppError::internal(format!("serialize submitted plan: {error}")))?;
    let expected_plan = serde_json::to_vec(&canonical_plan)
        .map_err(|error| AppError::internal(format!("serialize canonical plan: {error}")))?;
    if plan.review_digest != canonical_plan.review_digest || submitted_plan != expected_plan {
        return Err(AppError::forbidden(
            "plan does not match the canonical plan derived from the verified manifest",
        ));
    }

    // Verify each planned file artifact matches the manifest.
    for file in &plan.files {
        let pkg_path = Path::new(pkg_dir).join(&file.source);
        let file_bytes = adapter
            .read_file(&pkg_path)
            .map_err(|e| AppError::bad_request(format!("cannot read '{}': {e}", file.source)))?;
        let actual_hash = manifest::sha256_hex(&file_bytes);
        let actual_size = file_bytes.len() as u64;

        let expected = verified_manifest
            .artifacts
            .iter()
            .find(|a| a.path == file.source);
        match expected {
            Some(artifact) => {
                if actual_hash != artifact.sha256 {
                    return Err(AppError::forbidden(format!(
                        "artifact '{}' hash mismatch: expected {} got {}",
                        file.source, artifact.sha256, actual_hash
                    )));
                }
                if actual_size != artifact.size_bytes {
                    return Err(AppError::unprocessable(format!(
                        "artifact '{}' size mismatch: expected {} got {}",
                        file.source, artifact.size_bytes, actual_size
                    )));
                }
            }
            None => {
                return Err(AppError::forbidden(format!(
                    "plan file '{}' not found in verified manifest artifacts",
                    file.source
                )));
            }
        }
    }

    // Resolve package directory for file copying.
    let package_dir_path = input.package_dir.as_deref().map(Path::new);

    // Execute phases in order.
    let phases = Phase::execution_sequence();
    for &phase in phases {
        let phase_key = phase.as_str().to_string();
        let entry = journal
            .phases
            .entry(phase_key.clone())
            .or_insert_with(|| PhaseEntry {
                status: PhaseStatus::Pending,
                started_at: None,
                completed_at: None,
                error: None,
            });

        if entry.status == PhaseStatus::Completed && !(compose && phase == Phase::Units) {
            continue;
        }

        // Mark in-progress.
        entry.status = PhaseStatus::InProgress;
        entry.started_at = Some(adapter.now_iso8601());
        entry.error = None;
        journal.current_phase = phase_key.clone();
        journal.updated_at = adapter.now_iso8601();
        save_journal(adapter, &journal_path, &journal)?;

        // Execute the phase.
        let phase_context = PhaseContext {
            verified_artifacts: &verified_manifest.artifacts,
            package_dir: package_dir_path,
            data_directory: configuration
                .map(|configuration| configuration.storage.data_directory.as_str())
                .unwrap_or(DATA_SUBDIR),
            backup_directory: configuration
                .map(|configuration| configuration.storage.backup_directory.as_str())
                .unwrap_or(BACKUP_DIR),
            network: configuration.map(|configuration| &configuration.network),
            deployment_kind: configuration.map(|configuration| configuration.deployment_kind),
            operation_id,
        };
        let result = execute_phase(
            adapter,
            phase,
            plan,
            &mut journal,
            &journal_path,
            &phase_context,
        );
        match result {
            Ok(()) => {
                let entry = journal.phases.get_mut(&phase_key).unwrap();
                entry.status = PhaseStatus::Completed;
                entry.completed_at = Some(adapter.now_iso8601());
                journal.updated_at = adapter.now_iso8601();
                save_journal(adapter, &journal_path, &journal)?;
            }
            Err(e) => {
                let entry = journal.phases.get_mut(&phase_key).unwrap();
                entry.status = PhaseStatus::Failed;
                entry.error = Some(e.to_string());
                journal.current_phase = phase_key.clone();
                journal.updated_at = adapter.now_iso8601();
                save_journal(adapter, &journal_path, &journal)?;

                return Ok(build_apply_result(&journal, false, &journal_path));
            }
        }
    }

    // Save installed manifest for later inspect/remove.
    let manifest_path = state_dir.join("installed.json");
    let manifest_data = serde_json::json!({
        "product": plan.product,
        "version": plan.version,
        "plan_digest": plan.review_digest,
        "installed_at": adapter.now_iso8601(),
    });
    adapter
        .write_file(
            &manifest_path,
            serde_json::to_string_pretty(&manifest_data)
                .unwrap_or_default()
                .as_bytes(),
        )
        .map_err(|e| AppError::internal(format!("cannot save installed manifest: {e}")))?;

    Ok(build_apply_result(&journal, true, &journal_path))
}

/// Write a per-resource intent entry to the journal and save.
///
/// The write-ahead intent must be durable before the mutation runs. A journal
/// failure is a hard failure: we do not mutate without a truthful record.
fn record_resource_intent(
    adapter: &dyn CommandAdapter,
    journal_path: &Path,
    journal: &mut Journal,
    resource_type: &str,
    identity: &str,
) -> AppResult<()> {
    journal.resources.push(ResourceEntry {
        resource_type: resource_type.to_string(),
        identity: identity.to_string(),
        status: ResourceStatus::Intent,
        error: None,
    });
    journal.updated_at = adapter.now_iso8601();
    save_journal(adapter, journal_path, journal)
}

/// Mark the last matching resource entry as completed and save.
fn record_resource_completed(
    adapter: &dyn CommandAdapter,
    journal_path: &Path,
    journal: &mut Journal,
    resource_type: &str,
    identity: &str,
) -> AppResult<()> {
    if let Some(entry) = journal.resources.iter_mut().rev().find(|r| {
        r.resource_type == resource_type
            && r.identity == identity
            && r.status == ResourceStatus::Intent
    }) {
        entry.status = ResourceStatus::Completed;
    }
    journal.updated_at = adapter.now_iso8601();
    save_journal(adapter, journal_path, journal)
}

/// Mark the last matching resource entry as failed and save.
fn record_resource_failed(
    adapter: &dyn CommandAdapter,
    journal_path: &Path,
    journal: &mut Journal,
    resource_type: &str,
    identity: &str,
    error: &str,
) -> AppResult<()> {
    if let Some(entry) = journal.resources.iter_mut().rev().find(|r| {
        r.resource_type == resource_type
            && r.identity == identity
            && r.status == ResourceStatus::Intent
    }) {
        entry.status = ResourceStatus::Failed;
        entry.error = Some(error.to_string());
    }
    journal.updated_at = adapter.now_iso8601();
    save_journal(adapter, journal_path, journal)
}

/// Check if a resource was already completed (for resume idempotency).
fn is_resource_completed(journal: &Journal, resource_type: &str, identity: &str) -> bool {
    journal.resources.iter().any(|r| {
        r.resource_type == resource_type
            && r.identity == identity
            && r.status == ResourceStatus::Completed
    })
}

struct PhaseContext<'a> {
    verified_artifacts: &'a [ArtifactEntry],
    package_dir: Option<&'a Path>,
    data_directory: &'a str,
    backup_directory: &'a str,
    network: Option<&'a v2::NetworkConfiguration>,
    deployment_kind: Option<v2::DeploymentKind>,
    operation_id: Option<&'a str>,
}

fn write_compose_runtime_files(
    adapter: &dyn CommandAdapter,
    journal: &mut Journal,
    journal_path: &Path,
    context: &PhaseContext<'_>,
) -> AppResult<()> {
    let operation_id = context.operation_id.ok_or_else(|| {
        AppError::bad_request("Compose apply requires a durable v2 operation identity")
    })?;
    let operation_uuid = uuid::Uuid::parse_str(operation_id)
        .map_err(|_| AppError::unprocessable("Compose operation identity is invalid"))?;
    let network = context.network.ok_or_else(|| {
        AppError::bad_request("Compose apply requires reviewed network configuration")
    })?;

    let image_ref_path = Path::new(COMPOSE_DIR).join("image-ref");
    let image_ref = read_compose_package_value(adapter, &image_ref_path, "image reference")?;
    let image_id_path = Path::new(COMPOSE_DIR).join("image-id");
    let image_id = read_compose_package_value(adapter, &image_id_path, "image ID")?;
    let digest = image_ref
        .strip_prefix("localhost/helicoid-server:sha256-")
        .ok_or_else(|| AppError::forbidden("signed Compose image reference is invalid"))?;
    if digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || image_id != format!("sha256:{digest}")
    {
        return Err(AppError::forbidden(
            "signed Compose image reference and image ID do not match",
        ));
    }

    let publish_address = match network.scope {
        v2::NetworkScope::Lan | v2::NetworkScope::PrivateDns => {
            network.bind_address.as_deref().ok_or_else(|| {
                AppError::bad_request("Compose LAN or private DNS bind_address is required")
            })?
        }
        _ => "127.0.0.1",
    };
    let runtime_image_ref = format!(
        "localhost/helicoid-server:install-{}",
        operation_uuid.simple()
    );
    let environment = format!(
        "HELICOID_PUBLISH_ADDRESS={publish_address}\n\
         HELICOID_AUTHORITY_PORT={}\n\
         HELICOID_DATA_ROOT={DATA_DIR}\n\
         HELICOID_DATABASE_PATH={}/hs-server.db\n\
         HELICOID_BACKUP_DIRECTORY={}\n\
         HELICOID_BACKUP_TARGET={}\n\
         HELICOID_OPERATION_ID={operation_id}\n\
         HELICOID_IMAGE_REF={runtime_image_ref}\n",
        network.authority_port,
        context.data_directory,
        context.backup_directory,
        context.backup_directory,
    );
    write_journaled_product_file(
        adapter,
        journal,
        journal_path,
        Path::new(COMPOSE_DIR).join(".env").as_path(),
        environment.as_bytes(),
        0o644,
    )?;

    for (certificate, source, destination) in [
        (
            true,
            Path::new(TLS_CERTIFICATE_PATH),
            Path::new(COMPOSE_DIR).join("tls/fullchain.pem"),
        ),
        (
            false,
            Path::new(TLS_PRIVATE_KEY_PATH),
            Path::new(COMPOSE_DIR).join("tls/private-key.pem"),
        ),
    ] {
        copy_journaled_compose_tls_file(
            adapter,
            journal,
            journal_path,
            source,
            &destination,
            certificate,
        )?;
    }
    Ok(())
}

fn install_compose_service(
    adapter: &dyn CommandAdapter,
    journal: &mut Journal,
    journal_path: &Path,
    context: &PhaseContext<'_>,
) -> AppResult<()> {
    let operation_id = context.operation_id.ok_or_else(|| {
        AppError::bad_request("Compose apply requires a durable v2 operation identity")
    })?;
    let operation_uuid = uuid::Uuid::parse_str(operation_id)
        .map_err(|_| AppError::unprocessable("Compose operation identity is invalid"))?;
    let project_name = compose_project_name(operation_id)?;
    let operation_compact = operation_uuid.simple().to_string();
    let image_ref = read_compose_package_value(
        adapter,
        &Path::new(COMPOSE_DIR).join("image-ref"),
        "image reference",
    )?;
    let image_id = read_compose_package_value(
        adapter,
        &Path::new(COMPOSE_DIR).join("image-id"),
        "image ID",
    )?;
    let runtime_ref = format!("localhost/helicoid-server:install-{operation_compact}");
    let image_archive = Path::new(COMPOSE_DIR).join("server-image.tar");
    let image_archive_text = image_archive.to_string_lossy().into_owned();
    let runtime_image_id = inspect_docker_image_id(adapter, &runtime_ref)?;

    match runtime_image_id {
        Some(found) if found == image_id => {
            reconcile_owned_resource(
                adapter,
                journal,
                journal_path,
                "compose_image_tag",
                &runtime_ref,
            )?;
        }
        Some(_) => {
            return Err(AppError::conflict(
                "the operation-specific Compose image tag refers to a different image",
                None,
            ));
        }
        None => {
            let package_image_id = inspect_docker_image_id(adapter, &image_ref)?;
            match package_image_id {
                Some(found) if found == image_id => {}
                Some(_) => {
                    return Err(AppError::conflict(
                        "the signed Compose image reference is already assigned to a different image",
                        None,
                    ));
                }
                None => {
                    record_resource_intent(
                        adapter,
                        journal_path,
                        journal,
                        "compose_package_image",
                        &image_ref,
                    )?;
                    let args = vec![
                        "image".to_string(),
                        "load".to_string(),
                        "--input".to_string(),
                        image_archive_text,
                    ];
                    if let Err(error) =
                        run_docker_command(adapter, &args, "load signed image archive")
                    {
                        let message = format!("load signed Compose image archive: {error}");
                        let _ = record_resource_failed(
                            adapter,
                            journal_path,
                            journal,
                            "compose_package_image",
                            &image_ref,
                            &message,
                        );
                        return Err(AppError::internal(message));
                    }
                    if inspect_docker_image_id(adapter, &image_ref)?.as_deref() != Some(&image_id) {
                        return Err(AppError::conflict(
                            "loaded Compose image does not match the signed image ID",
                            None,
                        ));
                    }
                    record_resource_completed(
                        adapter,
                        journal_path,
                        journal,
                        "compose_package_image",
                        &image_ref,
                    )?;
                }
            }

            record_resource_intent(
                adapter,
                journal_path,
                journal,
                "compose_image_tag",
                &runtime_ref,
            )?;
            let args = vec![
                "image".to_string(),
                "tag".to_string(),
                image_ref.clone(),
                runtime_ref.clone(),
            ];
            if let Err(error) = run_docker_command(adapter, &args, "tag signed Compose image") {
                let message = format!("tag signed Compose image: {error}");
                let _ = record_resource_failed(
                    adapter,
                    journal_path,
                    journal,
                    "compose_image_tag",
                    &runtime_ref,
                    &message,
                );
                return Err(AppError::internal(message));
            }
            if inspect_docker_image_id(adapter, &runtime_ref)?.as_deref() != Some(&image_id) {
                return Err(AppError::conflict(
                    "operation-specific Compose image tag does not match the signed image ID",
                    None,
                ));
            }
            record_resource_completed(
                adapter,
                journal_path,
                journal,
                "compose_image_tag",
                &runtime_ref,
            )?;
        }
    }

    let existing_containers = compose_project_containers(adapter, &project_name)?;
    if existing_containers.len() > 1 {
        return Err(AppError::conflict(
            "Compose project has more than one server container; inspect the host before retrying",
            None,
        ));
    }
    let project_networks = compose_project_networks(adapter, &project_name)?;
    for network_id in &project_networks {
        verify_compose_network(adapter, network_id, &project_name)?;
    }
    let mut start_resource = None;
    let needs_start = if let Some(container_id) = existing_containers.first() {
        verify_compose_container(
            adapter,
            container_id,
            &project_name,
            operation_id,
            &image_id,
        )?;
        let state = compose_container_state(adapter, container_id)?;
        if state == "running" {
            false
        } else {
            let identity = project_name.clone();
            record_resource_intent(
                adapter,
                journal_path,
                journal,
                "compose_container_start",
                &identity,
            )?;
            start_resource = Some(("compose_container_start", identity));
            true
        }
    } else {
        record_resource_intent(
            adapter,
            journal_path,
            journal,
            "compose_project",
            &project_name,
        )?;
        start_resource = Some(("compose_project", project_name.clone()));
        true
    };
    if needs_start {
        let mut args = compose_base_args(&project_name);
        args.push("up".to_string());
        args.push("--detach".to_string());
        args.push("--pull".to_string());
        args.push("never".to_string());
        if let Err(error) = run_docker_command(adapter, &args, "start reviewed Compose project") {
            let message = format!("start Compose project: {error}");
            if let Some((resource_type, identity)) = start_resource.as_ref() {
                let _ = record_resource_failed(
                    adapter,
                    journal_path,
                    journal,
                    resource_type,
                    identity,
                    &message,
                );
            }
            return Err(AppError::internal(message));
        }
    }

    let containers = compose_project_containers(adapter, &project_name)?;
    if containers.len() != 1 {
        return Err(AppError::conflict(
            "Compose project does not contain exactly one server container",
            None,
        ));
    }
    let mut verified_containers = Vec::with_capacity(containers.len());
    for container_id in containers {
        verify_compose_container(
            adapter,
            &container_id,
            &project_name,
            operation_id,
            &image_id,
        )?;
        verified_containers.push(container_id);
    }
    for container_id in verified_containers {
        let identity = format!("{project_name}/{container_id}");
        let state = compose_container_state(adapter, &container_id)?;
        if state != "running" {
            return Err(AppError::conflict(
                format!("journaled Compose server did not reach running state (state: {state})"),
                None,
            ));
        }
        reconcile_owned_resource(
            adapter,
            journal,
            journal_path,
            "compose_container_start",
            &project_name,
        )?;
        if !is_resource_completed(journal, "compose_container", &identity) {
            if !journal.resources.iter().any(|resource| {
                resource.resource_type == "compose_container"
                    && resource.identity == identity
                    && resource.status == ResourceStatus::Intent
            }) {
                record_resource_intent(
                    adapter,
                    journal_path,
                    journal,
                    "compose_container",
                    &identity,
                )?;
            }
            record_resource_completed(
                adapter,
                journal_path,
                journal,
                "compose_container",
                &identity,
            )?;
        }
    }
    reconcile_owned_resource(
        adapter,
        journal,
        journal_path,
        "compose_project",
        &project_name,
    )?;
    journal.updated_at = adapter.now_iso8601();
    save_journal(adapter, journal_path, journal)
}

fn compose_base_args(project_name: &str) -> Vec<String> {
    vec![
        "compose".to_string(),
        "--project-name".to_string(),
        project_name.to_string(),
        "--project-directory".to_string(),
        COMPOSE_DIR.to_string(),
        "--env-file".to_string(),
        format!("{COMPOSE_DIR}/.env"),
        "-f".to_string(),
        format!("{COMPOSE_DIR}/compose.yaml"),
    ]
}

fn compose_project_name(operation_id: &str) -> AppResult<String> {
    let operation_uuid = uuid::Uuid::parse_str(operation_id)
        .map_err(|_| AppError::unprocessable("Compose operation identity is invalid"))?;
    let compact = operation_uuid.simple().to_string();
    Ok(format!("helicoid-{compact}"))
}

fn compose_project_containers(
    adapter: &dyn CommandAdapter,
    project_name: &str,
) -> AppResult<Vec<String>> {
    let args = vec![
        "ps".to_string(),
        "--all".to_string(),
        "--filter".to_string(),
        format!("label=com.docker.compose.project={project_name}"),
        "--format".to_string(),
        "{{.ID}}".to_string(),
    ];
    let output = run_docker_command(adapter, &args, "inspect Compose project containers")?;
    let mut ids = Vec::new();
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line.len() < 12 || !line.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AppError::internal(
                "Docker returned an invalid Compose container identity",
            ));
        }
        ids.push(line.to_ascii_lowercase());
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn is_valid_container_id(container_id: &str) -> bool {
    container_id.len() >= 12 && container_id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn compose_service_is_owned_and_running(
    adapter: &dyn CommandAdapter,
    operation_id: &str,
) -> AppResult<bool> {
    Ok(compose_owned_running_container(adapter, operation_id)?.is_some())
}

fn compose_owned_running_container(
    adapter: &dyn CommandAdapter,
    operation_id: &str,
) -> AppResult<Option<String>> {
    let project_name = compose_project_name(operation_id)?;
    let containers = compose_project_containers(adapter, &project_name)?;
    if containers.is_empty() {
        return Ok(None);
    }
    if containers.len() != 1 {
        return Err(AppError::conflict(
            "journaled Compose project has an unexpected container count",
            None,
        ));
    }
    let image_id = read_compose_package_value(
        adapter,
        &Path::new(COMPOSE_DIR).join("image-id"),
        "image ID",
    )?;
    verify_compose_container(
        adapter,
        &containers[0],
        &project_name,
        operation_id,
        &image_id,
    )?;
    let container_id = containers[0].clone();
    let state = docker_command_output(
        adapter,
        &[
            "inspect".to_string(),
            "--format={{.State.Status}}".to_string(),
            container_id.clone(),
        ],
        "inspect Compose server state",
    )?;
    Ok((state.trim() == "running").then_some(container_id))
}

fn verify_compose_container(
    adapter: &dyn CommandAdapter,
    container_id: &str,
    project_name: &str,
    operation_id: &str,
    expected_image_id: &str,
) -> AppResult<()> {
    verify_compose_container_labels(adapter, container_id, project_name, operation_id)?;
    let image_id = docker_command_output(
        adapter,
        &[
            "inspect".to_string(),
            "--format={{.Image}}".to_string(),
            container_id.to_string(),
        ],
        "inspect Compose container image",
    )?;
    if image_id.trim() != expected_image_id {
        return Err(AppError::conflict(
            "Compose container uses an image other than the signed package image",
            None,
        ));
    }
    Ok(())
}

fn compose_container_state(adapter: &dyn CommandAdapter, container_id: &str) -> AppResult<String> {
    let state = docker_command_output(
        adapter,
        &[
            "inspect".to_string(),
            "--format={{.State.Status}}".to_string(),
            container_id.to_string(),
        ],
        "inspect Compose server state",
    )?;
    let state = state.trim();
    if state.is_empty()
        || state.len() > 32
        || !state
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err(AppError::internal(
            "Docker returned an invalid container state",
        ));
    }
    Ok(state.to_string())
}

fn compose_container_health_state(
    adapter: &dyn CommandAdapter,
    container_id: &str,
) -> AppResult<String> {
    let state = docker_command_output(
        adapter,
        &[
            "inspect".to_string(),
            "--format={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}".to_string(),
            container_id.to_string(),
        ],
        "inspect Compose server health",
    )?;
    let state = state.trim();
    if !matches!(state, "healthy" | "starting" | "unhealthy" | "none") {
        return Err(AppError::internal(
            "Docker returned an invalid Compose health state",
        ));
    }
    Ok(state.to_string())
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeReadiness {
    bootstrap_ready: bool,
    server_ready_for_enrollment: bool,
}

fn compose_readiness_flags(
    health_state: &str,
    readiness: Option<&ComposeReadiness>,
) -> (bool, bool) {
    let Some(readiness) = readiness else {
        return (false, false);
    };
    (
        readiness.bootstrap_ready,
        health_state == "healthy" && readiness.server_ready_for_enrollment,
    )
}

fn compose_container_readiness(
    adapter: &dyn CommandAdapter,
    container_id: &str,
) -> AppResult<ComposeReadiness> {
    let output = docker_command_output(
        adapter,
        &[
            "exec".to_string(),
            container_id.to_string(),
            "hs-server".to_string(),
            "installer-readiness".to_string(),
            "--address".to_string(),
            "127.0.0.1:8787".to_string(),
        ],
        "query readiness in journaled Compose server",
    )?;
    serde_json::from_str(&output)
        .map_err(|_| AppError::internal("Compose server returned invalid readiness JSON"))
}

fn verify_compose_container_labels(
    adapter: &dyn CommandAdapter,
    container_id: &str,
    project_name: &str,
    operation_id: &str,
) -> AppResult<()> {
    let labels = docker_command_output(
        adapter,
        &[
            "inspect".to_string(),
            "--format={{json .Config.Labels}}".to_string(),
            container_id.to_string(),
        ],
        "inspect Compose container labels",
    )?;
    let labels: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&labels)
        .map_err(|_| AppError::internal("Docker returned invalid Compose container labels"))?;
    let label = |key: &str| labels.get(key).and_then(serde_json::Value::as_str);
    if label("com.docker.compose.project") != Some(project_name)
        || label("com.docker.compose.service") != Some("server")
        || label("com.helicoid.managed") != Some("true")
        || label("com.helicoid.operation-id") != Some(operation_id)
    {
        return Err(AppError::conflict(
            "Compose container labels do not match the journaled Helicoid project",
            None,
        ));
    }
    Ok(())
}

fn inspect_docker_image_id(
    adapter: &dyn CommandAdapter,
    image_ref: &str,
) -> AppResult<Option<String>> {
    let args = vec![
        "image".to_string(),
        "inspect".to_string(),
        "--format={{.Id}}".to_string(),
        image_ref.to_string(),
    ];
    let (stdout, stderr, code) = adapter
        .docker_command(&args)
        .map_err(|error| AppError::internal(format!("inspect Docker image: {error}")))?;
    if code != 0 {
        let diagnostic = String::from_utf8_lossy(&stderr).to_ascii_lowercase();
        if diagnostic.contains("no such image") {
            return Ok(None);
        }
        return Err(AppError::internal(format!(
            "Docker image inspection failed: {}",
            bounded_diagnostic(&diagnostic)
        )));
    }
    let image_id = String::from_utf8(stdout)
        .map_err(|_| AppError::internal("Docker returned a non-UTF-8 image ID"))?
        .trim()
        .to_string();
    if image_id.len() != 71
        || !image_id.starts_with("sha256:")
        || !image_id[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AppError::internal("Docker returned an invalid image ID"));
    }
    Ok(Some(image_id.to_ascii_lowercase()))
}

fn run_docker_command(
    adapter: &dyn CommandAdapter,
    args: &[String],
    action: &str,
) -> AppResult<String> {
    docker_command_output(adapter, args, action)
}

fn docker_command_output(
    adapter: &dyn CommandAdapter,
    args: &[String],
    action: &str,
) -> AppResult<String> {
    let (stdout, stderr, code) = adapter
        .docker_command(args)
        .map_err(|error| AppError::internal(format!("{action}: {error}")))?;
    if code != 0 {
        return Err(AppError::internal(format!(
            "{action} failed (exit {code}): {}",
            bounded_diagnostic(&String::from_utf8_lossy(&stderr))
        )));
    }
    String::from_utf8(stdout)
        .map_err(|_| AppError::internal(format!("{action} returned non-UTF-8 output")))
}

fn bounded_diagnostic(diagnostic: &str) -> String {
    const MAX_DIAGNOSTIC_BYTES: usize = 1024;
    let sanitized = diagnostic
        .chars()
        .filter(|character| !character.is_control() || *character == '\n' || *character == '\t')
        .take(MAX_DIAGNOSTIC_BYTES)
        .collect::<String>();
    if sanitized.is_empty() {
        "no diagnostic output".to_string()
    } else {
        sanitized
    }
}

fn reconcile_owned_resource(
    adapter: &dyn CommandAdapter,
    journal: &mut Journal,
    journal_path: &Path,
    resource_type: &str,
    identity: &str,
) -> AppResult<()> {
    let latest_status = journal
        .resources
        .iter()
        .rev()
        .find(|resource| resource.resource_type == resource_type && resource.identity == identity)
        .map(|resource| resource.status);
    match latest_status {
        Some(ResourceStatus::Completed) => return Ok(()),
        Some(ResourceStatus::Intent) => {}
        Some(ResourceStatus::Failed) | None => {
            record_resource_intent(adapter, journal_path, journal, resource_type, identity)?;
        }
    }
    record_resource_completed(adapter, journal_path, journal, resource_type, identity)
}

fn read_compose_package_value(
    adapter: &dyn CommandAdapter,
    path: &Path,
    label: &str,
) -> AppResult<String> {
    let metadata = adapter
        .symlink_metadata(path)
        .map_err(|error| AppError::internal(format!("inspect Compose {label}: {error}")))?;
    if metadata.is_symlink || metadata.is_dir || metadata.len == 0 || metadata.len > 256 {
        return Err(AppError::forbidden(format!(
            "installed Compose {label} has an invalid file shape"
        )));
    }
    let bytes = adapter
        .read_file(path)
        .map_err(|error| AppError::internal(format!("read Compose {label}: {error}")))?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| AppError::forbidden(format!("installed Compose {label} is not UTF-8")))?
        .trim();
    if value.is_empty() || value.len() > 128 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(AppError::forbidden(format!(
            "installed Compose {label} is invalid"
        )));
    }
    Ok(value.to_string())
}

fn write_journaled_product_file(
    adapter: &dyn CommandAdapter,
    journal: &mut Journal,
    journal_path: &Path,
    destination: &Path,
    contents: &[u8],
    mode: u32,
) -> AppResult<()> {
    let identity = destination.to_string_lossy().into_owned();
    if is_resource_completed(journal, "file", &identity) {
        let metadata = adapter.symlink_metadata(destination).map_err(|error| {
            AppError::internal(format!("inspect owned product file {identity}: {error}"))
        })?;
        if metadata.is_symlink || metadata.is_dir || metadata.len == 0 {
            return Err(AppError::forbidden(format!(
                "owned product file {identity} is not a regular file"
            )));
        }
        let existing = adapter.read_file(destination).map_err(|error| {
            AppError::internal(format!("read owned product file {identity}: {error}"))
        })?;
        if existing != contents {
            return Err(AppError::conflict(
                format!("owned product file {identity} changed after review"),
                None,
            ));
        }
        return Ok(());
    }

    reject_symlink_parents(adapter, &identity)?;
    if path_present(adapter, destination) {
        let metadata = adapter.symlink_metadata(destination).map_err(|error| {
            AppError::internal(format!("inspect existing product file {identity}: {error}"))
        })?;
        if metadata.is_symlink || metadata.is_dir || metadata.len == 0 {
            return Err(AppError::forbidden(format!(
                "existing product file {identity} is not a regular file"
            )));
        }
        let has_intent = journal.resources.iter().any(|resource| {
            resource.resource_type == "file"
                && resource.identity == identity
                && resource.status == ResourceStatus::Intent
        });
        if !has_intent {
            return Err(AppError::conflict(
                format!("product file already exists outside the install journal: {identity}"),
                None,
            ));
        }
        let existing = adapter.read_file(destination).map_err(|error| {
            AppError::internal(format!(
                "reconcile interrupted product file {identity}: {error}"
            ))
        })?;
        if existing != contents {
            return Err(AppError::conflict(
                format!(
                    "interrupted product file {identity} does not match the reviewed configuration"
                ),
                None,
            ));
        }
        record_resource_completed(adapter, journal_path, journal, "file", &identity)?;
        return Ok(());
    }

    record_resource_intent(adapter, journal_path, journal, "file", &identity)?;
    if let Err(error) = adapter.write_file(destination, contents) {
        let message = format!("write product file {identity}: {error}");
        let _ = record_resource_failed(adapter, journal_path, journal, "file", &identity, &message);
        return Err(AppError::internal(message));
    }
    if let Err(error) = adapter.set_permissions(destination, mode) {
        let message = format!("set permissions on product file {identity}: {error}");
        let _ = record_resource_failed(adapter, journal_path, journal, "file", &identity, &message);
        return Err(AppError::internal(message));
    }
    if !journal.resources_created.files.contains(&identity) {
        journal.resources_created.files.push(identity.clone());
        save_journal(adapter, journal_path, journal)?;
    }
    record_resource_completed(adapter, journal_path, journal, "file", &identity)
}

fn copy_journaled_compose_tls_file(
    adapter: &dyn CommandAdapter,
    journal: &mut Journal,
    journal_path: &Path,
    source: &Path,
    destination: &Path,
    certificate: bool,
) -> AppResult<()> {
    let identity = destination.to_string_lossy().into_owned();
    if is_resource_completed(journal, "compose_tls_file", &identity) {
        let metadata = adapter.symlink_metadata(destination).map_err(|error| {
            AppError::conflict(
                format!("journaled Compose TLS file is unavailable: {identity}: {error}"),
                None,
            )
        })?;
        if metadata.is_symlink || metadata.is_dir || metadata.len == 0 || metadata.len > 1024 * 1024
        {
            return Err(AppError::conflict(
                format!("journaled Compose TLS file has an invalid shape: {identity}"),
                None,
            ));
        }
        return Ok(());
    }
    reject_symlink_parents(adapter, &identity)?;
    if path_present(adapter, destination) {
        let has_intent = journal.resources.iter().any(|resource| {
            resource.resource_type == "compose_tls_file"
                && resource.identity == identity
                && resource.status == ResourceStatus::Intent
        });
        if !has_intent {
            return Err(AppError::conflict(
                format!("Compose TLS destination already exists outside the install journal: {identity}"),
                None,
            ));
        }
        let metadata = adapter.symlink_metadata(destination).map_err(|error| {
            AppError::internal(format!(
                "inspect interrupted Compose TLS file {identity}: {error}"
            ))
        })?;
        if metadata.is_symlink || metadata.is_dir || metadata.len == 0 || metadata.len > 1024 * 1024
        {
            return Err(AppError::conflict(
                format!("interrupted Compose TLS file has an invalid shape: {identity}"),
                None,
            ));
        }
        if !journal.resources_created.files.contains(&identity) {
            journal.resources_created.files.push(identity.clone());
            save_journal(adapter, journal_path, journal)?;
        }
        record_resource_completed(
            adapter,
            journal_path,
            journal,
            "compose_tls_file",
            &identity,
        )?;
        return Ok(());
    }

    record_resource_intent(
        adapter,
        journal_path,
        journal,
        "compose_tls_file",
        &identity,
    )?;
    if let Err(error) = adapter.copy_compose_tls_file(source, destination, certificate) {
        let message = format!("stage Compose TLS file {identity}: {error}");
        let _ = record_resource_failed(
            adapter,
            journal_path,
            journal,
            "compose_tls_file",
            &identity,
            &message,
        );
        return Err(AppError::internal(message));
    }
    if !journal.resources_created.files.contains(&identity) {
        journal.resources_created.files.push(identity.clone());
        save_journal(adapter, journal_path, journal)?;
    }
    record_resource_completed(
        adapter,
        journal_path,
        journal,
        "compose_tls_file",
        &identity,
    )
}

fn execute_phase(
    adapter: &dyn CommandAdapter,
    phase: Phase,
    plan: &InstallPlan,
    journal: &mut Journal,
    journal_path: &Path,
    context: &PhaseContext<'_>,
) -> AppResult<()> {
    match phase {
        Phase::ServiceUser => {
            if context.deployment_kind == Some(v2::DeploymentKind::LinuxCompose) {
                return Ok(());
            }
            let name = &plan.service_user.name;
            if !is_product_user(name) {
                return Err(AppError::forbidden(format!(
                    "refusing to manage non-product service user '{name}'"
                )));
            }
            if is_resource_completed(journal, "service_user", name) {
                return Ok(());
            }
            // The existence query must succeed before any mutation.
            let exists = adapter.query_user_exists(name).map_err(|e| {
                AppError::internal(format!("cannot query service user '{name}': {e}"))
            })?;
            if exists {
                // Already exists on the system.
                record_resource_completed(adapter, journal_path, journal, "service_user", name)?;
                return Ok(());
            }
            record_resource_intent(adapter, journal_path, journal, "service_user", name)?;
            match adapter.create_system_user(name, Path::new(BASE_DIR)) {
                Ok(()) => {
                    journal.resources_created.service_users.push(name.clone());
                    record_resource_completed(
                        adapter,
                        journal_path,
                        journal,
                        "service_user",
                        name,
                    )?;
                }
                Err(e) => {
                    let msg = format!("create user: {e}");
                    let _ = record_resource_failed(
                        adapter,
                        journal_path,
                        journal,
                        "service_user",
                        name,
                        &msg,
                    );
                    return Err(AppError::internal(msg));
                }
            }
        }
        Phase::Directories => {
            for dir in &plan.directories {
                if !dir.create {
                    continue;
                }
                if !is_product_directory(&dir.path) {
                    return Err(AppError::forbidden(format!(
                        "refusing to create non-product directory '{}'",
                        dir.path
                    )));
                }
                if is_resource_completed(journal, "directory", &dir.path) {
                    continue;
                }
                if dir.owner != "root" && dir.owner != SERVICE_USER && dir.owner != CONTAINER_OWNER
                {
                    return Err(AppError::forbidden(format!(
                        "refusing unsupported owner '{}' for directory '{}'",
                        dir.owner, dir.path
                    )));
                }
                let mode = u32::from_str_radix(&dir.mode, 8).map_err(|_| {
                    AppError::internal(format!(
                        "canonical directory mode is invalid for '{}'",
                        dir.path
                    ))
                })?;
                let already_journaled = journal.resources.iter().any(|resource| {
                    resource.resource_type == "directory" && resource.identity == dir.path
                });
                if path_present(adapter, Path::new(&dir.path)) {
                    match adapter.symlink_metadata(Path::new(&dir.path)) {
                        Ok(meta) if meta.is_symlink => {
                            let msg =
                                format!("directory '{}' is a symlink; refusing to adopt", dir.path);
                            let _ = record_resource_failed(
                                adapter,
                                journal_path,
                                journal,
                                "directory",
                                &dir.path,
                                &msg,
                            );
                            return Err(AppError::forbidden(msg));
                        }
                        Ok(meta) if !meta.is_dir => {
                            let msg =
                                format!("directory destination '{}' is not a directory", dir.path);
                            let _ = record_resource_failed(
                                adapter,
                                journal_path,
                                journal,
                                "directory",
                                &dir.path,
                                &msg,
                            );
                            return Err(AppError::conflict(msg, None));
                        }
                        Ok(_)
                            if !already_journaled
                                && !(dir.path == BASE_DIR
                                    && journal_path.starts_with(Path::new(BASE_DIR))) =>
                        {
                            return Err(AppError::conflict(
                                format!(
                                    "directory '{}' already exists outside this install journal",
                                    dir.path
                                ),
                                None,
                            ));
                        }
                        Ok(_) => {}
                        Err(e) => {
                            let msg = format!("cannot query directory '{}': {e}", dir.path);
                            let _ = record_resource_failed(
                                adapter,
                                journal_path,
                                journal,
                                "directory",
                                &dir.path,
                                &msg,
                            );
                            return Err(AppError::internal(msg));
                        }
                    }
                }
                if !already_journaled
                    || journal
                        .resources
                        .iter()
                        .rev()
                        .find(|resource| {
                            resource.resource_type == "directory" && resource.identity == dir.path
                        })
                        .is_some_and(|resource| resource.status != ResourceStatus::Intent)
                {
                    record_resource_intent(adapter, journal_path, journal, "directory", &dir.path)?;
                }
                if !path_present(adapter, Path::new(&dir.path)) {
                    reject_symlink_parents(adapter, &dir.path)?;
                    match adapter.create_dir_all(Path::new(&dir.path)) {
                        Ok(()) => {
                            journal.resources_created.directories.push(dir.path.clone());
                            save_journal(adapter, journal_path, journal)?;
                        }
                        Err(e) => {
                            let msg = format!("create dir '{}': {e}", dir.path);
                            let _ = record_resource_failed(
                                adapter,
                                journal_path,
                                journal,
                                "directory",
                                &dir.path,
                                &msg,
                            );
                            return Err(AppError::internal(msg));
                        }
                    }
                }
                if dir.owner != "root" {
                    if let Err(e) = adapter.set_owner(Path::new(&dir.path), &dir.owner) {
                        let msg = format!("set owner of directory '{}': {e}", dir.path);
                        let _ = record_resource_failed(
                            adapter,
                            journal_path,
                            journal,
                            "directory",
                            &dir.path,
                            &msg,
                        );
                        return Err(AppError::internal(msg));
                    }
                }
                if let Err(e) = adapter.set_permissions(Path::new(&dir.path), mode) {
                    let msg = format!("set mode on directory '{}': {e}", dir.path);
                    let _ = record_resource_failed(
                        adapter,
                        journal_path,
                        journal,
                        "directory",
                        &dir.path,
                        &msg,
                    );
                    return Err(AppError::internal(msg));
                }
                if !journal.resources_created.directories.contains(&dir.path) {
                    journal.resources_created.directories.push(dir.path.clone());
                }
                record_resource_completed(adapter, journal_path, journal, "directory", &dir.path)?;
            }
        }
        Phase::Files => {
            for file in &plan.files {
                if !is_product_file(&file.destination) {
                    return Err(AppError::forbidden(format!(
                        "refusing to write non-product destination '{}'",
                        file.destination
                    )));
                }
                if is_resource_completed(journal, "file", &file.destination) {
                    continue;
                }
                let src = if let Some(pkg_dir) = context.package_dir {
                    pkg_dir.join(&file.source)
                } else {
                    Path::new(&file.source).to_path_buf()
                };
                let dst = Path::new(&file.destination);
                // TOCTOU: re-query destination and parents immediately before write.
                reject_symlink_parents(adapter, &file.destination)?;
                if let Ok(meta) = adapter.symlink_metadata(dst) {
                    if meta.is_symlink {
                        let msg = format!(
                            "destination '{}' is a symlink; refusing to overwrite",
                            file.destination
                        );
                        let _ = record_resource_failed(
                            adapter,
                            journal_path,
                            journal,
                            "file",
                            &file.destination,
                            &msg,
                        );
                        return Err(AppError::forbidden(msg));
                    }
                }
                let expected_artifact = context
                    .verified_artifacts
                    .iter()
                    .find(|artifact| artifact.path == file.source)
                    .ok_or_else(|| {
                        AppError::forbidden(format!(
                            "plan file '{}' is not in the verified package manifest",
                            file.source
                        ))
                    })?;
                record_resource_intent(adapter, journal_path, journal, "file", &file.destination)?;
                match adapter.copy_verified_file(
                    &src,
                    dst,
                    &expected_artifact.sha256,
                    expected_artifact.size_bytes,
                ) {
                    Ok(()) => {}
                    Err(e) => {
                        let msg = format!("copy '{}': {e}", file.source);
                        let _ = record_resource_failed(
                            adapter,
                            journal_path,
                            journal,
                            "file",
                            &file.destination,
                            &msg,
                        );
                        return Err(AppError::internal(msg));
                    }
                }
                let mode = u32::from_str_radix(&file.mode, 8).unwrap_or(0o644);
                if let Err(e) = adapter.set_permissions(dst, mode) {
                    let msg = format!("chmod '{}': {e}", file.destination);
                    let _ = record_resource_failed(
                        adapter,
                        journal_path,
                        journal,
                        "file",
                        &file.destination,
                        &msg,
                    );
                    return Err(AppError::internal(msg));
                }
                journal
                    .resources_created
                    .files
                    .push(file.destination.clone());
                record_resource_completed(
                    adapter,
                    journal_path,
                    journal,
                    "file",
                    &file.destination,
                )?;
            }
            if context.deployment_kind == Some(v2::DeploymentKind::LinuxCompose) {
                write_compose_runtime_files(adapter, journal, journal_path, context)?;
            }
        }
        Phase::Units => {
            if context.deployment_kind == Some(v2::DeploymentKind::LinuxCompose) {
                install_compose_backup_units(adapter, journal, journal_path, plan, context)?;
                install_compose_service(adapter, journal, journal_path, context)?;
                return Ok(());
            }
            let signed_destinations: std::collections::HashSet<&str> =
                plan.files.iter().map(|f| f.destination.as_str()).collect();
            let unit_dest = format!("/etc/systemd/system/{UNIT_NAME}");

            for unit in &plan.units {
                if unit.action != "install" {
                    continue;
                }
                if !is_product_unit(&unit.name) {
                    return Err(AppError::forbidden(format!(
                        "refusing to manage non-product unit '{}'",
                        unit.name
                    )));
                }
                if is_resource_completed(journal, "unit", &unit.name) {
                    continue;
                }
                record_resource_intent(adapter, journal_path, journal, "unit", &unit.name)?;

                if signed_destinations.contains(unit_dest.as_str()) {
                    // Signed artifact already copied — do not overwrite.
                } else {
                    let unit_content = generate_unit_content(
                        &plan.service_user.name,
                        unit,
                        context.data_directory,
                        context.backup_directory,
                        context.network,
                        context.deployment_kind,
                    );
                    if let Err(e) = adapter.install_unit(&unit.name, unit_content.as_bytes()) {
                        let msg = format!("install unit '{}': {e}", unit.name);
                        let _ = record_resource_failed(
                            adapter,
                            journal_path,
                            journal,
                            "unit",
                            &unit.name,
                            &msg,
                        );
                        return Err(AppError::internal(msg));
                    }
                }
                if !journal.resources_created.units.contains(&unit.name) {
                    journal.resources_created.units.push(unit.name.clone());
                    save_journal(adapter, journal_path, journal)?;
                }
                if let Err(e) = adapter.systemd_daemon_reload() {
                    let msg = format!("daemon-reload: {e}");
                    let _ = record_resource_failed(
                        adapter,
                        journal_path,
                        journal,
                        "unit",
                        &unit.name,
                        &msg,
                    );
                    return Err(AppError::internal(msg));
                }
                if unit.enabled {
                    if let Err(e) = adapter.enable_unit(&unit.name) {
                        let msg = format!("enable unit '{}': {e}", unit.name);
                        let _ = record_resource_failed(
                            adapter,
                            journal_path,
                            journal,
                            "unit",
                            &unit.name,
                            &msg,
                        );
                        return Err(AppError::internal(msg));
                    }
                }
                record_resource_completed(adapter, journal_path, journal, "unit", &unit.name)?;
            }
        }
        Phase::Firewall => {
            for rule in &plan.firewall {
                let identity = format!("{}:{}:{}", rule.port, rule.protocol, rule.comment);
                if is_resource_completed(journal, "firewall_rule", &identity) {
                    continue;
                }
                record_resource_intent(adapter, journal_path, journal, "firewall_rule", &identity)?;
                match adapter.firewall_allow(rule.port, &rule.protocol, &rule.comment) {
                    Ok(()) => {
                        journal
                            .resources_created
                            .firewall_rules
                            .push(format!("{}:{}:{}", rule.port, rule.protocol, rule.comment));
                        record_resource_completed(
                            adapter,
                            journal_path,
                            journal,
                            "firewall_rule",
                            &identity,
                        )?;
                    }
                    Err(e) => {
                        let msg = format!("firewall allow {}/{}: {e}", rule.port, rule.protocol);
                        let _ = record_resource_failed(
                            adapter,
                            journal_path,
                            journal,
                            "firewall_rule",
                            &identity,
                            &msg,
                        );
                        return Err(AppError::internal(msg));
                    }
                }
            }
        }
        Phase::Completed | Phase::RolledBack => {}
    }
    Ok(())
}

fn install_compose_backup_units(
    adapter: &dyn CommandAdapter,
    journal: &mut Journal,
    journal_path: &Path,
    plan: &InstallPlan,
    context: &PhaseContext<'_>,
) -> AppResult<()> {
    for unit in &plan.units {
        let control_socket = unit.name == BACKUP_CONTROL_SOCKET_UNIT;
        let allowed = matches!(
            unit.name.as_str(),
            BACKUP_SERVICE_UNIT
                | BACKUP_TIMER_UNIT
                | BACKUP_CONTROL_SOCKET_UNIT
                | BACKUP_CONTROL_SERVICE_UNIT
        );
        if !allowed || unit.action != "install" || unit.enabled != control_socket {
            return Err(AppError::forbidden(
                "Compose installs may only own the enabled backup control socket and disabled product backup units",
            ));
        }
        let content = generate_unit_content(
            &plan.service_user.name,
            unit,
            context.data_directory,
            context.backup_directory,
            context.network,
            context.deployment_kind,
        );
        if is_resource_completed(journal, "unit", &unit.name) {
            match adapter.query_unit_exists(&unit.name) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(AppError::conflict(
                        format!("journaled systemd unit '{}' is missing", unit.name),
                        None,
                    ));
                }
                Err(error) => {
                    return Err(AppError::internal(format!(
                        "inspect journaled systemd unit '{}': {error}",
                        unit.name
                    )));
                }
            }
            let path = PathBuf::from(format!("/etc/systemd/system/{}", unit.name));
            let installed = adapter.read_file(&path).map_err(|error| {
                AppError::internal(format!("inspect journaled systemd unit: {error}"))
            })?;
            if installed != content.as_bytes() {
                return Err(AppError::conflict(
                    format!("journaled systemd unit '{}' was modified", unit.name),
                    None,
                ));
            }
            if control_socket {
                adapter
                    .enable_unit(&unit.name)
                    .and_then(|()| adapter.start_unit(&unit.name))
                    .map_err(|error| {
                        AppError::internal(format!(
                            "ensure Compose backup control socket is active: {error}"
                        ))
                    })?;
            }
            continue;
        }
        match adapter.query_unit_exists(&unit.name) {
            Ok(false) => {}
            Ok(true) => {
                let owned = journal
                    .resources_created
                    .units
                    .iter()
                    .any(|created| created == &unit.name);
                let interrupted_write = journal.resources.iter().any(|resource| {
                    resource.resource_type == "unit" && resource.identity == unit.name
                });
                if !owned && !interrupted_write {
                    return Err(AppError::conflict(
                        format!("systemd unit '{}' appeared after preflight", unit.name),
                        None,
                    ));
                }
                let path = PathBuf::from(format!("/etc/systemd/system/{}", unit.name));
                let existing = adapter.read_file(&path).map_err(|error| {
                    AppError::internal(format!("inspect owned systemd unit: {error}"))
                })?;
                if existing != content.as_bytes() {
                    return Err(AppError::conflict(
                        format!("journaled systemd unit '{}' was modified", unit.name),
                        None,
                    ));
                }
            }
            Err(error) => {
                return Err(AppError::internal(format!(
                    "inspect systemd unit '{}': {error}",
                    unit.name
                )));
            }
        }
        record_resource_intent(adapter, journal_path, journal, "unit", &unit.name)?;
        if let Err(error) = adapter.install_unit(&unit.name, content.as_bytes()) {
            let message = format!("install Compose backup unit '{}': {error}", unit.name);
            let _ = record_resource_failed(
                adapter,
                journal_path,
                journal,
                "unit",
                &unit.name,
                &message,
            );
            return Err(AppError::internal(message));
        }
        if !journal.resources_created.units.contains(&unit.name) {
            journal.resources_created.units.push(unit.name.clone());
            save_journal(adapter, journal_path, journal)?;
        }
        if let Err(error) = adapter.systemd_daemon_reload() {
            let message = format!("reload systemd after installing '{}': {error}", unit.name);
            let _ = record_resource_failed(
                adapter,
                journal_path,
                journal,
                "unit",
                &unit.name,
                &message,
            );
            return Err(AppError::internal(message));
        }
        record_resource_completed(adapter, journal_path, journal, "unit", &unit.name)?;
        if control_socket {
            if let Err(error) = adapter
                .enable_unit(&unit.name)
                .and_then(|()| adapter.start_unit(&unit.name))
            {
                let message = "could not start the Compose backup control socket";
                let _ = record_resource_failed(
                    adapter,
                    journal_path,
                    journal,
                    "unit",
                    &unit.name,
                    message,
                );
                return Err(AppError::internal(format!("{message}: {error}")));
            }
        }
    }
    Ok(())
}

fn generate_unit_content(
    service_user: &str,
    unit: &UnitSpec,
    data_directory: &str,
    backup_directory: &str,
    network: Option<&v2::NetworkConfiguration>,
    deployment_kind: Option<v2::DeploymentKind>,
) -> String {
    if unit.name == BACKUP_CONTROL_SOCKET_UNIT {
        return generate_backup_control_socket_unit_content();
    }
    if unit.name == BACKUP_CONTROL_SERVICE_UNIT {
        return generate_backup_control_service_unit_content();
    }
    if unit.name == BACKUP_SERVICE_UNIT {
        return generate_backup_service_unit_content(
            service_user,
            data_directory,
            backup_directory,
            deployment_kind,
        );
    }
    if unit.name == BACKUP_TIMER_UNIT {
        return generate_backup_timer_unit_content();
    }
    let (exec_start, credentials) = match network {
        Some(configuration)
            if matches!(
                configuration.scope,
                v2::NetworkScope::Lan | v2::NetworkScope::PrivateDns
            ) =>
        {
            let address = configuration
                .bind_address
                .as_deref()
                .expect("validated LAN or private DNS configuration has a bind address");
            let ip = address
                .parse::<IpAddr>()
                .expect("validated LAN or private DNS configuration has a literal IP address");
            let bind = SocketAddr::new(ip, configuration.authority_port);
            (
                format!(
                    "/opt/helicoid/bin/hs-server --data {data_directory}/hs-server.db serve-dual --local-bind 127.0.0.1:8787 --network-bind {bind} --tls-cert=%d/server-cert.pem --tls-key=%d/server-key.pem --allow-network",
                ),
                format!(
                    "LoadCredential=server-cert.pem:{TLS_CERTIFICATE_PATH}\nLoadCredential=server-key.pem:{TLS_PRIVATE_KEY_PATH}\n"
                ),
            )
        }
        _ => (
            format!(
                "/opt/helicoid/bin/hs-server --data {data_directory}/hs-server.db serve --bind 127.0.0.1:8787"
            ),
            String::new(),
        ),
    };
    format!(
        r#"[Unit]
Description=Helicoid Systems coordination server
After=network.target

[Service]
Type=simple
User={user}
ExecStart={exec_start}
{credentials}Restart={restart_policy}
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths={data_directory}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#,
        user = service_user,
        exec_start = exec_start,
        credentials = credentials,
        restart_policy = unit.restart_policy,
        data_directory = data_directory,
    )
}

fn generate_backup_control_socket_unit_content() -> String {
    format!(
        r#"[Unit]
Description=Helicoid Compose backup schedule control socket
Before=docker.service

[Socket]
ListenStream={socket_path}
Accept=yes
Service={service_unit}
MaxConnections=4
TriggerLimitIntervalSec=1min
TriggerLimitBurst=8
SocketUser=root
SocketGroup=root
SocketMode=0622
DirectoryMode=0711
RemoveOnStop=true

[Install]
WantedBy=sockets.target
"#,
        socket_path = BACKUP_CONTROL_SOCKET_PATH,
        service_unit = BACKUP_CONTROL_SERVICE_UNIT,
    )
}

fn generate_backup_control_service_unit_content() -> String {
    r#"[Unit]
Description=Helicoid Compose backup schedule request
CollectMode=inactive-or-failed

[Service]
Type=oneshot
User=root
ExecStart=/opt/helicoid/bin/hs-server backup compose-control-request
StandardInput=socket
StandardOutput=socket
StandardError=journal
TimeoutStartSec=90
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/etc/systemd/system /opt/helicoid/.installer /run/lock /run/systemd
"#
    .to_string()
}

fn generate_backup_service_unit_content(
    service_user: &str,
    data_directory: &str,
    backup_directory: &str,
    deployment_kind: Option<v2::DeploymentKind>,
) -> String {
    if deployment_kind == Some(v2::DeploymentKind::LinuxCompose) {
        return format!(
            r#"[Unit]
Description=Helicoid encrypted database backup for Compose
After=docker.service

[Service]
Type=oneshot
User=root
TimeoutStartSec=6h
ExecStart=/opt/helicoid/bin/hs-server backup scheduled-compose-create
LoadCredentialEncrypted=helicoid-backup-passphrase:{credential_path}
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/run/lock /var/run/docker.sock
StandardOutput=journal
StandardError=journal
"#,
            credential_path = COMPOSE_BACKUP_CREDENTIAL_PATH,
        );
    }
    format!(
        r#"[Unit]
Description=Helicoid encrypted database backup
Requisite={server_unit}
After={server_unit}

[Service]
Type=oneshot
User={service_user}
TimeoutStartSec=6h
ExecStart=/opt/helicoid/bin/hs-server --data {data_directory}/hs-server.db backup scheduled-create --directory {backup_directory}
LoadCredentialEncrypted=helicoid-backup-passphrase:{credential_path}
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths={data_directory} {backup_directory}
StandardOutput=journal
StandardError=journal
"#,
        server_unit = UNIT_NAME,
        service_user = service_user,
        data_directory = data_directory,
        backup_directory = backup_directory,
        credential_path = BACKUP_CREDENTIAL_PATH,
    )
}

fn generate_backup_timer_unit_content() -> String {
    format!(
        r#"[Unit]
Description=Daily Helicoid encrypted database backup

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true
RandomizedDelaySec=1h
Unit={service_unit}

[Install]
WantedBy=timers.target
"#,
        service_unit = BACKUP_SERVICE_UNIT,
    )
}

// ---------------------------------------------------------------------------
// Inspect
// ---------------------------------------------------------------------------

/// Read current installation state from the state directory.
pub fn inspect(adapter: &dyn CommandAdapter, input: &InspectInput) -> AppResult<InspectResult> {
    let state_dir = Path::new(&input.state_dir);
    let journal_path = state_dir.join("journal.json");
    let manifest_path = state_dir.join("installed.json");

    if !adapter.path_exists(&journal_path) {
        return Ok(InspectResult {
            contract_version: CONTRACT_VERSION,
            installed: false,
            version: None,
            phase: None,
            service_user: None,
            directories: vec![],
            units: vec![],
            data_dir: None,
            backup_dir: None,
            journal_path: None,
            last_operation: None,
            last_operation_ok: false,
        });
    }

    let journal_bytes = adapter
        .read_file(&journal_path)
        .map_err(|e| AppError::internal(format!("cannot read journal: {e}")))?;
    let journal: Journal = serde_json::from_slice(&journal_bytes)
        .map_err(|e| AppError::internal(format!("corrupt journal: {e}")))?;

    let (version, last_op) = if adapter.path_exists(&manifest_path) {
        let bytes = adapter
            .read_file(&manifest_path)
            .map_err(|e| AppError::internal(format!("cannot read installed manifest: {e}")))?;
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        let ver = v["version"].as_str().map(String::from);
        (ver, Some("apply".to_string()))
    } else {
        (None, None)
    };

    let last_op_ok = journal.current_phase == "completed";
    let installed = journal
        .phases
        .get("completed")
        .map(|e| e.status == PhaseStatus::Completed)
        .unwrap_or(false);

    Ok(InspectResult {
        contract_version: CONTRACT_VERSION,
        installed,
        version,
        phase: Some(journal.current_phase),
        service_user: journal.resources_created.service_users.first().cloned(),
        directories: journal.resources_created.directories.clone(),
        units: journal.resources_created.units.clone(),
        data_dir: Some(DATA_SUBDIR.to_string()),
        backup_dir: Some(BACKUP_DIR.to_string()),
        journal_path: Some(journal_path.to_string_lossy().to_string()),
        last_operation: last_op,
        last_operation_ok: last_op_ok,
    })
}

// ---------------------------------------------------------------------------
// Resume
// ---------------------------------------------------------------------------

/// Resume an interrupted apply by reloading the journal and continuing.
pub fn resume(
    adapter: &dyn CommandAdapter,
    input: &ApplyInput,
    state_dir: &Path,
) -> AppResult<ApplyResult> {
    // Resume is apply with an existing journal.
    apply(adapter, input, state_dir)
}

// ---------------------------------------------------------------------------
// Remove
// ---------------------------------------------------------------------------

/// Remove the installation. Data preserved by default.
///
/// Only product resources recorded as created by this installer are removed.
/// A tampered journal cannot aim removal at foreign users, units, or paths.
pub fn remove(adapter: &dyn CommandAdapter, input: &RemoveInput) -> AppResult<RemoveResult> {
    let state_dir = Path::new(&input.state_dir);
    let _operation_lock = acquire_lifecycle_operation_lock(adapter, state_dir)?;
    remove_with_storage(adapter, input, DATA_SUBDIR, BACKUP_DIR)
}

fn remove_with_storage(
    adapter: &dyn CommandAdapter,
    input: &RemoveInput,
    data_directory: &str,
    backup_directory: &str,
) -> AppResult<RemoveResult> {
    if input.contract_version != CONTRACT_VERSION {
        return Err(AppError::bad_request(format!(
            "unsupported installer contract_version: {} (expected {})",
            input.contract_version, CONTRACT_VERSION
        )));
    }
    if !input.confirm {
        return Err(AppError::bad_request("remove requires confirm: true"));
    }
    validate_storage_path(data_directory, &[DATA_SUBDIR], "data")?;
    validate_storage_path(backup_directory, &[BACKUP_DIR, BACKUP_ROOT], "backup")?;

    let state_dir = Path::new(&input.state_dir);
    let journal_path = state_dir.join("journal.json");

    let mut removed = Vec::new();
    let mut errors = Vec::new();

    // Load journal to know what was created.
    if adapter.path_exists(&journal_path) {
        match adapter.read_file(&journal_path) {
            Ok(bytes) => {
                let journal: Journal = serde_json::from_slice(&bytes)
                    .map_err(|e| AppError::internal(format!("corrupt journal: {e}")))?;
                let resources = &journal.resources_created;

                // Remove in reverse order.

                // Firewall rules — remove only exact owned rules including comment.
                for rule_str in &resources.firewall_rules {
                    if !is_product_firewall_identity(rule_str) {
                        errors.push(format!(
                            "refusing to remove non-product firewall rule: {rule_str}"
                        ));
                        continue;
                    }
                    let parts: Vec<&str> = rule_str.splitn(3, ':').collect();
                    if let (Some(port_str), Some(proto), Some(comment)) =
                        (parts.first(), parts.get(1), parts.get(2))
                    {
                        if let Ok(port) = port_str.parse::<u16>() {
                            if let Err(e) = adapter.firewall_deny_exact(port, proto, comment) {
                                errors.push(format!("firewall remove {rule_str}: {e}"));
                            } else {
                                removed.push(format!("firewall:{rule_str}"));
                            }
                        }
                    }
                }

                // Units.
                for unit in &resources.units {
                    if !is_product_unit(unit) {
                        errors.push(format!("refusing to remove non-product unit: {unit}"));
                        continue;
                    }
                    match adapter.query_unit_exists(unit) {
                        Ok(false) => continue,
                        Ok(true) => {}
                        Err(e) => {
                            errors.push(format!("cannot inspect unit {unit}: {e}"));
                            continue;
                        }
                    }
                    let _ = adapter.disable_unit(unit);
                    let _ = adapter.stop_unit(unit);
                    if let Err(e) = adapter.remove_unit(unit) {
                        errors.push(format!("unit remove {unit}: {e}"));
                    } else {
                        let _ = adapter.systemd_daemon_reload();
                        removed.push(format!("unit:{unit}"));
                    }
                }

                // Files.
                for file in &resources.files {
                    if !is_product_file(file) {
                        errors.push(format!("refusing to remove non-product file: {file}"));
                        continue;
                    }
                    if path_present(adapter, Path::new(file)) {
                        // Do not follow a symlink out of the product namespace.
                        match adapter.symlink_metadata(Path::new(file)) {
                            Ok(meta) if meta.is_symlink => {
                                errors.push(format!(
                                    "refusing to remove symlink at product path: {file}"
                                ));
                                continue;
                            }
                            Err(e) => {
                                errors.push(format!("cannot stat file {file}: {e}"));
                                continue;
                            }
                            Ok(_) => {}
                        }
                        if let Err(e) = adapter.remove_file(Path::new(file)) {
                            errors.push(format!("file remove {file}: {e}"));
                        } else {
                            removed.push(format!("file:{file}"));
                        }
                    }
                }

                // Directories (in reverse order, only product namespace).
                for dir in resources.directories.iter().rev() {
                    if !is_product_directory(dir) {
                        errors.push(format!("refusing to remove non-product directory: {dir}"));
                        continue;
                    }
                    let path = Path::new(dir);
                    if path_present(adapter, path) {
                        match adapter.symlink_metadata(path) {
                            Ok(meta) if meta.is_symlink => {
                                errors.push(format!(
                                    "refusing to remove symlink at product directory path: {dir}"
                                ));
                                continue;
                            }
                            Err(e) => {
                                errors.push(format!("cannot stat directory {dir}: {e}"));
                                continue;
                            }
                            Ok(_) => {}
                        }
                        match adapter.list_dir(path) {
                            Ok(entries) if !entries.is_empty() => {
                                // Preserve non-empty data/config directories. They are
                                // removed only by the explicit data-purge path below.
                                continue;
                            }
                            Err(e) => {
                                errors.push(format!("cannot inspect directory {dir}: {e}"));
                                continue;
                            }
                            Ok(_) => {}
                        }
                        if let Err(e) = adapter.remove_dir(path) {
                            errors.push(format!("dir remove {dir}: {e}"));
                        } else {
                            removed.push(format!("dir:{dir}"));
                        }
                    }
                }

                // Service user: only the product user we may have created.
                for user in &resources.service_users {
                    if !is_product_user(user) {
                        errors.push(format!(
                            "refusing to remove non-product service user: {user}"
                        ));
                        continue;
                    }
                    match adapter.query_user_exists(user) {
                        Ok(false) => continue,
                        Ok(true) => {}
                        Err(e) => {
                            errors.push(format!("cannot inspect service user {user}: {e}"));
                            continue;
                        }
                    }
                    if let Err(e) = adapter.remove_system_user(user) {
                        errors.push(format!("user remove {user}: {e}"));
                    } else {
                        removed.push(format!("user:{user}"));
                    }
                }
            }
            Err(e) => {
                errors.push(format!("cannot read journal: {e}"));
            }
        }
    }

    // Remove state directory (but preserve data unless explicitly asked).
    let data_dir = Path::new(data_directory);
    let backup_dir = Path::new(backup_directory);

    if input.delete_data {
        for (label, path) in [("data", data_dir), ("backup", backup_dir)] {
            if !path_present(adapter, path) {
                continue;
            }
            let path_text = path.to_string_lossy();
            if let Err(error) = reject_symlink_parents(adapter, &path_text) {
                errors.push(format!("{label} remove: {error}"));
                continue;
            }
            match adapter.symlink_metadata(path) {
                Ok(metadata) if metadata.is_symlink => {
                    errors.push(format!("refusing to remove symlink at {label} path"));
                    continue;
                }
                Err(error) => {
                    errors.push(format!("cannot inspect {label} path: {error}"));
                    continue;
                }
                Ok(_) => {}
            }
            if let Err(error) = adapter.remove_dir_all(path) {
                errors.push(format!("{label} remove: {error}"));
            }
        }
    }

    // Keep the ownership journal until every owned-resource operation has
    // succeeded. A retry can then skip resources already removed and continue
    // safely from the same allowlisted inventory.
    if errors.is_empty() {
        let manifest_path = state_dir.join("installed.json");
        if adapter.path_exists(&manifest_path) {
            if let Err(e) = adapter.remove_file(&manifest_path) {
                errors.push(format!("manifest remove: {e}"));
            }
        }
        if errors.is_empty() && adapter.path_exists(&journal_path) {
            if let Err(e) = adapter.remove_file(&journal_path) {
                errors.push(format!("journal remove: {e}"));
            }
        }
    }

    Ok(RemoveResult {
        contract_version: CONTRACT_VERSION,
        ok: errors.is_empty(),
        removed,
        data_preserved: !input.delete_data,
        data_dir: if input.delete_data {
            None
        } else {
            Some(data_directory.to_string())
        },
        backup_dir: if input.delete_data {
            None
        } else {
            Some(backup_directory.to_string())
        },
        errors,
    })
}

/// True only for firewall identities the canonical plan installs.
fn is_product_firewall_identity(identity: &str) -> bool {
    let plan = generate_canonical_plan("hs-server", "0.0.0");
    plan.firewall
        .iter()
        .any(|rule| format!("{}:{}:{}", rule.port, rule.protocol, rule.comment) == identity)
        || matches!(
            identity,
            "8920:tcp:hs-server TLS authority"
                | "21115:tcp:hs-server rendezvous"
                | "21116:tcp:hs-server rendezvous"
                | "21116:udp:hs-server rendezvous"
                | "21117:tcp:hs-server relay"
        )
}

/// Check if a path is under our owned namespace.
///
/// Requires a path-component boundary so `/opt/helicoid-evil` and
/// `/opt/helicoidfoo` are not treated as product paths.
fn is_owned_path(path: &str) -> bool {
    const ROOTS: [&str; 3] = [BASE_DIR, DATA_DIR, CONFIG_DIR];
    ROOTS.iter().any(|root| {
        path == *root
            || path
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// True only for paths the installer is allowed to create or remove.
fn is_product_file(path: &str) -> bool {
    is_owned_path(path)
        || path == format!("/etc/systemd/system/{UNIT_NAME}")
        || path == format!("/etc/systemd/system/{BACKUP_SERVICE_UNIT}")
        || path == format!("/etc/systemd/system/{BACKUP_TIMER_UNIT}")
        || path == format!("/etc/systemd/system/{BACKUP_CONTROL_SOCKET_UNIT}")
        || path == format!("/etc/systemd/system/{BACKUP_CONTROL_SERVICE_UNIT}")
}

/// True only for unit names the installer owns.
fn is_product_unit(name: &str) -> bool {
    matches!(
        name,
        UNIT_NAME
            | BACKUP_SERVICE_UNIT
            | BACKUP_TIMER_UNIT
            | BACKUP_CONTROL_SOCKET_UNIT
            | BACKUP_CONTROL_SERVICE_UNIT
    )
}

/// True only for service users the installer owns.
fn is_product_user(name: &str) -> bool {
    name == SERVICE_USER
}

/// True only for directories in the canonical product resource set.
fn is_product_directory(path: &str) -> bool {
    matches!(
        path,
        BASE_DIR
            | DATA_DIR
            | DATA_SUBDIR
            | BACKUP_DIR
            | CONFIG_DIR
            | "/opt/helicoid/compose"
            | "/opt/helicoid/compose/tls"
    ) || path == format!("{BASE_DIR}/bin")
        || [DATA_SUBDIR, BACKUP_DIR, BACKUP_ROOT]
            .iter()
            .any(|root| validate_storage_path(path, &[*root], "storage").is_ok())
}

/// Reject destination paths whose parent chain contains a symlink.
/// A symlinked parent redirects the write outside the product namespace.
fn reject_symlink_parents(adapter: &dyn CommandAdapter, destination: &str) -> AppResult<()> {
    let path = Path::new(destination);
    let mut current = PathBuf::new();
    for component in path.parent().unwrap_or(Path::new("")).components() {
        current.push(component);
        match adapter.symlink_metadata(&current) {
            Ok(meta) if meta.is_symlink => {
                return Err(AppError::forbidden(format!(
                    "destination parent '{}' is a symlink; refusing to write '{destination}'",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(_) if !adapter.path_exists(&current) => continue,
            Err(error) => {
                return Err(AppError::internal(format!(
                    "cannot stat destination parent '{}': {error}",
                    current.display()
                )));
            }
        }
    }
    Ok(())
}

/// Detect both ordinary paths and dangling symlinks. `path_exists` follows
/// symlinks, while `symlink_metadata` observes the link itself.
fn path_present(adapter: &dyn CommandAdapter, path: &Path) -> bool {
    adapter.path_exists(path) || adapter.symlink_metadata(path).is_ok()
}

// ---------------------------------------------------------------------------
// Journal helpers
// ---------------------------------------------------------------------------

fn create_journal(adapter: &dyn CommandAdapter, plan_digest: &str) -> Journal {
    let mut phases = BTreeMap::new();
    for &phase in Phase::execution_sequence() {
        phases.insert(
            phase.as_str().to_string(),
            PhaseEntry {
                status: PhaseStatus::Pending,
                started_at: None,
                completed_at: None,
                error: None,
            },
        );
    }
    let now = adapter.now_iso8601();
    Journal {
        contract_version: CONTRACT_VERSION,
        plan_digest: plan_digest.to_string(),
        started_at: now.clone(),
        updated_at: now,
        current_phase: "pending".to_string(),
        phases,
        resources_created: ResourcesCreated::default(),
        resources: Vec::new(),
    }
}

fn save_journal(adapter: &dyn CommandAdapter, path: &Path, journal: &Journal) -> AppResult<()> {
    let json = serde_json::to_string_pretty(journal)
        .map_err(|e| AppError::internal(format!("serialize journal: {e}")))?;
    adapter
        .write_file(path, json.as_bytes())
        .map_err(|e| AppError::internal(format!("save journal: {e}")))
}

fn build_apply_result(journal: &Journal, completed: bool, journal_path: &Path) -> ApplyResult {
    let phases_completed: Vec<String> = journal
        .phases
        .iter()
        .filter(|(_, e)| e.status == PhaseStatus::Completed)
        .map(|(k, _)| k.clone())
        .collect();

    let phase = if completed {
        "completed".to_string()
    } else {
        journal.current_phase.clone()
    };

    let errors: Vec<String> = journal
        .phases
        .iter()
        .filter(|(_, e)| e.status == PhaseStatus::Failed)
        .filter_map(|(_, e)| e.error.clone())
        .collect();

    let service_installed = journal
        .phases
        .get("units")
        .map(|e| e.status == PhaseStatus::Completed)
        .unwrap_or(false);

    ApplyResult {
        contract_version: CONTRACT_VERSION,
        ok: completed,
        phase,
        phases_completed,
        phase_journal_path: Some(journal_path.to_string_lossy().to_string()),
        service_installed,
        // Hosting/auth integration is not done: never claim a healthy server.
        bootstrap_ready: false,
        server_ready_for_enrollment: false,
        errors,
        warnings: vec![],
    }
}

/// Decode a hex string to exactly 32 bytes.
fn hex_decode_32(hex_str: &str) -> AppResult<[u8; 32]> {
    let bytes =
        hex::decode(hex_str).map_err(|e| AppError::bad_request(format!("invalid hex key: {e}")))?;
    if bytes.len() != 32 {
        return Err(AppError::bad_request(format!(
            "verifying key must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod compose_readiness_tests {
    use super::{compose_readiness_flags, ComposeReadiness};

    #[test]
    fn compose_readiness_distinguishes_bootstrap_from_enrollment() {
        let bootstrap = ComposeReadiness {
            bootstrap_ready: true,
            server_ready_for_enrollment: false,
        };
        assert_eq!(
            compose_readiness_flags("unhealthy", Some(&bootstrap)),
            (true, false)
        );

        let enrolled = ComposeReadiness {
            bootstrap_ready: false,
            server_ready_for_enrollment: true,
        };
        assert_eq!(
            compose_readiness_flags("healthy", Some(&enrolled)),
            (false, true)
        );
        assert_eq!(
            compose_readiness_flags("starting", Some(&enrolled)),
            (false, false)
        );
        assert_eq!(compose_readiness_flags("healthy", None), (false, false));
    }
}

#[cfg(test)]
mod compose_backup_schedule_tests {
    use super::{
        compose_scheduled_backup_args, generate_backup_service_unit_content,
        generate_canonical_compose_plan, BACKUP_CONTROL_SERVICE_UNIT, BACKUP_CONTROL_SOCKET_UNIT,
        BACKUP_SERVICE_UNIT, BACKUP_TIMER_UNIT, COMPOSE_BACKUP_CREDENTIAL_PATH,
    };
    use crate::installer::lifecycle_v2::{
        DeploymentConfiguration, DeploymentKind, NetworkConfiguration, NetworkScope,
        StorageConfiguration,
    };

    fn compose_configuration() -> DeploymentConfiguration {
        DeploymentConfiguration {
            deployment_kind: DeploymentKind::LinuxCompose,
            network: NetworkConfiguration {
                scope: NetworkScope::LoopbackDevelopment,
                authority_port: 8920,
                bind_address: None,
                client_hostname: None,
            },
            storage: StorageConfiguration {
                data_directory: "/var/lib/helicoid/data".to_string(),
                backup_directory: "/var/lib/helicoid/backups".to_string(),
                preserve_data_on_remove: true,
            },
        }
    }

    #[test]
    fn compose_plan_owns_host_backend_backup_units_and_control_socket() {
        let plan =
            generate_canonical_compose_plan("helicoid-server", "1.0.0", &compose_configuration());

        assert!(plan.files.iter().any(|file| {
            file.source == "artifacts/hs-server"
                && file.destination == "/opt/helicoid/bin/hs-server"
        }));
        assert_eq!(plan.units.len(), 4);
        assert!(plan
            .units
            .iter()
            .all(|unit| { unit.action == "install" && unit.restart_policy == "no" }));
        assert!(plan
            .units
            .iter()
            .any(|unit| { unit.name == BACKUP_CONTROL_SOCKET_UNIT && unit.enabled }));
        assert!(plan
            .units
            .iter()
            .any(|unit| { unit.name == BACKUP_CONTROL_SERVICE_UNIT && !unit.enabled }));
        assert!(plan
            .units
            .iter()
            .any(|unit| unit.name == BACKUP_SERVICE_UNIT));
        assert!(plan.units.iter().any(|unit| unit.name == BACKUP_TIMER_UNIT));
    }

    #[test]
    fn compose_backup_unit_keeps_credential_out_of_arguments_and_limits_host_access() {
        let content = generate_backup_service_unit_content(
            "unused-in-compose",
            "/var/lib/helicoid/data",
            "/var/lib/helicoid/backups",
            Some(DeploymentKind::LinuxCompose),
        );

        assert!(content.contains("User=root"));
        assert!(content
            .contains("ExecStart=/opt/helicoid/bin/hs-server backup scheduled-compose-create"));
        assert!(content.contains(&format!(
            "LoadCredentialEncrypted=helicoid-backup-passphrase:{COMPOSE_BACKUP_CREDENTIAL_PATH}"
        )));
        assert!(content.contains("RestrictAddressFamilies=AF_UNIX"));
        assert!(content.contains("ReadWritePaths=/run/lock /var/run/docker.sock"));
        assert!(!content.contains("--passphrase"));
    }

    #[test]
    fn compose_backup_exec_uses_only_verified_container_and_configured_paths() {
        let args = compose_scheduled_backup_args(
            "0123456789abcdef",
            "/var/lib/helicoid/data",
            "/var/lib/helicoid/backups",
        )
        .expect("valid Compose backup command");
        assert_eq!(
            args,
            [
                "exec",
                "--interactive",
                "0123456789abcdef",
                "hs-server",
                "--data",
                "/var/lib/helicoid/data/hs-server.db",
                "backup",
                "scheduled-stdin-create",
                "--directory",
                "/var/lib/helicoid/backups",
            ]
        );
        assert!(compose_scheduled_backup_args(
            "not-a-container",
            "/var/lib/helicoid/data",
            "/var/lib/helicoid/backups",
        )
        .is_err());
        assert!(compose_scheduled_backup_args(
            "0123456789abcdef",
            "relative/data",
            "/var/lib/helicoid/backups",
        )
        .is_err());
    }
}
