//! Installer state machine: preflight, plan, apply, inspect, resume, remove.
//!
//! Phase journal committed atomically. Retries idempotent. Interrupted apply
//! inspect/resume rechecks actual ownership. Cancellation/rollback tracks what
//! was actually created; never deletes previous data or global files.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::adapter::CommandAdapter;
use super::manifest;
use super::models::*;
use crate::error::{AppError, AppResult};

/// Minimum storage required (1 GiB).
const MIN_STORAGE_BYTES: u64 = 1024 * 1024 * 1024;

/// Required ports for hs-server.
const REQUIRED_PORTS: &[(u16, &str)] = &[
    (8920, "tcp"),
    (21115, "tcp"),
    (21116, "tcp"),
    (21116, "udp"),
    (21117, "tcp"),
];

/// Ports that are allowed to be occupied (not ours).
const ALLOWED_OCCUPIED_PORTS: &[(u16, &str)] =
    &[(80, "tcp"), (443, "tcp"), (21118, "tcp"), (21119, "tcp")];

/// Namespaced paths.
const BASE_DIR: &str = "/opt/helicoid";
const DATA_DIR: &str = "/var/lib/helicoid";
const DATA_SUBDIR: &str = "/var/lib/helicoid/data";
const BACKUP_DIR: &str = "/var/lib/helicoid/backups";
const CONFIG_DIR: &str = "/etc/helicoid";
const SERVICE_USER: &str = "hs-server";
const UNIT_NAME: &str = "hs-server.service";

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
            let ok = name.to_lowercase() == "ubuntu" && version.starts_with("26.");
            let reason = if !ok {
                Some(format!(
                    "unsupported OS: {name} {version} (require Ubuntu 26.x)"
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
    match adapter.query_storage(Path::new(DATA_DIR)) {
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

    match adapter.query_unit_exists(UNIT_NAME) {
        Ok(true) => {
            existing_units.push(UNIT_NAME.to_string());
            conflicts.push(format!("unit {UNIT_NAME} already exists"));
        }
        Ok(false) => {}
        Err(e) => {
            return Err(AppError::internal(format!(
                "cannot query service '{UNIT_NAME}': {e}"
            )));
        }
    }

    Ok(ServicesCheck {
        ok: conflicts.is_empty(),
        existing_units,
        conflicts,
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
                owner: SERVICE_USER.to_string(),
                mode: "0755".to_string(),
                create: true,
            },
            DirectorySpec {
                path: format!("{BASE_DIR}/bin"),
                owner: SERVICE_USER.to_string(),
                mode: "0755".to_string(),
                create: true,
            },
            DirectorySpec {
                path: DATA_DIR.to_string(),
                owner: SERVICE_USER.to_string(),
                mode: "0700".to_string(),
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
                owner: SERVICE_USER.to_string(),
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
        firewall: vec![
            FirewallRule {
                port: 8920,
                protocol: "tcp".to_string(),
                action: "allow".to_string(),
                comment: "hs-server TLS authority".to_string(),
            },
            FirewallRule {
                port: 21115,
                protocol: "tcp".to_string(),
                action: "allow".to_string(),
                comment: "hs-server rendezvous".to_string(),
            },
            FirewallRule {
                port: 21116,
                protocol: "tcp".to_string(),
                action: "allow".to_string(),
                comment: "hs-server rendezvous".to_string(),
            },
            FirewallRule {
                port: 21116,
                protocol: "udp".to_string(),
                action: "allow".to_string(),
                comment: "hs-server rendezvous".to_string(),
            },
            FirewallRule {
                port: 21117,
                protocol: "tcp".to_string(),
                action: "allow".to_string(),
                comment: "hs-server relay".to_string(),
            },
        ],
        listeners: vec![
            ListenerSpec {
                port: 8920,
                protocol: "tcp".to_string(),
                description: "TLS authority (not yet implemented)".to_string(),
            },
            ListenerSpec {
                port: 21115,
                protocol: "tcp".to_string(),
                description: "rendezvous".to_string(),
            },
            ListenerSpec {
                port: 21116,
                protocol: "tcp".to_string(),
                description: "rendezvous".to_string(),
            },
            ListenerSpec {
                port: 21116,
                protocol: "udp".to_string(),
                description: "rendezvous".to_string(),
            },
            ListenerSpec {
                port: 21117,
                protocol: "tcp".to_string(),
                description: "relay".to_string(),
            },
        ],
        migrations: MigrationSpec {
            schema_version: crate::db::SCHEMA_VERSION,
            backup_required: true,
        },
        not_implemented: vec![
            "TLS authority on port 8920 (pending TLS/MFA/routing package integration)".into(),
            "MFA enrollment".into(),
            "Remote control / screen observation".into(),
            "File jobs".into(),
            "Security recovery".into(),
        ],
    }
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
    if !input.confirm {
        return Err(AppError::bad_request("apply requires confirm: true"));
    }

    if !input.preflight.ok {
        return Err(AppError::bad_request("preflight is not ok; cannot apply"));
    }

    let plan = &input.plan;

    // Recheck that required ports are still available.
    // Query errors MUST deny apply — treating errors as "port free" is unsafe.
    // This runs before verification: runtime safety checks are independent of
    // trust anchor validation.
    for &(port, protocol) in REQUIRED_PORTS {
        match adapter.query_port_listener(port, protocol) {
            Ok(Some(_)) => {
                return Err(AppError::conflict(
                    format!("port {port}/{protocol} is now occupied; preflight state has changed"),
                    None,
                ));
            }
            Ok(None) => {} // port is free
            Err(e) => {
                return Err(AppError::conflict(
                    format!("cannot verify port {port}/{protocol} availability: {e}"),
                    None,
                ));
            }
        }
    }

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
    let mut canonical_plan =
        generate_canonical_plan(&verified_manifest.product, &verified_manifest.version);
    canonical_plan.review_digest = compute_plan_digest(&canonical_plan);

    // Compare the caller's review digest against the independently computed one.
    // A caller who modified any plan field (destinations, modes, units, etc.)
    // and recomputed the digest will be caught here.
    if plan.review_digest != canonical_plan.review_digest {
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

        if entry.status == PhaseStatus::Completed {
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
        let result = execute_phase(
            adapter,
            phase,
            plan,
            &mut journal,
            &journal_path,
            package_dir_path,
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

fn execute_phase(
    adapter: &dyn CommandAdapter,
    phase: Phase,
    plan: &InstallPlan,
    journal: &mut Journal,
    journal_path: &Path,
    package_dir: Option<&Path>,
) -> AppResult<()> {
    match phase {
        Phase::ServiceUser => {
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
                if adapter.path_exists(Path::new(&dir.path)) {
                    // Existing path must not be a symlink we would follow.
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
                        Ok(_) => {
                            record_resource_completed(
                                adapter,
                                journal_path,
                                journal,
                                "directory",
                                &dir.path,
                            )?;
                            continue;
                        }
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
                reject_symlink_parents(adapter, &dir.path)?;
                record_resource_intent(adapter, journal_path, journal, "directory", &dir.path)?;
                match adapter.create_dir_all(Path::new(&dir.path)) {
                    Ok(()) => {
                        journal.resources_created.directories.push(dir.path.clone());
                        record_resource_completed(
                            adapter,
                            journal_path,
                            journal,
                            "directory",
                            &dir.path,
                        )?;
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
                let src = if let Some(pkg_dir) = package_dir {
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
                record_resource_intent(adapter, journal_path, journal, "file", &file.destination)?;
                match adapter.copy_file(&src, dst) {
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
        }
        Phase::Units => {
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
                    let unit_content = generate_unit_content(&plan.service_user.name, unit);
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
                journal.resources_created.units.push(unit.name.clone());
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

fn generate_unit_content(service_user: &str, unit: &UnitSpec) -> String {
    format!(
        r#"[Unit]
Description=Helicoid Systems coordination server
After=network.target

[Service]
Type=simple
User={user}
ExecStart=/opt/helicoid/bin/hs-server --data /var/lib/helicoid/data/hs-server.db serve --bind 127.0.0.1:8787
Restart={restart_policy}
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#,
        user = service_user,
        restart_policy = unit.restart_policy,
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
    if !input.confirm {
        return Err(AppError::bad_request("remove requires confirm: true"));
    }

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
                    if adapter.path_exists(Path::new(file)) {
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
                    if !is_product_directory(dir) || !is_owned_path(dir) {
                        errors.push(format!("refusing to remove non-product directory: {dir}"));
                        continue;
                    }
                    let path = Path::new(dir);
                    if adapter.path_exists(path) {
                        if let Err(e) = adapter.remove_dir(path) {
                            // Directory may not be empty; that's ok.
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
    let data_dir = Path::new(DATA_SUBDIR);
    let backup_dir = Path::new(BACKUP_DIR);

    if input.delete_data {
        if adapter.path_exists(data_dir) {
            if let Err(e) = adapter.remove_dir_all(data_dir) {
                errors.push(format!("data remove: {e}"));
            }
        }
        if adapter.path_exists(backup_dir) {
            if let Err(e) = adapter.remove_dir_all(backup_dir) {
                errors.push(format!("backup remove: {e}"));
            }
        }
    }

    // Remove journal/manifest.
    if adapter.path_exists(&journal_path) {
        let _ = adapter.remove_file(&journal_path);
    }
    let manifest_path = state_dir.join("installed.json");
    if adapter.path_exists(&manifest_path) {
        let _ = adapter.remove_file(&manifest_path);
    }

    Ok(RemoveResult {
        contract_version: CONTRACT_VERSION,
        ok: errors.is_empty(),
        removed,
        data_preserved: !input.delete_data,
        data_dir: if input.delete_data {
            None
        } else {
            Some(DATA_SUBDIR.to_string())
        },
        backup_dir: if input.delete_data {
            None
        } else {
            Some(BACKUP_DIR.to_string())
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
    is_owned_path(path) || path == format!("/etc/systemd/system/{UNIT_NAME}")
}

/// True only for unit names the installer owns.
fn is_product_unit(name: &str) -> bool {
    name == UNIT_NAME
}

/// True only for service users the installer owns.
fn is_product_user(name: &str) -> bool {
    name == SERVICE_USER
}

/// True only for directories in the canonical product resource set.
fn is_product_directory(path: &str) -> bool {
    matches!(
        path,
        BASE_DIR | DATA_DIR | DATA_SUBDIR | BACKUP_DIR | CONFIG_DIR
    ) || path == format!("{BASE_DIR}/bin")
}

/// Reject destination paths whose parent chain contains a symlink.
/// A symlinked parent redirects the write outside the product namespace.
fn reject_symlink_parents(adapter: &dyn CommandAdapter, destination: &str) -> AppResult<()> {
    let path = Path::new(destination);
    let mut current = PathBuf::new();
    for component in path.parent().unwrap_or(Path::new("")).components() {
        current.push(component);
        if !adapter.path_exists(&current) {
            continue;
        }
        let meta = adapter.symlink_metadata(&current).map_err(|e| {
            AppError::internal(format!(
                "cannot stat destination parent '{}': {e}",
                current.display()
            ))
        })?;
        if meta.is_symlink {
            return Err(AppError::forbidden(format!(
                "destination parent '{}' is a symlink; refusing to write '{destination}'",
                current.display()
            )));
        }
    }
    Ok(())
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
