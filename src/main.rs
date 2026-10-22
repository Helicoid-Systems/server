//! hs-server CLI: init, bootstrap, serve.
//!
//! Default bind is loopback only. Network listeners require explicit TLS
//! opt-in and expose only the versioned API surface. This foundation still
//! provides no control or media authority (B03/RD03 proofs pending).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use std::os::unix::net::{Shutdown, UnixStream};

use clap::{Parser, Subcommand};

use hs_server::models::{BootstrapRequest, LoginRequest};
use hs_server::{db, open_service, service::Service, AppResult};

#[derive(Parser)]
#[command(
    name = "hs-server",
    about = "Helicoid Systems coordination server foundation (local accounts, manager enrollment, scoped inventory)"
)]
struct Cli {
    /// SQLite database path.
    #[arg(long, global = true, default_value = "./hs-server.db")]
    data: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the database schema if missing and print a single-use bootstrap token.
    Init,
    /// Check the local HTTP health endpoint without opening the database.
    Healthcheck {
        /// Literal-loopback health endpoint. Network addresses are refused.
        #[arg(long, default_value = "127.0.0.1:8787")]
        address: String,
    },
    /// Internal installer probe for bootstrap and enrollment readiness.
    #[command(hide = true)]
    InstallerReadiness {
        /// Literal-loopback health endpoint. Network addresses are refused.
        #[arg(long, default_value = "127.0.0.1:8787")]
        address: String,
    },
    /// Explicit schema-versioned migration with a consistent pre-migration backup.
    /// Never runs automatically on startup.
    Migrate {
        /// Directory for the pre-migration database backup.
        #[arg(long, default_value = "./hs-server-backups")]
        backup_dir: PathBuf,
    },
    /// Create, verify, restore, and manage retention for encrypted database snapshots.
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
    /// Consume the single-use bootstrap token to create the first administrator.
    Bootstrap {
        /// Bootstrap token from `hs-server init` (or HS_BOOTSTRAP_TOKEN).
        ///
        /// Opaque URL-safe base64 may begin with `-`; accept one value unchanged.
        #[arg(long, allow_hyphen_values = true)]
        token: Option<String>,
        #[arg(long)]
        username: String,
        /// Read the password from stdin (preferred over --password).
        #[arg(long)]
        password_stdin: bool,
        /// Password (avoid in shared shells; prefer --password-stdin).
        #[arg(long)]
        password: Option<String>,
        /// Optional manager public identity to approve during bootstrap.
        #[arg(long)]
        manager_public_identity: Option<String>,
        #[arg(long)]
        manager_friendly_name: Option<String>,
    },
    /// Bootstrap with real TOTP MFA (local CLI). Admin stays inactive until
    /// MFA confirmation and independently stored recovery material.
    BootstrapV2 {
        /// Bootstrap token from `hs-server init` (or HS_BOOTSTRAP_TOKEN).
        ///
        /// Opaque URL-safe base64 may begin with `-`; accept one value unchanged.
        #[arg(long, allow_hyphen_values = true)]
        token: Option<String>,
        #[arg(long)]
        username: String,
        /// Read the password from stdin.
        #[arg(long)]
        password_stdin: bool,
        /// Exact initiating manager Ed25519 public key (hex, 32 bytes).
        #[arg(long)]
        manager_public_key: Option<String>,
        /// Hex Ed25519 proof over hs-bootstrap-v2|deployment:<id>|token:<hash>|manager:<key>.
        /// Read from a file path to keep the signature out of argv when possible.
        #[arg(long)]
        manager_proof_file: Option<PathBuf>,
        /// Inline manager proof (avoid; prefer --manager-proof-file).
        #[arg(long)]
        manager_proof: Option<String>,
        #[arg(long)]
        manager_friendly_name: Option<String>,
        /// Write recovery codes to this private file (0600) instead of stdout.
        #[arg(long)]
        recovery_file: Option<PathBuf>,
    },
    /// Confirm a pending v2 MFA enrollment (TOTP + recovery stored attestation).
    ConfirmMfa {
        #[arg(long)]
        enrollment_id: String,
        /// Read the 6-digit TOTP code from stdin.
        #[arg(long)]
        totp_stdin: bool,
        /// Inline TOTP code (avoid; prefer --totp-stdin).
        #[arg(long)]
        totp_code: Option<String>,
        /// Required attestation that recovery codes were stored independently.
        #[arg(long)]
        recovery_stored: bool,
    },
    /// Cancel a pending v2 MFA enrollment (bootstrap cancellation).
    CancelMfa {
        #[arg(long)]
        enrollment_id: String,
    },
    /// Verify credentials against the local database without starting HTTP.
    CheckLogin {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        password: Option<String>,
    },
    /// Serve the HTTP API. Defaults to loopback only.
    Serve {
        /// Bind address. Default 127.0.0.1:8787. Plain HTTP stays loopback-only.
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
    },
    /// Serve the HTTPS API over real TLS. Literal loopback is the default.
    ///
    /// Requires a certificate PEM chain and a private key PEM in a
    /// product-owned private parent/file. Nonloopback binds require the
    /// explicit --allow-network option and use the v2-only API router.
    ServeTls {
        /// Bind address. Default 127.0.0.1:8920. Nonloopback is refused
        /// before any data or listener effect unless --allow-network is set.
        #[arg(long, default_value = "127.0.0.1:8920")]
        bind: String,
        /// Path to PEM certificate chain (owner-private file, at most 8 certs).
        #[arg(long)]
        tls_cert: PathBuf,
        /// Path to PEM private key (owner-private file, exactly one key).
        #[arg(long)]
        tls_key: PathBuf,
        /// Explicitly allow a nonloopback TLS listener. Legacy v1 routes stay
        /// disabled on network listeners.
        #[arg(long)]
        allow_network: bool,
    },
    /// Serve local administration and network TLS APIs from one process.
    /// Network exposure requires --allow-network and uses the v2-only router.
    ServeDual {
        /// Literal-loopback HTTP address used by local CLI/TUI workflows.
        #[arg(long, default_value = "127.0.0.1:8787")]
        local_bind: String,
        /// Nonloopback TLS address used by remote Manager clients.
        #[arg(long, default_value = "0.0.0.0:8920")]
        network_bind: String,
        /// PEM certificate chain in an owner-private parent/file.
        #[arg(long)]
        tls_cert: PathBuf,
        /// PEM private key in an owner-private parent/file.
        #[arg(long)]
        tls_key: PathBuf,
        /// Required opt-in before the network listener can be opened.
        #[arg(long)]
        allow_network: bool,
    },
    /// Guided Linux installer backend. Reads bounded versioned JSON from stdin.
    Installer {
        #[command(subcommand)]
        action: InstallerAction,
    },
}

#[derive(Subcommand)]
enum BackupAction {
    /// List encrypted database archives in a private directory.
    List {
        #[arg(
            long,
            value_name = "DIR",
            help = "Private directory containing encrypted .hsb archives"
        )]
        directory: Option<PathBuf>,
    },
    /// Create an encrypted, consistent snapshot at a new private file path.
    Create {
        #[arg(long)]
        output: Option<PathBuf>,
        /// Read the passphrase from stdin (creation reads two matching lines for confirmation).
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Create an unattended snapshot from a systemd-provided credential.
    #[command(hide = true)]
    ScheduledCreate {
        /// Directory for the new encrypted snapshot.
        #[arg(long)]
        directory: PathBuf,
    },
    /// Create a scheduled snapshot from a credential delivered on stdin.
    #[command(hide = true)]
    ScheduledStdinCreate {
        /// Directory for the new encrypted snapshot.
        #[arg(long)]
        directory: PathBuf,
    },
    /// Run the host-side Compose backup bridge using systemd's credential.
    #[command(hide = true)]
    ScheduledComposeCreate,
    /// Handle one fixed Compose backup schedule request from the systemd socket.
    #[command(hide = true)]
    ComposeControlRequest,
    /// Configure the encrypted daily backup credential and enable its timer.
    EnableSchedule,
    /// Stop and disable the daily backup timer without deleting its credential.
    DisableSchedule,
    /// Remove older scheduled backups after an interactive retention confirmation.
    Prune {
        #[arg(long)]
        directory: Option<PathBuf>,
        /// Number of newest scheduled archives to retain. Prompts for a value when omitted.
        #[arg(long)]
        keep: Option<usize>,
    },
    /// Authenticate and validate an encrypted database snapshot.
    Verify {
        #[arg(long)]
        input: Option<PathBuf>,
        /// Read one passphrase line from stdin; passphrases are never argv values.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Restore a verified backup to a new database file without overwriting.
    Restore {
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        /// Read one passphrase line from stdin; passphrases are never argv values.
        #[arg(long)]
        passphrase_stdin: bool,
    },
}

#[derive(Subcommand)]
enum InstallerAction {
    /// Report the exact lifecycle capabilities of this installer build.
    CapabilitiesV2,
    /// Run local-host preflight with v2 deployment configuration.
    PreflightV2,
    /// Read-only preflight checks (OS, arch, privileges, storage, ports, paths).
    Preflight,
    /// Generate an install plan from preflight + verified package.
    Plan {
        /// Path to extracted release package directory.
        #[arg(long)]
        package_dir: String,
        /// Ed25519 verifying key (hex, 32 bytes).
        #[arg(long)]
        verify_key: String,
    },
    /// Execute the reviewed plan with phase journal.
    Apply {
        /// Path to the installer state directory.
        #[arg(long, default_value = "/opt/helicoid/.installer")]
        state_dir: String,
        /// Path to the extracted release package directory.
        #[arg(long)]
        package_dir: Option<String>,
        /// Ed25519 verifying key (hex, 32 bytes) for re-verification.
        #[arg(long)]
        verify_key: Option<String>,
    },
    /// Resume an interrupted apply.
    Resume {
        /// Path to the installer state directory.
        #[arg(long, default_value = "/opt/helicoid/.installer")]
        state_dir: String,
    },
    /// Read current installation state.
    Inspect {
        /// Path to the installer state directory.
        #[arg(long, default_value = "/opt/helicoid/.installer")]
        state_dir: String,
    },
    /// Generate a v2 reviewed plan bound to deployment, network, and storage configuration.
    PlanV2 {
        /// Path to extracted signed release package directory.
        #[arg(long)]
        package_dir: String,
        /// Ed25519 verifying key (hex, 32 bytes).
        #[arg(long)]
        verify_key: String,
    },
    /// Apply a v2 reviewed plan and return its durable operation identity and phase state.
    ApplyV2 {
        /// Path to the installer state directory.
        #[arg(long, default_value = "/opt/helicoid/.installer")]
        state_dir: String,
    },
    /// Resume the exact v2 reviewed plan recorded by the interrupted operation.
    ResumeV2 {
        /// Path to the installer state directory.
        #[arg(long, default_value = "/opt/helicoid/.installer")]
        state_dir: String,
    },
    /// Read v2 durable operation state without changing the host.
    StatusV2 {
        /// Path to the installer state directory.
        #[arg(long, default_value = "/opt/helicoid/.installer")]
        state_dir: String,
    },
    /// Read the configuration recorded by the current v2 installer operation.
    ConfigurationV2 {
        /// Path to the installer state directory.
        #[arg(long, default_value = "/opt/helicoid/.installer")]
        state_dir: String,
    },
    /// Verify and stage one TUF release package. This does not install it.
    VerifyTufRelease {
        /// Out-of-band trusted TUF root metadata JSON.
        #[arg(long)]
        trusted_root: PathBuf,
        /// TUF metadata base URL (HTTPS, HTTP, or file:// for offline mirrors).
        #[arg(long)]
        metadata_url: String,
        /// TUF target files base URL (HTTPS, HTTP, or file:// for offline mirrors).
        #[arg(long)]
        targets_url: String,
        /// Signed target path, e.g. releases/linux-x86_64/1.2.3/manifest.json.
        #[arg(long)]
        manifest_target: String,
        /// Frozen target platform string selected from trusted host/preflight facts.
        #[arg(long)]
        platform: String,
        /// Existing package Ed25519 verifying key (hex, 32 bytes).
        #[arg(long)]
        verify_key: String,
        /// Persistent TUF datastore and verified package staging root.
        #[arg(long, default_value = "/opt/helicoid/.installer")]
        state_dir: PathBuf,
    },
    /// Remove the installation and retain a durable v2 operation result.
    RemoveV2 {
        /// Path to the installer state directory.
        #[arg(long, default_value = "/opt/helicoid/.installer")]
        state_dir: String,
    },
    /// Remove installation (data preserved by default).
    Remove,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        // Never print bodies; secrets must not appear in logs.
        .with_target(false)
        .init();

    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        // Error Display never includes passwords or tokens.
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> AppResult<()> {
    match cli.command {
        Command::Init => {
            let service = open_service(&cli.data)?;
            let token = service.create_bootstrap_token()?;
            println!("database ready: {}", cli.data.display());
            println!("schema_version: {}", db::SCHEMA_VERSION);
            println!();
            println!("single-use bootstrap token (shown once, stored hashed):");
            println!("{token}");
            println!();
            println!(
                "next: hs-server --data {} bootstrap --token <token> --username <admin>",
                cli.data.display()
            );
            Ok(())
        }
        Command::Healthcheck { address } => check_local_health(&address),
        Command::InstallerReadiness { address } => {
            let readiness = query_local_readiness(&address)?;
            let output = serde_json::to_string(&readiness).map_err(|error| {
                hs_server::AppError::internal(format!("serialize installer readiness: {error}"))
            })?;
            println!("{output}");
            Ok(())
        }
        Command::Migrate { backup_dir } => {
            let report = db::migrate(&cli.data, &backup_dir)?;
            println!(
                "migrated schema v{} -> v{}",
                report.from_version, report.to_version
            );
            println!("backup: {}", report.backup_path.display());
            println!("database ready: {}", cli.data.display());
            Ok(())
        }
        Command::Backup { action } => {
            match action {
                BackupAction::List { directory } => {
                    if !cfg!(unix) {
                        return Err(hs_server::AppError::not_implemented(
                            "encrypted database listing currently requires Unix private-file support",
                        ));
                    }
                    let directory =
                        read_backup_path(directory, "Backup directory: ", "--directory")?;
                    let archives = hs_server::backup::list_database_backups(&directory)?;
                    if archives.is_empty() {
                        println!("no encrypted database archives");
                    } else {
                        println!("encrypted database archives: {}", archives.len());
                        for archive in archives {
                            println!(
                                "{}\t{}\t{}",
                                archive.file_name,
                                archive.encrypted_bytes,
                                archive.modified_at_unix
                            );
                        }
                    }
                    Ok(())
                }
                BackupAction::Create {
                    output,
                    passphrase_stdin,
                } => {
                    if !cfg!(unix) {
                        return Err(hs_server::AppError::not_implemented(
                        "encrypted database backups currently require Unix private-file support",
                    ));
                    }
                    if !passphrase_stdin {
                        return Err(hs_server::AppError::bad_request(
                            "backup passphrases must be supplied with --passphrase-stdin",
                        ));
                    }
                    let output = read_backup_path(output, "New backup file path: ", "--output")?;
                    let passphrase = read_confirmed_backup_passphrase()?;
                    let report =
                        hs_server::backup::create_database_backup(&cli.data, &output, &passphrase)?;
                    println!("encrypted database backup created");
                    println!("path: {}", output.display());
                    println!("database_bytes: {}", report.database_bytes);
                    println!("encrypted_bytes: {}", report.encrypted_bytes);
                    println!("schema_version: {}", report.schema_version);
                    Ok(())
                }
                BackupAction::ScheduledCreate { directory } => {
                    if !cfg!(unix) {
                        return Err(hs_server::AppError::not_implemented(
                        "scheduled encrypted backups currently require Unix private-file support",
                    ));
                    }
                    let passphrase = read_systemd_backup_credential()?;
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| {
                            hs_server::AppError::internal("system clock is before the Unix epoch")
                        })?
                        .as_secs();
                    let output = directory.join(format!(
                        "hs-server-{timestamp}-{}.hsb",
                        uuid::Uuid::new_v4().simple()
                    ));
                    let report =
                        hs_server::backup::create_database_backup(&cli.data, &output, &passphrase)?;
                    println!("scheduled encrypted database backup created");
                    println!("path: {}", output.display());
                    println!("database_bytes: {}", report.database_bytes);
                    println!("encrypted_bytes: {}", report.encrypted_bytes);
                    println!("schema_version: {}", report.schema_version);
                    Ok(())
                }
                BackupAction::ScheduledStdinCreate { directory } => {
                    if !cfg!(unix) {
                        return Err(hs_server::AppError::not_implemented(
                            "scheduled encrypted backups currently require Unix private-file support",
                        ));
                    }
                    let passphrase = read_scheduled_backup_passphrase_stdin()?;
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| {
                            hs_server::AppError::internal("system clock is before the Unix epoch")
                        })?
                        .as_secs();
                    let output = directory.join(format!(
                        "hs-server-{timestamp}-{}.hsb",
                        uuid::Uuid::new_v4().simple()
                    ));
                    let report =
                        hs_server::backup::create_database_backup(&cli.data, &output, &passphrase)?;
                    println!("scheduled encrypted database backup created");
                    println!("path: {}", output.display());
                    println!("database_bytes: {}", report.database_bytes);
                    println!("encrypted_bytes: {}", report.encrypted_bytes);
                    println!("schema_version: {}", report.schema_version);
                    Ok(())
                }
                BackupAction::ScheduledComposeCreate => {
                    #[cfg(target_os = "linux")]
                    {
                        // SAFETY: geteuid is a side-effect-free query.
                        if unsafe { libc::geteuid() } != 0 {
                            return Err(hs_server::AppError::forbidden(
                                "scheduled Compose backup requires a root terminal",
                            ));
                        }
                        let passphrase = read_systemd_backup_credential()?;
                        let adapter = hs_server::installer::adapter::LinuxAdapter;
                        hs_server::installer::machine::create_scheduled_compose_backup_v2(
                            &adapter,
                            std::path::Path::new("/opt/helicoid/.installer"),
                            &passphrase,
                        )?;
                        println!("scheduled encrypted Compose database backup created");
                        return Ok(());
                    }
                    #[cfg(not(target_os = "linux"))]
                    Err(hs_server::AppError::not_implemented(
                        "scheduled Compose backups require Linux systemd",
                    ))
                }
                BackupAction::ComposeControlRequest => {
                    #[cfg(target_os = "linux")]
                    {
                        run_compose_backup_control_request()?;
                        return Ok(());
                    }
                    #[cfg(not(target_os = "linux"))]
                    Err(hs_server::AppError::not_implemented(
                        "Compose backup controls require Linux systemd",
                    ))
                }
                BackupAction::EnableSchedule => {
                    #[cfg(target_os = "linux")]
                    {
                        // SAFETY: geteuid is a side-effect-free query.
                        if unsafe { libc::geteuid() } != 0 {
                            if !is_compose_control_client() {
                                return Err(hs_server::AppError::forbidden(
                                    "scheduled backup setup requires the installed Compose TUI or a root terminal",
                                ));
                            }
                            let passphrase = read_confirmed_backup_passphrase()?;
                            request_compose_backup_control(1, Some(passphrase.as_slice()))?;
                            println!("daily encrypted database backup schedule enabled");
                            println!(
                                "the passphrase was stored as a host-encrypted systemd credential"
                            );
                            return Ok(());
                        }
                        let adapter = hs_server::installer::adapter::LinuxAdapter;
                        let state_dir = std::path::Path::new("/opt/helicoid/.installer");
                        let credential_path =
                            hs_server::installer::machine::backup_credential_path_v2(
                                &adapter, state_dir,
                            )?;
                        let passphrase = match std::fs::symlink_metadata(&credential_path) {
                            Ok(_) => None,
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                Some(read_confirmed_backup_passphrase()?)
                            }
                            Err(error) => {
                                return Err(hs_server::AppError::internal(format!(
                                    "inspect scheduled backup credential: {error}"
                                )))
                            }
                        };
                        hs_server::installer::machine::enable_backup_schedule_v2(
                            &adapter,
                            state_dir,
                            passphrase.as_ref().map(|value| value.as_slice()),
                        )?;
                        println!("daily encrypted database backup schedule enabled");
                        println!("the backup passphrase was stored as a host-encrypted systemd credential");
                        return Ok(());
                    }
                    #[cfg(not(target_os = "linux"))]
                    Err(hs_server::AppError::not_implemented(
                        "scheduled backups currently require Linux systemd",
                    ))
                }
                BackupAction::DisableSchedule => {
                    #[cfg(target_os = "linux")]
                    {
                        // SAFETY: geteuid is a side-effect-free query.
                        if unsafe { libc::geteuid() } != 0 {
                            if !is_compose_control_client() {
                                return Err(hs_server::AppError::forbidden(
                                    "scheduled backup changes require the installed Compose TUI or a root terminal",
                                ));
                            }
                            request_compose_backup_control(2, None)?;
                            println!("daily encrypted database backup schedule disabled");
                            println!(
                                "the encrypted credential and existing archives were retained"
                            );
                            return Ok(());
                        }
                        let adapter = hs_server::installer::adapter::LinuxAdapter;
                        hs_server::installer::machine::disable_backup_schedule_v2(
                            &adapter,
                            std::path::Path::new("/opt/helicoid/.installer"),
                        )?;
                        println!("daily encrypted database backup schedule disabled");
                        println!("the encrypted credential and existing archives were retained");
                        return Ok(());
                    }
                    #[cfg(not(target_os = "linux"))]
                    Err(hs_server::AppError::not_implemented(
                        "scheduled backups currently require Linux systemd",
                    ))
                }
                BackupAction::Prune { directory, keep } => {
                    if !cfg!(unix) {
                        return Err(hs_server::AppError::not_implemented(
                            "scheduled backup retention currently requires Unix private-file support",
                        ));
                    }
                    let directory =
                        read_backup_path(directory, "Scheduled backup directory: ", "--directory")?;
                    let keep = read_backup_keep_count(keep)?;
                    confirm_backup_prune(&directory, keep)?;
                    let report =
                        hs_server::backup::prune_scheduled_database_backups(&directory, keep)?;
                    println!("scheduled encrypted backup retention completed");
                    println!("matching_archives: {}", report.matching_archives);
                    println!("retained_archives: {}", report.retained_archives);
                    println!("removed_archives: {}", report.removed_archives);
                    Ok(())
                }
                BackupAction::Verify {
                    input,
                    passphrase_stdin,
                } => {
                    if !cfg!(unix) {
                        return Err(hs_server::AppError::not_implemented(
                        "encrypted database verification currently requires Unix private-file support",
                    ));
                    }
                    if !passphrase_stdin {
                        return Err(hs_server::AppError::bad_request(
                            "backup passphrases must be supplied with --passphrase-stdin",
                        ));
                    }
                    let input = read_backup_path(input, "Backup file path: ", "--input")?;
                    let passphrase = read_backup_passphrase("Backup passphrase (16+ bytes): ")?;
                    let report = hs_server::backup::verify_database_backup(&input, &passphrase)?;
                    println!("encrypted database backup verified");
                    println!("database_bytes: {}", report.database_bytes);
                    println!("encrypted_bytes: {}", report.encrypted_bytes);
                    println!("schema_version: {}", report.schema_version);
                    Ok(())
                }
                BackupAction::Restore {
                    input,
                    output,
                    passphrase_stdin,
                } => {
                    if !cfg!(unix) {
                        return Err(hs_server::AppError::not_implemented(
                        "encrypted database restore currently requires Unix private-file support",
                    ));
                    }
                    if !passphrase_stdin {
                        return Err(hs_server::AppError::bad_request(
                            "backup passphrases must be supplied with --passphrase-stdin",
                        ));
                    }
                    let input = read_backup_path(input, "Backup file path: ", "--input")?;
                    let output = read_backup_path(output, "New database file path: ", "--output")?;
                    let passphrase = read_backup_passphrase("Backup passphrase (16+ bytes): ")?;
                    let report =
                        hs_server::backup::restore_database_backup(&input, &output, &passphrase)?;
                    println!("encrypted database backup restored");
                    println!("path: {}", output.display());
                    println!("database_bytes: {}", report.database_bytes);
                    println!("encrypted_bytes: {}", report.encrypted_bytes);
                    println!("schema_version: {}", report.schema_version);
                    println!("prior sessions and pending authority were revoked");
                    Ok(())
                }
            }
        }
        Command::Bootstrap {
            token,
            username,
            password_stdin,
            password,
            manager_public_identity,
            manager_friendly_name,
        } => {
            let token = resolve_secret(token, "HS_BOOTSTRAP_TOKEN")?;
            let password = resolve_password(password, password_stdin)?;
            let service = open_service(&cli.data)?;
            let response = service.bootstrap(BootstrapRequest {
                bootstrap_token: token,
                username,
                password,
                manager_public_identity,
                manager_friendly_name,
            })?;
            println!("bootstrap complete");
            println!("server_state: {}", response.server_state);
            println!(
                "account: {} ({})",
                response.account.username, response.account.id
            );
            if let Some(manager) = response.manager {
                println!(
                    "manager: {} state={}",
                    manager.public_identity, manager.lifecycle_state
                );
            }
            println!();
            println!("next: hs-server --data {} serve", cli.data.display());
            Ok(())
        }
        Command::BootstrapV2 {
            token,
            username,
            password_stdin,
            manager_public_key,
            manager_proof_file,
            manager_proof,
            manager_friendly_name,
            recovery_file,
        } => {
            // Validate ALL output/platform preconditions BEFORE opening or
            // mutating the database and BEFORE printing any secret. A
            // recovery_file request requires a working private writer; on
            // unsupported platforms this fails closed with no side effects.
            if let Some(path) = &recovery_file {
                hs_server::private_file::preflight_new_private_file(path)?;
            }
            if !hs_server::private_file::persisted_v2_credentials_supported() {
                return Err(hs_server::AppError::not_implemented(
                    "NEW persisted v2 MFA credentials are not supported on this platform \
                     (no native-verified private credential store); refusing before \
                     bootstrap/enrollment. Legacy v1 loopback development remains available.",
                ));
            }

            let token = resolve_secret(token, "HS_BOOTSTRAP_TOKEN")?;
            let password = read_password_stdin()?;
            let _ = password_stdin;
            let proof = match (manager_proof_file, manager_proof) {
                (Some(path), _) => {
                    let bytes = std::fs::read_to_string(&path).map_err(|err| {
                        hs_server::AppError::bad_request(format!("read manager proof file: {err}"))
                    })?;
                    bytes.trim().to_string()
                }
                (None, Some(inline)) => inline,
                (None, None) => String::new(),
            };
            let service = open_service(&cli.data)?;
            let response = service.bootstrap_v2(hs_server::models::BootstrapV2Request {
                bootstrap_token: token,
                username,
                password,
                manager_public_key,
                manager_proof: if proof.is_empty() { None } else { Some(proof) },
                manager_friendly_name,
            })?;
            println!("bootstrap v2 enrollment created (admin inactive until MFA confirm)");
            println!(
                "account: {} ({}) state={}",
                response.username, response.account_id, response.account_state
            );
            println!("mfa_enrollment_id: {}", response.mfa_enrollment_id);
            println!();
            println!("totp_secret (enter into authenticator once, never log):");
            println!("{}", response.totp_secret_base32);
            println!();
            let recovery_body = format!("{}\n", response.recovery_codes.join("\n"));
            match recovery_file {
                Some(path) => {
                    write_private_file(&path, recovery_body.as_bytes())?;
                    println!("recovery codes written to private file: {}", path.display());
                    println!("store this file offline; the server keeps only hashes");
                }
                None => {
                    println!("recovery_codes (store independently, never log):");
                    println!("{}", recovery_body.trim_end());
                }
            }
            if let Some(key) = response.manager_public_key {
                println!();
                println!("manager device key bound: {key}");
            }
            println!();
            println!(
                "next: hs-server --data {} confirm-mfa --enrollment-id {} --totp-stdin --recovery-stored",
                cli.data.display(),
                response.mfa_enrollment_id
            );
            Ok(())
        }
        Command::ConfirmMfa {
            enrollment_id,
            totp_stdin,
            totp_code,
            recovery_stored,
        } => {
            let code = if totp_stdin {
                read_line_stdin("totp code")?
            } else {
                totp_code.ok_or_else(|| {
                    hs_server::AppError::bad_request("pass --totp-stdin or --totp-code")
                })?
            };
            let service = open_service(&cli.data)?;
            let response =
                service.confirm_mfa_enrollment(hs_server::models::MfaConfirmRequest {
                    mfa_enrollment_id: enrollment_id,
                    totp_code: code,
                    recovery_material_stored: recovery_stored,
                })?;
            println!(
                "mfa confirmed: account={} state={} mfa={}",
                response.account_id, response.account_state, response.mfa_status
            );
            Ok(())
        }
        Command::CancelMfa { enrollment_id } => {
            let service = open_service(&cli.data)?;
            service.cancel_mfa_enrollment(&enrollment_id)?;
            println!("mfa enrollment cancelled: {enrollment_id}");
            Ok(())
        }
        Command::CheckLogin {
            username,
            password_stdin,
            password,
        } => {
            let password = resolve_password(password, password_stdin)?;
            let service = open_service(&cli.data)?;
            let response = service.login(LoginRequest {
                username,
                password,
                manager_public_identity: None,
            })?;
            // Drop the ephemeral session immediately; this command only checks credentials.
            if let Ok(auth) = service.authenticate_token(&response.token) {
                let _ = service.logout(&auth);
            }
            println!("login ok: {}", response.account.username);
            Ok(())
        }
        Command::Serve { bind } => {
            let addr: SocketAddr = bind.parse().map_err(|err| {
                hs_server::AppError::bad_request(format!("invalid bind address: {err}"))
            })?;
            // Plain HTTP is loopback-only; network use requires serve-tls.
            hs_server::require_loopback_bind(addr)?;
            let service = open_service(&cli.data)?;
            serve_blocking(addr, service)
        }
        Command::ServeTls {
            bind,
            tls_cert,
            tls_key,
            allow_network,
        } => {
            // Order is the trust boundary: reject nonloopback without explicit
            // opt-in and unsupported platforms, and reject malformed TLS
            // material BEFORE opening the database or binding the listener.
            hs_server::tls::run_serve_tls_with_network(
                &cli.data,
                &bind,
                &tls_cert,
                &tls_key,
                allow_network,
            )
        }
        Command::ServeDual {
            local_bind,
            network_bind,
            tls_cert,
            tls_key,
            allow_network,
        } => hs_server::tls::run_serve_dual(
            &cli.data,
            &local_bind,
            &network_bind,
            &tls_cert,
            &tls_key,
            allow_network,
        ),
        Command::Installer { action } => run_installer(action),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
struct LocalReadiness {
    bootstrap_ready: bool,
    server_ready_for_enrollment: bool,
}

#[derive(serde::Deserialize)]
struct LocalHealthBody {
    status: String,
    accepting_authorized_operations: bool,
    bootstrap_completed: bool,
    features: LocalHealthFeatures,
}

#[derive(serde::Deserialize)]
struct LocalHealthFeatures {
    mfa: bool,
    manager_enrollment: bool,
}

#[derive(serde::Deserialize)]
struct LocalDeploymentBody {
    deployment_id: String,
}

/// Query one local HTTP JSON route with bounded I/O and strict framing.
fn query_local_json(address: SocketAddr, path: &'static str) -> AppResult<Vec<u8>> {
    const MAX_RESPONSE_BYTES: usize = 8 * 1024;
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(2)).map_err(|_| {
            hs_server::AppError::security_state_unavailable("local server endpoint is unavailable")
        })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| {
            hs_server::AppError::security_state_unavailable("cannot configure healthcheck timeout")
        })?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| {
            hs_server::AppError::security_state_unavailable("cannot configure healthcheck timeout")
        })?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|_| {
        hs_server::AppError::security_state_unavailable("cannot query local server endpoint")
    })?;

    let mut response = Vec::new();
    stream
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|_| {
            hs_server::AppError::security_state_unavailable("cannot read local server response")
        })?;
    if response.is_empty() || response.len() > MAX_RESPONSE_BYTES {
        return Err(hs_server::AppError::security_state_unavailable(
            "local server response is empty or exceeds its size limit",
        ));
    }

    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            hs_server::AppError::security_state_unavailable("local server response is incomplete")
        })?;
    let headers = std::str::from_utf8(&response[..header_end]).map_err(|_| {
        hs_server::AppError::security_state_unavailable("local server headers are invalid")
    })?;
    let status_line = headers.lines().next().unwrap_or_default();
    let mut status_fields = status_line.split_whitespace();
    if !matches!(status_fields.next(), Some("HTTP/1.0" | "HTTP/1.1"))
        || !matches!(status_fields.next(), Some("200"))
    {
        return Err(hs_server::AppError::security_state_unavailable(
            "local server endpoint did not return success",
        ));
    }
    let mut content_length = None;
    for line in headers.lines().skip(1) {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            hs_server::AppError::security_state_unavailable(
                "local server response contains a malformed header",
            )
        })?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err(hs_server::AppError::security_state_unavailable(
                "local server response contains an invalid header name",
            ));
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(hs_server::AppError::security_state_unavailable(
                "local server response used an unsupported transfer encoding",
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(hs_server::AppError::security_state_unavailable(
                    "local server response repeated its content length",
                ));
            }
            let length = value.trim().parse::<usize>().map_err(|_| {
                hs_server::AppError::security_state_unavailable(
                    "local server response has an invalid content length",
                )
            })?;
            if length > MAX_RESPONSE_BYTES {
                return Err(hs_server::AppError::security_state_unavailable(
                    "local server response exceeds its size limit",
                ));
            }
            content_length = Some(length);
        }
    }

    let body_start = header_end + 4;
    let body_bytes = &response[body_start..];
    if content_length != Some(body_bytes.len()) {
        return Err(hs_server::AppError::security_state_unavailable(
            "local server response body length does not match its header",
        ));
    }
    Ok(body_bytes.to_vec())
}

/// Confirm the local service has completed bootstrap and exposes its v2
/// deployment identity. A live socket alone never marks enrollment ready.
fn query_local_readiness(address: &str) -> AppResult<LocalReadiness> {
    let address: SocketAddr = address.parse().map_err(|err| {
        hs_server::AppError::bad_request(format!("invalid healthcheck address: {err}"))
    })?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(hs_server::AppError::bad_request(
            "healthcheck address must be a nonzero literal-loopback socket",
        ));
    }

    let health: LocalHealthBody = serde_json::from_slice(&query_local_json(address, "/health")?)
        .map_err(|_| {
            hs_server::AppError::security_state_unavailable("local health body is invalid")
        })?;
    if !readiness_probe_supported(&health) {
        return Ok(LocalReadiness {
            bootstrap_ready: false,
            server_ready_for_enrollment: false,
        });
    }

    let deployment: LocalDeploymentBody =
        serde_json::from_slice(&query_local_json(address, "/v2/deployment")?).map_err(|_| {
            hs_server::AppError::security_state_unavailable(
                "local deployment identity response is invalid",
            )
        })?;
    let deployment_id = deployment.deployment_id.trim();
    Ok(classify_local_readiness(&health, deployment_id))
}

fn readiness_probe_supported(health: &LocalHealthBody) -> bool {
    let bootstrap_pending = health.status == "degraded"
        && !health.accepting_authorized_operations
        && !health.bootstrap_completed;
    let enrollment_ready = health.status == "ok"
        && health.accepting_authorized_operations
        && health.bootstrap_completed;
    matches!(health.status.as_str(), "ok" | "degraded")
        && health.features.mfa
        && health.features.manager_enrollment
        && (bootstrap_pending || enrollment_ready)
}

fn classify_local_readiness(health: &LocalHealthBody, deployment_id: &str) -> LocalReadiness {
    let valid_deployment_identity = !deployment_id.is_empty() && deployment_id.len() <= 128;
    LocalReadiness {
        bootstrap_ready: health.status == "degraded"
            && !health.accepting_authorized_operations
            && !health.bootstrap_completed
            && health.features.mfa
            && health.features.manager_enrollment
            && valid_deployment_identity,
        server_ready_for_enrollment: health.status == "ok"
            && health.accepting_authorized_operations
            && health.bootstrap_completed
            && health.features.mfa
            && health.features.manager_enrollment
            && valid_deployment_identity,
    }
}

/// Probe the local server for container/systemd healthchecks. It deliberately
/// remains unhealthy until secure bootstrap and the v2 identity route work.
fn check_local_health(address: &str) -> AppResult<()> {
    let readiness = query_local_readiness(address)?;
    if readiness.server_ready_for_enrollment {
        return Ok(());
    }
    let message = if readiness.bootstrap_ready {
        "local server is ready for initial bootstrap but not yet for enrollment"
    } else {
        "local server is not ready for enrollment"
    };
    Err(hs_server::AppError::security_state_unavailable(message))
}

#[cfg(target_os = "linux")]
fn refresh_systemd_readiness(status: &mut hs_server::installer::lifecycle_v2::OperationStatus) {
    use hs_server::installer::lifecycle_v2::{DeploymentKind, OperationState};

    if status.configuration.deployment_kind != DeploymentKind::LinuxSystemd
        || status.state != OperationState::Completed
        || !status.service_installed
    {
        return;
    }

    match query_local_readiness("127.0.0.1:8787") {
        Ok(readiness) => {
            status.bootstrap_ready = readiness.bootstrap_ready;
            status.server_ready_for_enrollment = readiness.server_ready_for_enrollment;
        }
        Err(_) => {
            status.bootstrap_ready = false;
            status.server_ready_for_enrollment = false;
            status.result.warnings.push(
                "Local service health and deployment identity did not confirm enrollment readiness."
                    .to_string(),
            );
        }
    }
}

fn serve_blocking(addr: SocketAddr, service: Arc<Service>) -> AppResult<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| hs_server::AppError::internal(format!("tokio runtime: {err}")))?;

    runtime.block_on(async move {
        let maintenance_service = service.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(err) = maintenance_service.maintain_file_jobs() {
                    tracing::warn!(error = %err, "file-job expiry maintenance failed");
                }
                if let Err(err) = maintenance_service.maintain_file_requests() {
                    tracing::warn!(error = %err, "file-request deadline maintenance failed");
                }
                if let Err(err) = maintenance_service.maintain_audit_events() {
                    tracing::warn!(error = %err, "audit retention maintenance failed");
                }
            }
        });
        let app = hs_server::app(service);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|err| hs_server::AppError::internal(format!("bind {addr}: {err}")))?;
        tracing::info!(%addr, "hs-server listening (HTTP, development foundation)");
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("shutdown requested");
            })
            .await
            .map_err(|err| hs_server::AppError::internal(format!("serve: {err}")))?;
        Ok(())
    })
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn run_tuf_release_verification(
    adapter: &dyn hs_server::installer::CommandAdapter,
    trusted_root: &std::path::Path,
    metadata_url: &str,
    targets_url: &str,
    manifest_target: &str,
    platform: &str,
    verify_key: &str,
    state_dir: &std::path::Path,
) -> AppResult<()> {
    let platform = match hs_server::installer::models::InstallerTarget::from_platform_str(platform)
    {
        Some(platform) => platform,
        None => {
            return Err(hs_server::AppError::bad_request(
                "unknown installer target platform",
            ));
        }
    };
    let verifying_key = hex_decode_32(verify_key)?;
    let root_metadata = std::fs::symlink_metadata(trusted_root).map_err(|error| {
        hs_server::AppError::bad_request(format!("inspect trusted TUF root metadata: {error}"))
    })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_file() {
        return Err(hs_server::AppError::forbidden(
            "trusted TUF root metadata must be a regular non-symlink file",
        ));
    }
    if root_metadata.len() == 0 || root_metadata.len() > 1024 * 1024 {
        return Err(hs_server::AppError::unprocessable(
            "trusted TUF root metadata must be between 1 and 1048576 bytes",
        ));
    }
    let root_bytes = std::fs::read(trusted_root).map_err(|error| {
        hs_server::AppError::bad_request(format!("read trusted TUF root metadata: {error}"))
    })?;
    let metadata_url = url::Url::parse(metadata_url)
        .map_err(|_| hs_server::AppError::bad_request("invalid TUF metadata URL"))?;
    let targets_url = url::Url::parse(targets_url)
        .map_err(|_| hs_server::AppError::bad_request("invalid TUF targets URL"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| hs_server::AppError::internal(format!("create TUF runtime: {error}")))?;
    let release = runtime.block_on(hs_server::installer::tuf_update::verify_and_stage_release(
        adapter,
        &root_bytes,
        metadata_url,
        targets_url,
        manifest_target,
        &verifying_key,
        platform,
        state_dir,
    ))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&release).map_err(|error| {
            hs_server::AppError::internal(format!("serialize TUF release result: {error}"))
        })?
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_installer(_action: InstallerAction) -> AppResult<()> {
    Err(hs_server::AppError::unprocessable(format!(
        "installer requires a Linux host (running on {})",
        std::env::consts::OS
    )))
}

#[cfg(target_os = "linux")]
fn run_installer(action: InstallerAction) -> AppResult<()> {
    use hs_server::installer::lifecycle_v2;
    use hs_server::installer::machine;
    use hs_server::installer::models::*;

    if matches!(&action, InstallerAction::CapabilitiesV2) {
        let output =
            serde_json::to_string_pretty(&machine::lifecycle_capabilities_v2()).map_err(|err| {
                hs_server::AppError::internal(format!("serialize lifecycle capabilities: {err}"))
            })?;
        println!("{output}");
        return Ok(());
    }

    if let InstallerAction::VerifyTufRelease {
        trusted_root,
        metadata_url,
        targets_url,
        manifest_target,
        platform,
        verify_key,
        state_dir,
    } = &action
    {
        return run_tuf_release_verification(
            &adapter,
            trusted_root,
            metadata_url,
            targets_url,
            manifest_target,
            platform,
            verify_key,
            state_dir,
        );
    }

    // Bounded versioned JSON: refuse unbounded stdin before parsing.
    const MAX_INSTALLER_STDIN_BYTES: u64 = 8 * 1024 * 1024;
    let mut stdin_buf = String::new();
    let mut handle = std::io::stdin().take(MAX_INSTALLER_STDIN_BYTES + 1);
    handle
        .read_to_string(&mut stdin_buf)
        .map_err(|err| hs_server::AppError::bad_request(format!("read stdin: {err}")))?;
    if stdin_buf.len() as u64 > MAX_INSTALLER_STDIN_BYTES {
        return Err(hs_server::AppError::bad_request(format!(
            "installer input exceeds {MAX_INSTALLER_STDIN_BYTES} bytes"
        )));
    }

    let adapter = hs_server::installer::adapter::LinuxAdapter;

    let output: serde_json::Value = match action {
        InstallerAction::CapabilitiesV2 => {
            serde_json::to_value(machine::lifecycle_capabilities_v2()).map_err(|err| {
                hs_server::AppError::internal(format!("serialize lifecycle capabilities: {err}"))
            })?
        }
        InstallerAction::VerifyTufRelease { .. } => unreachable!("handled before reading stdin"),
        InstallerAction::Preflight => {
            let input: PreflightInput = serde_json::from_str(&stdin_buf).map_err(|err| {
                hs_server::AppError::bad_request(format!("invalid preflight input: {err}"))
            })?;
            let result = machine::preflight(&adapter, &input)?;
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize preflight result: {err}"))
            })?
        }
        InstallerAction::PreflightV2 => {
            let input: lifecycle_v2::PreflightInput =
                serde_json::from_str(&stdin_buf).map_err(|err| {
                    hs_server::AppError::bad_request(format!("invalid v2 preflight input: {err}"))
                })?;
            let result = machine::preflight_v2(&adapter, &input)?;
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize v2 preflight result: {err}"))
            })?
        }
        InstallerAction::Plan {
            package_dir,
            verify_key,
        } => {
            let mut input: PlanInput = serde_json::from_str(&stdin_buf).map_err(|err| {
                hs_server::AppError::bad_request(format!("invalid plan input: {err}"))
            })?;
            input.package_dir = package_dir;
            let key_bytes = hex_decode_32(&verify_key)?;
            let result = machine::plan(&adapter, &input, Some(&key_bytes))?;
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize plan result: {err}"))
            })?
        }
        InstallerAction::Apply {
            state_dir,
            package_dir,
            verify_key,
        } => {
            let mut input: ApplyInput = serde_json::from_str(&stdin_buf).map_err(|err| {
                hs_server::AppError::bad_request(format!("invalid apply input: {err}"))
            })?;
            if package_dir.is_some() {
                input.package_dir = package_dir;
            }
            if verify_key.is_some() {
                input.verify_key = verify_key;
            }
            let result = machine::apply(&adapter, &input, std::path::Path::new(&state_dir))?;
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize apply result: {err}"))
            })?
        }
        InstallerAction::Resume { state_dir } => {
            let input: ApplyInput = serde_json::from_str(&stdin_buf).map_err(|err| {
                hs_server::AppError::bad_request(format!("invalid resume input: {err}"))
            })?;
            let result = machine::resume(&adapter, &input, std::path::Path::new(&state_dir))?;
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize resume result: {err}"))
            })?
        }
        InstallerAction::Inspect { state_dir } => {
            let mut input: InspectInput = serde_json::from_str(&stdin_buf).map_err(|err| {
                hs_server::AppError::bad_request(format!("invalid inspect input: {err}"))
            })?;
            input.state_dir = state_dir;
            let result = machine::inspect(&adapter, &input)?;
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize inspect result: {err}"))
            })?
        }
        InstallerAction::PlanV2 {
            package_dir,
            verify_key,
        } => {
            let mut input: lifecycle_v2::PlanInput =
                serde_json::from_str(&stdin_buf).map_err(|err| {
                    hs_server::AppError::bad_request(format!("invalid v2 plan input: {err}"))
                })?;
            input.package_dir = package_dir;
            let key_bytes = hex_decode_32(&verify_key)?;
            let result = machine::plan_v2(&adapter, &input, Some(&key_bytes))?;
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize v2 plan result: {err}"))
            })?
        }
        InstallerAction::ApplyV2 { state_dir } => {
            let input: lifecycle_v2::ApplyInput =
                serde_json::from_str(&stdin_buf).map_err(|err| {
                    hs_server::AppError::bad_request(format!("invalid v2 apply input: {err}"))
                })?;
            let mut result = machine::apply_v2(&adapter, &input, std::path::Path::new(&state_dir))?;
            refresh_systemd_readiness(&mut result);
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize v2 operation result: {err}"))
            })?
        }
        InstallerAction::ResumeV2 { state_dir } => {
            let input: lifecycle_v2::ApplyInput =
                serde_json::from_str(&stdin_buf).map_err(|err| {
                    hs_server::AppError::bad_request(format!("invalid v2 resume input: {err}"))
                })?;
            let mut result =
                machine::resume_v2(&adapter, &input, std::path::Path::new(&state_dir))?;
            refresh_systemd_readiness(&mut result);
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize v2 operation result: {err}"))
            })?
        }
        InstallerAction::StatusV2 { state_dir } => {
            let input: lifecycle_v2::StatusInput =
                serde_json::from_str(&stdin_buf).map_err(|err| {
                    hs_server::AppError::bad_request(format!("invalid v2 status input: {err}"))
                })?;
            let mut result =
                machine::operation_status_v2(&adapter, &input, std::path::Path::new(&state_dir))?;
            refresh_systemd_readiness(&mut result);
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize v2 operation status: {err}"))
            })?
        }
        InstallerAction::ConfigurationV2 { state_dir } => {
            let result =
                machine::stored_configuration_v2(&adapter, std::path::Path::new(&state_dir))?;
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize stored v2 configuration: {err}"))
            })?
        }
        InstallerAction::RemoveV2 { state_dir } => {
            let input: lifecycle_v2::RemoveInput =
                serde_json::from_str(&stdin_buf).map_err(|err| {
                    hs_server::AppError::bad_request(format!("invalid v2 remove input: {err}"))
                })?;
            let result = machine::remove_v2(&adapter, &input, std::path::Path::new(&state_dir))?;
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize v2 remove result: {err}"))
            })?
        }
        InstallerAction::Remove => {
            let input: RemoveInput = serde_json::from_str(&stdin_buf).map_err(|err| {
                hs_server::AppError::bad_request(format!("invalid remove input: {err}"))
            })?;
            let result = machine::remove(&adapter, &input)?;
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize remove result: {err}"))
            })?
        }
    };

    let json = serde_json::to_string_pretty(&output)
        .map_err(|err| hs_server::AppError::internal(format!("serialize output: {err}")))?;
    println!("{json}");
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn hex_decode_32(hex_str: &str) -> AppResult<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .map_err(|err| hs_server::AppError::bad_request(format!("invalid hex key: {err}")))?;
    if bytes.len() != 32 {
        return Err(hs_server::AppError::bad_request(format!(
            "verifying key must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn resolve_secret(cli_value: Option<String>, env_key: &str) -> AppResult<String> {
    if let Some(value) = cli_value {
        return Ok(value);
    }
    if let Ok(value) = std::env::var(env_key) {
        if !value.is_empty() {
            return Ok(value);
        }
    }
    Err(hs_server::AppError::bad_request(format!(
        "missing secret: pass a flag or set {env_key}"
    )))
}

fn resolve_password(cli_value: Option<String>, password_stdin: bool) -> AppResult<String> {
    if password_stdin {
        return read_password_stdin();
    }
    if let Some(password) = cli_value {
        return Ok(password);
    }
    Err(hs_server::AppError::bad_request(
        "missing password: use --password-stdin or --password",
    ))
}

/// Read a password from stdin without echoing secrets into argv or logs.
fn read_password_stdin() -> AppResult<String> {
    let mut buffer = String::new();
    std::io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|err| hs_server::AppError::bad_request(format!("read password stdin: {err}")))?;
    let password = buffer.trim_end_matches(['\n', '\r']).to_string();
    if password.is_empty() {
        return Err(hs_server::AppError::bad_request(
            "password on stdin was empty",
        ));
    }
    Ok(password)
}

/// Read one bounded backup passphrase line without accepting argv material.
/// When stdin is a terminal, disable echo for the duration of the prompt.
fn read_confirmed_backup_passphrase() -> AppResult<Zeroizing<Vec<u8>>> {
    use subtle::ConstantTimeEq;

    let passphrase = read_backup_passphrase("New backup passphrase (16+ bytes): ")?;
    let confirmation = read_backup_passphrase("Confirm backup passphrase: ")?;
    if !bool::from(passphrase.as_slice().ct_eq(confirmation.as_slice())) {
        return Err(hs_server::AppError::bad_request(
            "backup passphrase confirmation did not match",
        ));
    }
    Ok(passphrase)
}

fn read_backup_passphrase(prompt: &str) -> AppResult<Zeroizing<Vec<u8>>> {
    use std::io::IsTerminal;

    let stdin = std::io::stdin();
    let terminal = stdin.is_terminal();
    if terminal {
        eprint!("{prompt}");
        std::io::stderr().flush().map_err(|err| {
            hs_server::AppError::bad_request(format!("write passphrase prompt: {err}"))
        })?;
    }
    #[cfg(unix)]
    let echo_guard = if terminal {
        Some(DisabledTerminalEcho::disable()?)
    } else {
        None
    };

    let mut passphrase = Zeroizing::new(Vec::with_capacity(128));
    let mut input = stdin.lock();
    loop {
        let mut byte = [0_u8; 1];
        let count = input.read(&mut byte).map_err(|err| {
            hs_server::AppError::bad_request(format!("read backup passphrase: {err}"))
        })?;
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        if passphrase.len() == 4096 {
            return Err(hs_server::AppError::bad_request(
                "backup passphrase exceeds the 4096-byte input limit",
            ));
        }
        passphrase.push(byte[0]);
    }
    drop(input);
    #[cfg(unix)]
    drop(echo_guard);
    if terminal {
        eprintln!();
    }
    if passphrase.last() == Some(&b'\r') {
        passphrase.pop();
    }
    if !(16..=4096).contains(&passphrase.len()) {
        return Err(hs_server::AppError::bad_request(
            "backup passphrase must contain 16 to 4096 bytes on one line",
        ));
    }
    Ok(passphrase)
}

/// Read the backup secret from systemd's per-service credential directory.
/// It is never accepted through argv, an ordinary environment value, or a
/// caller-selected path.
fn read_systemd_backup_credential() -> AppResult<Zeroizing<Vec<u8>>> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            hs_server::AppError::bad_request("systemd backup credential directory is unavailable")
        })?;
    let credential = directory.join("helicoid-backup-passphrase");
    let passphrase = hs_server::private_file::read_service_credential_file(&credential, 4096)?;
    if !(16..=4096).contains(&passphrase.len())
        || passphrase.contains(&b'\n')
        || passphrase.contains(&b'\r')
    {
        return Err(hs_server::AppError::bad_request(
            "systemd backup credential must contain 16 to 4096 bytes on one line",
        ));
    }
    Ok(passphrase)
}

/// Read a bounded scheduled-backup credential delivered directly to a
/// Compose container over Docker stdin. No newline framing or argv value is
/// accepted.
fn read_scheduled_backup_passphrase_stdin() -> AppResult<Zeroizing<Vec<u8>>> {
    read_scheduled_backup_passphrase(std::io::stdin())
}

fn read_scheduled_backup_passphrase(input: impl Read) -> AppResult<Zeroizing<Vec<u8>>> {
    let mut passphrase = Zeroizing::new(Vec::with_capacity(128));
    input
        .take(4097)
        .read_to_end(&mut passphrase)
        .map_err(|_| hs_server::AppError::bad_request("read scheduled backup credential"))?;
    if !(16..=4096).contains(&passphrase.len())
        || passphrase.contains(&b'\n')
        || passphrase.contains(&b'\r')
    {
        return Err(hs_server::AppError::bad_request(
            "scheduled backup credential must contain 16 to 4096 bytes on one line",
        ));
    }
    Ok(passphrase)
}

#[cfg(target_os = "linux")]
const COMPOSE_BACKUP_CONTROL_SOCKET: &str = "/run/helicoid/backup-control/backup-control.sock";

#[cfg(target_os = "linux")]
const COMPOSE_BACKUP_CONTROL_MAX_FRAME: usize = 5 + 4096;

#[cfg(target_os = "linux")]
const COMPOSE_LOG_CONTROL_MAX_RESPONSE: usize = 256 * 1024;

#[cfg(target_os = "linux")]
fn is_compose_control_client() -> bool {
    std::path::Path::new("/.dockerenv").is_file()
        && std::path::Path::new(COMPOSE_BACKUP_CONTROL_SOCKET).exists()
}

#[cfg(target_os = "linux")]
fn request_compose_backup_control(action: u8, passphrase: Option<&[u8]>) -> AppResult<()> {
    let credential = match (action, passphrase) {
        (1, Some(value))
            if (16..=4096).contains(&value.len())
                && !value.contains(&b'\n')
                && !value.contains(&b'\r') =>
        {
            value
        }
        (2, None) => &[][..],
        _ => {
            return Err(hs_server::AppError::bad_request(
                "invalid Compose backup control request",
            ));
        }
    };
    let mut stream = UnixStream::connect(COMPOSE_BACKUP_CONTROL_SOCKET).map_err(|_| {
        hs_server::AppError::internal("host backup schedule control is unavailable")
    })?;
    stream
        .write_all(&[action])
        .and_then(|()| stream.write_all(&(credential.len() as u32).to_be_bytes()))
        .and_then(|()| stream.write_all(credential))
        .and_then(|()| stream.shutdown(Shutdown::Write))
        .map_err(|_| hs_server::AppError::internal("send host backup schedule request"))?;
    let mut acknowledgement = [0_u8; 1];
    stream.read_exact(&mut acknowledgement).map_err(|_| {
        hs_server::AppError::internal("host backup schedule control returned no result")
    })?;
    if acknowledgement[0] != 1 {
        return Err(hs_server::AppError::unprocessable(
            "host rejected the backup schedule request; inspect the server journal",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_compose_backup_control_request() -> AppResult<()> {
    use std::os::fd::AsRawFd;

    let mut compose_logs = None;
    let result = (|| {
        verify_compose_control_peer()?;
        let mut frame = Zeroizing::new(Vec::with_capacity(256));
        std::io::stdin()
            .take((COMPOSE_BACKUP_CONTROL_MAX_FRAME + 1) as u64)
            .read_to_end(&mut frame)
            .map_err(|_| hs_server::AppError::bad_request("read backup schedule request"))?;
        if frame.len() > COMPOSE_BACKUP_CONTROL_MAX_FRAME || frame.len() < 5 {
            return Err(hs_server::AppError::bad_request(
                "backup schedule request length is invalid",
            ));
        }
        let action = frame[0];
        let length = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        if frame.len() != 5 + length {
            return Err(hs_server::AppError::bad_request(
                "backup schedule request framing is invalid",
            ));
        }
        let state_dir = std::path::Path::new("/opt/helicoid/.installer");
        let adapter = hs_server::installer::adapter::LinuxAdapter;
        match action {
            1 if (16..=4096).contains(&length) => {
                let passphrase = &frame[5..];
                if passphrase.contains(&b'\n') || passphrase.contains(&b'\r') {
                    return Err(hs_server::AppError::bad_request(
                        "backup passphrase must be one line",
                    ));
                }
                hs_server::installer::machine::enable_backup_schedule_v2(
                    &adapter,
                    state_dir,
                    Some(passphrase),
                )
            }
            2 if length == 0 => {
                hs_server::installer::machine::disable_backup_schedule_v2(&adapter, state_dir)
            }
            3 if length == 0 => {
                let logs = hs_server::installer::machine::recent_compose_service_logs_v2(
                    &adapter, state_dir,
                )?;
                if logs.len() > COMPOSE_LOG_CONTROL_MAX_RESPONSE {
                    return Err(hs_server::AppError::unprocessable(
                        "Compose service logs exceed the control response limit",
                    ));
                }
                compose_logs = Some(logs);
                Ok(())
            }
            _ => Err(hs_server::AppError::bad_request(
                "unsupported backup schedule request",
            )),
        }
    })();
    let mut output = std::io::stdout().lock();
    match (&result, compose_logs) {
        (Ok(()), Some(logs)) => {
            output
                .write_all(&[1])
                .and_then(|()| output.write_all(&(logs.len() as u32).to_be_bytes()))
                .and_then(|()| output.write_all(&logs))
                .map_err(|_| hs_server::AppError::internal("write Compose service log response"))?;
        }
        (Ok(()), None) => output
            .write_all(&[1])
            .map_err(|_| hs_server::AppError::internal("write backup schedule result"))?,
        (Err(_), _) => output
            .write_all(&[0])
            .map_err(|_| hs_server::AppError::internal("write backup schedule result"))?,
    }
    output
        .flush()
        .map_err(|_| hs_server::AppError::internal("flush backup control result"))?;
    result
}

#[cfg(target_os = "linux")]
fn verify_compose_control_peer() -> AppResult<()> {
    use std::mem::size_of;

    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt initializes `credentials` when it succeeds, and the
    // descriptor is systemd's accepted AF_UNIX stream on standard input.
    let result = unsafe {
        libc::getsockopt(
            std::io::stdin().as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != size_of::<libc::ucred>() {
        return Err(hs_server::AppError::forbidden(
            "backup schedule request has no verified local peer",
        ));
    }
    // SAFETY: getsockopt returned success and the exact expected structure size.
    let credentials = unsafe { credentials.assume_init() };
    if credentials.uid != 10001 || credentials.gid != 10001 {
        return Err(hs_server::AppError::forbidden(
            "backup schedule request is not from the Compose server identity",
        ));
    }
    Ok(())
}

fn read_backup_path(path: Option<PathBuf>, prompt: &str, argument: &str) -> AppResult<PathBuf> {
    if let Some(path) = path {
        return Ok(path);
    }

    use std::io::IsTerminal;

    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Err(hs_server::AppError::bad_request(format!(
            "provide {argument} when stdin is not an interactive terminal",
        )));
    }
    eprint!("{prompt}");
    std::io::stderr().flush().map_err(|err| {
        hs_server::AppError::bad_request(format!("write backup path prompt: {err}"))
    })?;
    let mut path = Zeroizing::new(Vec::with_capacity(256));
    let mut input = stdin.lock();
    loop {
        let mut byte = [0_u8; 1];
        let count = input
            .read(&mut byte)
            .map_err(|err| hs_server::AppError::bad_request(format!("read backup path: {err}")))?;
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        if path.len() == 4096 {
            return Err(hs_server::AppError::bad_request(
                "backup path exceeds the 4096-byte input limit",
            ));
        }
        path.push(byte[0]);
    }
    if path.last() == Some(&b'\r') {
        path.pop();
    }
    if path.is_empty() {
        return Err(hs_server::AppError::bad_request(
            "backup path must not be empty",
        ));
    }
    let path = String::from_utf8(path.to_vec())
        .map_err(|_| hs_server::AppError::bad_request("backup path must be valid UTF-8"))?;
    Ok(PathBuf::from(path))
}

fn read_backup_keep_count(keep: Option<usize>) -> AppResult<usize> {
    let keep = match keep {
        Some(keep) => keep,
        None => {
            let value = read_backup_prompt_line(
                "Keep how many newest scheduled archives? [30]: ",
                "backup retention count",
                32,
            )?;
            if value.is_empty() {
                30
            } else {
                value.parse::<usize>().map_err(|_| {
                    hs_server::AppError::bad_request("backup retention count must be a number")
                })?
            }
        }
    };
    if !(1..=10_000).contains(&keep) {
        return Err(hs_server::AppError::bad_request(
            "backup retention must keep between 1 and 10000 scheduled archives",
        ));
    }
    Ok(keep)
}

fn confirm_backup_prune(directory: &std::path::Path, keep: usize) -> AppResult<()> {
    let confirmation = read_backup_prompt_line(
        &format!(
            "This removes older files named hs-server-<timestamp>-<uuid>.hsb from {} and keeps the newest {keep}. Type 'prune backups' to continue: ",
            directory.display()
        ),
        "backup retention confirmation",
        32,
    )?;
    if confirmation != "prune backups" {
        return Err(hs_server::AppError::bad_request(
            "backup retention was not confirmed",
        ));
    }
    Ok(())
}

fn read_backup_prompt_line(prompt: &str, what: &str, max_bytes: usize) -> AppResult<String> {
    use std::io::{BufRead, IsTerminal};

    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Err(hs_server::AppError::bad_request(format!(
            "{what} requires an interactive terminal",
        )));
    }
    eprint!("{prompt}");
    std::io::stderr().flush().map_err(|error| {
        hs_server::AppError::bad_request(format!("write {what} prompt: {error}"))
    })?;
    let mut line = String::new();
    let bytes_read = stdin
        .lock()
        .take((max_bytes + 1) as u64)
        .read_line(&mut line)
        .map_err(|error| hs_server::AppError::bad_request(format!("read {what}: {error}")))?;
    if bytes_read == 0 || bytes_read > max_bytes || !line.ends_with('\n') {
        return Err(hs_server::AppError::bad_request(format!(
            "{what} must be a line of at most {max_bytes} bytes",
        )));
    }
    Ok(line.trim_end_matches(&['\r', '\n'][..]).to_string())
}

#[cfg(unix)]
struct DisabledTerminalEcho(libc::termios);

#[cfg(unix)]
impl DisabledTerminalEcho {
    fn disable() -> AppResult<Self> {
        let fd = libc::STDIN_FILENO;
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `tcgetattr` initializes the supplied termios structure on success.
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(hs_server::AppError::bad_request(
                "could not disable terminal echo for backup passphrase",
            ));
        }
        // SAFETY: `tcgetattr` returned success and initialized the structure.
        let original = unsafe { original.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !libc::ECHO;
        // SAFETY: `hidden` is initialized and remains alive for the call.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
            return Err(hs_server::AppError::bad_request(
                "could not disable terminal echo for backup passphrase",
            ));
        }
        Ok(Self(original))
    }
}

#[cfg(unix)]
impl Drop for DisabledTerminalEcho {
    fn drop(&mut self) {
        // SAFETY: the original terminal settings were captured from stdin.
        let _ = unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0) };
    }
}

/// Read a single trimmed line from stdin (TOTP codes, short factors).
fn read_line_stdin(what: &str) -> AppResult<String> {
    use std::io::BufRead;
    let mut line = String::new();
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    handle
        .read_line(&mut line)
        .map_err(|err| hs_server::AppError::bad_request(format!("read {what} stdin: {err}")))?;
    let value = line.trim().to_string();
    if value.is_empty() {
        return Err(hs_server::AppError::bad_request(format!(
            "{what} on stdin was empty"
        )));
    }
    Ok(value)
}

/// Write recovery material to a new private file (create-new only).
///
/// Delegates to [`hs_server::private_file::create_new_private_file`], which
/// never overwrites, never follows symlinks, and fails closed on platforms
/// without a verified secure create-new path. Secrets are not printed on error.
fn write_private_file(path: &std::path::Path, contents: &[u8]) -> AppResult<()> {
    hs_server::private_file::create_new_private_file(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Disposable invalid token beginning with `-` (URL-safe base64 alphabet).
    /// Parser must preserve it opaque; backend still denies it.
    const LEADING_HYPHEN_TOKEN: &str = "-iDisposableInvalidToken00000000000000000";

    #[test]
    fn scheduled_compose_backup_stdin_is_bounded_and_unframed() {
        let secret = b"0123456789abcdef";
        let accepted = read_scheduled_backup_passphrase(std::io::Cursor::new(secret))
            .expect("valid systemd credential");
        assert_eq!(accepted.as_slice(), secret);

        for rejected in [b"short".as_slice(), b"0123456789abcdef\n".as_slice()] {
            assert!(read_scheduled_backup_passphrase(std::io::Cursor::new(rejected)).is_err());
        }
        assert!(read_scheduled_backup_passphrase(std::io::Cursor::new(vec![b'x'; 4097])).is_err());
    }

    fn bootstrap_token(cli: &Cli) -> Option<&str> {
        match &cli.command {
            Command::Bootstrap { token, .. } | Command::BootstrapV2 { token, .. } => {
                token.as_deref()
            }
            _ => None,
        }
    }

    fn readiness_health(
        status: &str,
        accepting_authorized_operations: bool,
        bootstrap_completed: bool,
        mfa: bool,
        manager_enrollment: bool,
    ) -> LocalHealthBody {
        LocalHealthBody {
            status: status.to_string(),
            accepting_authorized_operations,
            bootstrap_completed,
            features: LocalHealthFeatures {
                mfa,
                manager_enrollment,
            },
        }
    }

    #[test]
    fn bootstrap_parses_leading_hyphen_token_as_separate_value() {
        let cli = Cli::try_parse_from([
            "hs-server",
            "bootstrap",
            "--token",
            LEADING_HYPHEN_TOKEN,
            "--username",
            "admin",
            "--password-stdin",
        ])
        .expect("bootstrap must accept opaque leading-hyphen --token VALUE");
        assert_eq!(bootstrap_token(&cli), Some(LEADING_HYPHEN_TOKEN));
        assert!(matches!(cli.command, Command::Bootstrap { .. }));
    }

    #[test]
    fn bootstrap_v2_parses_leading_hyphen_token_as_separate_value() {
        let cli = Cli::try_parse_from([
            "hs-server",
            "bootstrap-v2",
            "--token",
            LEADING_HYPHEN_TOKEN,
            "--username",
            "admin",
            "--password-stdin",
        ])
        .expect("bootstrap-v2 must accept opaque leading-hyphen --token VALUE");
        assert_eq!(bootstrap_token(&cli), Some(LEADING_HYPHEN_TOKEN));
        assert!(matches!(cli.command, Command::BootstrapV2 { .. }));
    }

    #[test]
    fn backup_restore_allows_interactive_path_prompts() {
        let cli = Cli::try_parse_from(["hs-server", "backup", "restore", "--passphrase-stdin"])
            .expect("restore paths may be prompted on a terminal");
        assert!(matches!(
            cli.command,
            Command::Backup {
                action: BackupAction::Restore {
                    input: None,
                    output: None,
                    passphrase_stdin: true,
                }
            }
        ));
    }

    #[test]
    fn installer_readiness_detects_service_ready_for_initial_bootstrap() {
        let health = readiness_health("degraded", false, false, true, true);
        assert!(readiness_probe_supported(&health));
        assert_eq!(
            classify_local_readiness(&health, "deployment-123"),
            LocalReadiness {
                bootstrap_ready: true,
                server_ready_for_enrollment: false,
            }
        );
    }

    #[test]
    fn installer_readiness_requires_completed_bootstrap_for_enrollment() {
        let health = readiness_health("ok", true, true, true, true);
        assert!(readiness_probe_supported(&health));
        assert_eq!(
            classify_local_readiness(&health, "deployment-123"),
            LocalReadiness {
                bootstrap_ready: false,
                server_ready_for_enrollment: true,
            }
        );
    }

    #[test]
    fn installer_readiness_refuses_degraded_bootstrapped_service() {
        let health = readiness_health("degraded", false, true, true, true);
        assert!(!readiness_probe_supported(&health));
        assert_eq!(
            classify_local_readiness(&health, "deployment-123"),
            LocalReadiness {
                bootstrap_ready: false,
                server_ready_for_enrollment: false,
            }
        );
    }

    #[test]
    fn installer_readiness_requires_mfa_features_and_valid_identity() {
        let without_mfa = readiness_health("degraded", false, false, false, true);
        assert!(!readiness_probe_supported(&without_mfa));
        assert_eq!(
            classify_local_readiness(&without_mfa, "deployment-123"),
            LocalReadiness {
                bootstrap_ready: false,
                server_ready_for_enrollment: false,
            }
        );

        let ready = readiness_health("degraded", false, false, true, true);
        assert_eq!(
            classify_local_readiness(&ready, ""),
            LocalReadiness {
                bootstrap_ready: false,
                server_ready_for_enrollment: false,
            }
        );
        assert_eq!(
            classify_local_readiness(&ready, &"x".repeat(129)),
            LocalReadiness {
                bootstrap_ready: false,
                server_ready_for_enrollment: false,
            }
        );
    }
}
