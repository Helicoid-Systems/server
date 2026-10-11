//! hs-server CLI: init, bootstrap, serve.
//!
//! Default bind is loopback only. No LAN listener is opened unless the operator
//! passes an explicit address, and this foundation still provides no control or
//! media authority (B03/RD03 proofs pending).

use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

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
    /// Explicit schema-versioned migration with a consistent pre-migration backup.
    /// Never runs automatically on startup.
    Migrate {
        /// Directory for the pre-migration database backup.
        #[arg(long, default_value = "./hs-server-backups")]
        backup_dir: PathBuf,
    },
    /// Consume the single-use bootstrap token to create the first administrator.
    Bootstrap {
        /// Bootstrap token from `hs-server init` (or HS_BOOTSTRAP_TOKEN).
        #[arg(long)]
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
        #[arg(long)]
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
        /// Bind address. Default 127.0.0.1:8787. LAN binds are not authorized
        /// by this foundation build.
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
    },
    /// Serve the HTTPS API over real TLS. Literal loopback only.
    ///
    /// Requires a certificate PEM chain and a private key PEM in a
    /// product-owned private parent/file. This is HTTPS transport only;
    /// a public listener stays unavailable until auth/device/channel/route
    /// gates pass. Windows is explicitly unsupported.
    ServeTls {
        /// Bind address. Default 127.0.0.1:8920. Nonloopback is refused
        /// before any credential, data, or listener effect.
        #[arg(long, default_value = "127.0.0.1:8920")]
        bind: String,
        /// Path to PEM certificate chain (private file, at most 8 certs).
        #[arg(long)]
        tls_cert: PathBuf,
        /// Path to PEM private key (private file, exactly one key).
        #[arg(long)]
        tls_key: PathBuf,
    },
    /// Guided Linux installer backend. Reads bounded versioned JSON from stdin.
    Installer {
        #[command(subcommand)]
        action: InstallerAction,
    },
}

#[derive(Subcommand)]
enum InstallerAction {
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
            // Literal loopback only until LAN admission/security is real.
            hs_server::require_loopback_bind(addr)?;
            let service = open_service(&cli.data)?;
            serve_blocking(addr, service)
        }
        Command::ServeTls {
            bind,
            tls_cert,
            tls_key,
        } => {
            // Order is the trust boundary: reject nonloopback and unsupported
            // platforms, and reject malformed TLS material, BEFORE any
            // credential/data file open, DB creation, or listener bind.
            hs_server::tls::run_serve_tls(&cli.data, &bind, &tls_cert, &tls_key)
        }
        Command::Installer { action } => run_installer(action),
    }
}

fn serve_blocking(addr: SocketAddr, service: Arc<Service>) -> AppResult<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| hs_server::AppError::internal(format!("tokio runtime: {err}")))?;

    runtime.block_on(async move {
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

#[cfg(not(target_os = "linux"))]
fn run_installer(_action: InstallerAction) -> AppResult<()> {
    Err(hs_server::AppError::unprocessable(format!(
        "installer requires a Linux host (running on {})",
        std::env::consts::OS
    )))
}

#[cfg(target_os = "linux")]
fn run_installer(action: InstallerAction) -> AppResult<()> {
    use hs_server::installer::machine;
    use hs_server::installer::models::*;

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
        InstallerAction::Preflight => {
            let input: PreflightInput = serde_json::from_str(&stdin_buf).map_err(|err| {
                hs_server::AppError::bad_request(format!("invalid preflight input: {err}"))
            })?;
            let result = machine::preflight(&adapter, &input)?;
            serde_json::to_value(result).map_err(|err| {
                hs_server::AppError::internal(format!("serialize preflight result: {err}"))
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

#[cfg(target_os = "linux")]
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
