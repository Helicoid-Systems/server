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
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|err| {
                hs_server::AppError::bad_request(format!("read password stdin: {err}"))
            })?;
        let password = buffer.trim_end_matches(['\n', '\r']).to_string();
        if password.is_empty() {
            return Err(hs_server::AppError::bad_request(
                "password on stdin was empty",
            ));
        }
        return Ok(password);
    }
    if let Some(password) = cli_value {
        return Ok(password);
    }
    Err(hs_server::AppError::bad_request(
        "missing password: use --password-stdin or --password",
    ))
}
