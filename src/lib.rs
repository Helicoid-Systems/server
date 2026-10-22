//! HS coordination server foundation.
//!
//! Independently buildable Rust service providing local accounts, single-use
//! bootstrap, manager enrollment distinct from operator auth, scoped inventory,
//! and explicit security-state-unavailable behavior. Plain HTTP and default
//! HTTPS are loopback-only; explicitly enabled TLS uses a v2-only network
//! router. Deployment and media/control acceptance remain pending.

pub mod admission;
pub mod audit;
pub mod auth_v2;
pub mod authority_cutover;
pub mod backup;
pub mod crypto;
pub mod db;
pub mod endpoint_auth;
pub mod error;
pub mod file_jobs;
pub mod file_requests;
pub mod http;
pub mod installer;
pub mod interactions;
pub mod models;
pub mod private_file;
#[cfg(windows)]
mod private_file_windows;
pub mod service;
pub mod tls;

pub use error::{AppError, AppResult};
pub use service::{AuthContext, EndpointAuthContext, SecurityState, Service};

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

/// Open the store and wrap it in a shared service.
pub fn open_service(db_path: &Path) -> AppResult<Arc<Service>> {
    let db = db::open(db_path)?;
    Ok(Arc::new(Service::new(db)))
}

/// Build an HTTP router bound to the service.
pub fn app(service: Arc<Service>) -> axum::Router {
    http::router(service)
}

/// Build the v2-only router for an explicitly enabled TLS network listener.
pub fn network_app(service: Arc<Service>) -> axum::Router {
    http::network_router(service)
}

/// Literal loopback only for plaintext/development listeners.
pub fn require_loopback_bind(addr: SocketAddr) -> AppResult<()> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(AppError::bad_request(
            "refusing non-loopback plaintext bind; use serve-tls with explicit network opt-in",
        ))
    }
}
