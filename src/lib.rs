//! HS coordination server foundation.
//!
//! Independently buildable Rust service providing local accounts, single-use
//! bootstrap, manager enrollment distinct from operator auth, scoped inventory,
//! and explicit security-state-unavailable behavior. Loopback-only by default;
//! no production LAN/control/media authority (see BUILD-REPORT.md).

pub mod auth_v2;
pub mod crypto;
pub mod db;
pub mod error;
pub mod http;
pub mod installer;
pub mod models;
pub mod service;

pub use error::{AppError, AppResult};
pub use service::{AuthContext, SecurityState, Service};

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

/// Literal loopback only. Non-loopback binds are refused until LAN admission
/// and security are real (B03/RD03).
pub fn require_loopback_bind(addr: SocketAddr) -> AppResult<()> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(AppError::bad_request(
            "refusing non-loopback bind address; literal loopback only until LAN admission and security are real",
        ))
    }
}
