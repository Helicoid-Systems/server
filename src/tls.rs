//! Real HTTPS transport prerequisite (loopback only).
//!
//! Trust boundary: TLS private material must be loaded only from a
//! product-owned private parent/file through a validated held descriptor,
//! and a non-loopback bind must be refused **before** any credential, data,
//! or listener effect. Malformed, mismatched, duplicate, or oversize TLS
//! files are rejected before binding and before the store is opened.
//!
//! This is HTTPS *transport* only. A public listener remains unavailable
//! until complete auth/device/channel/route gates pass; no v1/bootstrap or
//! setup UI is exposed publicly here. Literal-loopback serve-tls is available
//! on Unix and Windows through the native-verified private_file held reader;
//! all other platforms remain explicitly unsupported.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::private_file;

/// Default literal-loopback bind for `serve-tls`.
pub const DEFAULT_TLS_BIND: &str = "127.0.0.1:8920";

/// Hard bound on certificate-chain PEM and private-key PEM bytes.
pub const MAX_TLS_PEM_BYTES: usize = 64 * 1024;

/// Maximum number of certificates in a PEM chain.
pub const MAX_TLS_CERT_CHAIN: usize = 8;

/// Bounded TLS handshake timeout (stalled clients are dropped).
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounded graceful shutdown drain.
pub const TLS_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// ALPN protocols served: HTTP/2 first, then HTTP/1.1. Set explicitly;
/// never a permissive or empty fallback.
const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// True when this platform has a verified private credential boundary for
/// TLS material. Unix and Windows qualify through the native-verified
/// private_file held reader (no path reopen, held descriptor, bounded
/// zeroized reads). All other platforms remain explicitly unsupported.
pub fn tls_transport_supported() -> bool {
    cfg!(any(unix, windows))
}

/// Validated listener + server TLS configuration.
#[derive(Clone)]
pub struct TlsTransport {
    addr: SocketAddr,
    config: axum_server::tls_rustls::RustlsConfig,
}

impl TlsTransport {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn config(&self) -> axum_server::tls_rustls::RustlsConfig {
        self.config.clone()
    }
}

/// Validate bind address, platform support, and TLS material **before** any
/// store open or listener bind.
///
/// Order is intentional:
/// 1. parse bind
/// 2. literal-loopback guard (reject nonloopback before any file open)
/// 3. platform refusal (Windows before data/key reads)
/// 4. held-file reads of cert/key + PEM parse/bind checks
pub fn validate_serve_tls_inputs(
    bind: &str,
    cert_path: &Path,
    key_path: &Path,
) -> AppResult<TlsTransport> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|err| AppError::bad_request(format!("invalid bind address: {err}")))?;
    crate::require_loopback_bind(addr)?;

    if !tls_transport_supported() {
        return Err(AppError::not_implemented(
            "HTTPS transport is not supported on this platform; \
             refusing serve-tls without a native-verified private credential boundary. \
             Unix and Windows verified; all other platforms explicitly unsupported.",
        ));
    }

    let server_config = load_server_config(cert_path, key_path)?;
    let config = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
    Ok(TlsTransport { addr, config })
}

/// Full `serve-tls` entry used by the CLI. Validates bind/platform/TLS
/// before any store open or listener bind, then opens the store and serves
/// with a bounded handshake timeout and bounded graceful shutdown.
pub fn run_serve_tls(data: &Path, bind: &str, cert_path: &Path, key_path: &Path) -> AppResult<()> {
    let transport = validate_serve_tls_inputs(bind, cert_path, key_path)?;
    let service = crate::open_service(data)?;
    serve_blocking(transport, service)
}

/// Serve the existing router over real TLS on a literal-loopback listener.
pub fn serve_blocking(
    transport: TlsTransport,
    service: Arc<crate::service::Service>,
) -> AppResult<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| AppError::internal(format!("tokio runtime: {err}")))?;

    runtime.block_on(async move {
        let app = crate::app(service);
        let addr = transport.addr();
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|err| AppError::internal(format!("bind {addr}: {err}")))?;
        tracing::info!(%addr, "hs-server listening (HTTPS, loopback prerequisite)");
        let acceptor = axum_server::tls_rustls::RustlsAcceptor::new(transport.config())
            .handshake_timeout(TLS_HANDSHAKE_TIMEOUT);
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown requested");
            shutdown_handle.graceful_shutdown(Some(TLS_SHUTDOWN_TIMEOUT));
        });
        axum_server::from_tcp(
            listener
                .into_std()
                .map_err(|err| AppError::internal(format!("tcp std listener: {err}")))?,
        )
        .map_err(|err| AppError::internal(format!("tls listener: {err}")))?
        .acceptor(acceptor)
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .map_err(|err| AppError::internal(format!("serve-tls: {err}")))?;
        Ok(())
    })
}

/// Load certificate chain and private key PEM through held descriptors and
/// build an explicit-provider rustls [`rustls::ServerConfig`].
///
/// TLS1.2 is the minimum and TLS1.3 is preferred (version list order).
/// There is no plaintext fallback and no permissive verifier. App-owned PEM
/// and DER copies of private material are held in [`zeroize::Zeroizing`]
/// and cleared on drop (including parse/refusal paths). Diagnostics never
/// include key or certificate contents.
pub fn load_server_config(
    cert_path: &Path,
    key_path: &Path,
) -> AppResult<Arc<rustls::ServerConfig>> {
    // Both materials must sit in a product-owned private parent/file.
    // The held-file reader enforces that on the verified descriptor and
    // returns a Zeroizing buffer so partial reads are cleared on drop.
    let cert_pem = private_file::read_existing_private_file(cert_path, MAX_TLS_PEM_BYTES)?;
    let key_pem = private_file::read_existing_private_file(key_path, MAX_TLS_PEM_BYTES)?;

    let (certs, key) = parse_tls_pem(&cert_pem, &key_pem)?;
    build_server_config(certs, key)
}

/// Wrap a freshly parsed private key so the DER bytes are cleared on drop
/// (`PrivateKeyDer` implements `Zeroize` but not `Drop`/`ZeroizeOnDrop`).
fn guard_key(
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Zeroizing<rustls::pki_types::PrivateKeyDer<'static>> {
    Zeroizing::new(key)
}

/// PEM bounds: chain certificates `1..=MAX_TLS_CERT_CHAIN`, exactly one
/// private key. Rejects malformed, empty, or duplicate keys before binding.
/// Every parsed private key (including a wrong key item in the certificate
/// file) is placed in [`Zeroizing`] immediately so refusal paths clear it.
fn parse_tls_pem(
    mut cert_pem: &[u8],
    mut key_pem: &[u8],
) -> AppResult<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    Zeroizing<rustls::pki_types::PrivateKeyDer<'static>>,
)> {
    let mut certs = Vec::new();
    for item in rustls_pemfile::read_all(&mut cert_pem) {
        match item.map_err(|_| AppError::bad_request("certificate PEM is malformed"))? {
            rustls_pemfile::Item::X509Certificate(cert) => certs.push(cert),
            // Private key material does not belong in the certificate file.
            // Zeroize the refused item before returning.
            rustls_pemfile::Item::Pkcs1Key(key) => {
                let _guarded = guard_key(rustls::pki_types::PrivateKeyDer::from(key));
                return Err(AppError::bad_request(
                    "certificate PEM must contain only X.509 certificates",
                ));
            }
            rustls_pemfile::Item::Pkcs8Key(key) => {
                let _guarded = guard_key(rustls::pki_types::PrivateKeyDer::from(key));
                return Err(AppError::bad_request(
                    "certificate PEM must contain only X.509 certificates",
                ));
            }
            rustls_pemfile::Item::Sec1Key(key) => {
                let _guarded = guard_key(rustls::pki_types::PrivateKeyDer::from(key));
                return Err(AppError::bad_request(
                    "certificate PEM must contain only X.509 certificates",
                ));
            }
            _ => {
                return Err(AppError::bad_request(
                    "certificate PEM must contain only X.509 certificates",
                ))
            }
        }
    }
    if certs.is_empty() {
        return Err(AppError::bad_request(
            "certificate PEM contains no certificates",
        ));
    }
    if certs.len() > MAX_TLS_CERT_CHAIN {
        return Err(AppError::bad_request(format!(
            "certificate chain exceeds {MAX_TLS_CERT_CHAIN} certificates"
        )));
    }

    // Guarded owner for every parsed key; refusal drops zeroize the set.
    let mut keys: Vec<Zeroizing<rustls::pki_types::PrivateKeyDer<'static>>> = Vec::new();
    for item in rustls_pemfile::read_all(&mut key_pem) {
        match item.map_err(|_| AppError::bad_request("private key PEM is malformed"))? {
            rustls_pemfile::Item::Pkcs1Key(key) => {
                keys.push(guard_key(rustls::pki_types::PrivateKeyDer::from(key)))
            }
            rustls_pemfile::Item::Pkcs8Key(key) => {
                keys.push(guard_key(rustls::pki_types::PrivateKeyDer::from(key)))
            }
            rustls_pemfile::Item::Sec1Key(key) => {
                keys.push(guard_key(rustls::pki_types::PrivateKeyDer::from(key)))
            }
            // Non-key sections (and any future Item variants) are refused.
            _ => {
                return Err(AppError::bad_request(
                    "private key PEM must contain exactly one private key and no other sections",
                ))
            }
        }
    }
    if keys.len() != 1 {
        // Zeroizing drop clears zero or duplicate key material.
        return Err(AppError::bad_request(
            "private key PEM must contain exactly one private key",
        ));
    }
    let key = keys.into_iter().next().ok_or_else(|| {
        AppError::bad_request("private key PEM must contain exactly one private key")
    })?;

    Ok((certs, key))
}

/// Build a rustls server config with an explicit crypto provider, TLS1.2
/// minimum / TLS1.3 preferred, explicit ALPN, and no client auth.
///
/// Key/cert binding and TLS signatures stay in the maintained rustls/aws-lc-rs
/// path: `any_supported_type` borrows the guarded DER, `CertifiedKey::keys_match`
/// enforces SPKI consistency, and `SingleCertAndKey` is the maintained
/// resolver. The app-owned DER is dropped (zeroized) only after the provider
/// has accepted it; it is never transferred into `with_single_cert` or cloned.
fn build_server_config(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: Zeroizing<rustls::pki_types::PrivateKeyDer<'static>>,
) -> AppResult<Arc<rustls::ServerConfig>> {
    // Explicit provider: never install a process-global permissive default.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    // Borrow the guarded DER; the provider copies into its own signing key.
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).map_err(|_| {
        AppError::bad_request("TLS private key is not supported by the crypto provider")
    })?;
    // Clear app-owned DER immediately after the maintained provider accepted it.
    drop(key);

    let certified_key = rustls::sign::CertifiedKey::new(certs, signing_key);
    certified_key.keys_match().map_err(|_| {
        AppError::bad_request(
            "TLS certificate/private key binding failed (mismatched or invalid material)",
        )
    })?;
    let resolver = Arc::new(rustls::sign::SingleCertAndKey::from(certified_key));

    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|err| AppError::bad_request(format!("tls protocol versions: {err}")))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    // ALPN is set explicitly (axum_server::from_config requires this).
    config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(config))
}
