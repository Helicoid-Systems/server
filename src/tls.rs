//! Real HTTPS transport for loopback development and explicit v2 network use.
//!
//! Trust boundary: TLS private material must be loaded only from a
//! owner-private parent/file through a validated held descriptor,
//! Non-loopback binds require an explicit CLI opt-in and use a v2-only router.
//! Malformed, mismatched, duplicate, or oversize TLS files are rejected
//! before binding and before the store is opened.
//! Installer preflight can also require the leaf certificate to cover the
//! configured DNS name or IP; this subject-name check does not establish CA
//! trust or validate the certificate chain.
//!
//! TLS is mandatory for network binds. The network router excludes all v1
//! routes and keeps versioned bootstrap, endpoint enrollment, and auth-v2
//! operations behind their own token, proof, and authorization checks.
//! Literal-loopback serve-tls remains the default. Unix and Windows use the
//! native-verified private_file held reader; other platforms remain unsupported.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sha2::Digest;
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
    network_routes: bool,
    certificate_sha256: String,
}

impl TlsTransport {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn config(&self) -> axum_server::tls_rustls::RustlsConfig {
        self.config.clone()
    }

    pub fn serves_network_routes(&self) -> bool {
        self.network_routes
    }

    /// Digest of the exact validated public certificate-chain PEM bytes.
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }
}

/// Validate bind address, platform support, and TLS material **before** any
/// store open or listener bind.
///
/// Order is intentional:
/// 1. parse bind
/// 2. require explicit opt-in for nonloopback addresses
/// 3. platform refusal before TLS or store reads
/// 4. held-file reads of cert/key + PEM parse/bind checks
pub fn validate_serve_tls_inputs(
    bind: &str,
    cert_path: &Path,
    key_path: &Path,
) -> AppResult<TlsTransport> {
    validate_serve_tls_inputs_with_network(bind, cert_path, key_path, false)
}

/// Validate TLS material and an explicit network-listener opt-in before any
/// store open. Non-loopback address values are rejected unless the operator
/// passed the opt-in flag; those listeners receive only the v2 router.
pub fn validate_serve_tls_inputs_with_network(
    bind: &str,
    cert_path: &Path,
    key_path: &Path,
    allow_network: bool,
) -> AppResult<TlsTransport> {
    validate_serve_tls_inputs_with_network_and_name(bind, cert_path, key_path, allow_network, None)
}

/// Validate TLS material and require the leaf certificate to cover the
/// expected DNS name or IP address. Used by installers when their exported
/// client endpoint is known before service apply.
pub fn validate_serve_tls_inputs_with_network_and_name(
    bind: &str,
    cert_path: &Path,
    key_path: &Path,
    allow_network: bool,
    expected_server_name: Option<&str>,
) -> AppResult<TlsTransport> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|err| AppError::bad_request(format!("invalid bind address: {err}")))?;
    if !addr.ip().is_loopback() && !allow_network {
        crate::require_loopback_bind(addr)?;
    }

    if !tls_transport_supported() {
        return Err(AppError::not_implemented(
            "HTTPS transport is not supported on this platform; \
             refusing serve-tls without a native-verified private credential boundary. \
             Unix and Windows verified; all other platforms explicitly unsupported.",
        ));
    }

    let (server_config, certificate_sha256) =
        load_server_config_with_digest_and_name(cert_path, key_path, expected_server_name)?;
    let config = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
    let network_routes = !addr.ip().is_loopback();
    Ok(TlsTransport {
        addr,
        config,
        network_routes,
        certificate_sha256,
    })
}

/// Full `serve-tls` entry used by the CLI. Validates bind/platform/TLS
/// before any store open or listener bind, then opens the store and serves
/// with a bounded handshake timeout and bounded graceful shutdown.
pub fn run_serve_tls(data: &Path, bind: &str, cert_path: &Path, key_path: &Path) -> AppResult<()> {
    run_serve_tls_with_network(data, bind, cert_path, key_path, false)
}

/// Network listener entry used only when the operator explicitly enables it.
/// Input validation still precedes opening the database or binding the socket.
pub fn run_serve_tls_with_network(
    data: &Path,
    bind: &str,
    cert_path: &Path,
    key_path: &Path,
    allow_network: bool,
) -> AppResult<()> {
    let transport =
        validate_serve_tls_inputs_with_network(bind, cert_path, key_path, allow_network)?;
    let service = crate::open_service(data)?;
    serve_blocking(transport, service)
}

/// Run the loopback development API beside the v2-only TLS network API.
/// Input validation and TLS loading happen before the database is opened.
pub fn run_serve_dual(
    data: &Path,
    local_bind: &str,
    network_bind: &str,
    cert_path: &Path,
    key_path: &Path,
    allow_network: bool,
) -> AppResult<()> {
    if !allow_network {
        return Err(AppError::bad_request(
            "serve-dual requires the explicit --allow-network option",
        ));
    }
    let local_addr: SocketAddr = local_bind
        .parse()
        .map_err(|err| AppError::bad_request(format!("invalid local bind address: {err}")))?;
    crate::require_loopback_bind(local_addr)?;
    let network_addr: SocketAddr = network_bind
        .parse()
        .map_err(|err| AppError::bad_request(format!("invalid network bind address: {err}")))?;
    if network_addr.ip().is_loopback() {
        return Err(AppError::bad_request(
            "serve-dual requires a nonloopback network TLS bind address",
        ));
    }
    if local_addr.port() == 0 || network_addr.port() == 0 {
        return Err(AppError::bad_request(
            "serve-dual listener ports must be nonzero",
        ));
    }
    if local_addr.port() == network_addr.port() {
        return Err(AppError::bad_request(
            "local and network listeners must use different ports",
        ));
    }
    let transport =
        validate_serve_tls_inputs_with_network(network_bind, cert_path, key_path, true)?;

    let service = crate::open_service(data)?;
    serve_dual_blocking(local_addr, transport, service)
}

/// Serve the selected loopback or v2-only network router over real TLS.
pub fn serve_blocking(
    transport: TlsTransport,
    service: Arc<crate::service::Service>,
) -> AppResult<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| AppError::internal(format!("tokio runtime: {err}")))?;

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
        let network_routes = transport.serves_network_routes();
        let app = if network_routes {
            crate::network_app(service)
        } else {
            crate::app(service)
        };
        let addr = transport.addr();
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|err| AppError::internal(format!("bind {addr}: {err}")))?;
        tracing::info!(%addr, network_routes, "hs-server listening over HTTPS");
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

/// Serve both local development management and network TLS APIs from one
/// shared service. The HTTP router is bound only to a literal loopback address;
/// the network listener uses the v2-only router.
fn serve_dual_blocking(
    local_addr: SocketAddr,
    transport: TlsTransport,
    service: Arc<crate::service::Service>,
) -> AppResult<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| AppError::internal(format!("tokio runtime: {err}")))?;

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

        let local_listener = tokio::net::TcpListener::bind(local_addr)
            .await
            .map_err(|err| AppError::internal(format!("bind local {local_addr}: {err}")))?;
        let network_listener = tokio::net::TcpListener::bind(transport.addr())
            .await
            .map_err(|err| {
                AppError::internal(format!("bind network {}: {err}", transport.addr()))
            })?;
        let network_listener = network_listener
            .into_std()
            .map_err(|err| AppError::internal(format!("network tcp std listener: {err}")))?;
        let local_app = crate::app(service.clone());
        let network_app = crate::network_app(service);
        let network_handle = axum_server::Handle::new();
        let tls_acceptor = axum_server::tls_rustls::RustlsAcceptor::new(transport.config())
            .handshake_timeout(TLS_HANDSHAKE_TIMEOUT);
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let mut local_shutdown_rx = shutdown_tx.subscribe();
        let local_shutdown = async move {
            if !*local_shutdown_rx.borrow() {
                let _ = local_shutdown_rx.changed().await;
            }
        };
        let local_server = async move {
            axum::serve(local_listener, local_app)
                .with_graceful_shutdown(local_shutdown)
                .await
        };
        let network_server = axum_server::from_tcp(network_listener)
            .map_err(|err| AppError::internal(format!("tls listener: {err}")))?
            .acceptor(tls_acceptor)
            .handle(network_handle.clone())
            .serve(network_app.into_make_service());
        tokio::pin!(local_server);
        tokio::pin!(network_server);

        tracing::info!(%local_addr, network_addr = %transport.addr(),
            "hs-server listening on loopback HTTP and v2-only network HTTPS");
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|err| AppError::internal(format!("wait for shutdown signal: {err}")))?;
                tracing::info!("shutdown requested");
                let _ = shutdown_tx.send(true);
                network_handle.graceful_shutdown(Some(TLS_SHUTDOWN_TIMEOUT));
                let (local_result, network_result) = tokio::time::timeout(
                    TLS_SHUTDOWN_TIMEOUT,
                    async { tokio::join!(local_server, network_server) },
                )
                .await
                .map_err(|_| AppError::internal("dual-listener shutdown timed out"))?;
                local_result.map_err(|err| AppError::internal(format!("serve local: {err}")))?;
                network_result.map_err(|err| AppError::internal(format!("serve network TLS: {err}")))?;
                Ok(())
            }
            result = &mut local_server => {
                let _ = shutdown_tx.send(true);
                network_handle.graceful_shutdown(Some(TLS_SHUTDOWN_TIMEOUT));
                result.map_err(|err| AppError::internal(format!("serve local: {err}")))?;
                tokio::time::timeout(TLS_SHUTDOWN_TIMEOUT, &mut network_server)
                    .await
                    .map_err(|_| AppError::internal("network listener shutdown timed out"))?
                    .map_err(|err| AppError::internal(format!("serve network TLS: {err}")))?;
                Ok(())
            }
            result = &mut network_server => {
                let _ = shutdown_tx.send(true);
                result.map_err(|err| AppError::internal(format!("serve network TLS: {err}")))?;
                tokio::time::timeout(TLS_SHUTDOWN_TIMEOUT, &mut local_server)
                    .await
                    .map_err(|_| AppError::internal("local listener shutdown timed out"))?
                    .map_err(|err| AppError::internal(format!("serve local: {err}")))?;
                Ok(())
            }
        }
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
    load_server_config_with_digest(cert_path, key_path).map(|(config, _)| config)
}

fn load_server_config_with_digest(
    cert_path: &Path,
    key_path: &Path,
) -> AppResult<(Arc<rustls::ServerConfig>, String)> {
    load_server_config_with_digest_and_name(cert_path, key_path, None)
}

fn load_server_config_with_digest_and_name(
    cert_path: &Path,
    key_path: &Path,
    expected_server_name: Option<&str>,
) -> AppResult<(Arc<rustls::ServerConfig>, String)> {
    // Both materials must sit in a private parent/file owned by the process.
    // The held-file reader enforces that on the verified descriptor and
    // returns a Zeroizing buffer so partial reads are cleared on drop.
    let cert_pem = private_file::read_existing_private_file(cert_path, MAX_TLS_PEM_BYTES)?;
    let key_pem = private_file::read_existing_private_file(key_path, MAX_TLS_PEM_BYTES)?;

    let certificate_sha256 = format!("{:x}", sha2::Sha256::digest(&cert_pem));
    let (certs, key) = parse_tls_pem(&cert_pem, &key_pem)?;
    if let Some(expected_server_name) = expected_server_name {
        validate_certificate_name(&certs, expected_server_name)?;
    }
    Ok((build_server_config(certs, key)?, certificate_sha256))
}

fn validate_certificate_name(
    certs: &[rustls::pki_types::CertificateDer<'static>],
    expected_server_name: &str,
) -> AppResult<()> {
    let leaf_der = certs
        .first()
        .ok_or_else(|| AppError::bad_request("certificate PEM contains no certificates"))?;
    let leaf_der = rustls::pki_types::CertificateDer::from(leaf_der.as_ref());
    let leaf = webpki::EndEntityCert::try_from(&leaf_der).map_err(|_| {
        AppError::bad_request("TLS leaf certificate is invalid for the configured Manager endpoint")
    })?;
    let server_name = rustls::pki_types::ServerName::try_from(expected_server_name)
        .map_err(|_| AppError::bad_request("configured Manager hostname or IP is invalid"))?;
    leaf.verify_is_valid_for_subject_name(&server_name)
        .map_err(|_| {
            AppError::bad_request(
                "TLS certificate does not cover the configured Manager hostname or IP",
            )
        })
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
                ));
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
                ));
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
