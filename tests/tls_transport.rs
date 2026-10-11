//! Real HTTPS transport proofs for `serve-tls` and the held-file TLS reader.
//!
//! Platform applicability:
//! - Portable tests (help/default text, required flags, public-bind refusal
//!   with zero DB) run on Unix and Windows.
//! - Unix-only success helpers and genuine TLS socket tests are `cfg(unix)`:
//!   production `load_server_config` / private writer return `NotImplemented`
//!   on Windows, so a fixture that calls `create_new_private_file` cannot
//!   succeed there.
//! - Windows keeps explicit denial tests (library + actual CLI). No
//!   production mock bypass for Windows unsupported private stores.
//!
//! Scope:
//! - Library/fixture socket tests use a short-handshake acceptor built from
//!   `load_server_config` + `axum_server` on a `TcpListener`. They prove
//!   material parsing, loopback gating, and real TLS I/O, **not** the CLI
//!   process wiring or the production 10s handshake constant.
//! - `actual_cli_*` tests spawn the real `hs-server` binary and cover
//!   required flags, default bind text, public refusal with zero DB, and
//!   (Unix) HTTPS `/health` plus bounded SIGINT shutdown.
//!
//! These tests use disposable rcgen-generated certificates written as test
//! fixtures only. No runtime laboratory grant/CA exists in product code.
//! Product apps stay closed; listeners here are literal loopback.

use std::net::SocketAddr;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;

use hs_server::private_file::read_existing_private_file;
#[allow(unused_imports)]
use hs_server::tls::tls_transport_supported;
use hs_server::tls::{self, run_serve_tls};

#[cfg(unix)]
use hs_server::private_file::create_new_private_file;
#[cfg(unix)]
use hs_server::tls::{
    load_server_config, MAX_TLS_CERT_CHAIN, MAX_TLS_PEM_BYTES, TLS_HANDSHAKE_TIMEOUT,
    TLS_SHUTDOWN_TIMEOUT,
};
#[cfg(unix)]
use std::sync::Arc;

/// Tempdir forced owner-private (0700) so private-store policy accepts it.
fn private_tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().canonicalize().expect("canonicalize");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    (dir, path)
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

/// Write an existing private file without create-new semantics (for fixtures
/// that must start at a non-0600 mode or empty contents). Unix-only helpers
/// use this; Windows denial tests seed with `std::fs::write`.
#[cfg(unix)]
fn write_fixture(path: &Path, contents: &[u8], mode: u32) {
    std::fs::write(path, contents).expect("write fixture");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod fixture");
}

// ----- disposable rcgen test material (Unix fixtures only) -----

#[cfg(unix)]
struct TestPki {
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

/// Generate a throwaway CA and a server certificate for `sans`.
#[cfg(unix)]
fn test_pki(sans: &[&str]) -> TestPki {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "HS TLS Test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let server_key = KeyPair::generate().expect("server key");
    let server_params =
        CertificateParams::new(sans.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
            .expect("server params");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("sign server");

    TestPki {
        ca_pem: ca_cert.pem(),
        cert_pem: server_cert.pem(),
        key_pem: server_key.serialize_pem(),
    }
}

/// Write cert/key as private files under `base` and return their paths.
#[cfg(unix)]
fn write_tls_material(base: &Path, pki: &TestPki) -> (PathBuf, PathBuf) {
    let cert_path = base.join("server.crt");
    let key_path = base.join("server.key");
    create_new_private_file(&cert_path, pki.cert_pem.as_bytes()).expect("write cert");
    create_new_private_file(&key_path, pki.key_pem.as_bytes()).expect("write key");
    (cert_path, key_path)
}

// ----- held-file reader refusals (no path re-open after verify) -----

#[cfg(unix)]
#[test]
fn held_file_reads_same_verified_descriptor() {
    let (_dir, base) = private_tempdir();
    let path = base.join("material.pem");
    create_new_private_file(&path, b"PRIVATE-MATERIAL").expect("create");
    assert_eq!(mode_of(&path), 0o600, "fixture must be owner-only");
    let got = read_existing_private_file(&path, 1024).expect("read");
    assert_eq!(&got[..], &b"PRIVATE-MATERIAL"[..]);
}

#[cfg(unix)]
#[test]
fn held_file_refuses_symlink_without_reading_target() {
    let (_dir, base) = private_tempdir();
    let target = base.join("target.pem");
    std::fs::write(&target, b"TARGET-SECRET").expect("target");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let link = base.join("link.pem");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let err = read_existing_private_file(&link, 1024).expect_err("must refuse symlink");
    let msg = err.to_string();
    assert!(
        msg.contains("symlink")
            || msg.contains("symbolic")
            || msg.contains("not a regular file")
            || msg.contains("refusing"),
        "msg={msg}"
    );
    assert!(
        !msg.contains("TARGET-SECRET"),
        "error must not include file contents"
    );
}

#[cfg(unix)]
#[test]
fn held_file_refuses_fifo_without_hang() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt;
    let (_dir, base) = private_tempdir();
    let path = base.join("fifo.pem");
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("cstr");
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo");
    let err = read_existing_private_file(&path, 1024).expect_err("must refuse FIFO");
    let msg = err.to_string();
    assert!(
        msg.contains("not a regular file") || msg.contains("refusing"),
        "msg={msg}"
    );
    let meta = std::fs::symlink_metadata(&path).expect("fifo meta");
    assert!(meta.file_type().is_fifo(), "FIFO preserved");
}

#[cfg(unix)]
#[test]
fn held_file_refuses_bad_permissions() {
    let (_dir, base) = private_tempdir();
    let path = base.join("world-readable.pem");
    write_fixture(&path, b"NOT-PRIVATE", 0o644);
    let err = read_existing_private_file(&path, 1024).expect_err("must refuse 0644");
    let msg = err.to_string();
    assert!(
        msg.contains("private") || msg.contains("permissions") || msg.contains("refusing"),
        "msg={msg}"
    );
    assert!(!msg.contains("NOT-PRIVATE"));
}

#[cfg(unix)]
#[test]
fn held_file_refuses_hardlink() {
    let (_dir, base) = private_tempdir();
    let path = base.join("linked.pem");
    create_new_private_file(&path, b"LINKED-SECRET").expect("create");
    let extra = base.join("extra-link.pem");
    std::fs::hard_link(&path, &extra).expect("hard link");
    let err = read_existing_private_file(&path, 1024).expect_err("must refuse nlink!=1");
    let msg = err.to_string();
    assert!(
        msg.contains("link count") || msg.contains("refusing"),
        "msg={msg}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn held_file_refuses_unsafe_allow_acl() {
    // Attach an everyone-allow ACL; existing objects are never mutated, so
    // the reader must refuse before returning contents.
    let (_dir, base) = private_tempdir();
    let path = base.join("acl.pem");
    create_new_private_file(&path, b"ACL-SECRET").expect("create");
    add_everyone_allow_read_acl(&path);
    let err = read_existing_private_file(&path, 1024).expect_err("must refuse allow ACL");
    let msg = err.to_string();
    assert!(
        msg.contains("ACL") || msg.contains("acl") || msg.contains("refusing"),
        "msg={msg}"
    );
    assert!(!msg.contains("ACL-SECRET"));
}

#[cfg(unix)]
#[test]
fn held_file_refuses_oversize_before_return() {
    let (_dir, base) = private_tempdir();
    let path = base.join("big.pem");
    let big = vec![0x41u8; 4096];
    create_new_private_file(&path, &big).expect("create");
    let err = read_existing_private_file(&path, 1024).expect_err("must refuse oversize");
    let msg = err.to_string();
    assert!(msg.contains("exceeds"), "msg={msg}");
}

#[cfg(unix)]
#[test]
fn held_file_missing_path_is_refused() {
    let (_dir, base) = private_tempdir();
    let err = read_existing_private_file(&base.join("nope.pem"), 1024).expect_err("missing");
    let _ = err;
}

#[cfg(windows)]
#[test]
fn windows_held_file_read_refuses_public_file_and_reads_private() {
    let (_dir, base) = private_tempdir();
    let public_path = base.join("public.pem");
    std::fs::write(&public_path, b"PUBLIC").expect("seed");
    let err =
        read_existing_private_file(&public_path, 1024).expect_err("must refuse non-private file");
    let msg = err.to_string();
    assert!(
        msg.contains("not owned") || msg.contains("refusing") || msg.contains("private"),
        "msg={msg}"
    );
    assert!(!msg.contains("PUBLIC"));

    let private_path = base.join("material.pem");
    create_new_private_file(&private_path, b"PRIVATE-MATERIAL").expect("create private");
    let got = read_existing_private_file(&private_path, 1024).expect("read private");
    assert_eq!(got.as_slice(), b"PRIVATE-MATERIAL");
}

// ----- TLS PEM bounds and binding (before any listener/DB) -----

#[cfg(unix)]
#[test]
fn load_rejects_missing_files_without_db() {
    let (_dir, base) = private_tempdir();
    let data = base.join("hs-server.db");
    let cert = base.join("missing.crt");
    let key = base.join("missing.key");
    let err = run_serve_tls(&data, "127.0.0.1:8920", &cert, &key).expect_err("must refuse");
    let _ = err;
    assert!(
        !data.exists(),
        "DB must not be created on missing TLS files"
    );
}

#[cfg(unix)]
#[test]
fn load_rejects_oversize_material_without_db() {
    let (_dir, base) = private_tempdir();
    let data = base.join("hs-server.db");
    let cert = base.join("big.crt");
    let key = base.join("big.key");
    let big = vec![b'A'; MAX_TLS_PEM_BYTES + 1];
    write_fixture(&cert, &big, 0o600);
    write_fixture(&key, &big, 0o600);
    let err =
        run_serve_tls(&data, "127.0.0.1:8920", &cert, &key).expect_err("must refuse oversize");
    let msg = err.to_string();
    assert!(msg.contains("exceeds"), "msg={msg}");
    assert!(
        !data.exists(),
        "DB must not be created on oversize TLS files"
    );
}

#[cfg(unix)]
#[test]
fn load_rejects_empty_certificate_pem_without_db() {
    let (_dir, base) = private_tempdir();
    let data = base.join("hs-server.db");
    let pki = test_pki(&["localhost"]);
    let cert = base.join("empty.crt");
    let key = base.join("server.key");
    // Cert file holds no certificates.
    write_fixture(
        &cert,
        b"-----BEGIN NOTES-----\nnot-a-cert\n-----END NOTES-----\n",
        0o600,
    );
    create_new_private_file(&key, pki.key_pem.as_bytes()).expect("key");
    let err = run_serve_tls(&data, "127.0.0.1:8920", &cert, &key).expect_err("must refuse");
    let msg = err.to_string();
    assert!(
        msg.contains("no certificates") || msg.contains("malformed") || msg.contains("only"),
        "msg={msg}"
    );
    assert!(!data.exists());
}

#[cfg(unix)]
#[test]
fn load_rejects_chain_longer_than_bound() {
    let (_dir, base) = private_tempdir();
    let data = base.join("hs-server.db");
    let pki = test_pki(&["localhost"]);
    let cert = base.join("long.crt");
    let key = base.join("server.key");
    let mut chain = String::new();
    for _ in 0..(MAX_TLS_CERT_CHAIN + 1) {
        chain.push_str(&pki.cert_pem);
    }
    write_fixture(&cert, chain.as_bytes(), 0o600);
    create_new_private_file(&key, pki.key_pem.as_bytes()).expect("key");
    let err = run_serve_tls(&data, "127.0.0.1:8920", &cert, &key).expect_err("must refuse chain");
    let msg = err.to_string();
    assert!(
        msg.contains("exceeds") && msg.contains("certificate"),
        "msg={msg}"
    );
    assert!(!data.exists());
}

#[cfg(unix)]
#[test]
fn load_rejects_duplicate_keys() {
    let (_dir, base) = private_tempdir();
    let data = base.join("hs-server.db");
    let pki = test_pki(&["localhost"]);
    let other = test_pki(&["localhost"]);
    let cert = base.join("server.crt");
    let key = base.join("dup.key");
    let mut keys = String::new();
    keys.push_str(&pki.key_pem);
    keys.push_str(&other.key_pem);
    create_new_private_file(&cert, pki.cert_pem.as_bytes()).expect("cert");
    write_fixture(&key, keys.as_bytes(), 0o600);
    let err = run_serve_tls(&data, "127.0.0.1:8920", &cert, &key).expect_err("duplicate keys");
    let msg = err.to_string();
    assert!(msg.contains("exactly one private key"), "msg={msg}");
    assert!(!data.exists());
}

#[cfg(unix)]
#[test]
fn load_rejects_zero_keys() {
    let (_dir, base) = private_tempdir();
    let data = base.join("hs-server.db");
    let pki = test_pki(&["localhost"]);
    let cert = base.join("server.crt");
    let key = base.join("nokey.key");
    create_new_private_file(&cert, pki.cert_pem.as_bytes()).expect("cert");
    write_fixture(
        &key,
        b"-----BEGIN NOTES-----\nno key here\n-----END NOTES-----\n",
        0o600,
    );
    let err = run_serve_tls(&data, "127.0.0.1:8920", &cert, &key).expect_err("zero keys");
    let msg = err.to_string();
    assert!(
        msg.contains("exactly one private key") || msg.contains("only"),
        "msg={msg}"
    );
    assert!(!data.exists());
}

#[cfg(unix)]
#[test]
fn load_rejects_mismatched_key_before_db_and_bind() {
    let (_dir, base) = private_tempdir();
    let data = base.join("hs-server.db");
    let pki = test_pki(&["localhost"]);
    let other = test_pki(&["localhost"]);
    let cert = base.join("server.crt");
    let key = base.join("other.key");
    create_new_private_file(&cert, pki.cert_pem.as_bytes()).expect("cert");
    create_new_private_file(&key, other.key_pem.as_bytes()).expect("key");
    let err = run_serve_tls(&data, "127.0.0.1:8920", &cert, &key).expect_err("mismatch");
    let msg = err.to_string();
    assert!(
        msg.contains("binding failed") || msg.contains("mismatched") || msg.contains("invalid"),
        "msg={msg}"
    );
    assert!(
        !msg.contains("PRIVATE") && !msg.contains("BEGIN"),
        "no material in error"
    );
    assert!(!data.exists(), "DB must not be created on mismatched key");
}

#[cfg(unix)]
#[test]
fn public_bind_refuses_before_store_effects() {
    let (_dir, base) = private_tempdir();
    let pki = test_pki(&["localhost"]);
    let (cert, key) = write_tls_material(&base, &pki);
    for bind in [
        "0.0.0.0:8920",
        "192.168.1.10:8920",
        "[::]:8920",
        "127.0.0.1:8920:extra",
    ] {
        let data = base.join(format!("hs-{}.db", bind.replace([':', '[', ']'], "_")));
        let err = run_serve_tls(&data, bind, &cert, &key).expect_err("must refuse public bind");
        let msg = err.to_string();
        if bind.contains("extra") {
            assert!(msg.contains("invalid bind address"), "msg={msg}");
        } else {
            assert!(
                msg.contains("loopback") || msg.contains("non-loopback"),
                "msg={msg}"
            );
        }
        assert!(
            !data.exists(),
            "no DB for refused bind {bind} (data={})",
            data.display()
        );
    }
}

#[cfg(unix)]
#[test]
fn loopback_bind_is_accepted_by_guard_and_material_loads() {
    let (_dir, base) = private_tempdir();
    let pki = test_pki(&["localhost"]);
    let (cert, key) = write_tls_material(&base, &pki);
    let transport =
        tls::validate_serve_tls_inputs("127.0.0.1:8920", &cert, &key).expect("loopback + material");
    assert!(transport.addr().ip().is_loopback());
    assert_eq!(transport.addr().port(), 8920);
}

/// Portable constant check: default bind is literal loopback :8920 on every
/// platform, including Windows (which still refuses serve-tls later).
#[test]
fn default_tls_bind_is_literal_loopback_8920() {
    let addr: SocketAddr = tls::DEFAULT_TLS_BIND.parse().expect("default bind");
    assert!(addr.ip().is_loopback());
    assert_eq!(addr.port(), 8920);
}

#[cfg(windows)]
#[test]
fn windows_serve_tls_refuses_before_data_or_key_reads() {
    let (_dir, base) = private_tempdir();
    assert!(!tls_transport_supported(), "must not claim Windows TLS");
    let data = base.join("hs-server.db");
    let cert = base.join("server.crt");
    let key = base.join("server.key");
    std::fs::write(
        &cert,
        b"-----BEGIN CERTIFICATE-----\nMIIA\n-----END CERTIFICATE-----\n",
    )
    .expect("seed cert");
    std::fs::write(
        &key,
        b"-----BEGIN PRIVATE KEY-----\nMIIA\n-----END PRIVATE KEY-----\n",
    )
    .expect("seed key");
    let err = run_serve_tls(&data, "127.0.0.1:8920", &cert, &key)
        .expect_err("must deny serve-tls on Windows");
    let msg = err.to_string();
    assert!(
        msg.contains("not supported")
            || msg.contains("not implemented")
            || msg.contains("refusing"),
        "msg={msg}"
    );
    assert!(!data.exists(), "no DB on Windows refusal");
    assert!(!msg.contains("MIIA"), "no material in error");
}

// ----- genuine TLS sockets (fixture acceptor; not CLI wiring; Unix-only) -----
// Windows cannot run these: load_server_config / private writer are
// NotImplemented there. Portable and Windows denial coverage lives above
// and in the actual CLI section below.

#[cfg(unix)]
struct TestServer {
    addr: SocketAddr,
    handle: axum_server::Handle<SocketAddr>,
    join: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    _db: tempfile::TempDir,
}

#[cfg(unix)]
async fn spawn_tls_server(base: &Path, pki: &TestPki) -> TestServer {
    let (cert_path, key_path) = write_tls_material(base, pki);
    let server_config = load_server_config(&cert_path, &key_path).expect("load server config");
    let config = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
    let db_dir = tempfile::tempdir().expect("db dir");
    {
        use std::os::unix::fs::PermissionsExt;
        let p = db_dir.path().canonicalize().expect("canonicalize");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let data = db_dir.path().join("hs-server.db");
    let service = hs_server::open_service(&data).expect("open service");
    let app = hs_server::app(service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let std_listener = listener.into_std().expect("std listener");
    std_listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    // Short handshake timeout so stalled-handshake tests stay bounded.
    let acceptor = axum_server::tls_rustls::RustlsAcceptor::new(config)
        .handshake_timeout(Duration::from_secs(2));
    let join = tokio::spawn(async move {
        axum_server::from_tcp(std_listener)?
            .acceptor(acceptor)
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
    });
    TestServer {
        addr,
        handle,
        join,
        _db: db_dir,
    }
}

/// Client config that trusts only the supplied test CA (no OS fallback).
#[cfg(unix)]
fn client_config_for(ca_pem: &str) -> rustls::ClientConfig {
    use rustls::pki_types::pem::PemObject;
    use rustls::RootCertStore;
    let mut roots = RootCertStore::empty();
    let ca = rustls::pki_types::CertificateDer::from_pem_slice(ca_pem.as_bytes())
        .expect("parse test CA");
    roots.add(ca).expect("add test CA");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("client protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[cfg(unix)]
async fn tls_get_health(
    addr: SocketAddr,
    client_config: rustls::ClientConfig,
    server_name: &str,
) -> Result<serde_json::Value, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|err| format!("tcp connect: {err}"))?;
    let connector = TlsConnector::from(Arc::new(client_config));
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|err| format!("server name: {err}"))?;
    let mut tls = connector
        .connect(name, stream)
        .await
        .map_err(|err| format!("tls handshake: {err}"))?;

    let req = format!("GET /health HTTP/1.1\r\nHost: {server_name}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes())
        .await
        .map_err(|err| format!("write request: {err}"))?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf)
        .await
        .map_err(|err| format!("read response: {err}"))?;
    let text = String::from_utf8_lossy(&buf);
    let body_start = text
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .ok_or_else(|| format!("no HTTP body in response: {text:?}"))?;
    if !text.starts_with("HTTP/1.1 2") {
        return Err(format!("non-success status line: {text:?}"));
    }
    let body = &text[body_start..];
    serde_json::from_str(body).map_err(|err| format!("health JSON: {err} body={body:?}"))
}

#[cfg(unix)]
#[tokio::test]
async fn valid_test_ca_hostname_serves_real_health_json() {
    let (_dir, base) = private_tempdir();
    let pki = test_pki(&["localhost", "127.0.0.1"]);
    let server = spawn_tls_server(&base, &pki).await;
    let client = client_config_for(&pki.ca_pem);
    let health = tls_get_health(server.addr, client, "localhost")
        .await
        .expect("health over TLS");
    // Fresh store is degraded until bootstrap; either state is real /health JSON.
    let status = health.get("status").and_then(|v| v.as_str());
    assert!(
        matches!(status, Some("ok") | Some("degraded")),
        "health={health}"
    );
    assert!(
        health
            .get("storage_schema_version")
            .and_then(|v| v.as_i64())
            .is_some(),
        "health must be real JSON from /health: {health}"
    );
    server
        .handle
        .graceful_shutdown(Some(Duration::from_secs(2)));
    let _ = tokio::time::timeout(Duration::from_secs(5), server.join).await;
}

#[cfg(unix)]
#[tokio::test]
async fn foreign_ca_is_refused() {
    let (_dir, base) = private_tempdir();
    let pki = test_pki(&["localhost"]);
    let foreign = test_pki(&["localhost"]);
    let server = spawn_tls_server(&base, &pki).await;
    let client = client_config_for(&foreign.ca_pem);
    let err = tls_get_health(server.addr, client, "localhost")
        .await
        .expect_err("foreign CA must be refused");
    assert!(
        err.contains("tls handshake") || err.contains("certificate") || err.contains("alert"),
        "err={err}"
    );
    server
        .handle
        .graceful_shutdown(Some(Duration::from_secs(2)));
    let _ = tokio::time::timeout(Duration::from_secs(5), server.join).await;
}

#[cfg(unix)]
#[tokio::test]
async fn wrong_hostname_is_refused() {
    let (_dir, base) = private_tempdir();
    // Certificate is only valid for other.example.
    let pki = test_pki(&["other.example"]);
    let server = spawn_tls_server(&base, &pki).await;
    let client = client_config_for(&pki.ca_pem);
    let err = tls_get_health(server.addr, client, "localhost")
        .await
        .expect_err("wrong name must be refused");
    assert!(
        err.contains("tls handshake")
            || err.contains("certificate")
            || err.contains("alert")
            || err.contains("NotValidForName"),
        "err={err}"
    );
    server
        .handle
        .graceful_shutdown(Some(Duration::from_secs(2)));
    let _ = tokio::time::timeout(Duration::from_secs(5), server.join).await;
}

#[cfg(unix)]
#[tokio::test]
async fn plaintext_request_cannot_access_http_body() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (_dir, base) = private_tempdir();
    let pki = test_pki(&["localhost"]);
    let server = spawn_tls_server(&base, &pki).await;

    let mut stream = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("tcp connect");
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write plaintext");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    assert!(
        !text.contains("\"status\"") && !text.contains("accepting_authorized_operations"),
        "plaintext must not reach HTTP body, got: {text:?}"
    );
    assert!(
        !text.starts_with("HTTP/1.1"),
        "plaintext must not receive an HTTP response, got: {text:?}"
    );

    server
        .handle
        .graceful_shutdown(Some(Duration::from_secs(2)));
    let _ = tokio::time::timeout(Duration::from_secs(5), server.join).await;
}

#[cfg(unix)]
#[tokio::test]
async fn stalled_handshake_is_bounded_and_dropped() {
    use tokio::io::AsyncReadExt;

    let (_dir, base) = private_tempdir();
    let pki = test_pki(&["localhost"]);
    let server = spawn_tls_server(&base, &pki).await;

    // Connect and send nothing: the acceptor must drop the stalled handshake
    // within its bounded timeout (2s in this fixture server).
    let mut stream = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("tcp connect");
    let mut buf = [0u8; 16];
    let start = std::time::Instant::now();
    let read = tokio::time::timeout(Duration::from_secs(6), stream.read(&mut buf)).await;
    let elapsed = start.elapsed();
    match read {
        Ok(Ok(0)) => {
            // Server closed the stalled handshake.
        }
        Ok(Ok(n)) => {
            // A TLS alert is also an acceptable bounded close.
            assert!(n > 0, "alert bytes or close");
        }
        Ok(Err(_)) => {}
        Err(_) => panic!("stalled handshake was not closed within bound"),
    }
    assert!(
        elapsed < Duration::from_secs(5),
        "handshake close must be bounded, took {elapsed:?}"
    );
    // Production constant stays a real bound.
    assert!(TLS_HANDSHAKE_TIMEOUT >= Duration::from_secs(1));
    assert!(TLS_HANDSHAKE_TIMEOUT <= Duration::from_secs(30));

    server
        .handle
        .graceful_shutdown(Some(Duration::from_secs(2)));
    let _ = tokio::time::timeout(Duration::from_secs(5), server.join).await;
}

#[cfg(unix)]
#[tokio::test]
async fn graceful_shutdown_is_bounded() {
    let (_dir, base) = private_tempdir();
    let pki = test_pki(&["localhost"]);
    let server = spawn_tls_server(&base, &pki).await;
    let client = client_config_for(&pki.ca_pem);
    let health = tls_get_health(server.addr, client, "localhost")
        .await
        .expect("health before shutdown");
    let status = health.get("status").and_then(|v| v.as_str());
    assert!(
        matches!(status, Some("ok") | Some("degraded")),
        "health={health}"
    );

    let start = std::time::Instant::now();
    server
        .handle
        .graceful_shutdown(Some(TLS_SHUTDOWN_TIMEOUT.min(Duration::from_secs(3))));
    let joined = tokio::time::timeout(Duration::from_secs(8), server.join).await;
    let elapsed = start.elapsed();
    assert!(joined.is_ok(), "graceful shutdown must complete");
    assert!(
        elapsed < Duration::from_secs(7),
        "graceful shutdown must be bounded, took {elapsed:?}"
    );
    assert!(TLS_SHUTDOWN_TIMEOUT >= Duration::from_secs(1));
    assert!(TLS_SHUTDOWN_TIMEOUT <= Duration::from_secs(60));
}

// ----- macOS ACL helper (fixture only; mirrors private_file tests) -----

#[cfg(target_os = "macos")]
fn add_everyone_allow_read_acl(path: &Path) {
    type AclT = *mut libc::c_void;
    type AclEntryT = *mut libc::c_void;
    type AclPermsetT = *mut libc::c_void;
    const ACL_EXTENDED_ALLOW: i32 = 1;
    const ACL_READ_DATA: i32 = 1 << 1;
    extern "C" {
        fn acl_init(count: libc::c_int) -> AclT;
        fn acl_create_entry(acl_p: *mut AclT, entry_p: *mut AclEntryT) -> libc::c_int;
        fn acl_set_tag_type(entry: AclEntryT, tag: i32) -> libc::c_int;
        fn acl_get_permset(entry: AclEntryT, permset_p: *mut AclPermsetT) -> libc::c_int;
        fn acl_add_perm(permset: AclPermsetT, perm: i32) -> libc::c_int;
        fn acl_set_fd(fd: libc::c_int, acl: AclT) -> libc::c_int;
        fn acl_free(obj: *mut libc::c_void) -> libc::c_int;
    }
    use std::os::unix::io::AsRawFd;
    let file = std::fs::File::open(path).expect("open for acl");
    unsafe {
        let mut acl = acl_init(1);
        assert!(!acl.is_null(), "acl_init");
        let mut entry: AclEntryT = std::ptr::null_mut();
        assert_eq!(acl_create_entry(&mut acl, &mut entry), 0);
        assert_eq!(acl_set_tag_type(entry, ACL_EXTENDED_ALLOW), 0);
        let mut ps: AclPermsetT = std::ptr::null_mut();
        assert_eq!(acl_get_permset(entry, &mut ps), 0);
        assert_eq!(acl_add_perm(ps, ACL_READ_DATA), 0);
        assert_eq!(acl_set_fd(file.as_raw_fd(), acl), 0, "acl_set_fd");
        acl_free(acl.cast());
    }
}

// ----- actual `hs-server` binary CLI (implementation, not fixture acceptor) -----
// Portable tests run on Unix and Windows. Unix-only CLI proofs that need a
// live HTTPS listener or SIGINT are cfg(unix). Windows gets an explicit
// denial test for serve-tls before material/data effects.

fn hs_server_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hs-server"))
}

/// Allocate a loopback port by binding and dropping a listener.
fn reserve_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    listener.local_addr().expect("local addr").port()
}

/// Owned `hs-server` child. `Drop` kills/waits only this child so a test
/// panic before SIGINT cannot leak a live process (no shell cleanup).
#[cfg(unix)]
struct CliChild {
    child: std::process::Child,
}

#[cfg(unix)]
impl CliChild {
    fn spawn(args: &[&str]) -> Self {
        let child = std::process::Command::new(hs_server_bin())
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn hs-server");
        CliChild { child }
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().expect("try_wait")
    }

    fn wait_for_exit(&mut self, bound: Duration) -> std::process::ExitStatus {
        let deadline = std::time::Instant::now() + bound;
        loop {
            if let Some(status) = self.try_wait() {
                return status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("hs-server did not exit within {bound:?}");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

#[cfg(unix)]
impl Drop for CliChild {
    fn drop(&mut self) {
        // Only the owned child is cleaned up — never a shell or other PIDs.
        // Success path already reaped via wait_for_exit; this covers panic
        // or assertion failure before that.
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            _ => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

#[cfg(unix)]
fn send_sigint(child: &std::process::Child) {
    let rc = unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    assert_eq!(rc, 0, "SIGINT");
}

/// Portable: required flags are enforced on every platform.
#[test]
fn actual_cli_serve_tls_requires_cert_and_key_flags() {
    let out = std::process::Command::new(hs_server_bin())
        .args(["serve-tls", "--bind", "127.0.0.1:0"])
        .output()
        .expect("run serve-tls without material");
    assert!(
        !out.status.success(),
        "must fail without --tls-cert/--tls-key"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tls-cert") || stderr.contains("required"),
        "stderr={stderr}"
    );
}

/// Portable: help documents the loopback default and required paths.
#[test]
fn actual_cli_help_shows_default_loopback_8920() {
    let out = std::process::Command::new(hs_server_bin())
        .args(["serve-tls", "--help"])
        .output()
        .expect("help");
    assert!(out.status.success(), "help must succeed");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("127.0.0.1:8920"),
        "help must show default bind, got: {text}"
    );
    assert!(text.contains("--tls-cert"), "help must document --tls-cert");
    assert!(text.contains("--tls-key"), "help must document --tls-key");
}

/// Portable: nonloopback bind must refuse before material/data effects.
/// Uses nonexistent cert/key paths so a loopback-guard ordering bug cannot
/// be masked by PKI setup. No PKI required on any platform.
#[test]
fn actual_cli_public_bind_refuses_with_zero_db() {
    let (_dir, base) = private_tempdir();
    let data = base.join("hs-server.db");
    let cert = base.join("missing.crt");
    let key = base.join("missing.key");
    // Intentionally nonexistent: refuse must not depend on material presence.
    let bind = format!("0.0.0.0:{}", reserve_loopback_port());
    let out = std::process::Command::new(hs_server_bin())
        .args([
            "--data",
            data.to_str().expect("data utf8"),
            "serve-tls",
            "--bind",
            &bind,
            "--tls-cert",
            cert.to_str().expect("cert utf8"),
            "--tls-key",
            key.to_str().expect("key utf8"),
        ])
        .output()
        .expect("run serve-tls public bind");
    assert!(!out.status.success(), "public bind must refuse");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("loopback") || combined.contains("non-loopback"),
        "output={combined}"
    );
    assert!(!data.exists(), "no DB may be created on public refusal");
    assert!(!cert.exists() && !key.exists(), "no material files created");
}

/// Windows: actual CLI refuses serve-tls on literal loopback before
/// material reads or DB creation (native private credential boundary is
/// missing; NotImplemented / explicit refusal). Nonexistent cert/key paths.
#[cfg(windows)]
#[test]
fn actual_windows_cli_refuses_serve_tls_before_material_or_data() {
    let (_dir, base) = private_tempdir();
    assert!(
        !tls_transport_supported(),
        "must not claim Windows TLS transport"
    );
    let data = base.join("hs-server.db");
    let cert = base.join("missing.crt");
    let key = base.join("missing.key");
    let bind = format!("127.0.0.1:{}", reserve_loopback_port());
    let out = std::process::Command::new(hs_server_bin())
        .args([
            "--data",
            data.to_str().expect("data utf8"),
            "serve-tls",
            "--bind",
            &bind,
            "--tls-cert",
            cert.to_str().expect("cert utf8"),
            "--tls-key",
            key.to_str().expect("key utf8"),
        ])
        .output()
        .expect("run serve-tls on Windows");
    assert!(
        !out.status.success(),
        "Windows serve-tls must refuse on literal loopback"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("not supported")
            || combined.contains("not implemented")
            || combined.contains("refusing"),
        "output={combined}"
    );
    assert!(!data.exists(), "no DB on Windows CLI refusal");
    assert!(
        !cert.exists() && !key.exists(),
        "no material/output files created on Windows refusal"
    );
}

/// Unix-only: live HTTPS `/health` against the real process plus bounded
/// SIGINT shutdown. Needs create_new_private_file (NotImplemented on Windows).
#[cfg(unix)]
#[tokio::test]
async fn actual_cli_https_health_and_bounded_sigint() {
    let (_dir, base) = private_tempdir();
    let pki = test_pki(&["localhost", "127.0.0.1"]);
    let (cert, key) = write_tls_material(&base, &pki);
    let data = base.join("hs-server.db");
    let port = reserve_loopback_port();
    let bind = format!("127.0.0.1:{port}");

    let mut child = CliChild::spawn(&[
        "--data",
        data.to_str().expect("data utf8"),
        "serve-tls",
        "--bind",
        &bind,
        "--tls-cert",
        cert.to_str().expect("cert utf8"),
        "--tls-key",
        key.to_str().expect("key utf8"),
    ]);

    // Wait until the real process accepts TCP on the requested port.
    let addr: SocketAddr = bind.parse().expect("bind addr");
    let mut ready = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            ready = true;
            break;
        }
        if let Some(status) = child.try_wait() {
            panic!("hs-server exited before listen: {status:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "hs-server did not accept TCP within bound");

    // Real HTTPS /health against the actual process.
    let client = client_config_for(&pki.ca_pem);
    let health = tls_get_health(addr, client, "localhost")
        .await
        .expect("health against real CLI");
    let status = health.get("status").and_then(|v| v.as_str());
    assert!(
        matches!(status, Some("ok") | Some("degraded")),
        "health={health}"
    );
    assert!(
        health
            .get("storage_schema_version")
            .and_then(|v| v.as_i64())
            .is_some(),
        "health must be real JSON: {health}"
    );

    // Bounded SIGINT shutdown of the real process.
    send_sigint(&child.child);
    let start = std::time::Instant::now();
    let exit_status = child.wait_for_exit(Duration::from_secs(10));
    let elapsed = start.elapsed();
    assert!(
        exit_status.success(),
        "SIGINT exit must be clean: {exit_status:?}"
    );
    assert!(
        elapsed < Duration::from_secs(9),
        "SIGINT shutdown must be bounded, took {elapsed:?}"
    );
    // Drop is now a no-op (already reaped); it would kill on earlier panic.
}

#[cfg(unix)]
#[test]
fn load_rejects_private_key_inside_certificate_file() {
    let (_dir, base) = private_tempdir();
    let data = base.join("hs-server.db");
    let pki = test_pki(&["localhost"]);
    let cert = base.join("cert-with-key.crt");
    let key = base.join("server.key");
    // Certificate file wrongly also holds the private key PEM.
    let mut mixed = String::new();
    mixed.push_str(&pki.cert_pem);
    mixed.push_str(&pki.key_pem);
    write_fixture(&cert, mixed.as_bytes(), 0o600);
    create_new_private_file(&key, pki.key_pem.as_bytes()).expect("key");
    let err = run_serve_tls(&data, "127.0.0.1:8920", &cert, &key).expect_err("must refuse");
    let msg = err.to_string();
    assert!(
        msg.contains("only X.509") || msg.contains("certificate PEM"),
        "msg={msg}"
    );
    assert!(
        !msg.contains("PRIVATE KEY") && !msg.contains("BEGIN"),
        "no material in error"
    );
    assert!(!data.exists());
}
