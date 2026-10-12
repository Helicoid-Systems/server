//! Real HTTPS transport proofs for `serve-tls` and the held-file TLS reader.
//!
//! Platform applicability:
//! - Portable tests (help/default text, required flags, public-bind refusal
//!   with zero DB) run on every platform.
//! - Disposable PKI / material parse / bounds / binding / real TLS socket /
//!   actual-binary HTTPS proofs are `cfg(any(unix, windows))`: they use the
//!   native-verified private_file held reader and the supported-platform TLS
//!   transport. Other targets must not compile or run those helpers.
//! - True Unix filesystem fixtures (mode 0644, FIFO, symlink, hardlink) and
//!   the macOS extended-ACL fixture stay `cfg(unix)` / `cfg(target_os)`.
//! - Windows process cleanup uses owned `Child::kill`/`wait` only — that is
//!   not a graceful CTRL_C/service-stop proof.
//!
//! Scope:
//! - Library/fixture socket tests use a short-handshake acceptor built from
//!   `load_server_config` + `axum_server` on a `TcpListener`. They prove
//!   material parsing, loopback gating, and real TLS I/O, **not** the CLI
//!   process wiring or the production 10s handshake constant. The fixture
//!   acceptor uses 2s; the production constant stays `TLS_HANDSHAKE_TIMEOUT`
//!   (10s) and is asserted separately as a real bound.
//! - `actual_cli_*` tests spawn the real `hs-server` binary and cover
//!   required flags, default bind text, public refusal with zero DB, and
//!   HTTPS `/health` (Unix also proves bounded SIGINT shutdown; Windows
//!   proves bounded kill/reap process cleanup only).
//!
//! These tests use disposable rcgen-generated certificates written as test
//! fixtures only. No runtime laboratory grant/CA exists in product code.
//! Product apps stay closed; listeners here are literal loopback.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hs_server::private_file::create_new_private_file;
#[cfg(any(unix, windows))]
use hs_server::private_file::read_existing_private_file;
use hs_server::tls::{self, DEFAULT_TLS_BIND};
#[cfg(any(unix, windows))]
use hs_server::tls::{
    load_server_config, run_serve_tls, MAX_TLS_CERT_CHAIN, MAX_TLS_PEM_BYTES,
    TLS_HANDSHAKE_TIMEOUT, TLS_SHUTDOWN_TIMEOUT,
};
#[cfg(any(unix, windows))]
use std::sync::Arc;

/// Tempdir whose `base` is a genuine private product child on Windows
/// (created via `ensure_private_store_dir` — no silent re-ACL of TempDir or
/// ancestors) and owner-private (0700) on Unix.
fn private_tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    #[cfg(windows)]
    let base = {
        let child = dir.path().join("hs-store");
        hs_server::private_file::ensure_private_store_dir(&child)
            .expect("windows private product child");
        child
    };
    #[cfg(not(windows))]
    let base = {
        let path = dir.path().canonicalize().expect("canonicalize");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        path
    };
    (dir, base)
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
/// that must start at a non-0600 mode). Unix-only helpers use this.
#[cfg(unix)]
fn write_fixture(path: &Path, contents: &[u8], mode: u32) {
    std::fs::write(path, contents).expect("write fixture");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod fixture");
}

/// Write TLS/fixture material as a genuine private file on every supported
/// platform.
///
/// Unix: owner-only `0600` write (matches the historical fixtures).
/// Windows: `create_new_private_file` inside the product child (protected
/// DACL from create-new; never re-ACL an existing object). Oversize payloads
/// exceed the create-new bound, so Windows seeds a private file then replaces
/// contents without mutating its DACL — the held reader still sees a genuine
/// private object and applies the oversize refusal.
#[cfg(any(unix, windows))]
fn write_private_material(path: &Path, contents: &[u8]) {
    #[cfg(unix)]
    write_fixture(path, contents, 0o600);
    #[cfg(windows)]
    {
        if contents.len() > hs_server::private_file::MAX_PRIVATE_PAYLOAD_BYTES {
            create_new_private_file(path, b"seed").expect("seed private fixture");
            std::fs::write(path, contents).expect("write oversize private fixture");
        } else {
            create_new_private_file(path, contents).expect("create private fixture");
        }
    }
}

// ----- disposable rcgen test material (Unix + Windows fixtures) -----

#[cfg(any(unix, windows))]
struct TestPki {
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

/// Generate a throwaway CA and a server certificate for `sans`.
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
fn write_tls_material(base: &Path, pki: &TestPki) -> (PathBuf, PathBuf) {
    let cert_path = base.join("server.crt");
    let key_path = base.join("server.key");
    create_new_private_file(&cert_path, pki.cert_pem.as_bytes()).expect("write cert");
    create_new_private_file(&key_path, pki.key_pem.as_bytes()).expect("write key");
    (cert_path, key_path)
}

// ----- held-file reader refusals (no path re-open after verify) -----
// True Unix mode/link/FIFO/symlink fixtures stay Unix. Windows coverage for
// the same boundary uses make_public_file and the TLS loader below.

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

/// Replace the DACL of an existing file with a test Everyone-allow ACL.
/// `SetNamedSecurityInfoW` writes the DACL only; the owner is unchanged.
/// Aligned `Vec<u64>` / array storage; buffers live through the call.
#[cfg(windows)]
fn install_untrusted_allow_dacl(path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        AddAccessAllowedAceEx, CreateWellKnownSid, InitializeAcl, WinWorldSid, ACL_REVISION,
        DACL_SECURITY_INFORMATION, PSID,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_LIST_DIRECTORY};

    let mut world_storage = [0u64; 9];
    let mut world_len = std::mem::size_of_val(&world_storage) as u32;
    let world_ps: PSID = world_storage.as_mut_ptr() as PSID;
    assert!(
        unsafe { CreateWellKnownSid(WinWorldSid, std::ptr::null_mut(), world_ps, &mut world_len) }
            != 0
    );

    let mut acl_storage = [0u64; 32];
    let acl_ptr = acl_storage.as_mut_ptr() as *mut windows_sys::Win32::Security::ACL;
    let acl_len = std::mem::size_of_val(&acl_storage) as u32;
    unsafe {
        assert!(InitializeAcl(acl_ptr, acl_len, ACL_REVISION) != 0);
        assert!(
            AddAccessAllowedAceEx(
                acl_ptr,
                ACL_REVISION,
                0,
                FILE_GENERIC_READ | FILE_LIST_DIRECTORY,
                world_ps
            ) != 0
        );
        let mut wpath: Vec<u16> = path.as_os_str().encode_wide().collect();
        wpath.push(0);
        let rc = SetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl_ptr,
            std::ptr::null_mut(),
        );
        assert_eq!(rc, 0, "SetNamedSecurityInfoW public DACL rc={rc}");
    }
}

/// Build a non-private leaf whose owner is the current user.
///
/// The leaf is created through `create_new_private_file` first (currentUser
/// owner + protected DACL). Only then is its DACL replaced with the test
/// Everyone-allow ACL. Elevated CI default owner is Administrators, so a
/// raw `std::fs::write` leaf would be refused on owner before the reader
/// ever inspects the untrusted DACL — that would not exercise this boundary.
#[cfg(windows)]
fn make_public_file(path: &Path, contents: &[u8]) {
    create_new_private_file(path, contents).expect("create owned private leaf");
    // Positive precondition: genuine private material is readable.
    let got = read_existing_private_file(path, contents.len()).expect("private held read");
    assert_eq!(
        got.as_slice(),
        contents,
        "fixture contents before DACL mutation"
    );
    install_untrusted_allow_dacl(path);
}

/// Refusal must be the nontrusted-principal / DACL allowlist boundary, not a
/// broad owner or shape mismatch that could mask a bad fixture.
#[cfg(windows)]
fn assert_untrusted_dacl_refusal(msg: &str) {
    assert!(
        msg.contains("ACCESS_ALLOWED ACE names a principal outside the")
            || msg.contains("principal outside the")
            || (msg.contains("ACCESS_ALLOWED ACE") && msg.contains("allowlist")),
        "expected nontrusted-principal/DACL refusal, msg={msg}"
    );
    assert!(
        !msg.contains("not owned"),
        "must be DACL/principal refusal, not owner: {msg}"
    );
    assert!(
        !msg.contains("not a regular file"),
        "must be DACL/principal refusal, not shape: {msg}"
    );
}

#[cfg(windows)]
#[test]
fn windows_held_file_read_refuses_untrusted_dacl_and_reads_private() {
    let (_dir, base) = private_tempdir();
    let public_path = base.join("public.pem");
    make_public_file(&public_path, b"PUBLIC");
    let err =
        read_existing_private_file(&public_path, 1024).expect_err("must refuse non-private file");
    let msg = err.to_string();
    assert_untrusted_dacl_refusal(&msg);
    assert!(!msg.contains("PUBLIC"));

    let private_path = base.join("material.pem");
    create_new_private_file(&private_path, b"PRIVATE-MATERIAL").expect("create private");
    let got = read_existing_private_file(&private_path, 1024).expect("read private");
    assert_eq!(got.as_slice(), b"PRIVATE-MATERIAL");
}

// ----- TLS PEM bounds and binding (before any listener/DB) -----

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
#[test]
fn load_rejects_oversize_material_without_db() {
    let (_dir, base) = private_tempdir();
    let data = base.join("hs-server.db");
    let cert = base.join("big.crt");
    let key = base.join("big.key");
    let big = vec![b'A'; MAX_TLS_PEM_BYTES + 1];
    write_private_material(&cert, &big);
    write_private_material(&key, &big);
    let err =
        run_serve_tls(&data, "127.0.0.1:8920", &cert, &key).expect_err("must refuse oversize");
    let msg = err.to_string();
    assert!(msg.contains("exceeds"), "msg={msg}");
    assert!(
        !data.exists(),
        "DB must not be created on oversize TLS files"
    );
}

#[cfg(any(unix, windows))]
#[test]
fn load_rejects_empty_certificate_pem_without_db() {
    let (_dir, base) = private_tempdir();
    let data = base.join("hs-server.db");
    let pki = test_pki(&["localhost"]);
    let cert = base.join("empty.crt");
    let key = base.join("server.key");
    // Cert file holds no certificates.
    write_private_material(
        &cert,
        b"-----BEGIN NOTES-----\nnot-a-cert\n-----END NOTES-----\n",
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

#[cfg(any(unix, windows))]
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
    write_private_material(&cert, chain.as_bytes());
    create_new_private_file(&key, pki.key_pem.as_bytes()).expect("key");
    let err = run_serve_tls(&data, "127.0.0.1:8920", &cert, &key).expect_err("must refuse chain");
    let msg = err.to_string();
    assert!(
        msg.contains("exceeds") && msg.contains("certificate"),
        "msg={msg}"
    );
    assert!(!data.exists());
}

#[cfg(any(unix, windows))]
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
    write_private_material(&key, keys.as_bytes());
    let err = run_serve_tls(&data, "127.0.0.1:8920", &cert, &key).expect_err("duplicate keys");
    let msg = err.to_string();
    assert!(msg.contains("exactly one private key"), "msg={msg}");
    assert!(!data.exists());
}

#[cfg(any(unix, windows))]
#[test]
fn load_rejects_zero_keys() {
    let (_dir, base) = private_tempdir();
    let data = base.join("hs-server.db");
    let pki = test_pki(&["localhost"]);
    let cert = base.join("server.crt");
    let key = base.join("nokey.key");
    create_new_private_file(&cert, pki.cert_pem.as_bytes()).expect("cert");
    write_private_material(
        &key,
        b"-----BEGIN NOTES-----\nno key here\n-----END NOTES-----\n",
    );
    let err = run_serve_tls(&data, "127.0.0.1:8920", &cert, &key).expect_err("zero keys");
    let msg = err.to_string();
    assert!(
        msg.contains("exactly one private key") || msg.contains("only"),
        "msg={msg}"
    );
    assert!(!data.exists());
}

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
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
    write_private_material(&cert, mixed.as_bytes());
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

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
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
/// platform.
#[test]
fn default_tls_bind_is_literal_loopback_8920() {
    let addr: SocketAddr = DEFAULT_TLS_BIND.parse().expect("default bind");
    assert!(addr.ip().is_loopback());
    assert_eq!(addr.port(), 8920);
}

// ----- Windows: unsafe material refused by the actual TLS loader -----
// Untrusted DACL and hardlink refusals run through the production held
// reader / TLS loader before any DB or listener effect. Leaves are created
// via create_new_private_file (currentUser owner) so refusal is the
// DACL/principal boundary, not an elevated default-owner mismatch.

#[cfg(windows)]
#[test]
fn windows_tls_loader_refuses_untrusted_dacl_material_before_db() {
    let (_dir, base) = private_tempdir();
    let pki = test_pki(&["localhost"]);
    let data = base.join("hs-server.db");
    let cert = base.join("server.crt");
    let key = base.join("server.key");

    // Cert: owned private leaf, positive held read, then untrusted DACL.
    create_new_private_file(&cert, pki.cert_pem.as_bytes()).expect("cert");
    create_new_private_file(&key, pki.key_pem.as_bytes()).expect("key");
    read_existing_private_file(&cert, MAX_TLS_PEM_BYTES).expect("private cert held read");
    read_existing_private_file(&key, MAX_TLS_PEM_BYTES).expect("private key held read");
    // Genuine private material loads before mutation (precondition).
    let _ = load_server_config(&cert, &key).expect("private material loads");

    install_untrusted_allow_dacl(&cert);
    let err = load_server_config(&cert, &key).expect_err("untrusted cert DACL must be refused");
    let msg = err.to_string();
    assert_untrusted_dacl_refusal(&msg);
    assert!(!msg.contains("BEGIN"), "no material in error");
    let err = run_serve_tls(&data, "127.0.0.1:8920", &cert, &key)
        .expect_err("untrusted cert DACL must refuse serve-tls");
    let msg = err.to_string();
    assert_untrusted_dacl_refusal(&msg);
    assert!(!data.exists(), "no DB on untrusted cert DACL refusal");

    // Key: fresh owned leaves, mutate only the key DACL.
    let data2 = base.join("hs-server2.db");
    let cert2 = base.join("server2.crt");
    let key2 = base.join("server2.key");
    create_new_private_file(&cert2, pki.cert_pem.as_bytes()).expect("cert");
    create_new_private_file(&key2, pki.key_pem.as_bytes()).expect("key");
    read_existing_private_file(&cert2, MAX_TLS_PEM_BYTES).expect("private cert2 held read");
    read_existing_private_file(&key2, MAX_TLS_PEM_BYTES).expect("private key2 held read");
    install_untrusted_allow_dacl(&key2);
    let err = load_server_config(&cert2, &key2).expect_err("untrusted key DACL must be refused");
    let msg = err.to_string();
    assert_untrusted_dacl_refusal(&msg);
    assert!(!msg.contains("BEGIN"), "no material in error");
    let err = run_serve_tls(&data2, "127.0.0.1:8920", &cert2, &key2)
        .expect_err("untrusted key DACL must refuse serve-tls");
    let msg = err.to_string();
    assert_untrusted_dacl_refusal(&msg);
    assert!(!data2.exists(), "no DB on untrusted key DACL refusal");
}

#[cfg(windows)]
#[test]
fn windows_tls_loader_refuses_hardlinked_key_before_db() {
    let (_dir, base) = private_tempdir();
    let pki = test_pki(&["localhost"]);
    let data = base.join("hs-server.db");
    let (cert, key) = write_tls_material(&base, &pki);
    let extra = base.join("extra-link.key");
    std::fs::hard_link(&key, &extra).expect("hard link key");
    let err = run_serve_tls(&data, "127.0.0.1:8920", &cert, &key)
        .expect_err("hardlinked key must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("link count") || msg.contains("refusing"),
        "msg={msg}"
    );
    assert!(!data.exists(), "no DB on hardlinked key refusal");
}

// ----- genuine TLS sockets (fixture acceptor; not CLI wiring) -----
// Fixture acceptor handshake timeout is 2s so stalled-handshake tests stay
// bounded. That does **not** prove the production 10s `TLS_HANDSHAKE_TIMEOUT`
// constant; that bound is asserted explicitly below and in the CLI test.

#[cfg(any(unix, windows))]
struct TestServer {
    addr: SocketAddr,
    handle: axum_server::Handle<SocketAddr>,
    join: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    _db: tempfile::TempDir,
}

#[cfg(any(unix, windows))]
impl TestServer {
    /// Graceful shutdown with the original 2s grace / 5s join bounds, then
    /// require all three layers: the join timeout must succeed, the
    /// `JoinHandle` must not be a panic/`JoinError`, and the serve task's
    /// inner `Result` must be `Ok`. The held TempDir stays alive until this
    /// returns (no fixture cleanup before confirmed join).
    async fn shutdown_and_confirm(self) {
        self.handle.graceful_shutdown(Some(Duration::from_secs(2)));
        let joined = tokio::time::timeout(Duration::from_secs(5), self.join)
            .await
            .expect("serve task must join within 5s bound");
        let serve_result = joined.expect("serve task must not panic");
        assert!(
            serve_result.is_ok(),
            "serve task inner result must be Ok: {serve_result:?}"
        );
    }
}

#[cfg(any(unix, windows))]
async fn spawn_tls_server(base: &Path, pki: &TestPki) -> TestServer {
    let (cert_path, key_path) = write_tls_material(base, pki);
    let server_config = load_server_config(&cert_path, &key_path).expect("load server config");
    let config = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
    let (db_dir, db_base) = private_tempdir();
    let data = db_base.join("hs-server.db");
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
    // Production serve-tls uses TLS_HANDSHAKE_TIMEOUT (10s), asserted below.
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
#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
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
    server.shutdown_and_confirm().await;
}

#[cfg(any(unix, windows))]
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
    server.shutdown_and_confirm().await;
}

#[cfg(any(unix, windows))]
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
    server.shutdown_and_confirm().await;
}

#[cfg(any(unix, windows))]
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

    server.shutdown_and_confirm().await;
}

#[cfg(any(unix, windows))]
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
    // Production constant stays a real bound (fixture acceptor is 2s and does
    // not prove this value).
    assert_eq!(TLS_HANDSHAKE_TIMEOUT, Duration::from_secs(10));

    server.shutdown_and_confirm().await;
}

#[cfg(any(unix, windows))]
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
    let join_result = joined.expect("graceful shutdown must complete");
    let serve_result = join_result.expect("serve task must not panic");
    assert!(
        serve_result.is_ok(),
        "serve task inner result must be Ok: {serve_result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(7),
        "graceful shutdown must be bounded, took {elapsed:?}"
    );
    assert_eq!(TLS_SHUTDOWN_TIMEOUT, Duration::from_secs(10));
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
// Portable tests run on every platform. Unix proves bounded SIGINT zero-exit
// shutdown. Windows proves owned Child.kill/wait process cleanup only — that
// is NOT a graceful CTRL_C/service-stop proof (the library Handle test above
// is the portable graceful proof). No CTRL_C/CTRL_BREAK is broadcast.

fn hs_server_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hs-server"))
}

/// Allocate a loopback port by binding and dropping a listener.
fn reserve_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    listener.local_addr().expect("local addr").port()
}

/// Owned `hs-server` child. `Drop` kills/waits only this child so a test
/// panic before shutdown cannot leak a live process (no shell cleanup).
#[cfg(any(unix, windows))]
struct CliChild {
    child: std::process::Child,
}

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
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

/// Spawn the real process on an ephemeral literal-loopback port with genuine
/// private material.
#[cfg(any(unix, windows))]
fn spawn_cli_tls(base: &Path, pki: &TestPki) -> (CliChild, SocketAddr, PathBuf) {
    let (cert, key) = write_tls_material(base, pki);
    let data = base.join("hs-server.db");
    let port = reserve_loopback_port();
    let bind = format!("127.0.0.1:{port}");
    let child = CliChild::spawn(&[
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
    let addr: SocketAddr = bind.parse().expect("bind addr");
    (child, addr, data)
}

/// Wait until the owned child accepts TCP, under a **single** 10s monotonic
/// deadline. Each connect attempt is bounded by `timeout_at(deadline, …)` so
/// an OS connect cannot outlive the deadline between attempts; the retry
/// pause is an async sleep capped by the remaining time. Polls owned-child
/// exit so a crash before listen fails fast. No CPU-blocking connect/sleep.
#[cfg(any(unix, windows))]
async fn wait_cli_listening(child: &mut CliChild, addr: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait() {
            panic!("hs-server exited before listen: {status:?}");
        }
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or_default();
        if remaining.is_zero() {
            panic!("hs-server did not accept TCP within bound");
        }
        match tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => return,
            Ok(Err(_)) => {
                let next_attempt =
                    deadline.min(tokio::time::Instant::now() + Duration::from_millis(50));
                tokio::time::sleep_until(next_attempt).await;
            }
            Err(_) => panic!("hs-server did not accept TCP within bound"),
        }
    }
}

/// Unix-only: live HTTPS `/health` against the real process plus bounded
/// SIGINT zero-exit shutdown.
#[cfg(unix)]
#[tokio::test]
async fn actual_cli_https_health_and_bounded_sigint() {
    let (_dir, base) = private_tempdir();
    let pki = test_pki(&["localhost", "127.0.0.1"]);
    let (mut child, addr, _data) = spawn_cli_tls(&base, &pki);
    wait_cli_listening(&mut child, addr).await;

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

    // Bounded SIGINT shutdown of the real process (Unix).
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

/// Windows-only: live HTTPS `/health` against the real process, then owned
/// `Child::kill`/`wait` process cleanup. This is NOT a graceful CTRL_C or
/// service-stop proof — do not claim Windows CtrlC acceptance from kill.
#[cfg(windows)]
#[tokio::test]
async fn actual_windows_cli_https_health_and_bounded_kill() {
    let (_dir, base) = private_tempdir();
    let pki = test_pki(&["localhost", "127.0.0.1"]);
    let (mut child, addr, data) = spawn_cli_tls(&base, &pki);
    wait_cli_listening(&mut child, addr).await;
    assert!(
        data.exists(),
        "real CLI creates the store after material load"
    );

    // Actual pinned-TLS /health against the real process.
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

    // Owned kill/reap only (process cleanup). Not CTRL_C, not service-stop.
    let start = std::time::Instant::now();
    child.child.kill().expect("kill owned child");
    let exit_status = child.wait_for_exit(Duration::from_secs(5));
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(4),
        "kill/reap must be bounded, took {elapsed:?}"
    );
    let _ = exit_status;
    // Drop is now a no-op (already reaped); it would kill on earlier panic.
}
