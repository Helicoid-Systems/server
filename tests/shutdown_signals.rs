//! Service-manager stop requests must reach the same graceful shutdown path
//! as an interactive Ctrl-C.
//!
//! launchd and systemd stop a hosted server with `SIGTERM`. These tests spawn
//! the real `hs-server` binary against a disposable loopback store, confirm it
//! is actually serving, deliver `SIGTERM` to that owned child only, and require
//! a clean bounded exit. They prove the signal wiring, not a service manager:
//! no launchctl/systemctl, privilege, global config, or system resource is
//! touched. Ctrl-C (`SIGINT`) must keep working on both entry points; the
//! `serve` parity case is below and `serve-tls` keeps its existing SIGINT proof
//! in `tests/tls_transport.rs`. Two cases hold an incomplete request open: one
//! proves the post-stop drain is bounded against a client that never finishes,
//! the other that normal uptime is never timed.
//!
//! Unix-only: `SIGTERM`/`SIGINT` are Unix signals. Windows keeps its existing
//! CTRL_C wiring and has no equivalent stop request to exercise here.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Upper bound on the whole stop request: launchd/systemd escalate to `SIGKILL`
/// when a service overruns its own stop window, so a hang is a failure here too.
const SHUTDOWN_BOUND: Duration = Duration::from_secs(10);

fn hs_server_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hs-server"))
}

/// Allocate a loopback port by binding and dropping a listener.
fn reserve_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    listener.local_addr().expect("local addr").port()
}

/// Disposable owner-private base directory for store and TLS material.
///
/// Mirrors the product boundary: the parent is `0700` and files are `0600`, so
/// the private-store and held-file readers accept the fixture exactly as they
/// accept a real deployment.
fn private_tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let base = dir.path().canonicalize().expect("canonicalize");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).expect("chmod base");
    (dir, base)
}

fn write_private_material(path: &Path, contents: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).expect("write material");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod material");
}

/// Owned `hs-server` child. `Drop` kills/waits only this child so a failed
/// assertion cannot leak a live server process.
struct CliChild {
    child: Child,
}

impl CliChild {
    fn spawn(args: &[&str]) -> Self {
        let child = Command::new(hs_server_bin())
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn hs-server");
        CliChild { child }
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().expect("try_wait")
    }

    fn wait_for_exit(&mut self, bound: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + bound;
        loop {
            if let Some(status) = self.try_wait() {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("hs-server did not exit within {bound:?}");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Remaining piped output after exit. Only called once the child is reaped,
    /// so these reads cannot block on a live process.
    fn drain_output(&mut self) -> String {
        let mut text = String::new();
        if let Some(mut stdout) = self.child.stdout.take() {
            let _ = stdout.read_to_string(&mut text);
        }
        if let Some(mut stderr) = self.child.stderr.take() {
            let _ = stderr.read_to_string(&mut text);
        }
        text
    }
}

impl Drop for CliChild {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            _ => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

/// Wait until the owned child accepts TCP under one monotonic deadline, and
/// fail fast if it exits before listening.
fn wait_listening(child: &mut CliChild, addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait() {
            panic!("hs-server exited before listen: {status:?}");
        }
        if Instant::now() >= deadline {
            panic!("hs-server did not accept TCP within bound");
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// One plain-HTTP `/health` request against the real process. Returns the
/// status line so a not-yet-serving or misrouted listener cannot pass.
fn http_status_line(addr: SocketAddr) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect health");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    let text = String::from_utf8_lossy(&response).into_owned();
    text.lines().next().unwrap_or_default().to_string()
}

/// Start `serve` on a disposable store and wait until `/health` answers, so a
/// signal is only delivered to a fully serving process.
fn spawn_serving_serve(base: &Path) -> (CliChild, SocketAddr) {
    let data = base.join("hs-server.db");
    let bind = format!("127.0.0.1:{}", reserve_loopback_port());
    let mut child = CliChild::spawn(&[
        "--data",
        data.to_str().expect("data utf8"),
        "serve",
        "--bind",
        &bind,
    ]);
    let addr: SocketAddr = bind.parse().expect("bind addr");
    wait_listening(&mut child, addr);
    assert_eq!(http_status_line(addr), "HTTP/1.1 200 OK");
    (child, addr)
}

/// Deliver `signal` to the owned child only.
fn send_signal(child: &Child, signal: libc::c_int, name: &str) {
    let rc = unsafe { libc::kill(child.id() as i32, signal) };
    assert_eq!(rc, 0, "{name}");
}

/// Deliver `signal` to the owned child only, then require the graceful path:
/// zero exit, within the stop bound, rather than the default signal disposition.
fn assert_graceful_stop(mut child: CliChild, signal: libc::c_int, name: &str) {
    send_signal(&child.child, signal, name);
    let start = Instant::now();
    let status = child.wait_for_exit(SHUTDOWN_BOUND);
    let elapsed = start.elapsed();
    assert!(
        status.success(),
        "{name} must take the graceful path, not the default signal disposition: {status:?}"
    );
    assert!(
        elapsed < SHUTDOWN_BOUND,
        "{name} shutdown must be bounded, took {elapsed:?}"
    );
}

/// SIGTERM to `serve` (the launchd/systemd stop signal) must be a clean,
/// bounded, zero-exit shutdown.
#[test]
fn sigterm_gracefully_stops_serve() {
    let (_dir, base) = private_tempdir();
    let (child, _addr) = spawn_serving_serve(&base);
    assert_graceful_stop(child, libc::SIGTERM, "SIGTERM");
}

/// Ctrl-C into `serve` must keep working through the shared stop future.
#[test]
fn sigint_gracefully_stops_serve() {
    let (_dir, base) = private_tempdir();
    let (child, _addr) = spawn_serving_serve(&base);
    assert_graceful_stop(child, libc::SIGINT, "SIGINT");
}

/// The drain bound applies only after a stop request: an incomplete request
/// may stay open past the bound during normal uptime without expiring the
/// server, and other requests keep being served.
#[test]
fn incomplete_request_does_not_expire_normal_uptime() {
    let (_dir, base) = private_tempdir();
    let (mut child, addr) = spawn_serving_serve(&base);
    let mut held = TcpStream::connect(addr).expect("hold connection");
    held.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n")
        .expect("write partial request");
    held.flush().expect("flush partial request");

    // Longer than the post-stop drain bound, with no stop request made.
    std::thread::sleep(Duration::from_secs(6));
    assert!(
        child.try_wait().is_none(),
        "normal uptime must not be timed"
    );
    assert_eq!(http_status_line(addr), "HTTP/1.1 200 OK");
    // Ending the test kills the owned child; no stop request was made.
}

/// A client that starts a request and never finishes it must not hold plain
/// `serve` past its drain bound: SIGTERM still finishes within the bound and
/// reports the forced drain instead of hanging or claiming a clean stop.
#[test]
fn sigterm_bounds_plain_http_drain_with_incomplete_request() {
    let (_dir, base) = private_tempdir();
    let (mut child, addr) = spawn_serving_serve(&base);

    // Open a request and stop before the header terminator. The server can
    // never complete it, and axum waits for every connection on shutdown.
    let mut held = TcpStream::connect(addr).expect("hold connection");
    held.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n")
        .expect("write partial request");
    held.flush().expect("flush partial request");
    // The listener was already accepting; give it time to take this connection
    // before the stop request so the drain really is exercised.
    std::thread::sleep(Duration::from_millis(250));
    // Normal uptime is untimed: the held connection must not disturb serving.
    assert_eq!(http_status_line(addr), "HTTP/1.1 200 OK");

    send_signal(&child.child, libc::SIGTERM, "SIGTERM");
    let start = Instant::now();
    let status = child.wait_for_exit(SHUTDOWN_BOUND);
    let elapsed = start.elapsed();
    let output = child.drain_output();
    drop(held);

    assert_eq!(
        status.code(),
        Some(1),
        "a forced drain must be reported, not a clean exit: {status:?}"
    );
    assert!(
        output.contains("plain HTTP shutdown timed out"),
        "forced drain must name its cause: {output}"
    );
    assert!(
        elapsed < SHUTDOWN_BOUND,
        "SIGTERM drain must be bounded, took {elapsed:?}"
    );
}

/// SIGTERM to `serve-tls` must be a clean, bounded, zero-exit shutdown.
#[test]
fn sigterm_gracefully_stops_serve_tls() {
    let (_dir, base) = private_tempdir();
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed material");
    let cert = base.join("server.crt");
    let key = base.join("server.key");
    write_private_material(&cert, issued.cert.pem().as_bytes());
    write_private_material(&key, issued.key_pair.serialize_pem().as_bytes());

    let data = base.join("hs-server.db");
    let bind = format!("127.0.0.1:{}", reserve_loopback_port());
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
    let addr: SocketAddr = bind.parse().expect("bind addr");
    wait_listening(&mut child, addr);

    assert_graceful_stop(child, libc::SIGTERM, "SIGTERM");
}
