#!/usr/bin/env python3
"""Real-socket coturn allocation-expiry lab runner.

Starts a pinned turnserver on loopback, exercises REST credential + allocation
lifetime boundaries over real TLS/TCP + UDP relay, and records measured
timestamps/packet counts without secrets.

Scenarios (see lab README):
  1. allocate_and_forward     — real relay forwarding before expiry
  2. refresh_after_expiry     — retained key Refresh after authorization stops
  3. silent_client_expires    — silent client, allocation timer destroys relay
  4. late_allocate_rejected   — new Allocate after credential timestamp expiry
  5. wrong_auth_rejected      — wrong password refused
  6. allocation_isolation     — independent allocation not affected
  7. matching_cleanup         — no leftover listeners/sockets after stop

Timing modes:
  --mode accelerated  short authorization (~15s) for diagnosis
  --mode boundary60   real 60-second authorization boundary trial
  --mode lastfraction fresh-window last-fraction Refresh cutoff probe
  --mode clockfault   test-only CLOCK_MONOTONIC failure injection binary
                      (compile-time seam; fault injection, not OS fault)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import turn_protocol as tp  # noqa: E402

LAB_ROOT_ENV = os.environ.get("LAB_ROOT", "").strip()
DEFAULT_TURNSERVER = os.environ.get(
    "TURNSERVER_BIN",
    "/tmp/hs-finish-20261013/relay-lab/coturn-src/bin/turnserver",
)


def lab_root() -> Path:
    """Private scratch root. Honor LAB_ROOT end-to-end (CI runner.temp)."""
    if LAB_ROOT_ENV:
        return Path(LAB_ROOT_ENV)
    return Path("/tmp/hs-finish-20261013/relay-lab")


def private_workdir(prefix: str) -> Path:
    """Create a private 0700 workdir outside the repository.

    Never allocate scratch inside the checked-in harness tree.
    """
    base = lab_root() / "run"
    base.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))
    os.chmod(workdir, 0o700)
    return workdir


def now_mono() -> float:
    return time.monotonic()


def now_wall() -> float:
    """Float wall clock for honest sub-second measurement."""
    return time.time()


def now_wall_int() -> int:
    """Integer wall clock ONLY for REST timestamp generation."""
    return int(time.time())


def rest_username(expiry_ts: int, user: str, sep: str = ":") -> str:
    return f"{expiry_ts}{sep}{user}"


def rest_password(username: str, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), username.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(mac).decode("ascii")


class LabResult:
    def __init__(self) -> None:
        self.scenarios: dict[str, dict] = {}
        self.meta: dict = {}

    def record(self, name: str, **kwargs) -> None:
        entry = {
            "name": name,
            "recorded_wall": now_wall(),
            "recorded_mono": now_mono(),
        }
        entry.update(kwargs)
        self.scenarios[name] = entry
        status = kwargs.get("status", "?")
        print(f"  => {name}: {status}", flush=True)

    def to_json(self) -> str:
        return json.dumps({"meta": self.meta, "scenarios": self.scenarios}, indent=2, sort_keys=True)


def generate_certs(cert_dir: Path) -> tuple[Path, Path]:
    """Return (cert, key). The self-signed cert is the lab trust root."""
    cert = cert_dir / "server.crt"
    key = cert_dir / "server.key"
    if cert.exists() and key.exists():
        return cert, key
    cert_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert),
            "-days", "2", "-nodes",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    os.chmod(key, stat.S_IRUSR | stat.S_IWUSR)
    return cert, key


def write_turn_config(
    conf_path: Path,
    secret: str,
    cert: Path,
    key: Path,
    udp_port: int,
    tls_port: int,
    max_allocate_lifetime: int,
) -> Path:
    # Secrets only in this 0600 config; never in argv or console.
    # TLS/TCP control plane on loopback; UDP relay bounded to high ports.
    # no-tcp: no plain TCP client listener. no-dtls: no DTLS listener.
    # no-cli: no admin CLI listener. allow-loopback-peers: lab peer on 127.0.0.1.
    conf = f"""# relay-lab ephemeral turnserver config (generated)
listening-port={udp_port}
tls-listening-port={tls_port}
listening-ip=127.0.0.1
relay-ip=127.0.0.1
external-ip=127.0.0.1
min-port=49152
max-port=49252
fingerprint
use-auth-secret
static-auth-secret={secret}
realm=relay-lab.invalid
server-name=relay-lab
cert={cert}
pkey={key}
max-allocate-lifetime={max_allocate_lifetime}
stale-nonce=600
verbose
no-software-attribute
no-tcp
no-dtls
no-cli
allow-loopback-peers
"""
    conf_path.write_text(conf)
    os.chmod(conf_path, stat.S_IRUSR | stat.S_IWUSR)
    return conf_path


def start_turnserver(binary: Path, conf: Path, log_path: Path) -> subprocess.Popen:
    log_f = open(log_path, "ab")
    # Config file holds the secret; argv only carries paths.
    proc = subprocess.Popen(
        [str(binary), "-c", str(conf)],
        stdout=log_f,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    log_f.close()
    return proc


def wait_port(host: str, port: int, timeout: float = 10.0, udp: bool = False) -> bool:
    deadline = now_mono() + timeout
    while now_mono() < deadline:
        try:
            if udp:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.3)
                s.connect((host, port))
                s.close()
                return True
            else:
                s = socket.create_connection((host, port), timeout=0.3)
                s.close()
                return True
        except OSError:
            time.sleep(0.1)
    return False


def proc_alive(proc: subprocess.Popen) -> bool:
    return proc.poll() is None


def kill_turnserver(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        proc.terminate()
    deadline = now_mono() + 5.0
    while now_mono() < deadline and proc.poll() is None:
        time.sleep(0.05)
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.wait(timeout=5)


def open_tls_channel(host: str, port: int, verbose: bool, ca_cert: Path) -> tp.TurnChannel:
    """TLS/TCP channel verified against the generated lab CA/cert.

    No CERT_NONE fallback. Hostname check uses SAN DNS:localhost.
    """
    if ca_cert is None or not Path(ca_cert).is_file():
        raise RuntimeError("ca_cert is required; refusing unverified TLS")
    raw = tp.connect_tcp(host, port)
    ctx = ssl.create_default_context(cafile=str(ca_cert))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    # coturn selects TURN via ALPN "stun.turn" (see ServerALPNCallback).
    try:
        ctx.set_alpn_protocols(["stun.turn", "stun.nat-discovery"])
    except (ValueError, NotImplementedError, AttributeError):
        pass
    tls = ctx.wrap_socket(raw, server_hostname="localhost")
    tls.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return tp.TurnChannel(tls, verbose=verbose)


def listen_udp_peer(bind_port: int = 0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", bind_port))
    s.settimeout(2.0)
    return s


def drain_udp(sock: socket.socket, budget: float = 1.0) -> list[bytes]:
    """Drain datagrams until budget expires. Never block past budget.

    Each recvfrom is bounded by the *remaining* budget, not the socket's
    default timeout. Caller socket timeout is restored on return.
    """
    got: list[bytes] = []
    deadline = now_mono() + budget
    prev_timeout = sock.gettimeout()
    try:
        while True:
            remaining = deadline - now_mono()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, _ = sock.recvfrom(4096)
                got.append(data)
            except socket.timeout:
                break
    finally:
        sock.settimeout(prev_timeout)
    return got


def recv_udp_matching(sock: socket.socket, nonce: bytes, budget: float) -> bool:
    """Return True immediately on matching nonce within budget.

    Each recvfrom is bounded by the remaining budget (not the socket's
    default timeout). Non-matching datagrams are skipped until budget
    expires. Caller socket timeout is restored on return.
    """
    deadline = now_mono() + budget
    prev_timeout = sock.gettimeout()
    try:
        while True:
            remaining = deadline - now_mono()
            if remaining <= 0:
                return False
            sock.settimeout(remaining)
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                return False
            if data == nonce:
                return True
    finally:
        sock.settimeout(prev_timeout)


def scenario_forward_before_expiry(
    ch: tp.TurnChannel,
    peer_sock: socket.socket,
    payload: bytes,
    result: LabResult,
) -> bool:
    """CreatePermission + Send/Data over real UDP relay before expiry."""
    peer_port = peer_sock.getsockname()[1]
    ok, err = ch.create_permission("127.0.0.1", peer_port)
    if not ok:
        result.record("allocate_and_forward", status="FAIL", step="create_permission", error=err)
        return False
    if not ch.relayed_addr:
        result.record("allocate_and_forward", status="FAIL", step="no_relayed_addr")
        return False
    relayed_ip, relayed_port = ch.relayed_addr[1], ch.relayed_addr[2]
    nonce_a = os.urandom(24)
    nonce_b = os.urandom(24)
    # Peer -> relayed address; turnserver should Data-indicate to client.
    peer_sock.sendto(nonce_a, (relayed_ip, relayed_port))
    time.sleep(0.3)
    # Client -> peer via Send indication (distinct nonce).
    ch.send_indication("127.0.0.1", peer_port, nonce_b)
    time.sleep(0.2)
    peer_got = drain_udp(peer_sock, 1.0)
    client_data = []
    deadline = now_mono() + 1.0
    while now_mono() < deadline:
        got = ch.recv_data(timeout=0.3)
        if got:
            client_data.append(got)
        else:
            break
    peer_saw = any(d == nonce_b for d in peer_got)
    client_saw = any(d[1] == nonce_a for d in client_data)
    forwarded = peer_saw or client_saw
    result.record(
        "allocate_and_forward",
        status="PASS" if forwarded else "FAIL",
        forwarded=forwarded,
        peer_saw_nonce_b=peer_saw,
        client_saw_nonce_a=client_saw,
        peer_packets=len(peer_got),
        client_data_ind=len(client_data),
        relayed=f"{relayed_ip}:{relayed_port}",
        alloc_lifetime=ch.alloc_lifetime,
    )
    return forwarded


def scenario_refresh_after_expiry(
    ch: tp.TurnChannel,
    secret: str,
    username: str,
    password: str,
    auth_expiry_ts: int,
    result: LabResult,
    sample_interval: float,
    post_expiry_window: float,
) -> dict:
    """Keep Refreshing with the retained key after REST timestamp expiry.

    Baseline failure signature: Refresh still succeeds after auth_expiry_ts.
    Expected patched behavior: Refresh fails or lifetime collapses to <=0.
    """
    samples = []
    t_end = now_mono() + (max(0, auth_expiry_ts - now_wall()) + post_expiry_window) + 2.0
    # Always sample through and past the wall-clock expiry.
    while now_mono() < t_end:
        wall = now_wall()
        mono = now_mono()
        try:
            ok, lifetime, err = ch.refresh(lifetime=600)
        except (BrokenPipeError, ConnectionResetError, OSError, ssl.SSLError):
            ok, lifetime, err = False, None, "transport_closed"
        sample = {
            "wall": wall,
            "mono": mono,
            "ok": ok,
            "lifetime": lifetime,
            "err": err,
            "past_expiry": wall >= auth_expiry_ts,
        }
        samples.append(sample)
        time.sleep(sample_interval)

    past = [s for s in samples if s["past_expiry"]]
    past_ok = [s for s in past if s["ok"]]
    past_fail = [s for s in past if not s["ok"]]
    # Failure of the authorization bound: any successful Refresh after expiry.
    unbounded = len(past_ok) > 0
    max_past_lifetime = max((s["lifetime"] or 0) for s in past_ok) if past_ok else 0
    result.record(
        "refresh_after_expiry",
        status="FAIL" if unbounded else "PASS",
        # FAIL means the authorization bound did NOT hold (the defect).
        unbounded_after_expiry=unbounded,
        samples_past_expiry=len(past),
        successful_after_expiry=len(past_ok),
        failed_after_expiry=len(past_fail),
        max_granted_lifetime_after_expiry=max_past_lifetime,
        auth_expiry_ts=auth_expiry_ts,
        first_past_ok=next((s for s in past_ok), None),
        last_sample=samples[-1] if samples else None,
    )
    return {"samples": samples, "unbounded": unbounded}


def scenario_silent_client_after_wait(
    ch: tp.TurnChannel,
    peer_sock: socket.socket,
    result: LabResult,
    auth_expiry_ts: int,
    pre_ok: bool,
) -> dict:
    """Probe a client that has been silent (no Refresh) through auth expiry.

    Baseline failure signature: path still alive after auth_expiry_ts.
    Expected patched behavior: authorization deadline destroyed the relay.
    """
    if not ch.relayed_addr:
        result.record("silent_client_expires", status="FAIL", step="no_relayed_addr")
        return {"destroyed": False}
    peer_port = peer_sock.getsockname()[1]
    destroyed = False
    refresh_ok = False
    refresh_err = None
    post_packets = 0
    try:
        ch.send_indication("127.0.0.1", peer_port, b"post-silent")
        post_packets = len(drain_udp(peer_sock, 1.0))
    except (BrokenPipeError, ConnectionResetError, OSError, ssl.SSLError):
        destroyed = True
    try:
        ok, lifetime, err = ch.refresh(lifetime=60)
        refresh_ok = ok
        refresh_err = err
        if not ok:
            destroyed = True
    except (BrokenPipeError, ConnectionResetError, OSError, ssl.SSLError):
        destroyed = True
    if post_packets == 0 and not refresh_ok:
        destroyed = True
    # Require a real pre-silence UDP nonce receipt AND post-bound rejection.
    passed = bool(destroyed and pre_ok and post_packets == 0)
    result.record(
        "silent_client_expires",
        status="PASS" if passed else "FAIL",
        destroyed=destroyed,
        pre_ok=pre_ok,
        post_packets=post_packets,
        post_bound_packet_rejected=bool(post_packets == 0),
        refresh_ok=refresh_ok,
        refresh_err=refresh_err,
        auth_expiry_ts=auth_expiry_ts,
        past_expiry=now_wall() >= auth_expiry_ts,
    )
    return {"destroyed": destroyed}


def scenario_late_allocate(
    host: str,
    tls_port: int,
    secret: str,
    username: str,
    password: str,
    result: LabResult,
    ca_cert: Path,
) -> None:
    """New Allocate after credential timestamp must be rejected."""
    ch = open_tls_channel(host, tls_port, verbose=False, ca_cert=ca_cert)
    try:
        if not ch.bind_challenge():
            result.record("late_allocate_rejected", status="FAIL", step="challenge")
            return
        ch.set_credentials(username, password)
        ok, lifetime, err = ch.allocate(lifetime=600)
        rejected = (not ok) and err in (401, 438, 441, 400, 508)
        # 401 expected for expired REST timestamp
        result.record(
            "late_allocate_rejected",
            status="PASS" if not ok else "FAIL",
            allocate_ok=ok,
            error=err,
            lifetime=lifetime,
            note="expired REST timestamp must refuse new Allocate",
        )
    finally:
        ch.close()


def scenario_wrong_auth(
    host: str,
    tls_port: int,
    secret: str,
    result: LabResult,
    ca_cert: Path,
    window_s: int = 30,
) -> None:
    """Wrong password must be refused on a FRESH valid REST username.

    The original username may already be expired by the time this seam runs;
    a correct password would also fail then, so that is not credential-denial
    evidence. Use a fresh username still inside its validity window, prove a
    paired good-credential Allocate + real nonce with that same window, then
    require a genuine auth rejection for the wrong password. A timeout /
    verify:no_response is NOT an authenticated wrong-password verdict.
    """
    auth_expiry_ts = now_wall_int() + int(window_s)
    username = rest_username(auth_expiry_ts, "wrongauth")
    good_password = rest_password(username, secret)

    # Paired good-credential proof (same current validity window).
    ch_good = open_tls_channel(host, tls_port, verbose=False, ca_cert=ca_cert)
    good_alloc_ok = False
    good_nonce = False
    good_err = None
    good_lifetime = None
    try:
        if not ch_good.bind_challenge():
            result.record(
                "wrong_auth_rejected",
                status="NotVerified",
                step="good_challenge",
                defect_reproduced=False,
            )
            return
        ch_good.set_credentials(username, good_password)
        ok_g, lifetime_g, err_g = ch_good.allocate(lifetime=600)
        good_alloc_ok = bool(ok_g)
        good_err = err_g
        good_lifetime = lifetime_g
        if good_alloc_ok:
            peer = listen_udp_peer()
            try:
                if ch_good.create_permission("127.0.0.1", peer.getsockname()[1])[0]:
                    good_nonce = peer_delivers_nonce(ch_good, peer)
            finally:
                try:
                    peer.close()
                except OSError:
                    pass
    finally:
        try:
            ch_good.close()
        except OSError:
            pass

    paired = good_alloc_ok and good_nonce

    # Wrong password on the same fresh username (still valid).
    ch_bad = open_tls_channel(host, tls_port, verbose=False, ca_cert=ca_cert)
    try:
        if not ch_bad.bind_challenge():
            result.record(
                "wrong_auth_rejected",
                status="NotVerified",
                step="bad_challenge",
                paired_good_alloc=good_alloc_ok,
                paired_good_nonce=good_nonce,
                defect_reproduced=False,
            )
            return
        ch_bad.set_credentials(username, "not-the-right-password")
        ok_b, lifetime_b, err_b = ch_bad.allocate(lifetime=600)
        # Genuine authenticated rejection: an error class code, not a timeout.
        auth_rejected = (not ok_b) and err_b in (401, 438, 441, 400, 508)
        timeout_like = (err_b is None) or (
            isinstance(err_b, str) and err_b.startswith("verify:")
        )
        if not paired:
            status = "NotVerified"
        elif timeout_like:
            status = "NotVerified"
        elif ok_b:
            status = "FAIL"
        else:
            status = "PASS" if auth_rejected else "FAIL"
        result.record(
            "wrong_auth_rejected",
            status=status,
            allocate_ok=ok_b,
            error=err_b,
            lifetime=lifetime_b,
            paired_good_alloc=good_alloc_ok,
            paired_good_nonce=good_nonce,
            paired_good_err=good_err,
            paired_good_lifetime=good_lifetime,
            auth_rejected=bool(auth_rejected),
            timeout_like=bool(timeout_like),
            fresh_username_valid=True,
            note=(
                "fresh valid REST username + wrong password; "
                "paired good-credential nonce required; "
                "timeout/no_response is not authenticated wrong-password evidence"
            ),
        )
    finally:
        try:
            ch_bad.close()
        except OSError:
            pass


def peer_delivers_nonce(
    ch: tp.TurnChannel,
    peer_sock: socket.socket,
    payload: bytes | None = None,
    timeout: float = 0.8,
) -> bool:
    """Peer -> relayed address must produce a real Data indication nonce."""
    if not ch.relayed_addr:
        return False
    relayed_ip, relayed_port = ch.relayed_addr[1], ch.relayed_addr[2]
    nonce = payload if payload is not None else os.urandom(24)
    try:
        peer_sock.sendto(nonce, (relayed_ip, relayed_port))
    except OSError:
        return False
    deadline = now_mono() + timeout
    while now_mono() < deadline:
        got = ch.recv_data(timeout=0.3)
        if not got:
            continue
        if got[1] == nonce:
            return True
    return False


def client_send_arrives(
    ch: tp.TurnChannel,
    peer_sock: socket.socket,
    payload: bytes | None = None,
    timeout: float = 0.8,
) -> bool:
    """Client Send indication must arrive as a real UDP payload at the peer."""
    peer_port = peer_sock.getsockname()[1]
    nonce = payload if payload is not None else os.urandom(24)
    try:
        ch.send_indication("127.0.0.1", peer_port, nonce)
    except (BrokenPipeError, ConnectionResetError, OSError, ssl.SSLError):
        return False
    return recv_udp_matching(peer_sock, nonce, timeout)


def scenario_isolation(
    ch_del: tp.TurnChannel,
    ch_keep: tp.TurnChannel,
    peer_del: socket.socket,
    peer_keep: socket.socket,
    result: LabResult,
) -> None:
    """Independent allocation: real nonce delivery, not metadata-only.

    Require independent actual nonce delivery for the retained allocation
    before AND after deletion, and actual absence on the deleted relay.
    """
    if not (ch_del.relayed_addr and ch_keep.relayed_addr):
        result.record(
            "allocation_isolation",
            status="FAIL",
            step="missing_relayed_addrs",
            del_relayed=bool(ch_del.relayed_addr),
            keep_relayed=bool(ch_keep.relayed_addr),
        )
        return
    same = ch_del.relayed_addr[2] == ch_keep.relayed_addr[2]
    if not (ch_del.create_permission("127.0.0.1", peer_del.getsockname()[1])[0]):
        result.record("allocation_isolation", status="FAIL", step="del_permission")
        return
    if not (ch_keep.create_permission("127.0.0.1", peer_keep.getsockname()[1])[0]):
        result.record("allocation_isolation", status="FAIL", step="keep_permission")
        return

    keep_forward_before = peer_delivers_nonce(ch_keep, peer_keep)
    del_forward_before = peer_delivers_nonce(ch_del, peer_del)
    try:
        ok_del, _, err_del = ch_del.refresh(lifetime=0)
    except (BrokenPipeError, ConnectionResetError, OSError, ssl.SSLError):
        ok_del, err_del = False, "transport_closed"
    time.sleep(0.4)
    try:
        ok_keep, lifetime_keep, err_keep = ch_keep.refresh(lifetime=300)
    except (BrokenPipeError, ConnectionResetError, OSError, ssl.SSLError):
        ok_keep, lifetime_keep, err_keep = False, None, "transport_closed"

    keep_forward_after = peer_delivers_nonce(ch_keep, peer_keep)
    del_forward_after = peer_delivers_nonce(ch_del, peer_del)

    isolated = bool(
        (not same)
        and ok_del
        and keep_forward_before
        and del_forward_before
        and keep_forward_after
        and (not del_forward_after)
    )
    result.record(
        "allocation_isolation",
        status="PASS" if isolated else "FAIL",
        distinct_relays=bool(not same),
        del_relayed_port=ch_del.relayed_addr[2],
        keep_relayed_port=ch_keep.relayed_addr[2],
        del_delete_ok=ok_del,
        del_delete_err=err_del,
        keep_refresh_ok=ok_keep,
        keep_lifetime=lifetime_keep,
        keep_refresh_err=err_keep,
        keep_forward_before=bool(keep_forward_before),
        del_forward_before=bool(del_forward_before),
        keep_forward_after=bool(keep_forward_after),
        del_forward_after=bool(del_forward_after),
        note="actual UDP nonce delivery required; no metadata-only substitute",
    )


def scenario_last_fraction_refresh(
    host: str,
    tls_port: int,
    secret: str,
    result: LabResult,
    ca_cert: Path,
    window_s: int,
    poll_interval: float = 0.15,
    auth_expiry_ts: int | None = None,
) -> None:
    """Fresh-window last-fraction Refresh + actual post-bound packet cutoff.

    Uses a NEW TLS channel and a NEW REST credential whose authorization
    window starts now (unless auth_expiry_ts is provided by the caller who
    already issued the credential). Timing is float wall + a sampled fixed
    monotonic target for deadline-0.3.

    PASS requires:
      * real pre-forward immediately preceding the attempt
      * 0 < deadline_wall - attempt_wall <= 0.5 (honest sub-second window)
      * no full-lifetime regrant and no Refresh lifetime past the deadline
      * ZERO unique probes newly sent after the claimed bound arrive
        (including the immediate 0.4s interval). Any post-bound arrival
        is a REST timestamp cutoff failure, not green.
    """
    cred_issue_wall = now_wall()
    cred_issue_mono = now_mono()
    if auth_expiry_ts is None:
        # REST timestamp generation only: integer seconds.
        auth_expiry_ts = now_wall_int() + int(window_s)
    deadline_wall = float(auth_expiry_ts)

    username = rest_username(auth_expiry_ts, "lastfrac")
    password = rest_password(username, secret)

    ch = open_tls_channel(host, tls_port, verbose=False, ca_cert=ca_cert)
    try:
        if not ch.bind_challenge():
            result.record(
                "last_fraction_refresh",
                status="NotVerified",
                step="challenge",
                defect_reproduced=False,
            )
            return
        ch.set_credentials(username, password)
        alloc_wall = now_wall()
        alloc_mono = now_mono()
        ok, lifetime, err = ch.allocate(lifetime=600)
        if not ok:
            result.record(
                "last_fraction_refresh",
                status="NotVerified",
                step="allocate",
                error=err,
                cred_issue_wall=cred_issue_wall,
                alloc_wall=alloc_wall,
                defect_reproduced=False,
            )
            return
        peer = listen_udp_peer()
        try:
            if not ch.create_permission("127.0.0.1", peer.getsockname()[1])[0]:
                result.record(
                    "last_fraction_refresh",
                    status="NotVerified",
                    step="permission",
                    defect_reproduced=False,
                )
                return

            def probe_timed() -> tuple[bool, float, float]:
                n = os.urandom(24)
                send_wall = now_wall()
                send_mono = now_mono()
                try:
                    ch.send_indication("127.0.0.1", peer.getsockname()[1], n)
                    # Return immediately on matching nonce; bound by budget.
                    got = recv_udp_matching(peer, n, 0.4)
                except (BrokenPipeError, ConnectionResetError, OSError, ssl.SSLError):
                    got = False
                return got, send_wall, send_mono

            pre_forward, pre_wall, pre_mono = probe_timed()
            if not pre_forward:
                result.record(
                    "last_fraction_refresh",
                    status="NotVerified",
                    step="pre_forward",
                    pre_forward=False,
                    note="pre-forward required before last-fraction window; not a native defect claim",
                    window_s=window_s,
                    cred_issue_wall=cred_issue_wall,
                    deadline_wall=deadline_wall,
                    defect_reproduced=False,
                )
                return

            # Sample a fixed monotonic target for deadline-0.3.
            map_wall = now_wall()
            map_mono = now_mono()
            target_wall = deadline_wall - 0.3
            target_mono = map_mono + (target_wall - map_wall)
            if map_mono >= target_mono + 0.05:
                result.record(
                    "last_fraction_refresh",
                    status="NotVerified",
                    step="missed_window",
                    pre_forward=True,
                    note=(
                        "already past deadline-0.3 before wait; deny missed window; "
                        "not a reproduced-native-defect claim"
                    ),
                    window_s=window_s,
                    cred_issue_wall=cred_issue_wall,
                    deadline_wall=deadline_wall,
                    map_wall=map_wall,
                    target_wall=target_wall,
                    in_last_fraction=False,
                    defect_reproduced=False,
                )
                return
            while now_mono() < target_mono:
                remain = target_mono - now_mono()
                time.sleep(min(0.05, max(0.0, remain)))

            # Real pre-forward immediately preceding the attempt.
            imm_forward, imm_wall, imm_mono = probe_timed()
            if not imm_forward:
                result.record(
                    "last_fraction_refresh",
                    status="NotVerified",
                    step="immediate_pre_forward",
                    pre_forward=True,
                    immediate_pre_forward=False,
                    note="forwarding must be alive immediately before Refresh; not a native defect claim",
                    window_s=window_s,
                    cred_issue_wall=cred_issue_wall,
                    deadline_wall=deadline_wall,
                    in_last_fraction=False,
                    defect_reproduced=False,
                )
                return

            attempt_mono = now_mono()
            attempt_wall = now_wall()
            try:
                ok_r, lifetime_r, err_r = ch.refresh(lifetime=600)
            except (BrokenPipeError, ConnectionResetError, OSError, ssl.SSLError):
                ok_r, lifetime_r, err_r = False, None, "transport_closed"

            deadline_minus_attempt = deadline_wall - attempt_wall
            in_last_fraction = 0.0 < deadline_minus_attempt <= 0.5
            attempt_before_deadline = attempt_wall < deadline_wall

            # Continuous unique probes. ANY newly sent probe after the claimed
            # bound that arrives is a cutoff violation (including +0.4s).
            samples: list[dict] = []
            cutoff_violations: list[dict] = []
            post_bound_packet_arrivals = 0
            last_success_rel = None
            first_failure_rel = None
            last_success_send_wall = None
            first_failure_send_wall = None

            end_mono = map_mono + ((deadline_wall + 2.0) - map_wall)
            while now_mono() < end_mono:
                got, send_wall, send_mono = probe_timed()
                rel = send_mono - cred_issue_mono
                samples.append(
                    {
                        "send_wall": send_wall,
                        "send_mono": send_mono,
                        "rel_s": round(float(rel), 6),
                        "got": bool(got),
                        "after_deadline": bool(send_wall >= deadline_wall),
                    }
                )
                if got and send_wall < deadline_wall:
                    if last_success_rel is None or rel > last_success_rel:
                        last_success_rel = round(float(rel), 6)
                        last_success_send_wall = send_wall
                if send_wall >= deadline_wall:
                    if got:
                        post_bound_packet_arrivals += 1
                        cutoff_violations.append(
                            {
                                "send_wall": send_wall,
                                "send_mono": send_mono,
                                "rel_s": round(float(rel), 6),
                                "got": True,
                            }
                        )
                    elif first_failure_rel is None:
                        first_failure_rel = round(float(rel), 6)
                        first_failure_send_wall = send_wall
                time.sleep(poll_interval)

            # Explicit immediate post-bound probes at +0.05 .. +1.0
            for off in (0.05, 0.15, 0.25, 0.40, 0.60, 1.00):
                target = deadline_wall + off
                while now_wall() < target:
                    time.sleep(min(0.05, max(0.0, target - now_wall())))
                got, send_wall, send_mono = probe_timed()
                samples.append(
                    {
                        "send_wall": send_wall,
                        "send_mono": send_mono,
                        "rel_s": round(float(send_mono - cred_issue_mono), 6),
                        "got": bool(got),
                        "after_deadline": bool(send_wall >= deadline_wall),
                        "planned_offset_s": off,
                    }
                )
                if got and send_wall >= deadline_wall:
                    post_bound_packet_arrivals += 1
                    cutoff_violations.append(
                        {
                            "send_wall": send_wall,
                            "send_mono": send_mono,
                            "rel_s": round(float(send_mono - cred_issue_mono), 6),
                            "got": True,
                            "planned_offset_s": off,
                        }
                    )

            past_expiry = now_wall() > deadline_wall
            post_forward = any(
                s.get("after_deadline") and s.get("got") for s in samples
            )
            transport_dead = False
            try:
                ch.refresh(lifetime=60)
            except (BrokenPipeError, ConnectionResetError, OSError, ssl.SSLError):
                transport_dead = True

            regrant = bool(ok_r and (lifetime_r is not None and lifetime_r >= int(window_s)))
            extends_past_deadline = bool(
                ok_r
                and lifetime_r is not None
                and (attempt_wall + float(lifetime_r) > deadline_wall)
            )
            # PASS only with honest sub-second attempt and zero post-bound arrivals.
            bound_holds = bool(
                pre_forward
                and imm_forward
                and in_last_fraction
                and attempt_before_deadline
                and (not regrant)
                and (not extends_past_deadline)
                and past_expiry
                and (not post_forward)
                and post_bound_packet_arrivals == 0
            )
            # Missed window / setup / protocol failure is NotVerified with
            # defect_reproduced=false — never a reproduced-native-defect claim.
            concrete_defect = bool(
                (isinstance(post_bound_packet_arrivals, int) and post_bound_packet_arrivals > 0)
                or (isinstance(len(cutoff_violations), int) and len(cutoff_violations) > 0)
                or (in_last_fraction and ok_r and (regrant or extends_past_deadline))
            )
            if not pre_forward or not imm_forward:
                status = "NotVerified"
                note = "setup/protocol failure before last-fraction window; not a native defect claim"
            elif not in_last_fraction:
                status = "NotVerified"
                note = (
                    "refresh missed planned last-fraction window; "
                    "not a green bound and not a reproduced-native-defect claim"
                )
            elif bound_holds:
                status = "PASS"
                note = ""
            elif concrete_defect:
                status = "FAIL"
                if post_bound_packet_arrivals > 0:
                    note = (
                        "REST timestamp cutoff failure: newly sent post-bound probe "
                        "arrived; not a hard-60s-from-issue claim"
                    )
                elif extends_past_deadline:
                    note = "Refresh lifetime extends past credential timestamp deadline"
                else:
                    note = "authenticated last-fraction Refresh re-granted lifetime past bound"
            else:
                status = "NotVerified"
                note = "in-window attempt without concrete defect evidence; not a native defect claim"

            result.record(
                "last_fraction_refresh",
                status=status,
                window_s=window_s,
                auth_expiry_ts=auth_expiry_ts,
                deadline_wall=deadline_wall,
                cred_issue_wall=cred_issue_wall,
                cred_issue_mono=cred_issue_mono,
                cred_to_deadline_s=round(deadline_wall - cred_issue_wall, 6),
                alloc_wall=alloc_wall,
                alloc_mono=alloc_mono,
                alloc_to_deadline_s=round(deadline_wall - alloc_wall, 6),
                pre_forward=pre_forward,
                pre_forward_wall=pre_wall,
                immediate_pre_forward=imm_forward,
                immediate_pre_forward_wall=imm_wall,
                refresh_ok=ok_r,
                refresh_lifetime=lifetime_r,
                refresh_err=err_r,
                attempt_mono=attempt_mono,
                attempt_wall=attempt_wall,
                attempt_relative_s=round(float(attempt_mono - cred_issue_mono), 6),
                attempt_relative_from_alloc_s=round(float(attempt_mono - alloc_mono), 6),
                deadline_minus_attempt_s=round(float(deadline_minus_attempt), 6),
                in_last_fraction=bool(in_last_fraction),
                attempt_before_deadline=bool(attempt_before_deadline),
                regrant_full_lifetime=bool(regrant),
                extends_past_deadline=bool(extends_past_deadline),
                post_forward=bool(post_forward),
                post_bound_packet_arrivals=int(post_bound_packet_arrivals),
                cutoff_violations=int(len(cutoff_violations)),
                cutoff_violation_samples=cutoff_violations[:8],
                transport_dead=transport_dead,
                past_expiry=bool(past_expiry),
                bound_holds=bound_holds,
                concrete_defect=bool(concrete_defect),
                last_success_rel_s=last_success_rel,
                last_success_send_wall=last_success_send_wall,
                first_failure_rel_s=first_failure_rel,
                first_failure_send_wall=first_failure_send_wall,
                poll_interval=poll_interval,
                cutoff_samples=len(samples),
                map_wall=map_wall,
                map_mono=map_mono,
                target_wall=target_wall,
                note=note,
                measurement_note=(
                    "float wall + sampled fixed monotonic target; "
                    "REST integer timestamps only at credential generation; "
                    "hard60 from issue Not Verified"
                ),
            )
        finally:
            try:
                peer.close()
            except OSError:
                pass
    finally:
        try:
            ch.close()
        except OSError:
            pass


def past_expiry_now(auth_expiry_ts: int | float) -> bool:
    return now_wall() >= float(auth_expiry_ts)


def scenario_cleanup_check(
    proc: subprocess.Popen,
    log_path: Path,
    udp_port: int,
    tls_port: int,
    result: LabResult,
) -> None:
    """Process-owned cleanup: after SIGTERM, no leftover listeners, process reaped."""
    kill_turnserver(proc)
    time.sleep(0.3)
    reaped = proc.poll() is not None
    udp_free = True
    tls_free = True
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", udp_port))
        s.close()
    except OSError:
        udp_free = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", tls_port))
        s.close()
    except OSError:
        tls_free = False
    log_tail = ""
    if log_path.exists():
        raw = log_path.read_bytes()[-2000:]
        # Never include secrets; config uses a random secret never printed.
        log_tail = raw.decode("utf-8", errors="replace")
        # Redact anything that looks like base64 secrets just in case
        log_tail = "".join(c if c.isalnum() or c in " \n\t:./_-[]()" else "." for c in log_tail)
    result.record(
        "matching_cleanup",
        status="PASS" if (reaped and udp_free and tls_free) else "FAIL",
        process_reaped=reaped,
        returncode=proc.returncode,
        udp_port_free=udp_free,
        tls_port_free=tls_free,
    )


def write_result(result: LabResult, out_arg: str, workdir: Path) -> Path:
    result.meta.setdefault("inv_id", os.environ.get("INV_ID", ""))
    result.meta["finished_wall"] = now_wall()
    result.meta["finished_mono"] = now_mono()
    out_path = Path(out_arg) if out_arg else workdir / "result.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(result.to_json())
    print(f"wrote {out_path}", flush=True)
    print(result.to_json(), flush=True)
    return out_path


def finalize_fail_closed(result: LabResult, out_arg: str, workdir: Path, why: str) -> int:
    result.meta["mandatory_status"] = result.meta.get("mandatory_status", {})
    result.meta["mandatory_all_pass"] = False
    result.meta["authorization_bound_holds"] = False
    result.meta["defect_reproduced"] = False
    result.meta["fail_closed_reason"] = why
    write_result(result, out_arg, workdir)
    return 1


def run_lastfraction_focus(args: argparse.Namespace, binary: Path) -> int:
    """Coordinator-faithful last-fraction probe on a fresh allocation.

    Allocate with short REST auth, forward a nonce, Refresh 0.3s before the
    bound, then require no actual peer UDP after expiry.
    """
    result = LabResult()
    result.meta = {
        "mode": "lastfraction",
        "auth_seconds": args.auth_seconds,
        "turnserver_bin": str(binary),
        "turnserver_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "started_wall": now_wall(),
        "started_mono": now_mono(),
        "transport": "tls-tcp + udp-relay",
        "tls_verify": "generated-ca",
        "inv_id": os.environ.get("INV_ID", ""),
    }
    scratch = private_workdir("lastfrac-")
    workdir = scratch
    secret = secrets.token_urlsafe(32)
    cert, key = generate_certs(workdir / "certs")
    udp_port = args.udp_port or _pick_port(socket.SOCK_DGRAM)
    tls_port = args.tls_port or _pick_port(socket.SOCK_STREAM)
    conf_path = write_turn_config(
        workdir / "turnserver.conf", secret, cert, key, udp_port, tls_port,
        max_allocate_lifetime=args.max_allocate_lifetime or 600,
    )
    log_path = workdir / "turnserver.log"
    print(f"workdir={workdir}", flush=True)
    proc = start_turnserver(binary, conf_path, log_path)
    channels: list[tp.TurnChannel] = []
    peers: list[socket.socket] = []
    try:
        if not wait_port("127.0.0.1", tls_port, timeout=12.0):
            result.record("boot", status="FAIL", step="tls_port_not_listening")
            return finalize_fail_closed(result, args.out, workdir, "tls_port_not_listening")
        result.record("boot", status="PASS", udp_port=udp_port, tls_port=tls_port)
        # REST timestamp generation only (integer seconds).
        auth_expiry_ts = now_wall_int() + args.auth_seconds
        username = rest_username(auth_expiry_ts, args.user)
        password = rest_password(username, secret)
        ch = open_tls_channel("127.0.0.1", tls_port, verbose=args.verbose, ca_cert=cert)
        channels.append(ch)
        if not ch.bind_challenge():
            result.record("boot", status="FAIL", step="challenge")
            return finalize_fail_closed(result, args.out, workdir, "challenge")
        ch.set_credentials(username, password)
        ok, lifetime, err = ch.allocate(lifetime=600)
        if not ok:
            result.record("boot", status="FAIL", step="allocate", error=err)
            return finalize_fail_closed(result, args.out, workdir, "allocate")
        result.meta["initial_alloc_lifetime"] = lifetime
        result.meta["auth_expiry_ts"] = auth_expiry_ts
        result.meta["deadline_wall"] = float(auth_expiry_ts)
        peer = listen_udp_peer()
        peers.append(peer)
        if not ch.create_permission("127.0.0.1", peer.getsockname()[1])[0]:
            result.record("boot", status="FAIL", step="permission")
            return finalize_fail_closed(result, args.out, workdir, "permission")
        scenario_last_fraction_refresh(
            "127.0.0.1",
            tls_port,
            secret,
            result,
            cert,
            window_s=args.auth_seconds,
            auth_expiry_ts=auth_expiry_ts,
        )
        scenario_cleanup_check(proc, log_path, udp_port, tls_port, result)
        lf = result.scenarios.get("last_fraction_refresh", {})
        c = result.scenarios.get("matching_cleanup", {})
        post_arrivals = lf.get("post_bound_packet_arrivals", 0)
        cutoff_violations = lf.get("cutoff_violations", 0)
        in_window = lf.get("in_last_fraction") is True
        concrete_lf = bool(
            lf.get("concrete_defect") is True
            or (isinstance(post_arrivals, int) and post_arrivals > 0)
            or (isinstance(cutoff_violations, int) and cutoff_violations > 0)
            or (
                in_window
                and lf.get("refresh_ok") is True
                and (lf.get("regrant_full_lifetime") is True or lf.get("extends_past_deadline") is True)
            )
        )
        all_pass = (
            lf.get("status") == "PASS"
            and c.get("status") == "PASS"
            and lf.get("bound_holds") is True
            and post_arrivals == 0
        )
        result.meta["mandatory_status"] = {
            "boot": result.scenarios.get("boot", {}).get("status"),
            "last_fraction_refresh": lf.get("status"),
            "matching_cleanup": c.get("status"),
        }
        result.meta["mandatory_all_pass"] = all_pass
        result.meta["authorization_bound_holds"] = bool(lf.get("bound_holds"))
        # Missed window / setup failure must NOT claim a reproduced native defect.
        result.meta["defect_reproduced"] = bool(concrete_lf and in_window)
        write_result(result, args.out, workdir)
        return 0 if all_pass else 1
    finally:
        for ch in channels:
            try:
                ch.close()
            except OSError:
                pass
        for peer in peers:
            try:
                peer.close()
            except OSError:
                pass
        if proc_alive(proc):
            kill_turnserver(proc)


def run_clockfault_focus(args: argparse.Namespace, binary: Path) -> int:
    """Clock-fault injection: real native binary must deny new/renewed authority.

    Uses a test-only compile-time seam (TURN_TEST_CLOCK_FAULT) that makes
    turn_monotonic_ms return its failure sentinel. This is fault injection,
    not OS clock-fault acceptance. Expected: Allocate and Refresh fail closed
    even with a still-valid REST timestamp. Never deadline-0 unlimited.
    """
    result = LabResult()
    result.meta = {
        "mode": "clockfault",
        "fault_injection": True,
        "fault_kind": "TURN_TEST_CLOCK_FAULT compile-time seam",
        "os_clock_mutated": False,
        "auth_seconds": args.auth_seconds,
        "turnserver_bin": str(binary),
        "turnserver_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "started_wall": now_wall(),
        "started_mono": now_mono(),
        "transport": "tls-tcp + udp-relay",
        "tls_verify": "generated-ca",
        "inv_id": os.environ.get("INV_ID", ""),
    }
    scratch = private_workdir("clockfault-")
    workdir = scratch
    secret = secrets.token_urlsafe(32)
    cert, key = generate_certs(workdir / "certs")
    udp_port = args.udp_port or _pick_port(socket.SOCK_DGRAM)
    tls_port = args.tls_port or _pick_port(socket.SOCK_STREAM)
    conf_path = write_turn_config(
        workdir / "turnserver.conf", secret, cert, key, udp_port, tls_port,
        max_allocate_lifetime=args.max_allocate_lifetime or 600,
    )
    log_path = workdir / "turnserver.log"
    print(f"workdir={workdir}", flush=True)
    proc = start_turnserver(binary, conf_path, log_path)
    channels: list[tp.TurnChannel] = []
    try:
        if not wait_port("127.0.0.1", tls_port, timeout=12.0):
            result.record("boot", status="FAIL", step="tls_port_not_listening")
            return finalize_fail_closed(result, args.out, workdir, "tls_port_not_listening")
        result.record("boot", status="PASS", udp_port=udp_port, tls_port=tls_port)

        # Valid REST credential (integer timestamp still in the future).
        auth_expiry_ts = now_wall_int() + args.auth_seconds
        username = rest_username(auth_expiry_ts, args.user)
        password = rest_password(username, secret)
        result.meta["auth_expiry_ts"] = auth_expiry_ts

        ch = open_tls_channel("127.0.0.1", tls_port, verbose=args.verbose, ca_cert=cert)
        channels.append(ch)
        if not ch.bind_challenge():
            result.record("clockfault_allocate_denied", status="FAIL", step="challenge")
            return finalize_fail_closed(result, args.out, workdir, "challenge")
        ch.set_credentials(username, password)

        ok, lifetime, err = ch.allocate(lifetime=600)
        allocate_denied = (not ok) and (lifetime is None) and (
            err in (401, 437, 438, 508) or (isinstance(err, str) and err.startswith("verify:"))
        )
        # Fail-closed means: no successful grant. A 401/437/expired-style
        # rejection is the desired outcome. Unlimited/600s grant is a defect.
        regrant = bool(ok and lifetime is not None and lifetime >= 1)
        result.record(
            "clockfault_allocate_denied",
            status="PASS" if (allocate_denied or (not ok and not regrant)) else "FAIL",
            allocate_ok=ok,
            lifetime=lifetime,
            error=err,
            fail_closed=bool(not ok and lifetime is None),
            granted_unlimited=bool(ok and lifetime is not None and lifetime >= 600),
            note="fault injection: valid REST ts but monotonic clock failure must deny",
        )

        ok_r, lifetime_r, err_r = ch.refresh(lifetime=600)
        refresh_denied = (not ok_r) and (lifetime_r is None)
        result.record(
            "clockfault_refresh_denied",
            status="PASS" if refresh_denied else "FAIL",
            refresh_ok=ok_r,
            lifetime=lifetime_r,
            error=err_r,
            fail_closed=refresh_denied,
            granted_unlimited=bool(ok_r and lifetime_r is not None and lifetime_r >= 600),
            note="fault injection: Refresh must not renew authority on clock failure",
        )

        scenario_cleanup_check(proc, log_path, udp_port, tls_port, result)

        a = result.scenarios.get("clockfault_allocate_denied", {})
        r = result.scenarios.get("clockfault_refresh_denied", {})
        c = result.scenarios.get("matching_cleanup", {})
        all_pass = (
            a.get("status") == "PASS"
            and r.get("status") == "PASS"
            and c.get("status") == "PASS"
            and a.get("granted_unlimited") is False
            and r.get("granted_unlimited") is False
        )
        result.meta["mandatory_status"] = {
            "boot": result.scenarios.get("boot", {}).get("status"),
            "clockfault_allocate_denied": a.get("status"),
            "clockfault_refresh_denied": r.get("status"),
            "matching_cleanup": c.get("status"),
        }
        result.meta["mandatory_all_pass"] = all_pass
        result.meta["authorization_bound_holds"] = all_pass
        result.meta["defect_reproduced"] = False
        write_result(result, args.out, workdir)
        return 0 if all_pass else 1
    finally:
        for ch in channels:
            try:
                ch.close()
            except OSError:
                pass
        if proc_alive(proc):
            kill_turnserver(proc)


def run_lab(args: argparse.Namespace) -> int:
    binary = Path(args.turnserver_bin)
    if not binary.is_file():
        print(f"turnserver binary not found: {binary}", file=sys.stderr)
        return 2

    auth_seconds = args.auth_seconds
    post_expiry_window = args.post_expiry_window
    sample_interval = args.sample_interval
    silent_wait = args.silent_wait

    result = LabResult()
    result.meta = {
        "mode": args.mode,
        "auth_seconds": auth_seconds,
        "post_expiry_window": post_expiry_window,
        "sample_interval": sample_interval,
        "silent_wait": silent_wait,
        "turnserver_bin": str(binary),
        "turnserver_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "started_wall": now_wall(),
        "started_mono": now_mono(),
        "host": "127.0.0.1",
        "transport": "tls-tcp + udp-relay",
        "inv_id": os.environ.get("INV_ID", ""),
        "lab_root": str(lab_root()),
    }

    workdir = private_workdir("run-")
    secret = secrets.token_urlsafe(32)
    cert, key = generate_certs(workdir / "certs")
    udp_port = args.udp_port or _pick_port(socket.SOCK_DGRAM)
    tls_port = args.tls_port or _pick_port(socket.SOCK_STREAM)

    conf_path = write_turn_config(
        workdir / "turnserver.conf",
        secret,
        cert,
        key,
        udp_port,
        tls_port,
        max_allocate_lifetime=args.max_allocate_lifetime,
    )
    log_path = workdir / "turnserver.log"

    print(f"workdir={workdir}", flush=True)
    print(f"ports udp={udp_port} tls={tls_port}", flush=True)

    proc = start_turnserver(binary, conf_path, log_path)
    channels: list[tp.TurnChannel] = []
    peers: list[socket.socket] = []
    try:
        if not wait_port("127.0.0.1", tls_port, timeout=12.0):
            result.record("boot", status="FAIL", step="tls_port_not_listening")
            if log_path.exists():
                sys.stderr.write(log_path.read_text(errors="replace")[-4000:])
            return finalize_fail_closed(result, args.out, workdir, "tls_port_not_listening")
        # UDP listening-port is client-facing UDP; for TLS/TCP clients the
        # TLS port is the control plane. We primarily use TLS/TCP.
        result.record("boot", status="PASS", udp_port=udp_port, tls_port=tls_port)

        # REST timestamp generation only (integer seconds).
        auth_expiry_ts = now_wall_int() + auth_seconds
        username = rest_username(auth_expiry_ts, args.user)
        password = rest_password(username, secret)

        # Primary channel A: allocate now (inside authorization window)
        ch_a = open_tls_channel("127.0.0.1", tls_port, verbose=args.verbose, ca_cert=cert)
        channels.append(ch_a)
        if not ch_a.bind_challenge():
            result.record("boot", status="FAIL", step="challenge")
            return finalize_fail_closed(result, args.out, workdir, "challenge")
        ch_a.set_credentials(username, password)
        ok, lifetime, err = ch_a.allocate(lifetime=600)
        if not ok:
            result.record("boot", status="FAIL", step="allocate", error=err)
            return finalize_fail_closed(result, args.out, workdir, "allocate")
        result.meta["initial_alloc_lifetime"] = lifetime
        result.meta["username_shape"] = f"{auth_expiry_ts}:{args.user}"
        result.meta["auth_expiry_ts"] = auth_expiry_ts
        result.meta["deadline_wall"] = float(auth_expiry_ts)
        result.meta["tls_verify"] = "generated-ca"
        result.meta["ca_cert_sha256"] = hashlib.sha256(cert.read_bytes()).hexdigest()

        peer_a = listen_udp_peer()
        peer_b = listen_udp_peer()
        peer_c = listen_udp_peer()
        peer_keep = listen_udp_peer()
        peers.extend([peer_a, peer_b, peer_c, peer_keep])

        # 1) Forwarding before expiry (channel A)
        scenario_forward_before_expiry(ch_a, peer_a, b"lab-forward-0001", result)

        # 6) Isolation early (A and C live): delete C, A must survive.
        ch_c = open_tls_channel("127.0.0.1", tls_port, verbose=args.verbose, ca_cert=cert)
        channels.append(ch_c)
        ch_c.bind_challenge()
        ch_c.set_credentials(username, password)
        ok_c, lifetime_c, err_c = ch_c.allocate(lifetime=600)
        result.record(
            "isolation_setup_c",
            status="PASS" if ok_c else "FAIL",
            ok=ok_c,
            lifetime=lifetime_c,
            err=err_c,
        )
        if ok_c:
            scenario_isolation(ch_c, ch_a, peer_c, peer_keep, result)
        else:
            result.record("allocation_isolation", status="FAIL", step="isolation_allocate_c", error=err_c)

        # 3) Prepare silent client B (allocate now, confirm path with a real
        #    UDP nonce receipt, then stay silent — no Refresh — through expiry).
        ch_b = open_tls_channel("127.0.0.1", tls_port, verbose=args.verbose, ca_cert=cert)
        channels.append(ch_b)
        ch_b.bind_challenge()
        ch_b.set_credentials(username, password)
        ok_b, lifetime_b, err_b = ch_b.allocate(lifetime=600)
        result.record(
            "isolation_setup",
            status="PASS" if ok_b else "FAIL",
            ok=ok_b,
            lifetime=lifetime_b,
            err=err_b,
        )
        silent_pre_ok = False
        silent_pre_note = ""
        if ok_b:
            if not ch_b.create_permission("127.0.0.1", peer_b.getsockname()[1])[0]:
                silent_pre_note = "permission_failed"
            else:
                silent_pre_ok = client_send_arrives(ch_b, peer_b, b"pre-silent-nonce")
                if not silent_pre_ok:
                    silent_pre_note = "no_udp_nonce_receipt_before_silence"
        result.meta["silent_pre_ok"] = bool(silent_pre_ok)
        result.meta["silent_pre_note"] = silent_pre_note

        # 2) Repeated Refresh on A through and past expiry (B stays silent).
        refresh_info = scenario_refresh_after_expiry(
            ch_a,
            secret,
            username,
            password,
            auth_expiry_ts,
            result,
            sample_interval=sample_interval,
            post_expiry_window=post_expiry_window,
        )

        # 3b) Silent client B: probe after auth expiry with no Refresh on B.
        if ok_b:
            scenario_silent_client_after_wait(ch_b, peer_b, result, auth_expiry_ts, silent_pre_ok)
        else:
            result.record("silent_client_expires", status="FAIL", step="allocate", error=err_b)

        # 2b) Last-fraction Refresh on a FRESH allocation/credential window.
        #     Accelerated uses a 7s window; boundary60 uses a real 60s window.
        lf_window = 7 if args.mode == "accelerated" else 60
        scenario_last_fraction_refresh(
            "127.0.0.1", tls_port, secret, result, cert, window_s=lf_window
        )

        # 4) Late allocate (after expiry)
        scenario_late_allocate("127.0.0.1", tls_port, secret, username, password, result, ca_cert=cert)

        # 5) Wrong auth (fresh valid REST username + wrong password + paired good-cred)
        scenario_wrong_auth("127.0.0.1", tls_port, secret, result, ca_cert=cert)

        for ch in channels:
            try:
                ch.close()
            except OSError:
                pass
        for peer in peers:
            try:
                peer.close()
            except OSError:
                pass

        # 7) Cleanup
        scenario_cleanup_check(proc, log_path, udp_port, tls_port, result)

        # Gate summary: exit status ANDs every mandatory scenario.
        mandatory = (
            "boot",
            "allocate_and_forward",
            "allocation_isolation",
            "refresh_after_expiry",
            "silent_client_expires",
            "last_fraction_refresh",
            "late_allocate_rejected",
            "wrong_auth_rejected",
            "matching_cleanup",
        )
        mandatory_status = {k: result.scenarios.get(k, {}).get("status") for k in mandatory}
        all_pass = all(v == "PASS" for v in mandatory_status.values())
        unbounded = result.scenarios.get("refresh_after_expiry", {}).get("unbounded_after_expiry")
        lf = result.scenarios.get("last_fraction_refresh", {})
        silent = result.scenarios.get("silent_client_expires", {})
        post_arrivals = lf.get("post_bound_packet_arrivals", 0)
        cutoff_violations = lf.get("cutoff_violations", 0)
        bound_holds = lf.get("bound_holds")
        silent_destroyed = silent.get("destroyed")
        result.meta["mandatory_status"] = mandatory_status
        result.meta["mandatory_all_pass"] = all_pass
        result.meta["authorization_bound_holds"] = bool(
            (unbounded is False) and all_pass and (bound_holds is True) and (silent_destroyed is True)
        )
        # Concrete native-defect evidence only. Missed window / setup failure
        # (silent_pre_ok false, in_last_fraction false without packet proof)
        # must NOT be reported as a reproduced-native-defect.
        lf_in_window = lf.get("in_last_fraction") is True
        concrete_refresh = unbounded is True
        concrete_lf = bool(
            lf.get("concrete_defect") is True
            or (isinstance(post_arrivals, int) and post_arrivals > 0)
            or (isinstance(cutoff_violations, int) and cutoff_violations > 0)
            or (
                lf_in_window
                and lf.get("refresh_ok") is True
                and (lf.get("regrant_full_lifetime") is True or lf.get("extends_past_deadline") is True)
            )
        )
        concrete_silent = bool(silent_pre_ok and silent_destroyed is False)
        result.meta["defect_reproduced"] = bool(
            concrete_refresh or concrete_lf or concrete_silent
        )
        write_result(result, args.out, workdir)

        # Exit 0 only when every mandatory scenario PASSES. A reproduced
        # stock defect is a real lab outcome (exit 1), not a harness crash.
        return 0 if all_pass else 1
    finally:
        for ch in channels:
            try:
                ch.close()
            except OSError:
                pass
        for peer in peers:
            try:
                peer.close()
            except OSError:
                pass
        if proc_alive(proc):
            kill_turnserver(proc)


def _pick_port(sock_type: int) -> int:
    if sock_type == socket.SOCK_DGRAM:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def main() -> int:
    p = argparse.ArgumentParser(description="coturn allocation-expiry lab runner")
    p.add_argument("--turnserver-bin", default=DEFAULT_TURNSERVER)
    p.add_argument("--mode", choices=("accelerated", "boundary60", "lastfraction", "clockfault"),
                   default="accelerated")
    p.add_argument("--auth-seconds", type=int, default=None,
                   help="REST credential lifetime in seconds (default by mode)")
    p.add_argument("--post-expiry-window", type=float, default=8.0,
                   help="seconds to keep Refreshing after auth expiry")
    p.add_argument("--sample-interval", type=float, default=1.0)
    p.add_argument("--silent-wait", type=float, default=None,
                   help="seconds to wait for silent-client destruction")
    p.add_argument("--max-allocate-lifetime", type=int, default=None,
                   help="server max-allocate-lifetime (default by mode)")
    p.add_argument("--udp-port", type=int, default=0)
    p.add_argument("--tls-port", type=int, default=0)
    p.add_argument("--user", default="labuser")
    p.add_argument("--out", default="")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    # Bound argument durations so a mis-invocation cannot hang the runner.
    if args.auth_seconds is not None and not (1 <= args.auth_seconds <= 90):
        p.error("--auth-seconds must be in 1..90")
    if not (1.0 <= args.post_expiry_window <= 20.0):
        p.error("--post-expiry-window must be in 1..20")
    if not (0.2 <= args.sample_interval <= 5.0):
        p.error("--sample-interval must be in 0.2..5")
    if args.silent_wait is not None and not (0.0 <= args.silent_wait <= 30.0):
        p.error("--silent-wait must be in 0..30")
    if args.max_allocate_lifetime is not None and not (1 <= args.max_allocate_lifetime <= 600):
        p.error("--max-allocate-lifetime must be in 1..600")

    if args.auth_seconds is None:
        if args.mode == "accelerated":
            args.auth_seconds = 15
        elif args.mode == "lastfraction":
            args.auth_seconds = 7
        else:
            args.auth_seconds = 60
    if args.silent_wait is None:
        args.silent_wait = 12.0 if args.mode == "accelerated" else 25.0
    if args.max_allocate_lifetime is None:
        # Keep allocations long enough to Refresh past auth expiry; the
        # authorization deadline (not the lifetime timer) is under test.
        args.max_allocate_lifetime = 600

    if args.mode == "lastfraction":
        return run_lastfraction_focus(args, Path(args.turnserver_bin))
    if args.mode == "clockfault":
        return run_clockfault_focus(args, Path(args.turnserver_bin))
    return run_lab(args)


if __name__ == "__main__":
    sys.exit(main())
