#!/usr/bin/env python3
"""Owned regression: Refresh lifetime=0 must drop stale permission/channel auth.

Reproduces the coordinator reallocation failure mode without editing frozen
protocol/oracle modules: same TLS connection deletes then reallocates; a peer
that only had the OLD CreatePermission must NOT forward after the replacement
allocation. Independent allocation B must keep forwarding.

Requires PATCHED_BIN (and optionally STOCK_BIN) in the environment.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_expiry_lab as lab  # noqa: E402


def task_workdir() -> Path:
    """Private 0700 workdir under a created LAB_ROOT or the tempfile default."""
    lab_root_env = os.environ.get("LAB_ROOT", "").strip()
    if lab_root_env:
        base = Path(lab_root_env)
    else:
        base = Path(tempfile.gettempdir()) / "relay-lab-delrealloc"
    base.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="owned-delrealloc-", dir=str(base)))
    os.chmod(workdir, 0o700)
    return workdir


def run_one(binary: Path) -> dict:
    out = task_workdir()
    os.environ["LAB_ROOT"] = str(out)
    os.environ["TMPDIR"] = str(out)
    secret = secrets.token_urlsafe(32)
    crt, key = lab.generate_certs(out / "certs")
    udp = lab._pick_port(socket.SOCK_DGRAM)
    tls = lab._pick_port(socket.SOCK_STREAM)
    conf = lab.write_turn_config(
        out / "turnserver.conf", secret, crt, key, udp, tls, max_allocate_lifetime=600
    )
    proc = lab.start_turnserver(binary, conf, out / "turnserver.log")
    channels = []
    peers = []
    rec = {
        "binary": str(binary),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "scope": "owned delete-realloc stale permission seam",
    }
    try:
        if not lab.wait_port("127.0.0.1", tls, timeout=10):
            raise RuntimeError("boot unavailable")
        expiry = int(time.time()) + 30
        user = lab.rest_username(expiry, "delrealloc")
        password = lab.rest_password(user, secret)
        for _ in range(2):
            ch = lab.open_tls_channel("127.0.0.1", tls, verbose=False, ca_cert=crt)
            channels.append(ch)
            if not ch.bind_challenge():
                raise RuntimeError("challenge failed")
            ch.set_credentials(user, password)
            ok, lifetime, err = ch.allocate(lifetime=600)
            if not ok:
                raise RuntimeError(f"allocate failed: {err}")
            peer = lab.listen_udp_peer()
            peers.append(peer)
            if not ch.create_permission("127.0.0.1", peer.getsockname()[1])[0]:
                raise RuntimeError("permission failed")
        rec["A_pre"] = lab.peer_delivers_nonce(channels[0], peers[0])
        rec["B_pre"] = lab.peer_delivers_nonce(channels[1], peers[1])
        ok, life, err = channels[0].refresh(lifetime=0)
        rec["delete_ok"] = bool(ok) and life == 0
        time.sleep(0.2)
        rec["A_after_delete"] = lab.peer_delivers_nonce(channels[0], peers[0])
        rec["B_after_delete"] = lab.peer_delivers_nonce(channels[1], peers[1])
        ok, life, err = channels[0].allocate(lifetime=600)
        rec["realloc_ok"] = bool(ok)
        if ok:
            rec["old_permission_forwarded"] = lab.peer_delivers_nonce(channels[0], peers[0])
            new_ok = channels[0].create_permission("127.0.0.1", peers[0].getsockname()[1])[0]
            rec["new_permission_ok"] = bool(new_ok)
            rec["new_permission_forwarded"] = (
                lab.peer_delivers_nonce(channels[0], peers[0]) if new_ok else False
            )
        rec["B_final"] = lab.peer_delivers_nonce(channels[1], peers[1])
        rec["passed"] = all(
            [
                rec.get("A_pre"),
                rec.get("B_pre"),
                rec.get("delete_ok"),
                not rec.get("A_after_delete"),
                rec.get("B_after_delete"),
                rec.get("realloc_ok"),
                not rec.get("old_permission_forwarded", True),
                rec.get("new_permission_ok"),
                rec.get("new_permission_forwarded"),
                rec.get("B_final"),
            ]
        )
    finally:
        for c in channels:
            try:
                c.close()
            except OSError:
                pass
        for p in peers:
            try:
                p.close()
            except OSError:
                pass
        lab.kill_turnserver(proc)
        rec["owned_child_reaped"] = proc.poll() is not None
        (out / "receipt.json").write_text(json.dumps(rec, indent=2) + "\n")
        rec["receipt"] = str(out / "receipt.json")
    return rec


def main() -> int:
    patched = os.environ.get("PATCHED_BIN")
    if not patched:
        print("FAIL: PATCHED_BIN required")
        return 2
    rec = run_one(Path(patched))
    print(json.dumps(rec, indent=2))
    if not rec.get("passed"):
        print("FAIL: stale permission authorized replacement allocation")
        return 1
    print("PASS: delete-realloc stale permission seam")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
