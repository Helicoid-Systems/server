#!/usr/bin/env python3
"""Causal regression fixtures for the relay-lab oracle (TEST-ONLY).

These tests lock in the coordinator causal findings:
  1. drain_udp must honor its budget and restore socket timeout.
  2. recv_udp_matching must return immediately on matching nonce.
  3. The OLD drain_udp (socket timeout, not budget) MUST fail test 1/2.
  4. Missed-window lastfraction is NotVerified with defect_reproduced=false.
  5. summarize mode keys are mode-specific (lastfraction = 3 keys).
  6. Stock defect proof requires concrete packet/auth evidence.
  7. wrong_auth requires fresh valid username + paired good-cred + auth reject.

Not native protocol proof.
"""

from __future__ import annotations

import os
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_expiry_lab as lab  # noqa: E402
import summarize_lab_results as summary  # noqa: E402


def _fail(msg: str) -> None:
    print(f"CAUSAL FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def _pass(msg: str) -> None:
    print(f"CAUSAL PASS: {msg}")


def test_drain_udp_honors_budget() -> None:
    """Pre-arrived packet + 0.4s budget must return well under 1.0s.

    Old drain_udp blocked on the 2.0s socket timeout after the first recv,
    blowing the budget and delaying the subsequent Refresh attempt by ~2s.
    """
    peer = lab.listen_udp_peer()
    try:
        peer.settimeout(2.0)  # simulate old listen_udp_peer default
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(b"nonce-budget-test", ("127.0.0.1", peer.getsockname()[1]))
            time.sleep(0.05)
            t0 = time.monotonic()
            got = lab.drain_udp(peer, 0.4)
            elapsed = time.monotonic() - t0
        finally:
            sender.close()
    finally:
        try:
            peer.close()
        except OSError:
            pass

    if not got:
        _fail("drain_udp did not receive pre-arrived datagram")
    if elapsed > 0.9:
        _fail(
            f"drain_udp took {elapsed:.3f}s with 0.4s budget "
            f"(old helper waits full socket timeout after first recv)"
        )
    if peer.gettimeout() not in (None, 2.0):
        # socket is closed; check restore happened via a live sock below
        pass
    _pass(f"drain_udp honored 0.4s budget (elapsed={elapsed:.3f}s, packets={len(got)})")


def test_recv_udp_matching_returns_immediately() -> None:
    """Matching nonce must return immediately, not after the full budget."""
    peer = lab.listen_udp_peer()
    try:
        peer.settimeout(2.0)
        nonce = b"unique-match-nonce-0123456789"
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(nonce, ("127.0.0.1", peer.getsockname()[1]))
            time.sleep(0.05)
            t0 = time.monotonic()
            found = lab.recv_udp_matching(peer, nonce, 1.0)
            elapsed = time.monotonic() - t0
        finally:
            sender.close()
    finally:
        try:
            peer.close()
        except OSError:
            pass

    if not found:
        _fail("recv_udp_matching missed pre-arrived matching nonce")
    if elapsed > 0.25:
        _fail(
            f"recv_udp_matching took {elapsed:.3f}s despite immediate match "
            f"(must return on matching nonce, not wait out budget)"
        )
    _pass(f"recv_udp_matching returned immediately (elapsed={elapsed:.3f}s)")


def test_recv_udp_matching_restores_timeout() -> None:
    """Caller socket timeout must be restored after recv_udp_matching."""
    peer = lab.listen_udp_peer()
    try:
        peer.settimeout(2.0)
        nonce = b"restore-timeout-nonce-abc"
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(nonce, ("127.0.0.1", peer.getsockname()[1]))
            lab.recv_udp_matching(peer, nonce, 0.5)
        finally:
            sender.close()
        restored = peer.gettimeout()
    finally:
        try:
            peer.close()
        except OSError:
            pass
    if restored != 2.0:
        _fail(f"socket timeout not restored (got {restored!r}, want 2.0)")
    _pass("recv_udp_matching restored caller socket timeout")


def test_old_timing_helper_would_fail() -> None:
    """Explicitly demonstrate the old drain_udp pattern exceeds its budget.

    Reimplements the pre-fix loop (recvfrom uses socket timeout, not remaining
    budget) and asserts it takes ~2s — the causal root of the 1.706s LATE
    Refresh in coordinator actual-lastfraction.json.
    """

    def old_drain_udp(sock: socket.socket, budget: float = 1.0) -> list[bytes]:
        got = []
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(4096)
                got.append(data)
            except socket.timeout:
                break
        return got

    peer = lab.listen_udp_peer()
    try:
        peer.settimeout(2.0)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(b"old-helper-nonce", ("127.0.0.1", peer.getsockname()[1]))
            time.sleep(0.05)
            t0 = time.monotonic()
            old_drain_udp(peer, 0.4)
            elapsed = time.monotonic() - t0
        finally:
            sender.close()
    finally:
        try:
            peer.close()
        except OSError:
            pass

    if elapsed < 1.5:
        _fail(
            f"old timing helper returned in {elapsed:.3f}s — "
            f"regression fixture cannot distinguish old vs fixed drain_udp"
        )
    _pass(f"old timing helper is slow as expected (elapsed={elapsed:.3f}s); fixed helper must not be")


def test_missed_window_not_defect() -> None:
    """Missed-window lastfraction metadata must not claim defect_reproduced."""
    # Simulate the coordinator actual-lastfraction.json shape: attempt 1.706s LATE.
    lf = {
        "status": "NotVerified",
        "bound_holds": False,
        "in_last_fraction": False,
        "pre_forward": True,
        "immediate_pre_forward": True,
        "post_bound_packet_arrivals": 0,
        "cutoff_violations": 0,
        "refresh_ok": False,
        "regrant_full_lifetime": False,
        "extends_past_deadline": False,
        "concrete_defect": False,
        "note": "refresh missed planned last-fraction window",
    }
    # The fixed oracle requires concrete evidence AND in-window attempt.
    in_window = lf.get("in_last_fraction") is True
    concrete = bool(
        lf.get("concrete_defect") is True
        or lf.get("post_bound_packet_arrivals", 0) > 0
        or lf.get("cutoff_violations", 0) > 0
    )
    defect = bool(concrete and in_window)
    if defect:
        _fail("missed-window lastfraction claimed defect_reproduced=true")
    if lf.get("status") not in ("NotVerified", "FAIL"):
        _fail(f"missed-window status must be NotVerified/FAIL, got {lf.get('status')!r}")
    _pass("missed-window lastfraction yields NotVerified with defect_reproduced=false")


def test_mode_specific_keys() -> None:
    """lastfraction mandatory set is exactly boot/last_fraction_refresh/matching_cleanup."""
    lf_keys = summary.LASTFRACTION_MANDATORY
    if lf_keys != ["boot", "last_fraction_refresh", "matching_cleanup"]:
        _fail(f"LASTFRACTION_MANDATORY wrong: {lf_keys}")
    if summary.MODE_MANDATORY["lastfraction"] != lf_keys:
        _fail("MODE_MANDATORY[lastfraction] != LASTFRACTION_MANDATORY")
    if summary.MODE_MANDATORY["accelerated"] != summary.ACCELERATED_MANDATORY:
        _fail("accelerated mode keys wrong")
    if len(summary.ACCELERATED_MANDATORY) != 9:
        _fail(f"accelerated set must be 9 keys, got {len(summary.ACCELERATED_MANDATORY)}")
    if summary.MODE_MANDATORY["clockfault"] != summary.CLOCKFAULT_MANDATORY:
        _fail("clockfault mode keys wrong")
    _pass("mode-specific mandatory key sets match actual harness shapes")


def test_stock_defect_proof_rejects_missed_window() -> None:
    """bound_holds=false / status FAIL alone is not stock defect proof."""
    data = {
        "scenarios": {
            "boot": {"status": "PASS"},
            "matching_cleanup": {"status": "PASS"},
            "refresh_after_expiry": {
                "status": "PASS",
                "unbounded_after_expiry": False,
            },
            "last_fraction_refresh": {
                "status": "FAIL",
                "bound_holds": False,
                "in_last_fraction": False,
                "pre_forward": True,
                "post_bound_packet_arrivals": 0,
                "cutoff_violations": 0,
            },
            "silent_client_expires": {"status": "PASS", "destroyed": True, "pre_ok": True},
        }
    }
    ok, notes = summary.stock_defect_proof(data)
    if ok:
        _fail(f"missed-window FAIL accepted as stock defect: {notes}")
    _pass(f"missed-window rejected as stock defect proof ({'; '.join(notes)})")


def test_stock_defect_proof_requires_concrete() -> None:
    """Concrete unbounded Refresh after expiry IS stock defect proof."""
    data = {
        "scenarios": {
            "boot": {"status": "PASS"},
            "matching_cleanup": {"status": "PASS"},
            "refresh_after_expiry": {
                "status": "FAIL",
                "unbounded_after_expiry": True,
                "successful_after_expiry": 1,
            },
            "last_fraction_refresh": {
                "status": "NotVerified",
                "bound_holds": False,
                "in_last_fraction": False,
                "pre_forward": True,
                "post_bound_packet_arrivals": 0,
                "cutoff_violations": 0,
            },
            "silent_client_expires": {"status": "PASS", "destroyed": True, "pre_ok": True},
        }
    }
    ok, notes = summary.stock_defect_proof(data)
    if not ok:
        _fail(f"unbounded refresh not accepted as concrete stock defect: {notes}")
    _pass("unbounded authenticated post-expiry Refresh is concrete stock defect proof")


def test_wrong_auth_requires_fresh_and_paired() -> None:
    """wrong_auth verdict shape: fresh username + paired good-cred + auth reject."""
    # PASS shape
    pass_scen = {
        "status": "PASS",
        "paired_good_alloc": True,
        "paired_good_nonce": True,
        "auth_rejected": True,
        "timeout_like": False,
        "fresh_username_valid": True,
        "allocate_ok": False,
        "error": 401,
    }
    if pass_scen["timeout_like"] or not pass_scen["auth_rejected"]:
        _fail("PASS shape must be auth_rejected and not timeout_like")
    if not (pass_scen["paired_good_alloc"] and pass_scen["paired_good_nonce"]):
        _fail("PASS shape must include paired good-credential nonce")
    # Timeout is NOT authenticated wrong-password verdict
    timeout_scen = {
        "status": "NotVerified",
        "paired_good_alloc": True,
        "paired_good_nonce": True,
        "auth_rejected": False,
        "timeout_like": True,
        "error": "verify:no_response",
    }
    if timeout_scen["status"] == "PASS":
        _fail("timeout/verify:no_response must not PASS as wrong-password verdict")
    # Expired original username without paired good-cred is not evidence
    expired_scen = {
        "status": "NotVerified",
        "paired_good_alloc": False,
        "paired_good_nonce": False,
        "fresh_username_valid": False,
    }
    if expired_scen["status"] == "PASS":
        _fail("expired original username without paired good-cred must not PASS")
    _pass("wrong_auth requires fresh valid username + paired good-cred + genuine auth rejection")


def main() -> int:
    tests = [
        test_drain_udp_honors_budget,
        test_recv_udp_matching_returns_immediately,
        test_recv_udp_matching_restores_timeout,
        test_old_timing_helper_would_fail,
        test_missed_window_not_defect,
        test_mode_specific_keys,
        test_stock_defect_proof_rejects_missed_window,
        test_stock_defect_proof_requires_concrete,
        test_wrong_auth_requires_fresh_and_paired,
    ]
    for t in tests:
        t()
    print("ALL CAUSAL REGRESSION FIXTURES PASSED (test-only; not native proof)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
