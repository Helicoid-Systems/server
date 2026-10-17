#!/usr/bin/env python3
"""Fail-closed aggregator for relay-lab package results.

Reads per-scenario metadata JSON written by run_expiry_lab.py and enforces
typed booleans, expected child exits, mandatory verdicts, per-invocation
correlation, binary identity hashes, and explicit stock defect proof.
Any missing/corrupt/stale/unexpected result fails the package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any


# mode/scenario identities used by scripts/run-lab.sh
CASES: list[dict[str, Any]] = [
    {
        "name": "pkg-stock-accelerated",
        "kind": "stock",
        "mode": "accelerated",
        "expected_exit": 1,
        "require_defect": True,
        "require_all_pass": False,
    },
    {
        "name": "pkg-patched-accelerated",
        "kind": "patched",
        "mode": "accelerated",
        "expected_exit": 0,
        "require_defect": False,
        "require_all_pass": True,
    },
    {
        "name": "pkg-stock-lastfraction",
        "kind": "stock",
        "mode": "lastfraction",
        "expected_exit": 1,
        "require_defect": True,
        "require_all_pass": False,
    },
    {
        "name": "pkg-patched-lastfraction",
        "kind": "patched",
        "mode": "lastfraction",
        "expected_exit": 0,
        "require_defect": False,
        "require_all_pass": True,
    },
    {
        "name": "pkg-patched-boundary60",
        "kind": "patched",
        "mode": "boundary60",
        "expected_exit": 0,
        "require_defect": False,
        "require_all_pass": True,
    },
    {
        "name": "pkg-clockfault",
        "kind": "clockfault",
        "mode": "clockfault",
        "expected_exit": 0,
        "require_defect": False,
        "require_all_pass": True,
    },
]

ACCELERATED_MANDATORY = [
    "boot",
    "allocate_and_forward",
    "allocation_isolation",
    "refresh_after_expiry",
    "silent_client_expires",
    "last_fraction_refresh",
    "late_allocate_rejected",
    "wrong_auth_rejected",
    "matching_cleanup",
]

# Actual lastfraction harness outputs exactly these keys (not the 9-key set).
LASTFRACTION_MANDATORY = [
    "boot",
    "last_fraction_refresh",
    "matching_cleanup",
]

CLOCKFAULT_MANDATORY = [
    "boot",
    "clockfault_allocate_denied",
    "clockfault_refresh_denied",
    "matching_cleanup",
]

MODE_MANDATORY: dict[str, list[str]] = {
    "accelerated": ACCELERATED_MANDATORY,
    "boundary60": ACCELERATED_MANDATORY,
    "lastfraction": LASTFRACTION_MANDATORY,
    "clockfault": CLOCKFAULT_MANDATORY,
}


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)


def is_bool(v: Any) -> bool:
    return isinstance(v, bool)


def typed_true(v: Any) -> bool:
    return v is True


def typed_false(v: Any) -> bool:
    return v is False


def load_json(path: Path) -> tuple[dict | None, str | None]:
    if not path.is_file():
        return None, "missing"
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"unreadable:{exc}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"corrupt:{exc}"
    if not isinstance(data, dict):
        return None, "corrupt:not-object"
    return data, None


def load_exit(path: Path) -> tuple[int | None, str | None]:
    if not path.is_file():
        return None, "missing-exit-record"
    try:
        text = path.read_text(encoding="utf-8").strip()
        return int(text), None
    except (OSError, ValueError) as exc:
        return None, f"corrupt-exit:{exc}"


def file_sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def scenarios_or_empty(data: dict) -> dict:
    s = data.get("scenarios")
    return s if isinstance(s, dict) else {}


def stock_defect_proof(data: dict) -> tuple[bool, list[str]]:
    """Explicit stock defect proof.

    Requires successful boot/cleanup/pre-forward AND concrete authenticated
    post-expiry success or actual packet proof. status FAIL / bound_holds=false
    alone is NOT defect proof (a missed window is not a stock defect).
    """
    notes: list[str] = []
    scenarios = scenarios_or_empty(data)
    if not scenarios:
        return False, ["scenarios-missing"]

    boot = scenarios.get("boot")
    cleanup = scenarios.get("matching_cleanup")
    refresh = scenarios.get("refresh_after_expiry")
    lastf = scenarios.get("last_fraction_refresh")
    silent = scenarios.get("silent_client_expires")

    boot_ok = isinstance(boot, dict) and boot.get("status") == "PASS"
    cleanup_ok = isinstance(cleanup, dict) and cleanup.get("status") == "PASS"
    if not boot_ok:
        notes.append("boot not PASS")
    if not cleanup_ok:
        notes.append("matching_cleanup not PASS")

    # Concrete evidence A: authenticated Refresh success after expiry.
    unbounded = refresh.get("unbounded_after_expiry") if isinstance(refresh, dict) else None
    if typed_true(unbounded):
        notes.append("refresh_after_expiry.unbounded_after_expiry=true")
        concrete_refresh = True
    else:
        concrete_refresh = False
        if isinstance(refresh, dict) and not is_bool(unbounded):
            notes.append("refresh_after_expiry.unbounded_after_expiry not typed bool")

    # Concrete evidence B: actual post-bound packet arrivals / cutoff violations
    # after a genuine pre-forward (not a missed-window metadata-only FAIL).
    concrete_packets = False
    pre_ok = False
    in_window = False
    if isinstance(lastf, dict):
        pre_ok = lastf.get("pre_forward") is True
        in_window = lastf.get("in_last_fraction") is True
        post_arrivals = lastf.get("post_bound_packet_arrivals")
        cutoff_violations = lastf.get("cutoff_violations")
        bound_holds = lastf.get("bound_holds")
        if isinstance(post_arrivals, int) and post_arrivals > 0:
            concrete_packets = True
            notes.append(f"last_fraction_refresh.post_bound_packet_arrivals={post_arrivals}")
        if isinstance(cutoff_violations, int) and cutoff_violations > 0:
            concrete_packets = True
            notes.append(f"last_fraction_refresh.cutoff_violations={cutoff_violations}")
        if typed_false(bound_holds):
            notes.append("last_fraction_refresh.bound_holds=false (not alone sufficient)")
        # In-window authenticated regrant/extends is concrete.
        if in_window and lastf.get("refresh_ok") is True and (
            lastf.get("regrant_full_lifetime") is True
            or lastf.get("extends_past_deadline") is True
        ):
            concrete_packets = True
            notes.append("last_fraction_refresh.in-window regrant/extends past bound")

    # Concrete evidence C: silent client stayed alive despite real pre-silence
    # nonce receipt (setup-fail silent_pre_ok=false is NOT defect evidence).
    concrete_silent = False
    if isinstance(silent, dict):
        silent_pre = silent.get("pre_ok")
        silent_destroyed = silent.get("destroyed")
        if typed_false(silent_destroyed) and typed_true(silent_pre):
            concrete_silent = True
            notes.append("silent_client_expires.destroyed=false after real pre_ok")
        elif typed_false(silent_destroyed):
            notes.append("silent_client_expires.destroyed=false without pre_ok (setup)")

    # Missed-window / setup-only FAIL is not a stock defect.
    if not concrete_refresh and not concrete_packets and not concrete_silent:
        # Explicitly reject bound_holds=false / status FAIL alone.
        if isinstance(lastf, dict) and lastf.get("status") == "FAIL" and not in_window:
            notes.append("lastfraction FAIL was missed-window; not stock defect proof")
        notes.append("no concrete stock defect signal (packet/auth proof required)")
        return False, notes

    if not (boot_ok and cleanup_ok):
        notes.append("boot/cleanup must PASS before stock defect proof")
        return False, notes

    # Pre-forward required for packet-based proof; refresh-based proof needs
    # the refresh scenario's own successful setup (unbounded already implies
    # the channel was live). Require pre_ok whenever lastfraction is cited.
    if concrete_packets and not pre_ok:
        notes.append("packet proof requires successful pre-forward")
        return False, notes

    return True, notes


def check_binary_hash(
    meta: dict, kind: str, stock_bin: str, patched_bin: str, clockfault_bin: str
) -> list[str]:
    problems: list[str] = []
    expected_path = {
        "stock": stock_bin,
        "patched": patched_bin,
        "clockfault": clockfault_bin,
    }.get(kind, "")
    if not expected_path:
        return problems
    recorded = meta.get("turnserver_sha256")
    actual = file_sha256(Path(expected_path))
    if actual is None:
        problems.append(f"{kind}: binary missing for hash check: {expected_path}")
        return problems
    if not recorded:
        problems.append(f"{kind}: meta.turnserver_sha256 missing")
    elif recorded != actual:
        problems.append(
            f"{kind}: binary hash mismatch recorded={recorded} actual={actual}"
        )
    return problems


def check_case(
    case: dict[str, Any],
    run_dir: Path,
    inv_id: str,
    now: float,
    stock_bin: str,
    patched_bin: str,
    clockfault_bin: str,
) -> list[str]:
    problems: list[str] = []
    name = case["name"]
    out = run_dir / f"{name}.json"
    exit_path = run_dir / f"{name}.exit"

    data, err = load_json(out)
    if data is None:
        problems.append(f"{name}: result {err}")
        return problems

    rc, rc_err = load_exit(exit_path)
    if rc is None:
        problems.append(f"{name}: {rc_err}")
        return problems

    if rc != case["expected_exit"]:
        problems.append(f"{name}: child exit {rc} != expected {case['expected_exit']}")

    meta = data.get("meta")
    if not isinstance(meta, dict):
        problems.append(f"{name}: meta missing")
        return problems

    mode = meta.get("mode")
    if mode != case["mode"]:
        problems.append(f"{name}: mode {mode!r} != expected {case['mode']!r}")

    # Per-invocation correlation: required and must match exactly.
    result_inv = meta.get("inv_id")
    if not result_inv:
        problems.append(f"{name}: missing inv_id (per-invocation correlation required)")
    elif result_inv != inv_id:
        problems.append(f"{name}: stale inv_id {result_inv!r} != {inv_id!r}")

    started = meta.get("started_wall")
    finished = meta.get("finished_wall")
    if not isinstance(started, (int, float)) or not isinstance(finished, (int, float)):
        problems.append(f"{name}: missing typed started/finished wall clocks")
    else:
        if finished < started:
            problems.append(f"{name}: finished_wall < started_wall")
        age = now - float(finished)
        if age > 3600:
            problems.append(f"{name}: stale result age {age:.1f}s")

    problems.extend(
        check_binary_hash(meta, case["kind"], stock_bin, patched_bin, clockfault_bin)
    )

    mandatory = meta.get("mandatory_status")
    if not isinstance(mandatory, dict):
        problems.append(f"{name}: mandatory_status missing")
        mandatory = {}

    all_pass = meta.get("mandatory_all_pass")
    defect = meta.get("defect_reproduced")
    if not is_bool(all_pass):
        problems.append(f"{name}: mandatory_all_pass not typed bool")
    if not is_bool(defect):
        problems.append(f"{name}: defect_reproduced not typed bool")

    expected_keys = MODE_MANDATORY.get(case["mode"] or case["kind"], ACCELERATED_MANDATORY)
    if case["kind"] == "clockfault":
        expected_keys = CLOCKFAULT_MANDATORY
    elif case["mode"] == "lastfraction":
        expected_keys = LASTFRACTION_MANDATORY
    else:
        expected_keys = ACCELERATED_MANDATORY

    scenarios = scenarios_or_empty(data)

    # Mandatory verdicts must hold against actual scenarios AND meta summary.
    for key in expected_keys:
        if key not in mandatory:
            problems.append(f"{name}: missing mandatory verdict {key}")
        elif mandatory.get(key) != "PASS" and case["require_all_pass"]:
            problems.append(f"{name}: mandatory {key}={mandatory.get(key)!r} (want PASS)")
        scen = scenarios.get(key)
        if not isinstance(scen, dict):
            problems.append(f"{name}: missing scenario object {key}")
        else:
            scen_status = scen.get("status")
            if case["require_all_pass"] and scen_status != "PASS":
                problems.append(
                    f"{name}: scenario {key} status={scen_status!r} (want PASS)"
                )
            # meta.mandatory_status must agree with scenarios[key].status
            if key in mandatory and mandatory.get(key) != scen_status:
                problems.append(
                    f"{name}: mandatory_status[{key}]={mandatory.get(key)!r} "
                    f"!= scenario status {scen_status!r}"
                )

    if case["require_all_pass"]:
        if not typed_true(all_pass):
            problems.append(f"{name}: mandatory_all_pass is not True")
        if not typed_false(defect):
            problems.append(f"{name}: defect_reproduced is not False (native gate failed)")
        # Patched lastfraction must actually land in the last-fraction window.
        if case["mode"] == "lastfraction":
            lf = scenarios.get("last_fraction_refresh")
            if not isinstance(lf, dict) or lf.get("in_last_fraction") is not True:
                problems.append(
                    f"{name}: last_fraction_refresh.in_last_fraction is not True"
                )
            if isinstance(lf, dict) and lf.get("bound_holds") is not True:
                problems.append(f"{name}: last_fraction_refresh.bound_holds is not True")
    elif case["require_defect"]:
        if typed_true(all_pass):
            problems.append(f"{name}: stock claimed mandatory_all_pass=True")
        ok_defect, notes = stock_defect_proof(data)
        if not ok_defect:
            problems.append(f"{name}: stock defect not proven ({'; '.join(notes)})")
        if not typed_true(defect):
            problems.append(f"{name}: defect_reproduced is not True for stock")
        for key in expected_keys:
            if key not in scenarios:
                problems.append(f"{name}: stock missing scenario {key}")

    return problems


def main() -> int:
    p = argparse.ArgumentParser(description="relay-lab fail-closed summary")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--inv-id", required=True)
    p.add_argument("--stock-bin", default="")
    p.add_argument("--patched-bin", default="")
    p.add_argument("--clockfault-bin", default="")
    args = p.parse_args()

    if not args.inv_id:
        fail("--inv-id is required (per-invocation correlation)")
        return 2

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        fail(f"run-dir missing: {run_dir}")
        return 2

    now = time.time()
    problems: list[str] = []
    rows: list[str] = []

    for case in CASES:
        name = case["name"]
        out = run_dir / f"{name}.json"
        data, err = load_json(out)
        rc, _ = load_exit(run_dir / f"{name}.exit")
        if data is None:
            rows.append(f"{name}: MISSING/{err} exit={rc}")
        else:
            meta = data.get("meta", {}) if isinstance(data.get("meta"), dict) else {}
            rows.append(
                f"{name}: mode={meta.get('mode')} "
                f"mandatory_all_pass={meta.get('mandatory_all_pass')} "
                f"defect_reproduced={meta.get('defect_reproduced')} "
                f"inv_id={meta.get('inv_id')!r} exit={rc}"
            )
        problems.extend(
            check_case(
                case,
                run_dir,
                args.inv_id,
                now,
                args.stock_bin,
                args.patched_bin,
                args.clockfault_bin,
            )
        )

    for row in rows:
        print(row)

    if problems:
        for msg in problems:
            fail(msg)
        print("SUMMARY FAIL")
        return 1

    print("SUMMARY OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
