#!/usr/bin/env bash
# Launcher regression fixtures for scripts/run-lab.sh + summarize_lab_results.py
# TEST-ONLY. These stubs are NOT native proof and must never be described as such.
#
# Fixture safety: ALWAYS create a NEW private mktemp subdirectory beneath the
# allowed fixture base (TMPDIR). Never write into or overwrite caller LAB_ROOT
# binaries/data.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_RELAY="$(cd "${SCRIPT_DIR}/.." && pwd)"
SUMMARY="${REPO_RELAY}/harness/summarize_lab_results.py"
RUN_LAB="${SCRIPT_DIR}/run-lab.sh"

# Allowed fixture base only. Never reuse caller LAB_ROOT as the fixture root.
FIXTURE_BASE="${TMPDIR:-/tmp}"
CALLER_LAB_ROOT="${LAB_ROOT:-}"
FIX_ROOT="$(mktemp -d "${FIXTURE_BASE}/relay-lab-launcher-fixture.XXXXXX")"
export LAB_ROOT="${FIX_ROOT}"
RUN_DIR="${LAB_ROOT}/run"
BIN_DIR="${LAB_ROOT}/bin"
mkdir -p "${RUN_DIR}" "${BIN_DIR}"

# Dummy binaries required by run-lab.sh existence checks — under FIX_ROOT only.
mkdir -p "${LAB_ROOT}/coturn-stock-20261017/bin"
printf 'stock-stub\n' > "${LAB_ROOT}/coturn-stock-20261017/bin/turnserver-stock"
printf 'bin-stub\n' > "${BIN_DIR}/turnserver-patched"
printf 'bin-stub\n' > "${BIN_DIR}/turnserver-clockfault"

# Setup-only probe for sentinel preservation: prove we never write caller LAB_ROOT.
if [[ "${1:-}" == "--sentinel-probe" ]]; then
  test -n "${FIX_ROOT}" || { echo "FIXTURE FAIL: probe FIX_ROOT empty" >&2; exit 1; }
  test "${LAB_ROOT}" = "${FIX_ROOT}" || { echo "FIXTURE FAIL: probe LAB_ROOT != FIX_ROOT" >&2; exit 1; }
  if [[ -n "${CALLER_LAB_ROOT}" ]]; then
    test "${FIX_ROOT}" != "${CALLER_LAB_ROOT}" \
      || { echo "FIXTURE FAIL: probe reused caller LAB_ROOT" >&2; exit 1; }
  fi
  # Dummies live only under FIX_ROOT; caller LAB_ROOT is untouched.
  test -f "${BIN_DIR}/turnserver-patched" || { echo "FIXTURE FAIL: probe dummy missing" >&2; exit 1; }
  echo "sentinel-probe OK (fixture root private)"
  exit 0
fi

STUB_DIR="${LAB_ROOT}/stub"
mkdir -p "${STUB_DIR}"
export STUB_DIR
# Per-invocation correlation id (exported so children stamp it).
export INV_ID="fixture-$$"

# Hash helper for sentinel preservation.
sha_files() {
  shasum -a 256 "$@" | awk '{print $1}' | sort
}

cat > "${STUB_DIR}/fake_harness.py" <<'PY'
#!/usr/bin/env python3
"""Stub harness for launcher fixtures only — not native protocol proof.

Shapes match the actual run_expiry_lab.py modes:
  lastfraction → boot, last_fraction_refresh, matching_cleanup
  clockfault   → boot, clockfault_allocate_denied, clockfault_refresh_denied, matching_cleanup
  else         → full 9-key accelerated set
"""
import hashlib, json, os, sys, time
from pathlib import Path

args = sys.argv[1:]
mode = "accelerated"
out = ""
turnserver_bin = ""
i = 0
while i < len(args):
    a = args[i]
    if a == "--mode":
        mode = args[i + 1]; i += 2; continue
    if a == "--out":
        out = args[i + 1]; i += 2; continue
    if a == "--turnserver-bin":
        turnserver_bin = args[i + 1]; i += 2; continue
    i += 1

behavior = os.environ.get("STUB_BEHAVIOR", "ok")
kind = "stock" if "stock" in turnserver_bin else ("clockfault" if "clockfault" in turnserver_bin else "patched")
name = Path(out).stem
now = time.time()
bin_sha = ""
if turnserver_bin and Path(turnserver_bin).is_file():
    bin_sha = hashlib.sha256(Path(turnserver_bin).read_bytes()).hexdigest()

if behavior == "crash":
    sys.exit(3)
if behavior == "unexpected-exit":
    sys.exit(7)
if behavior == "missing" and name == "pkg-patched-accelerated":
    sys.exit(1)
if behavior == "corrupt" and name == "pkg-patched-accelerated":
    Path(out).write_text("{not json")
    sys.exit(1 if kind == "stock" else 0)
if behavior == "stale" and name == "pkg-patched-accelerated":
    data = {
        "meta": {
            "mode": mode,
            "inv_id": "other-inv",
            "started_wall": now - 7200,
            "finished_wall": now - 7000,
            "mandatory_all_pass": True,
            "defect_reproduced": False,
            "mandatory_status": {},
            "turnserver_sha256": bin_sha,
        },
        "scenarios": {},
    }
    Path(out).write_text(json.dumps(data))
    Path(out).with_suffix(".exit").write_text("0")
    sys.exit(0)

def scenario_pass():
    return {
        "status": "PASS", "bound_holds": True, "destroyed": True,
        "unbounded_after_expiry": False, "post_bound_packet_arrivals": 0,
        "cutoff_violations": 0, "pre_ok": True, "pre_forward": True,
        "immediate_pre_forward": True, "in_last_fraction": True,
        "refresh_ok": False, "regrant_full_lifetime": False,
        "extends_past_deadline": False, "concrete_defect": False,
    }

def scenario_fail_defect():
    return {
        "status": "FAIL", "bound_holds": False, "destroyed": False,
        "unbounded_after_expiry": True, "post_bound_packet_arrivals": 2,
        "cutoff_violations": 2, "pre_ok": True, "pre_forward": True,
        "immediate_pre_forward": True, "in_last_fraction": True,
        "refresh_ok": True, "regrant_full_lifetime": True,
        "extends_past_deadline": True, "concrete_defect": True,
    }

def scenario_missed_window():
    """Missed-window FAIL must NOT count as stock defect proof."""
    return {
        "status": "NotVerified", "bound_holds": False, "destroyed": False,
        "unbounded_after_expiry": False, "post_bound_packet_arrivals": 0,
        "cutoff_violations": 0, "pre_ok": True, "pre_forward": True,
        "immediate_pre_forward": True, "in_last_fraction": False,
        "refresh_ok": False, "regrant_full_lifetime": False,
        "extends_past_deadline": False, "concrete_defect": False,
        "note": "refresh missed planned last-fraction window",
    }

if kind == "clockfault":
    scenarios = {
        "boot": scenario_pass(),
        "clockfault_allocate_denied": scenario_pass(),
        "clockfault_refresh_denied": scenario_pass(),
        "matching_cleanup": scenario_pass(),
    }
    all_pass = behavior != "all-fail"
    defect = False
elif mode == "lastfraction":
    scenarios = {
        "boot": scenario_pass(),
        "last_fraction_refresh": scenario_pass(),
        "matching_cleanup": scenario_pass(),
    }
    if behavior == "stock-no-defect":
        scenarios["last_fraction_refresh"] = scenario_missed_window()
        all_pass = False
        defect = False
    elif behavior == "missed-window":
        scenarios["last_fraction_refresh"] = scenario_missed_window()
        all_pass = False
        defect = False
    elif kind == "stock":
        scenarios["last_fraction_refresh"] = scenario_fail_defect()
        all_pass = False
        defect = True
    else:
        all_pass = behavior != "all-fail"
        defect = False
        if behavior == "all-fail":
            scenarios = {k: scenario_fail_defect() for k in scenarios}
elif kind == "stock":
    scenarios = {
        "boot": scenario_pass(),
        "allocate_and_forward": scenario_pass(),
        "allocation_isolation": scenario_pass(),
        "refresh_after_expiry": scenario_fail_defect(),
        "silent_client_expires": scenario_fail_defect(),
        "last_fraction_refresh": scenario_fail_defect(),
        "late_allocate_rejected": scenario_pass(),
        "wrong_auth_rejected": scenario_pass(),
        "matching_cleanup": scenario_pass(),
    }
    if behavior == "stock-no-defect":
        scenarios = {k: scenario_pass() for k in scenarios}
        scenarios["refresh_after_expiry"] = {
            "status": "PASS", "unbounded_after_expiry": False, "bound_holds": True,
            "post_bound_packet_arrivals": 0, "cutoff_violations": 0,
            "pre_forward": True, "immediate_pre_forward": True, "in_last_fraction": True,
        }
        scenarios["last_fraction_refresh"] = {
            "status": "NotVerified", "bound_holds": False,
            "post_bound_packet_arrivals": 0, "cutoff_violations": 0,
            "pre_forward": True, "immediate_pre_forward": True, "in_last_fraction": False,
            "concrete_defect": False,
        }
        scenarios["silent_client_expires"] = {
            "status": "PASS", "destroyed": True, "pre_ok": True, "post_packets": 0,
        }
        all_pass = True
        defect = False
    elif behavior == "missed-window":
        # Stock missed-window alone is not a stock defect.
        scenarios["last_fraction_refresh"] = scenario_missed_window()
        scenarios["refresh_after_expiry"] = {
            "status": "PASS", "unbounded_after_expiry": False,
            "post_bound_packet_arrivals": 0, "cutoff_violations": 0,
            "pre_forward": True, "in_last_fraction": False,
        }
        scenarios["silent_client_expires"] = {
            "status": "PASS", "destroyed": True, "pre_ok": True,
        }
        all_pass = False
        defect = False
    else:
        all_pass = False
        defect = True
else:
    scenarios = {
        "boot": scenario_pass(),
        "allocate_and_forward": scenario_pass(),
        "allocation_isolation": scenario_pass(),
        "refresh_after_expiry": scenario_pass(),
        "silent_client_expires": scenario_pass(),
        "last_fraction_refresh": scenario_pass(),
        "late_allocate_rejected": scenario_pass(),
        "wrong_auth_rejected": scenario_pass(),
        "matching_cleanup": scenario_pass(),
    }
    if behavior == "all-fail":
        scenarios = {k: scenario_fail_defect() for k in scenarios}
        all_pass = False
        defect = True
    else:
        all_pass = True
        defect = False

mandatory = {k: v.get("status") for k, v in scenarios.items()}
meta = {
    "mode": mode,
    "inv_id": os.environ.get("INV_ID", ""),
    "started_wall": now,
    "finished_wall": now + 0.2,
    "mandatory_status": mandatory,
    "mandatory_all_pass": all_pass,
    "defect_reproduced": defect,
    "turnserver_sha256": bin_sha,
    "turnserver_bin": turnserver_bin,
}
Path(out).write_text(json.dumps({"meta": meta, "scenarios": scenarios}, indent=2))
rc = 0 if all_pass else 1
if behavior == "all-fail" and kind != "stock":
    rc = 1
Path(out).with_suffix(".exit").write_text(str(rc))
sys.exit(rc)
PY
chmod +x "${STUB_DIR}/fake_harness.py"

# Point run-lab at the stub harness.
export HARNESS="${STUB_DIR}/fake_harness.py"
export SUMMARY
export STOCK_BIN="${LAB_ROOT}/coturn-stock-20261017/bin/turnserver-stock"
export PATCHED_BIN="${BIN_DIR}/turnserver-patched"
export CLOCKFAULT_BIN="${BIN_DIR}/turnserver-clockfault"

fail_case() {
  echo "FIXTURE FAIL: $1" >&2
  exit 1
}

pass_case() {
  echo "FIXTURE PASS: $1"
}

# 0) Fixture root is a private mktemp, never the caller LAB_ROOT.
test -n "${FIX_ROOT}" || fail_case "FIX_ROOT empty"
test -d "${FIX_ROOT}" || fail_case "FIX_ROOT missing"
if [[ -n "${CALLER_LAB_ROOT}" ]]; then
  test "${FIX_ROOT}" != "${CALLER_LAB_ROOT}" \
    || fail_case "fixture reused caller LAB_ROOT (unsafe overwrite risk)"
fi
pass_case "private mktemp fixture root (not caller LAB_ROOT)"

# 1) Happy path (nondefault LAB_ROOT honored)
rm -f "${RUN_DIR}"/*
STUB_BEHAVIOR=ok bash "${RUN_LAB}" > "${LAB_ROOT}/fixture-ok.log" 2>&1 \
  && pass_case "happy path nondefault LAB_ROOT" \
  || fail_case "happy path should exit 0 (see ${LAB_ROOT}/fixture-ok.log)"
test -d "${RUN_DIR}" && test -f "${RUN_DIR}/pkg-patched-accelerated.json" \
  || fail_case "results not under nondefault LAB_ROOT/run"
test -f "${RUN_DIR}/pkg-patched-lastfraction.json" \
  || fail_case "lastfraction result missing"

# 2) all-fail JSON (patched mandatory_all_pass=false) must fail wrapper
rm -f "${RUN_DIR}"/*
if STUB_BEHAVIOR=all-fail bash "${RUN_LAB}" > "${LAB_ROOT}/fixture-all-fail.log" 2>&1; then
  fail_case "all-fail JSON must not exit 0"
else
  pass_case "all-fail JSON rejected"
fi

# 3) unexpected child exit must fail
rm -f "${RUN_DIR}"/*
if STUB_BEHAVIOR=unexpected-exit bash "${RUN_LAB}" > "${LAB_ROOT}/fixture-unexpected.log" 2>&1; then
  fail_case "unexpected child exit must not exit 0"
else
  pass_case "unexpected child exit rejected"
fi

# 4) stock no-defect must fail
rm -f "${RUN_DIR}"/*
if STUB_BEHAVIOR=stock-no-defect bash "${RUN_LAB}" > "${LAB_ROOT}/fixture-stock-no-defect.log" 2>&1; then
  fail_case "stock no-defect must not exit 0"
else
  pass_case "stock no-defect rejected"
fi

# 5) stale file must fail
rm -f "${RUN_DIR}"/*
if STUB_BEHAVIOR=stale bash "${RUN_LAB}" > "${LAB_ROOT}/fixture-stale.log" 2>&1; then
  fail_case "stale result must not exit 0"
else
  pass_case "stale result rejected"
fi

# 6) missing result must fail
rm -f "${RUN_DIR}"/*
if STUB_BEHAVIOR=missing bash "${RUN_LAB}" > "${LAB_ROOT}/fixture-missing.log" 2>&1; then
  fail_case "missing result must not exit 0"
else
  pass_case "missing result rejected"
fi

# 7) corrupt result must fail
rm -f "${RUN_DIR}"/*
if STUB_BEHAVIOR=corrupt bash "${RUN_LAB}" > "${LAB_ROOT}/fixture-corrupt.log" 2>&1; then
  fail_case "corrupt result must not exit 0"
else
  pass_case "corrupt result rejected"
fi

# 8) crash (no JSON) must fail
rm -f "${RUN_DIR}"/*
if STUB_BEHAVIOR=crash bash "${RUN_LAB}" > "${LAB_ROOT}/fixture-crash.log" 2>&1; then
  fail_case "crash without JSON must not exit 0"
else
  pass_case "crash without JSON rejected"
fi

# 9) Missed-window lastfraction must not be accepted as stock defect proof
rm -f "${RUN_DIR}"/*
if STUB_BEHAVIOR=missed-window bash "${RUN_LAB}" > "${LAB_ROOT}/fixture-missed-window.log" 2>&1; then
  fail_case "missed-window must not exit 0 (no concrete stock defect)"
else
  pass_case "missed-window rejected as stock defect"
fi

# 10) Caller LAB_ROOT sentinel preservation — CRITICAL safety regression.
# Old bug: FIX_ROOT=${LAB_ROOT:-mktemp} wrote dummy text over real binaries.
# Fixed: always private mktemp; caller LAB_ROOT binaries must be preserved.
SENTINEL_ROOT="$(mktemp -d "${FIXTURE_BASE}/relay-lab-sentinel.XXXXXX")"
mkdir -p "${SENTINEL_ROOT}/bin" "${SENTINEL_ROOT}/coturn-stock-20261017/bin"
printf 'SENTINEL-PATCHED-REAL-BYTES\n' > "${SENTINEL_ROOT}/bin/turnserver-patched"
printf 'SENTINEL-CLOCKFAULT-REAL-BYTES\n' > "${SENTINEL_ROOT}/bin/turnserver-clockfault"
printf 'SENTINEL-STOCK-REAL-BYTES\n' > "${SENTINEL_ROOT}/coturn-stock-20261017/bin/turnserver-stock"
s_before="$(sha_files \
  "${SENTINEL_ROOT}/bin/turnserver-patched" \
  "${SENTINEL_ROOT}/bin/turnserver-clockfault" \
  "${SENTINEL_ROOT}/coturn-stock-20261017/bin/turnserver-stock")"

# Re-invoke setup path with LAB_ROOT=SENTINEL_ROOT. The fixed script must
# create its own mktemp and leave sentinel binaries byte-identical.
LAB_ROOT="${SENTINEL_ROOT}" TMPDIR="${FIXTURE_BASE}" \
  bash "${SCRIPT_DIR}/test-run-lab-launcher.sh" --sentinel-probe \
  > "${LAB_ROOT}/fixture-sentinel-probe.log" 2>&1 \
  || fail_case "sentinel-probe setup path failed (see fixture-sentinel-probe.log)"

s_after="$(sha_files \
  "${SENTINEL_ROOT}/bin/turnserver-patched" \
  "${SENTINEL_ROOT}/bin/turnserver-clockfault" \
  "${SENTINEL_ROOT}/coturn-stock-20261017/bin/turnserver-stock")"

if [[ "${s_before}" != "${s_after}" ]]; then
  fail_case "caller LAB_ROOT sentinel binaries were modified (unsafe fixture overwrite)"
fi
# Content must still be the sentinel text, not stub dummies.
grep -q 'SENTINEL-PATCHED-REAL-BYTES' "${SENTINEL_ROOT}/bin/turnserver-patched" \
  || fail_case "sentinel patched binary content replaced"
grep -q 'SENTINEL-STOCK-REAL-BYTES' "${SENTINEL_ROOT}/coturn-stock-20261017/bin/turnserver-stock" \
  || fail_case "sentinel stock binary content replaced"
pass_case "caller LAB_ROOT sentinel binaries preserved"

# 11) If caller provided a populated LAB_ROOT before we started, prove it too.
if [[ -n "${CALLER_LAB_ROOT}" && -d "${CALLER_LAB_ROOT}" ]]; then
  if [[ -f "${CALLER_LAB_ROOT}/bin/turnserver-patched" ]]; then
    c_before="$(sha_files "${CALLER_LAB_ROOT}/bin/turnserver-patched")"
    # We already ran all fixtures with LAB_ROOT=FIX_ROOT, so caller tree untouched.
    c_after="$(sha_files "${CALLER_LAB_ROOT}/bin/turnserver-patched")"
    [[ "${c_before}" == "${c_after}" ]] \
      || fail_case "pre-existing caller LAB_ROOT binary was modified"
    pass_case "pre-existing caller LAB_ROOT binary preserved"
  fi
fi

echo "ALL LAUNCHER FIXTURES PASSED (test-only; not native proof)"
echo "FIX_ROOT=${FIX_ROOT}"
