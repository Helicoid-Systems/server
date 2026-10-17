#!/usr/bin/env bash
# Run the relay-expiry lab scenarios against built binaries.
# Secrets stay in 0600 scratch files; results are metadata-only JSON.
# Fail-closed package gate: no false green aggregation.
set -euo pipefail

LAB_ROOT="${LAB_ROOT:-/tmp/hs-finish-20261013/relay-lab}"
BIN_DIR="${LAB_ROOT}/bin"
RUN_DIR="${LAB_ROOT}/run"
REPO_RELAY="${REPO_RELAY:-$(cd "$(dirname "$0")/.." && pwd)}"
HARNESS="${HARNESS:-${REPO_RELAY}/harness/run_expiry_lab.py}"
SUMMARY="${SUMMARY:-${REPO_RELAY}/harness/summarize_lab_results.py}"
STOCK_BIN="${STOCK_BIN:-${LAB_ROOT}/coturn-stock-20261017/bin/turnserver-stock}"
PATCHED_BIN="${PATCHED_BIN:-${BIN_DIR}/turnserver-patched}"
CLOCKFAULT_BIN="${CLOCKFAULT_BIN:-${BIN_DIR}/turnserver-clockfault}"

# Per-invocation correlation id must be visible to every child harness.
INV_ID="${INV_ID:-$(date +%s)-$$}"
export INV_ID

mkdir -p "${RUN_DIR}"
export TURNSERVER_BIN="${PATCHED_BIN}"
export LAB_ROOT

require_file() {
  local p="$1"
  if [[ ! -f "${p}" ]]; then
    echo "FAIL: required file missing: ${p}" >&2
    exit 2
  fi
}

require_file "${HARNESS}"
require_file "${SUMMARY}"
require_file "${STOCK_BIN}"
require_file "${PATCHED_BIN}"
require_file "${CLOCKFAULT_BIN}"

# Run one owned child. Clear only exact owned outputs first so a stale JSON
# can never satisfy this invocation. Record the real exit code.
run_case() {
  local name="$1"; shift
  local out="${RUN_DIR}/${name}.json"
  local log="${RUN_DIR}/${name}.out"
  local rc_file="${RUN_DIR}/${name}.exit"

  rm -f "${out}" "${log}" "${rc_file}"
  echo "===== ${name} (inv=${INV_ID}) ====="
  set +e
  python3 "${HARNESS}" "$@" --out "${out}" >"${log}" 2>&1
  local rc=$?
  set -e
  printf '%s\n' "${rc}" >"${rc_file}"
  echo "exit=${rc}"
  return 0
}

run_case "pkg-stock-accelerated"      --mode accelerated --turnserver-bin "${STOCK_BIN}"
run_case "pkg-patched-accelerated"    --mode accelerated --turnserver-bin "${PATCHED_BIN}"
run_case "pkg-stock-lastfraction"     --mode lastfraction --turnserver-bin "${STOCK_BIN}"
run_case "pkg-patched-lastfraction"   --mode lastfraction --turnserver-bin "${PATCHED_BIN}"
run_case "pkg-patched-boundary60"     --mode boundary60   --turnserver-bin "${PATCHED_BIN}"
run_case "pkg-clockfault"             --mode clockfault   --turnserver-bin "${CLOCKFAULT_BIN}"

python3 "${SUMMARY}" \
  --run-dir "${RUN_DIR}" \
  --inv-id "${INV_ID}" \
  --stock-bin "${STOCK_BIN}" \
  --patched-bin "${PATCHED_BIN}" \
  --clockfault-bin "${CLOCKFAULT_BIN}"
