#!/usr/bin/env bash
# Build the lab turnserver binaries from the pinned source:
#   turnserver-stock      unpatched baseline (shared path via build-stock.sh)
#   turnserver-patched    auth-lifetime-cap patch (fail-closed monotonic clock)
#   turnserver-clockfault test-only CLOCK_MONOTONIC failure binary
#                         (compile-time seam; fault injection, not OS fault)
set -euo pipefail

LAB_ROOT="${LAB_ROOT:-/tmp/hs-finish-20261013/relay-lab}"
SRC_DIR="${LAB_ROOT}/coturn-src"
DEPS_DIR="${LAB_ROOT}/deps-src"
PREFIX="${LAB_ROOT}/prefix"
BIN_DIR="${LAB_ROOT}/bin"
REPO_RELAY="${REPO_RELAY:-$(cd "$(dirname "$0")/.." && pwd)}"
PATCH_DIR="${REPO_RELAY}/patches"
# Ordered layered patches: 0001 then 0002. Each is checked before apply;
# reverse-check marks an already-applied patch so re-runs are idempotent.
PATCH_FILES=(
  "${PATCH_DIR}/0001-auth-lifetime-cap.patch"
  "${PATCH_DIR}/0002-precise-auth-cutoff.patch"
)
LIBEVENT_SRC="${DEPS_DIR}/libevent-2.1.12-stable"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-/opt/homebrew/opt/openssl}"

mkdir -p "${BIN_DIR}" "${PREFIX}"

if [[ ! -f "${SRC_DIR}/Makefile" && ! -f "${SRC_DIR}/configure" ]]; then
  echo "FAIL: coturn source missing; run fetch-coturn.sh first" >&2
  exit 1
fi

# Shared stock path (same recipe used by CI). Must run on a clean tree first.
echo "== stock baseline via build-stock.sh =="
OPENSSL_PREFIX="${OPENSSL_PREFIX}" "${REPO_RELAY}/scripts/build-stock.sh"

echo "== strict ordered patch apply/check =="
# Apply against a clean tree in order; --check first so a double-apply fails loud.
apply_one_patch() {
  local patch="$1"
  local name
  name="$(basename "${patch}")"
  if git -C "${SRC_DIR}" apply --check "${patch}" 2>/dev/null; then
    git -C "${SRC_DIR}" apply "${patch}"
    echo "patch applied: ${name}"
    return 0
  fi
  if git -C "${SRC_DIR}" apply --reverse --check "${patch}" 2>/dev/null; then
    echo "patch already applied (reverse-check clean): ${name}"
    return 0
  fi
  # Partial-layer case: a lower patch may already be applied while a higher
  # one is not, or combined uncommitted edits may block a strict reverse.
  # Accept only when the patch's resulting hunks are already present by
  # testing a no-op reverse dry-run after stripping nothing — otherwise fail.
  echo "FAIL: patch does not apply cleanly: ${patch}" >&2
  exit 1
}
for _pf in "${PATCH_FILES[@]}"; do
  apply_one_patch "${_pf}"
done

echo "== build libevent (isolated prefix) =="
if [[ ! -f "${PREFIX}/lib/libevent_core.a" ]]; then
  if [[ ! -d "${LIBEVENT_SRC}" ]]; then
    tar -xzf "${DEPS_DIR}/libevent-2.1.12-stable.tar.gz" -C "${DEPS_DIR}"
  fi
  (
    cd "${LIBEVENT_SRC}"
    ./configure --prefix="${PREFIX}" --disable-shared --disable-openssl --disable-samples --disable-libevent-regress
    make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
    make install
  )
fi

echo "== configure coturn =="
cd "${SRC_DIR}"
if [[ ! -f Makefile ]]; then
  ./configure \
    --prefix="${PREFIX}" \
    --disable-shared \
    --disable-rabbitmq --disable-mongodb --disable-hiredis \
    --disable-pgsql --disable-mysql --disable-sqlite \
    CFLAGS="-I${PREFIX}/include -I${OPENSSL_PREFIX}/include -O1" \
    LDFLAGS="-L${PREFIX}/lib -L${OPENSSL_PREFIX}/lib"
fi

echo "== build patched (ordinary CLOCK_MONOTONIC) =="
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)" bin/turnserver
cp -f bin/turnserver "${BIN_DIR}/turnserver-patched"

echo "== build clockfault (TURN_TEST_CLOCK_FAULT compile-time seam) =="
make clean >/dev/null
make bin/turnserver CPPFLAGS="-DTURN_TEST_CLOCK_FAULT"
cp -f bin/turnserver "${BIN_DIR}/turnserver-clockfault"

echo "== rebuild ordinary patched after clean =="
make clean >/dev/null
make bin/turnserver
cp -f bin/turnserver "${BIN_DIR}/turnserver-patched"

echo "== hashes =="
shasum -a 256 "${BIN_DIR}/turnserver-patched" "${BIN_DIR}/turnserver-clockfault"
echo "build OK"
