#!/usr/bin/env bash
# Build the unpatched stock coturn baseline used for defect reproduction.
# Shared by standalone docs and CI — one recipe, no duplicated inline builds.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=pins.sh
source "${SCRIPT_DIR}/pins.sh"

LAB_ROOT="${LAB_ROOT:-/tmp/hs-finish-20261013/relay-lab}"
STOCK_SRC="${STOCK_SRC:-${LAB_ROOT}/coturn-stock-src}"
DEPS_DIR="${LAB_ROOT}/deps-src"
PREFIX="${LAB_ROOT}/prefix"
STOCK_OUT_DIR="${STOCK_OUT_DIR:-${LAB_ROOT}/coturn-stock-20261017/bin}"

mkdir -p "${STOCK_OUT_DIR}" "${PREFIX}" "${DEPS_DIR}"

echo "== ensure pinned stock source =="
if [[ ! -d "${STOCK_SRC}/.git" ]]; then
  git clone --filter=blob:none --no-checkout "${REPO_URL}" "${STOCK_SRC}"
fi
git -C "${STOCK_SRC}" fetch --depth 1 origin "${PIN_COMMIT}"
git -C "${STOCK_SRC}" checkout --detach "${PIN_COMMIT}"
got="$(git -C "${STOCK_SRC}" rev-parse HEAD)"
if [[ "${got}" != "${PIN_COMMIT}" ]]; then
  echo "FAIL: stock HEAD ${got} != pinned ${PIN_COMMIT}" >&2
  exit 1
fi
# Refuse to build a patched/modified tree under a stock name.
if ! git -C "${STOCK_SRC}" diff --quiet HEAD --; then
  echo "FAIL: stock checkout has modified tracked source; refusing stock build" >&2
  git -C "${STOCK_SRC}" status --porcelain -uno >&2 || true
  exit 1
fi
if ! git -C "${STOCK_SRC}" diff --cached --quiet HEAD --; then
  echo "FAIL: stock checkout has staged tracked changes; refusing stock build" >&2
  exit 1
fi

echo "== ensure libevent (isolated prefix, OpenSSL enabled) =="
ensure_libevent "${PREFIX}" "${DEPS_DIR}"
export_relay_dep_env "${PREFIX}"
verify_libevent_prefix "${PREFIX}"

echo "== configure/build stock (unpatched) =="
(
  cd "${STOCK_SRC}"
  if [[ ! -f Makefile ]]; then
    ./configure \
      --prefix="${PREFIX}" \
      "${COTURN_CONFIGURE_ARGS[@]}" \
      CFLAGS="${CFLAGS}" \
      LDFLAGS="${LDFLAGS}"
  fi
  make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)" bin/turnserver
)
cp -f "${STOCK_SRC}/bin/turnserver" "${STOCK_OUT_DIR}/turnserver-stock"
echo "== stock hash =="
shasum -a 256 "${STOCK_OUT_DIR}/turnserver-stock"
echo "stock build OK"
