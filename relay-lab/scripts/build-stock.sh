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
OPENSSL_PREFIX="${OPENSSL_PREFIX:-/opt/homebrew/opt/openssl}"

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

echo "== ensure libevent (isolated prefix) =="
if [[ ! -f "${PREFIX}/lib/libevent_core.a" ]]; then
  if [[ ! -f "${DEPS_DIR}/${LIBEVENT_TARBALL}" ]]; then
    curl -fsSL -o "${DEPS_DIR}/${LIBEVENT_TARBALL}" "${LIBEVENT_URL}"
    echo "${LIBEVENT_SHA256}  ${DEPS_DIR}/${LIBEVENT_TARBALL}" | shasum -a 256 -c -
  fi
  if [[ ! -d "${DEPS_DIR}/libevent-2.1.12-stable" ]]; then
    tar -xzf "${DEPS_DIR}/${LIBEVENT_TARBALL}" -C "${DEPS_DIR}"
  fi
  (
    cd "${DEPS_DIR}/libevent-2.1.12-stable"
    ./configure --prefix="${PREFIX}" --disable-shared --disable-openssl --disable-samples --disable-libevent-regress
    make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
    make install
  )
fi

echo "== configure/build stock (unpatched) =="
(
  cd "${STOCK_SRC}"
  if [[ ! -f Makefile ]]; then
    ./configure \
      --prefix="${PREFIX}" \
      --disable-shared \
      --disable-rabbitmq --disable-mongodb --disable-hiredis \
      --disable-pgsql --disable-mysql --disable-sqlite \
      CFLAGS="-I${PREFIX}/include -I${OPENSSL_PREFIX}/include -O1" \
      LDFLAGS="-L${PREFIX}/lib -L${OPENSSL_PREFIX}/lib"
  fi
  make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)" bin/turnserver
)
cp -f "${STOCK_SRC}/bin/turnserver" "${STOCK_OUT_DIR}/turnserver-stock"
echo "== stock hash =="
shasum -a 256 "${STOCK_OUT_DIR}/turnserver-stock"
echo "stock build OK"
