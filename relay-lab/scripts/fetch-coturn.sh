#!/usr/bin/env bash
# Fetch pinned coturn 4.18.0 sources into the lab scratch tree.
# Bulk source stays in scratch only (never vendored into git).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=pins.sh
source "${SCRIPT_DIR}/pins.sh"

LAB_ROOT="${LAB_ROOT:-/tmp/hs-finish-20261013/relay-lab}"
SRC_DIR="${LAB_ROOT}/coturn-src"
DEPS_DIR="${LAB_ROOT}/deps-src"

mkdir -p "${LAB_ROOT}" "${DEPS_DIR}"

echo "== fetch coturn @ ${PIN_COMMIT} =="
if [[ ! -d "${SRC_DIR}/.git" ]]; then
  git clone --filter=blob:none --no-checkout "${REPO_URL}" "${SRC_DIR}"
fi
git -C "${SRC_DIR}" fetch --depth 1 origin "${PIN_COMMIT}"
git -C "${SRC_DIR}" checkout --detach "${PIN_COMMIT}"
got="$(git -C "${SRC_DIR}" rev-parse HEAD)"
if [[ "${got}" != "${PIN_COMMIT}" ]]; then
  echo "FAIL: coturn HEAD ${got} != pinned ${PIN_COMMIT}" >&2
  exit 1
fi
if git -C "${SRC_DIR}" cat-file -t "${PIN_TAG_OBJECT}" >/dev/null 2>&1; then
  echo "tag object ${PIN_TAG_OBJECT} present"
else
  echo "WARN: tag object ${PIN_TAG_OBJECT} not fetched (blob:none filter); commit pin still enforced"
fi
echo "coturn commit verified: ${got}"

echo "== fetch libevent =="
if [[ ! -f "${DEPS_DIR}/${LIBEVENT_TARBALL}" ]]; then
  curl -fsSL -o "${DEPS_DIR}/${LIBEVENT_TARBALL}" "${LIBEVENT_URL}"
fi
echo "${LIBEVENT_SHA256}  ${DEPS_DIR}/${LIBEVENT_TARBALL}" | shasum -a 256 -c -

echo "fetch OK"
