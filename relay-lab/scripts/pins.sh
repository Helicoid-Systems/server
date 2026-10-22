# Shared pins and dependency/configure flags for relay-lab fetch/build scripts
# (sourced, not executed).
PIN_COMMIT="23c6c1d32a3d2b21a56cee65d3203bcc4ea82d2b"
PIN_TAG_OBJECT="000296e7fdb41ed99ca325fcbd19d64404990980"
REPO_URL="https://github.com/coturn/coturn.git"
LIBEVENT_TARBALL="libevent-2.1.12-stable.tar.gz"
LIBEVENT_URL="https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/${LIBEVENT_TARBALL}"
LIBEVENT_SHA256="92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb"
LIBEVENT_VERSION="2.1.12-stable"

# Host OpenSSL prefix. Existing host install only — never apt/brew install from
# this lab. Override with OPENSSL_PREFIX (Linux CI sets /usr).
if [[ -z "${OPENSSL_PREFIX:-}" ]]; then
  if [[ -d /opt/homebrew/opt/openssl ]]; then
    OPENSSL_PREFIX="/opt/homebrew/opt/openssl"
  else
    OPENSSL_PREFIX="/usr"
  fi
fi

# Shared libevent configure flags for stock and patched builds.
# OpenSSL support MUST stay enabled: coturn configure probes
#   libevent_core libevent_extra libevent_openssl libevent_pthreads
# via pkg-config. `--disable-openssl` omits libevent_openssl and that probe
# fails with "Libevent2 development libraries are not installed properly".
# Do not flip this to --disable-openssl and do not drop --enable-openssl.
LIBEVENT_CONFIGURE_ARGS=(
  --disable-shared
  --enable-openssl
  --disable-samples
  --disable-libevent-regress
)

# Shared coturn configure flags for stock and patched builds (same recipe).
COTURN_CONFIGURE_ARGS=(
  --disable-shared
  --disable-rabbitmq --disable-mongodb --disable-hiredis
  --disable-pgsql --disable-mysql --disable-sqlite
)

# Idempotent build of pinned libevent into an isolated prefix with OpenSSL
# enabled. Rebuilds if a previous install lacks libevent_openssl.a.
# Usage: ensure_libevent "<prefix>" "<deps_dir>"
ensure_libevent() {
  local prefix="$1"
  local deps_dir="$2"
  local src="${deps_dir}/libevent-${LIBEVENT_VERSION}"
  local tarball="${deps_dir}/${LIBEVENT_TARBALL}"
  local nproc

  mkdir -p "${prefix}" "${deps_dir}"
  if [[ -f "${prefix}/lib/libevent_openssl.a" ]]; then
    echo "libevent ${LIBEVENT_VERSION} with OpenSSL already in ${prefix}"
    return 0
  fi
  if [[ ! -f "${tarball}" ]]; then
    curl -fsSL -o "${tarball}" "${LIBEVENT_URL}"
  fi
  echo "${LIBEVENT_SHA256}  ${tarball}" | shasum -a 256 -c -
  if [[ ! -d "${src}" ]]; then
    tar -xzf "${tarball}" -C "${deps_dir}"
  fi
  nproc="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
  (
    cd "${src}"
    ./configure --prefix="${prefix}" "${LIBEVENT_CONFIGURE_ARGS[@]}" \
      CPPFLAGS="-I${OPENSSL_PREFIX}/include" \
      LDFLAGS="-L${OPENSSL_PREFIX}/lib" \
      PKG_CONFIG_PATH="${OPENSSL_PREFIX}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
    make -j"${nproc}"
    make install
  )
  if [[ ! -f "${prefix}/lib/libevent_openssl.a" ]]; then
    echo "FAIL: ${prefix}/lib/libevent_openssl.a missing after libevent install" >&2
    return 1
  fi
}

# Export pkg-config/compiler paths so coturn configure resolves the isolated
# libevent (including libevent_openssl) first. Host OpenSSL paths are appended
# for libssl/libcrypto only. Callers must still verify no system libevent
# fallback when a probe is required (see verify_libevent_prefix).
# Usage: export_relay_dep_env "<prefix>"
export_relay_dep_env() {
  local prefix="$1"
  export PKG_CONFIG_PATH="${prefix}/lib/pkgconfig:${OPENSSL_PREFIX}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
  export CFLAGS="-I${prefix}/include -I${OPENSSL_PREFIX}/include -O1"
  export LDFLAGS="-L${prefix}/lib -L${OPENSSL_PREFIX}/lib"
}

# Fail unless every coturn-required libevent module resolves to the isolated
# prefix (blocks Homebrew/system libevent fallback). Uses pkg-config when
# available (Linux CI); otherwise reads the installed .pc files directly.
# Usage: verify_libevent_prefix "<prefix>"
verify_libevent_prefix() {
  local prefix="$1"
  local mod pc resolved
  local pcdir="${prefix}/lib/pkgconfig"
  for mod in libevent_core libevent_extra libevent_openssl libevent_pthreads; do
    if command -v pkg-config >/dev/null 2>&1; then
      if ! pkg-config --exists "${mod}"; then
        echo "FAIL: pkg-config cannot find ${mod}" >&2
        return 1
      fi
      resolved="$(pkg-config --variable=prefix "${mod}")"
      if [[ "${resolved}" != "${prefix}" ]]; then
        echo "FAIL: ${mod} resolves to '${resolved}', expected isolated prefix '${prefix}'" >&2
        return 1
      fi
    else
      pc="${pcdir}/${mod}.pc"
      if [[ ! -f "${pc}" ]]; then
        echo "FAIL: missing ${pc} (and pkg-config unavailable)" >&2
        return 1
      fi
      resolved="$(sed -n 's/^prefix=//p' "${pc}" | head -1)"
      if [[ "${resolved}" != "${prefix}" ]]; then
        echo "FAIL: ${mod}.pc prefix='${resolved}', expected '${prefix}'" >&2
        return 1
      fi
    fi
  done
  if [[ ! -f "${prefix}/lib/libevent_openssl.a" ]]; then
    echo "FAIL: ${prefix}/lib/libevent_openssl.a missing" >&2
    return 1
  fi
  echo "libevent modules resolve to isolated prefix: ${prefix}"
}
