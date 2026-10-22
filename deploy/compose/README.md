# Docker Compose deployment paths

The development Compose file builds the Rust server and Go TUI into one Linux
x64 image. It runs as UID/GID 10001, stores the database and local Manager
identity in a named volume, keeps the container root filesystem read-only,
drops Linux capabilities, and serves a loopback HTTP API beside a separate TLS
v2 API.

The development path is a source-build candidate. It requires network access
while Docker fetches the pinned Rust, Go, Debian, Cargo, and Go module
dependencies. It is not an offline release bundle.

The Linux release artifact builder also packages an amd64 image archive built
from the exact staged server and TUI binaries. The release Compose file uses a
content-derived local image tag and disables pulling, so installing that image
does not need a registry connection. The signed Linux package covers the
archive and Compose files together.

The release Compose file uses explicit bind mounts for its data root and backup
directory. Set those paths in `.env`, create them before starting Compose, and
make them writable by UID/GID 10001. The data-root mount also contains the
container's private Manager identity under `$HOME/.local/state/helicoid`, so
recreating the container does not replace the initiating device key. This
explicit host mapping lets the lifecycle backend preserve or remove the
reviewed data and backup directories. An explicit data purge also removes the
Compose TUI's private Manager identity; the default removal policy preserves
both.

The Linux lifecycle backend supports reviewed Compose plan, apply, resume,
status, and removal. It verifies the signed image archive, journals the
operation-specific image tag and project, checks container and network labels,
and stages the reviewed TLS pair into the project directory. Scheduled backups
use a root-owned systemd service and an AF_UNIX socket mounted into the
container. The socket accepts only the fixed enable/disable operations and
checks the connecting process UID/GID against the Compose server identity; the
container does not receive the Docker socket. Removal targets only owned
resources and keeps the shared content-tagged image. Online updates, restore,
and recovery are still pending for Compose.

## Release artifacts

On Linux x86_64, scripts/build-linux-artifact-dir.sh OUTPUT_DIR requires the
pinned Rust and Go toolchains plus Docker Buildx with a builder that supports
the Docker archive exporter. It adds these files under
OUTPUT_DIR/artifacts/compose/:

- server-image.tar: the offline-loadable Linux amd64 image.
- compose.yaml: the matching image reference and runtime configuration.
- image-ref and image-id: the local tag and Docker image ID.
- .env.example and tls/readme.md: initial configuration guidance.

Pass the resulting artifact directory to
scripts/package-linux-release.sh ARTIFACT_DIR VERSION SIGNING_KEY OUTPUT_DIR
to sign the complete package. The release image uses the same staged binaries
as the systemd package. Docker Engine and Compose are still prerequisites on
the deployment host.

## Prepare for a lifecycle-managed install

1. Install Docker Engine and Docker Compose plugin 2.17.0 or newer on Ubuntu
   x64. The source build uses Compose's named `hs-core` build context.
2. Prepare a certificate chain and private key for the server name clients
   will use. This package does not create or distribute a certificate
   authority, configure DNS, or change firewall rules.
3. Create the data and backup directories from `.env` and give them to UID/GID
   10001. For the defaults, run:

   ```sh
   install -d -o 10001 -g 10001 -m 0700 /var/lib/helicoid /var/lib/helicoid/backups
   ```
4. Set `deploy/compose/tls` and both PEM files to UID/GID 10001 with modes
   `0700` for the directory and `0600` for each file. The server verifies the
   ownership and permissions before opening the key.
5. Copy `.env.example` to `.env`. The default publishes TLS only on host
   loopback. Set `HELICOID_PUBLISH_ADDRESS=0.0.0.0` only when direct LAN
   access is intended and the certificate, client trust, and firewall are
   ready.

The guided `scripts/install-linux.sh` flow writes the reviewed runtime `.env`
and starts the signed offline image itself; it does not use the manual first
start commands below. After installation it prints the exact `docker compose
exec` command for local bootstrap and ongoing TUI administration. The local
HTTP API stays inside the container; only the reviewed TLS authority port is
published on the host. The lifecycle-managed release also mounts one host
systemd socket directory for encrypted backup schedule enable/disable requests.
Manual Compose startup creates the empty mount directory if needed, but backup
scheduling is available only after the lifecycle installer has started the
product-owned host socket.

## Release package first start

From the extracted package's `artifacts/compose` directory, load the signed
offline image and initialize the database before starting the service:

```sh
cp .env.example .env
install -d -o 10001 -g 10001 -m 0700 /var/lib/helicoid /var/lib/helicoid/backups
docker image load --input server-image.tar
docker compose -f compose.yaml run --rm --no-deps server \
  --data /var/lib/helicoid/data/server.db init
docker compose -f compose.yaml up -d
docker compose -f compose.yaml exec -it server helicoid-server bootstrap
```

The image load does not contact a registry. For custom paths, edit `.env`
before starting and create the corresponding host directories with UID/GID
10001 ownership. Keep the bootstrap token and recovery material out of shell
history, environment files, logs, and support exports.

## Development first start

From this directory, initialize the empty database once and retain the
single-use token from the terminal output:

```sh
cp .env.example .env
docker compose -f compose.yaml build
docker compose -f compose.yaml run --rm --no-deps server \
  --data /var/lib/helicoid/data/server.db init
docker compose -f compose.yaml up -d
docker compose -f compose.yaml exec -it server helicoid-server bootstrap
```

The last command runs the TUI inside the container. It uses the local-only
loopback API, creates the first Manager identity in the persistent volume,
and completes administrator MFA enrollment. Keep the bootstrap token and
recovery material out of shell history, environment files, logs, and support
exports.

Docker reports the service as healthy only after `/health` reports completed
bootstrap and an accepting authorization state. The healthcheck calls the
loopback API from inside the container; it does not verify external DNS,
certificate trust from a Manager device, firewall reachability, or endpoint
enrollment.

For later administration, use:

```sh
docker compose -f compose.yaml exec -it server helicoid-server
```

The network listener uses TLS and the v2-only router. Bootstrap and factor
recovery are available through the local TUI or CLI surfaces, not through the
network listener. The host-published port defaults to `127.0.0.1:8920`; a
local reverse proxy can reach it from the same host. Direct LAN publication
requires the explicit `.env` address change above. No public-edge, DNS, PKI,
proxy, or UFW configuration is applied by this Compose package.

The development `helicoid-state` volume contains both the SQLite store and the
initiating Manager's private key material. The release Compose file stores
those items in the configured host data root. Use the encrypted backup command
inside the running container; copying a live SQLite file or this entire
directory is not a consistent encrypted backup procedure. The server TUI can
also enable a host systemd timer on systemd 250 or newer. The root-owned timer
validates the installed project and image, then delivers the passphrase to the
running container over stdin. No automatic database migrations run on
container start.
