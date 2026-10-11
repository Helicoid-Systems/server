# Helicoid Systems — coordination server foundation

`hs-server` is an independently buildable Rust service owned by `modules/server`.
It provides the first durable slice of the Helicoid Systems coordination plane:
local accounts, single-use bootstrap, manager enrollment distinct from operator
auth, per-computer access scopes, bounded inventory reads, and explicit
security-state-unavailable behavior.

| Identity | Value |
| --- | --- |
| Product | **Helicoid** (Helicoid Systems) |
| Organization | Helicoid-Systems |
| Apps | **Helicoid Manager** (operator console), **Helicoid Computer** (managed endpoint) |

Repository: https://github.com/Helicoid-Systems/server. Durable release identifiers remain pending.

The Windows private-store candidate is under native review. Read-only [ACL diagnostics](https://github.com/Helicoid-Systems/server/actions/runs/38162915222) identified TrustedInstaller ancestor ownership and creation-only/inherit-only grants. The repair distinguishes ancestors from protected product objects, uses aligned native SID storage and scoped test privileges, and preserves exclusive create and live SQLite sidecar checks. The coordinator passes240 Mac tests, formatting, strict Clippy/build and Windows source type checks. These do not establish Windows runtime acceptance. Main retains accepted server `3a20aa0` until the complete native suite passes; public listeners, Windows TLS, installed services and recovery remain unavailable. Earlier native failures and the exact acceptance boundary are recorded in [BUILD-REPORT.md](BUILD-REPORT.md).


## What this foundation is

| Area | Status in this build |
| --- | --- |
| Local account bootstrap + login | Implemented (Argon2id passwords) |
| Opaque bearer sessions | Implemented (SHA-256 at rest, never logged) |
| Manager enrollment | Implemented as **loopback development identity fixtures** |
| D20 deny-before-approval | Implemented (pending manager cannot bind/login) |
| Per-computer access scopes | Implemented (explicit IDs or scope-all) |
| Bounded inventory reads | Implemented (hard cap 100) |
| Schema init / migration | Storage schema 2; explicit init or migration with consistent backup; never migrates on open |
| Security State Unavailable | Durable latch; restart never resets it; no auto-recovery |
| Required read/commit failures | Latch + `503 security_state_unavailable` (not bare 500) |
| v2 administrator MFA | TOTP enrollment, Ed25519 device proof and atomic challenge completion implemented for loopback development. **Unix private-store only** — see Windows section |
| v2 recovery credentials | Bounded, single-use factor recovery only; cannot issue normal sessions |
| Configurable operator MFA / scoped delegation | Unavailable; production policy still gated |
| File jobs / authority recovery and cutover | Explicitly unavailable (`501`) |
| Remote control / screen observation | Not present (B02/B03/RD03 proofs pending) |
| Bind policy | **Literal loopback only** (`127.0.0.1` / `::1`); other binds refused |
| HTTPS transport | `serve-tls`, default `127.0.0.1:8920`, maintained rustls TLS1.2/1.3 and private held-descriptor material reads; Unix only; public routes remain closed |
| Login throttle | v1 development map remains bounded/in-memory; v2 challenge throttles are durable and capacity-capped |
| Linux installer candidate | Signed-manifest verification, ownership-bounded journal and native adapter hardening; installed Linux acceptance still required |
| Windows/macOS host installation | Unavailable in this server build |
| Windows persistent v2 MFA | **Candidate / native Not Verified**: held no-follow handles, exact owner/SYSTEM/Administrators ACL and trusted file-child inheritance. Full native CI must pass before integration adoption |

Legacy v1 Manager `public_identity` values are **not** cryptographic production identities.
They are development fixtures for local/loopback integration until B03 freezes
signed endpoint/manager identity formats. Do not invent grant formats.

MFA-enrolled accounts refuse legacy password-only login through the service,
HTTP route and CLI. The final session transaction rechecks MFA state, account
state, the verified password hash and manager approval. Legacy accounts without
MFA remain an explicitly loopback-only development path. The Windows private-store candidate requires private current-user ownership and trusted child inheritance before explicit migration;
native refusal tests retain both the original database bytes and no-output checks.

The [v2 development contract](contracts/http-v2.md) describes deployment-bound
Ed25519 challenges, administrator enrollment, transaction boundaries and recovery
limits. Unix HTTPS transport is implemented as a loopback prerequisite. Production trust adoption, public authentication and public routes remain unavailable.
The v1 HTTP wire contract remains version 1; health separately reports storage
schema version 2. Reviewed authority baseline `3656c22` passed **209 tests** on macOS
(61 lib + 24 auth_v2 + 12 http_api + 44 installer + 29 installer_adapter +
12 installer_review + 6 mfa_legacy_boundary + 21 review_findings), formatting and clippy pass; this
does not establish production readiness. The HTTPS candidate adds 29 tests; coordinator acceptance is **238 Mac tests**, formatting, clippy and build. Native Linux/Windows HTTPS-candidate CI is pending.

Platform-split of `tests/installer_adapter.rs` (29 total): **19 portable**
(listener/parser/systemctl decode, read bounds, injected query faults) run on
every OS including Windows; **10 Unix-only** `cfg(unix)` real-filesystem
regressions cover the descriptor-relative atomic writer (`write_file_atomic`).
There is no Windows native service installer and no Windows atomic writer —
host installation on Windows/macOS remains unavailable.

Verified authority baseline `3656c22` ([CI 38139828063](https://github.com/Helicoid-Systems/server/actions/runs/38139828063)); HTTPS-candidate native counts remain pending:

| Platform | Verified total | Notes |
| --- | --- | --- |
| macOS | **209** (observed) | includes 5 Darwin-only extended-ACL tests |
| Linux | **203** | excludes 5 Darwin ACL tests and one Mac-only installer check |
| Windows | **182** | portable + 10 Windows denial/legacy tests; excludes Unix-only FS and Darwin ACL tests |

`hs-server --data /private-product-directory/hs-server.db serve-tls --tls-cert /private-product-directory/server.crt --tls-key /private-product-directory/server.key` requires operator-supplied certificate/key files. Each file is bounded at64KiB, owner-only, regular, singly linked and read through its verified held descriptor. It refuses malformed/mismatched material before opening data. Public binds and Windows TLS hosting refuse before reading material or creating data. Bootstrap remains local-only or inside verified SSH tunnels. These checks do not establish installation or enrollment readiness.

In-memory (nonpersistent) auth v2 tests run on **every** platform including
Windows and exercise real TOTP/Ed25519/recovery crypto. They are **not** a
production confidentiality claim and **not** a persistent-MFA support claim.

## Build and test

```sh
export CARGO_HOME=/tmp/hs-toolchain/cargo
export RUSTUP_HOME=/tmp/hs-toolchain/rustup
export PATH=/tmp/hs-toolchain/cargo/bin:$PATH
export CARGO_TARGET_DIR=/tmp/hs-build/server-target

cd modules/server
cargo fmt -- --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

Independent GitHub Actions workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
runs the three Linux checks for this crate as its own repository root, plus a
native `windows-latest` job (`cargo test --locked`, `cargo build --locked --release`)
that uploads a disposable development download bundle (`hs-server.exe`,
`scripts/start-development.cmd`, `scripts/start-development.ps1`, `scripts/windows-tester.md`).

## Operate (development)

```sh
# 1. Create schema and print a single-use bootstrap token (shown once, stored hashed).
hs-server --data ./hs-server.db init

# 2. Create the first administrator. Prefer stdin for the password.
printf '%s' 'your-long-password' | hs-server --data ./hs-server.db bootstrap \
  --token '<token-from-init>' --username admin --password-stdin \
  --manager-public-identity dev-manager-key --manager-friendly-name 'Lab manager'

# 3. Serve the HTTP API (loopback only — non-loopback binds are refused).
hs-server --data ./hs-server.db serve --bind 127.0.0.1:8787
```

`hs-server check-login --username admin --password-stdin` verifies credentials
without starting HTTP and immediately discards the ephemeral session.

Never log or print `password`, `token`, `bootstrap_token`, or `Authorization`.

## Windows 11 x64 development download

CI artifact `hs-server-windows-x64-dev` (from the `windows-latest` job) contains:

| File | Purpose |
| --- | --- |
| `hs-server.exe` | Release build of this server |
| [`scripts/start-development.cmd`](scripts/start-development.cmd) | Double-click launcher that retains errors |
| [`scripts/start-development.ps1`](scripts/start-development.ps1) | Disposable literal-loopback fixture launcher |
| [`scripts/windows-tester.md`](scripts/windows-tester.md) | Tester instructions and manual CLI steps |

`start-development.ps1` creates a fresh unique disposable database directory
(refuses any existing DB), prompts for a password of at least 12 characters
(hidden), passes that password to `hs-server` only via stdin, captures the init
bootstrap token in memory only, approves exactly `dev-manager-key` at bootstrap,
and serves on `http://127.0.0.1:8787` in the foreground until Ctrl+C.

It does **not** install a service, elevate, bypass execution policy, open
firewall ports, bind non-loopback, auto-create access scopes, or delete the
disposable directory. PowerShell cannot guarantee managed-string zeroization;
see `windows-tester.md` for the honest residual-risk table.

Connect **Helicoid Manager** in development-server mode:

```powershell
.\Helicoid.Manager.exe --development-server --development-manager-identity dev-manager-key
# or: .\Helicoid.Manager.exe --development-server=http://127.0.0.1:8787 --development-manager-identity dev-manager-key
```

Fixture values: address `http://127.0.0.1:8787`, manager identity `dev-manager-key`
(loopback development fixture, not a production cryptographic identity),
username `admin` (password is whatever you entered at the prompt).

### Windows private-store candidate and accepted legacy baseline

This candidate verifies held-handle owner/DACL boundaries before opening or
creating persistent credentials. Existing objects are never silently re-ACL'd;
unknown principals, unsafe namespace rights, aliases/reparse points and public
SQLite sidecars are refused. Native Windows runtime acceptance is still pending.
Installation, public hosting and Windows TLS are unavailable.

The accepted downloaded baseline `3a20aa0` opens a **legacy loopback development** store
(`StoreCapability::PersistentUnverified`):

- **Available:** v1 `init` / `bootstrap` / `check-login` / `serve` on literal
  loopback (the PowerShell fixture path above).
- **Denied:** NEW persisted v2 MFA credentials (`bootstrap-v2`, factor
  recovery, MFA enrollment confirm) — refused before the transaction and
  before any secret is printed. Recovery-file private creation is also denied.
- **Refused at open:** a database that already contains persisted MFA rows
  (`account_mfa`, `recovery_codes`, `mfa_enrollments`). There is no implicit
  migration and no exposure of existing v2 authority through legacy paths.
- **Privacy boundary:** the on-disk store is **not** claimed private on
  Windows (no native-verified owner/SYSTEM/administrators DACL). Treat the
  disposable development directory as readable by other local principals
  that can traverse to it. Do not place production credentials there.
- **Production hosting on Windows is unavailable.** Do not install as a
  service, do not expose beyond loopback, and do not claim MFA or
  confidential-storage support. Enabling Windows persistent v2 later
  requires an exact allowlist DACL verification on the held HANDLE plus
  native prove-success tests — never a SID blacklist.

In-memory nonpersistent stores still exercise real TOTP/Ed25519/recovery
crypto on Windows. That is a **narrower** proof than persistent MFA support.

## API contract

Native clients integrate from **[contracts/http-v1.md](contracts/http-v1.md)**.
HTTP wire shape is unchanged from that version-1 file.

## Security notes for this foundation

- Passwords: Argon2id via the maintained `argon2` crate (PHC strings).
- Session tokens: 32-byte OS RNG values; only SHA-256 digests are stored.
- Owner fields (capabilities, scopes) come from the session, never from request bodies.
- Administration capability does not imply inventory, observe, or operate rights.
- Single-use bootstrap token is hashed at rest and consumed transactionally.
- Durable Security State Unavailable latch: hydrated at service start with
  exact integer `0`/`1` (invalid values fail closed); required storage **and**
  lock-poison/internal failures latch and deny new authority; memory latch stays
  authoritative if the durable note cannot be written; **never auto-recovers**.
- Health is fail-closed: `accepting_authorized_operations` is true only after
  bootstrap completes and trust state is healthy. Missing deployment row latches.
- Non-loopback socket binds are refused before listen (CLI + `require_loopback_bind`).
- Login throttle map is bounded (dev budget 1024 keys, idle prune 15m); unknown
  keys fail closed when saturated. This is not production credential/MFA policy.
- Request types that carry secrets do not implement `Debug`.
- No TLS terminator, certificate bypass, or invented signed grants in-process.

## Out of scope here

Broader plan work (file jobs, production MFA policy, recovery/cutover, remote desktop,
native apps, production installers) remains required and unfinished. See
`BUILD-REPORT.md` for tested versus unproven boundaries.

On Windows, double-click `start-development.cmd` or run the PowerShell script
from an existing terminal. The CMD launcher keeps errors visible after the
child process stops and preserves the configured execution policy.


Current HTTPS prerequisite code `ccaf29a` passed **238 Mac, 231 Linux and189 native Windows tests**, formatting/Clippy/build and the actual Windows PowerShell development fixture. [Native CI38143445740](https://github.com/Helicoid-Systems/server/actions/runs/38143445740) provides the [Windows x64 development server](https://github.com/Helicoid-Systems/server/actions/runs/38143445740/artifacts/11703299972). Windows exercises explicit TLS/private-MFA refusal; it does not support HTTPS hosting in this revision. Public connections, installed services and production recovery remain unavailable.
