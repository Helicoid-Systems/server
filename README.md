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

Literal-loopback HTTPS now passes complete [CI38259032769](https://github.com/Helicoid-Systems/server/actions/runs/38259032769) at code `1d996692a248c4c743525e34c9481a6e4fe472c8`: **235 Linux and243 Windows tests**, strict Clippy, release build and both PowerShell launchers. The coordinator independently passes **242 Mac tests**, verifies the downloaded archive digest, PE x64 executable and companion scripts, and checks real Windows TLS health, wrong CA/name, plaintext, unsafe DACL/hardlink and bounded handshake/shutdown tests. [Download the development server bundle](https://github.com/Helicoid-Systems/server/actions/runs/38259032769/artifacts/11751622589). Windows process cleanup proves owned-child kill/reap; installed service-stop and Windows11 acceptance remain Not Verified.

Existing SQLite store files accept only currentUser/SYSTEM/Administrators ownership together with the strict held DACL/shape/link and protected-parent boundary. New objects, recovery/key reads and product directories remain current-user owned; foreign and TrustedInstaller store owners remain refused. The launcher chooses a missing path and lets the server create its protected folder. Literal-loopback HTTPS (`serve-tls`) on Unix and Windows uses the native-verified private_file held reader. Public authentication/listeners, installed services, recovery cutover and signing remain unavailable. This is a native private-store/MFA/CLI prerequisite plus a verified Windows loopback TLS prerequisite, not a completed deployment or worker/admission checkpoint. Historical failures and acceptance boundaries are in [BUILD-REPORT.md](BUILD-REPORT.md).

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
| v2 administrator MFA | TOTP enrollment, Ed25519 device proof and atomic challenge completion implemented for loopback development. Native private-store tests pass on Unix and Windows; public authentication remains gated |
| v2 recovery credentials | Bounded, single-use factor recovery only; cannot issue normal sessions |
| Configurable operator MFA / scoped delegation | Unavailable; production policy still gated |
| File jobs / authority recovery and cutover | Explicitly unavailable (`501`) |
| Remote control / screen observation | Not present (B02/B03/RD03 proofs pending) |
| Bind policy | **Literal loopback only** (`127.0.0.1` / `::1`); other binds refused |
| HTTPS transport | `serve-tls`, default `127.0.0.1:8920`, maintained rustls TLS1.2/1.3 and private held-descriptor material reads on Unix and Windows; public routes remain closed |
| Login throttle | v1 development map remains bounded/in-memory; v2 challenge throttles are durable and capacity-capped |
| Linux installer candidate | Signed-manifest verification, ownership-bounded journal and native adapter hardening; installed Linux acceptance still required |
| Installer package targets | Typed trusted target (`linux-x86_64`, `windows-x86_64`, `macos-arm64`, `macos-x86_64`) and portable artifact paths in [contracts/installer-package-targets-v1.md](contracts/installer-package-targets-v1.md); verification only — Windows/macOS installation remains unavailable |
| Windows/macOS host installation | Unavailable in this server build |
| Windows persistent v2 MFA | **Verified prerequisite**: real native bootstrap/MFA/reopen, strict current-user directories/material, trusted SQLite file owners and private child inheritance. Installed service identity and security review remain Not Verified |

Legacy v1 Manager `public_identity` values are **not** cryptographic production identities.
They are development fixtures for local/loopback integration until B03 freezes
signed endpoint/manager identity formats. Do not invent grant formats.

MFA-enrolled accounts refuse legacy password-only login through the service,
HTTP route and CLI. The final session transaction rechecks MFA state, account
state, the verified password hash and manager approval. Legacy accounts without
MFA remain an explicitly loopback-only development path. The Windows private store requires a protected current-user product directory, trusted child inheritance and verified trusted SQLite file ownership before explicit migration;
native refusal tests retain both the original database bytes and no-output checks.

The [v2 development contract](contracts/http-v2.md) describes deployment-bound
Ed25519 challenges, administrator enrollment, transaction boundaries and recovery
limits. Literal-loopback HTTPS transport is implemented on Unix and Windows as a
loopback prerequisite. Production trust adoption, public authentication and
public routes remain unavailable.
The v1 HTTP wire contract remains version1; health separately reports storage schema2. Current complete acceptance is **242 Mac,235 Linux and243 Windows tests** at `1d99669`. Native checks come from CI38259032769; Mac checks and artifact inspection were reproduced by the coordinator. Earlier `f01019f` (private-store) and `ccaf29a` (Unix TLS) artifacts refused Windows TLS and remain historical evidence in BUILD-REPORT.md.

Platform-split of `tests/installer_adapter.rs` (29 total): **19 portable**
(listener/parser/systemctl decode, read bounds, injected query faults) run on
every OS including Windows; **10 Unix-only** `cfg(unix)` real-filesystem
regressions cover the descriptor-relative atomic writer (`write_file_atomic`).
There is no Windows native service installer and no Windows atomic writer —
host installation on Windows/macOS remains unavailable.

Current native private-store/MFA/CLI and loopback HTTPS prerequisite:

| Platform | Verified total | Notes |
| --- | --- | --- |
| macOS | **242** | Coordinator full tests, formatting, strict Clippy and build |
| Linux | **235** | Native full tests, formatting and strict Clippy |
| Windows Server 2025 CI | **243** | Native full tests including24 TLS tests, strict Clippy, release and actual PowerShell5.1/7 launchers; installed Windows11 runtime and service-stop remain Not Verified |

`hs-server --data /private-product-directory/hs-server.db serve-tls --tls-cert /private-product-directory/server.crt --tls-key /private-product-directory/server.key` requires operator-supplied certificate/key files. Each file is bounded at64KiB, owner-only, regular, singly linked and read through its verified held descriptor. It refuses malformed/mismatched material before opening data. Public binds refuse before reading material or creating data on every platform. Bootstrap remains local-only or inside verified SSH tunnels. These checks do not establish installation or enrollment readiness.

In-memory (nonpersistent) auth v2 tests run on **every** platform including
Windows and exercise real TOTP/Ed25519/recovery crypto. They are **not** a
production confidentiality claim and **not** a persistent-MFA support claim.

## Build and test

```sh
cd modules/server
cargo fmt -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
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

`start-development.ps1` selects a fresh unique disposable database path
(refuses any existing path or DB) and lets `hs-server init` create the private
store directory (current-user owned, protected DACL; the launcher never
creates that folder with `New-Item` and never re-ACLs one), prompts for a
password of at least 12 characters (hidden), passes that password to
`hs-server` only via stdin, captures the init bootstrap token in memory only,
approves exactly `dev-manager-key` at bootstrap, and serves on
`http://127.0.0.1:8787` in the foreground until Ctrl+C.

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
SQLite sidecars are refused. Native Windows CI acceptance of the private-store and loopback TLS prerequisites is recorded above. Installation and public hosting remain unavailable.

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
- Bootstrap tokens are opaque URL-safe base64 and may begin with `-`; both
  `bootstrap` and `bootstrap-v2` accept `--token VALUE` unchanged (Clap
  `allow_hyphen_values` on that option only). Invalid tokens still fail closed.
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


Historical HTTPS prerequisite code `ccaf29a` passed **238 Mac, 231 Linux and189 native Windows tests**, formatting/Clippy/build and the actual Windows PowerShell development fixture. [Native CI38143445740](https://github.com/Helicoid-Systems/server/actions/runs/38143445740) provides the [Windows x64 development server](https://github.com/Helicoid-Systems/server/actions/runs/38143445740/artifacts/11703299972). That revision refused Windows HTTPS hosting. The current tree enables literal-loopback `serve-tls` on Unix and Windows through the native-verified private_file held reader; public connections, installed services and production recovery remain unavailable. Current native Linux/Windows TLS checks and coordinator artifact inspection are recorded above and in BUILD-REPORT.md.
