# BUILD-REPORT — Helicoid `hs-server` auth v2 prerequisite

## Inherit-only ACL fixture repair, 12 October 2026

Native [CI 38246041857](https://github.com/Helicoid-Systems/server/actions/runs/38246041857) at `c939c8f` passed Linux and 72 Windows library tests; the single failure was `trusted_store_owner_with_untrusted_dacl_is_refused` expecting a policy refusal after `add_ace` installed a Users `INHERIT_ONLY|OBJECT_INHERIT` ACE on a **regular file**. That leaf fixture did not establish on-disk retention of its intended ACE. Microsoft documents `INHERIT_ONLY` as a child-inheritance ACE; kernel filtering remains an inference because the failed run took no on-disk snapshot. Production `check_product_allow_aces` is unchanged.

Test-only repair in `src/private_file_windows.rs`: (1) keep the Administrators-owner + NULL DACL actual-file case; (2) replace the leaf inherit-only case with a current-write foreign Users ACE on a real store file plus an explicit `GetAce` retention precondition; (3) add `trusted_store_owner_with_unknown_inherit_only_on_acl_carrier_is_refused`, which uses a real directory solely as an OS ACL carrier that retains the unknown `INHERIT_ONLY|OBJECT_INHERIT` ACE (GetAce precondition; absence is a fixture error), sets Administrators owner, and requires `verify_private_store_file_on_handle` — the same owner+DACL seam as actual store files — to refuse. The public `windows_verify_private_store_file` file-kind guard is unchanged and the test asserts directory refusal. Recovery strict-owner, foreign/TI byte preservation, and product-dir inherit-only denials are retained. Scoped thread `SeRestorePrivilege` RAII only; no process privilege, skip, or weakened assertion. Removing the unknown inherit-only SID check makes the new fixture go red.

Production prefix of `private_file_windows.rs` (bytes before `// ----- native regression tests`) SHA-256 `b21a33d02b5f4b64b8b863596530f7d3ccf771871e8cddfa814654c348e8d7fb` is unchanged. Fresh coordinator checks: `cargo fmt -- --check` clean, `cargo test --locked` **240 Mac tests**, `cargo clippy --locked --all-targets -- -D warnings` clean. Mac commands do not execute the Windows ACL module. Native Windows acceptance of the repaired fixtures remains **Not Verified** until the next actual CI run. Sources: [ACE Inheritance](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance), [ACE Inheritance Rules](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules), [AddAccessAllowedAceEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addaccessallowedaceex) (fetched 12 October 2026).

## Trusted SQLite file owners, 12 October 2026

The actual [Windows run 38167890462](https://github.com/Helicoid-Systems/server/actions/runs/38167890462) at `44346bf` passed 67 library tests and failed only the two live/recreated SQLite sidecar checks. Both WAL and SHM were Administrators-owned; the process user was currentUser and the token default owner was Administrators. Linux passed. The earlier private seed creation repair passed its three migration/seed checks.

This bounded repair separates existing SQLite file verification from generic private material. A held DB/WAL/SHM/journal handle accepts current user, SYSTEM or Administrators ownership only after protected current-user product-parent, no-follow, regular-file, single-link and strict trusted-DACL checks. Explicit creates, product directories and recovery/key/material reads retain current-user ownership. No arbitrary token owner, TrustedInstaller, foreign SID, NULL/unsupported DACL or unknown granting ACE is admitted; existing files are never re-ACL'd. Four native regressions exercise trusted-owner/DACL combinations, foreign/TI byte preservation and the strict recovery boundary. Test owner changes use the existing scoped thread-only privilege fixture. The coordinator removed an invalid audit-only flag fixture because `AddAccessAllowedAceEx` does not accept that flag; production unsupported-ACE rejection was unchanged. [Microsoft API contract](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addaccessallowedaceex).

Recovered sanitized MiMo export `ses_ffe5ed38da822ffe1RKcnobODp` confirms every assistant turn used `xiaomi/mimo-v2.6-pro`. Fresh 12 October coordinator checks pass **240 Mac tests**, formatting, strict locked all-target Clippy and build. Temporary tools/logs from 11 October were cleared; this run restores disposable dependencies and records fresh checks. The historical Windows type harness was not rerun; complete Windows runtime acceptance remains **Not Verified at candidate publication**. Main's accepted server stays `3a20aa0` pending the full Linux/Windows tests, lint, release and fixture gates. Windows TLS, public routes, installed services, recovery and security review remain outstanding.

## SQLite fixture ownership and native diagnosis, 11 October 2026

[Native CI 38165068195](https://github.com/Helicoid-Systems/server/actions/runs/38165068195) at `ff98740` passes Linux and 64 Windows library tests but fails four database/sidecar owner checks. Ancestor-policy and scoped-privilege regressions pass. Three seed helpers let SQLite create the database before verification; the reviewed repair creates a private file through the protected API before SQLite opens it. It retains the actual old/current schemas, no-overwrite and byte-preservation checks.

MiMo exported metadata confirms `xiaomi/mimo-v2.6-pro`. Test-only diagnostics classify held object owners and the process default owner as current user, SYSTEM, Administrators, TrustedInstaller or other. The coordinator removed external error prose from diagnostic lines and collects both live sidecar roles before closing SQLite. No paths, account names, SIDs or file contents enter those lines. The hypothesis that elevated default ownership differs from the current user awaits actual Windows evidence; production owner acceptance remains unchanged.

Fresh coordinator checks pass **240 Mac tests**, formatting, strict all-target Clippy, build and the real Windows source/test type harness. The complete Windows store gate remains **Not Verified**. Main retains `3a20aa0`; the next native run must supply the sidecar ownership classifications before any compatibility change. Windows TLS, public listeners, installed hosting and recovery remain unavailable.

## Windows ancestor-policy repair from native evidence, 11 October 2026

The previous candidate `19f14d0` compiled but [CI38161333976](https://github.com/Helicoid-Systems/server/actions/runs/38161333976) passed24 library tests and failed32 on ancestor ownership. Bounded read-only [diagnostic38162915222](https://github.com/Helicoid-Systems/server/actions/runs/38162915222) then confirmed TrustedInstaller root ownership, Authenticated Users creation-only `0x4`, and inherit-only generic grants. No system ACL changed.

MiMo session metadata confirms only `xiaomi/mimo-v2.6-pro`. The reviewed repair admits exact TrustedInstaller ownership on ancestors only, ignores supported inherit-only ACEs on their current ancestor, and permits read/traverse plus `FILE_ADD_SUBDIRECTORY`. File-add/write-data, deletion and security mutation remain refused. Product owner and trusted principal rules stay strict, including unknown inherit-only grants. SID, token, security-descriptor and test ACL storage is aligned and owned. Held relative opens, no-follow checks and exclusive protected create preserve the existing privacy boundary; installed-service and path-based SQLite security review remain outstanding.

The coordinator corrected owner fixtures to use scoped thread impersonation, checking actual privilege assignment and restoring prior context even on unwind. A native regression checks that process privileges and previous thread context remain unchanged. These test privileges are absent from production code. New native ACL regressions cover creation-only and mutation grants, TrustedInstaller role separation, inherit-only role separation, no overwrite/re-ACL, and live SQLite files. Coordinator checks pass **240 Mac tests**, format, strict Clippy/build and real Windows module/test type checks. Full native Windows execution is **Not Verified at this candidate publication**; main's accepted server remains `3a20aa0`. Windows TLS, public listeners, installed hosting and recovery stay unavailable.

## Windows private-store candidate, 11 October 2026

MiMo Code metadata confirms `xiaomi/mimo-v2.6-pro`. This candidate adds Windows held-handle no-follow traversal, separate ancestor namespace and final private-object policies, exclusive kernel-private create, bounded private reads and protected trusted file-child inheritance for SQLite WAL/SHM/journal recreation. Existing objects are never silently re-ACL'd. Unix behavior, schema/auth protocols, Windows TLS refusal and public listener gates are unchanged.

Coordinator review repaired native pointer/API mismatches, required OBJECT_INHERIT rather than container-only inheritance, live sidecar tests, NT/Win32 path alias refusal, and a dangling absolute security-descriptor Owner SID. The descriptor now retains its owner allocation and aligned storage. Regression tests cover actual private create/read, unknown principals, NULL DACL, inheritance, hard links/reparse, sidecars during live writes/transactions and owner allocation churn.

Coordinator reproduced **238 Mac tests**, formatting, build and Clippy. A real-source Windows-target type harness (including this module's tests) passes Clippy with warnings denied; it excludes full-crate linkage and is **not runtime evidence**. Full native Linux/Windows CI is **Not Verified** at publication. A foreign-user owner test, installed service identity, production security review and recovery remain outstanding. The integration repository retains accepted server `3a20aa0` until native checks pass. This is a candidate, not a release or completed installer.

Native [CI38147363684](https://github.com/Helicoid-Systems/server/actions/runs/38147363684) at candidate `3741506515399750289edf727ffc8d1184a8d5d2` failed before Windows runtime: `create_new_private_file` was imported only on Unix in a Windows test. The reviewed repair fixes that import, creates genuine private product children before fixture writes, and tests real persisted MFA close/reopen plus corrupt-boundary byte preservation. WAL/SHM must exist while the DB is live; public negative fixtures receive explicit unknown-principal grants in aligned native ACL storage. Coordinator checks pass 238 Mac tests, format, strict Clippy and build. Windows-native acceptance remains **Not Verified** until the repaired candidate passes full CI; the module-only type harness excludes integration tests and runtime. Native [CI38160803572](https://github.com/Helicoid-Systems/server/actions/runs/38160803572) then found `E0609` in three Windows-only MFA assertions: the real DTO field is `totp_secret_base32`. The correction also runs bootstrap and persistent close/reopen behavior on Unix, so fixture DTO and persistence drift is compiled and exercised locally. Coordinator checks now pass **240 Mac tests**, format, strict Clippy and build. Windows ACL-specific corruption remains native-only; repaired native CI is still required. Windows TLS stays unavailable and the accepted integration pin remains `3a20aa0`.

## Current HTTPS prerequisite evidence, 11 October 2026

MiMo `xiaomi/mimo-v2.6-pro` implemented Unix loopback `serve-tls` on port8920 using maintained rustls/axum-server, with explicit TLS1.2/1.3, ALPN and bounded handshake/shutdown. The coordinator reviewed and repaired secret-buffer ownership: a fixed bounded held-descriptor read, guarded PEM/DER refusal paths, and borrowed key loading with maintained key/certificate matching. Parser/provider internal allocations are outside the app's zeroization guarantee. Public listeners and Windows TLS hosting remain unavailable.

Coordinator checks pass **238 Mac tests** (209 authority/installer baseline +29 TLS/CLI cases), formatting, clippy with warnings denied and build. Genuine TLS sockets cover trust/name/plaintext denial and bounded fixture handshakes. Actual binary tests cover required arguments, default bind, public denial before material/data effects, real TLS health and SIGINT shutdown. Native [CI38143445740](https://github.com/Helicoid-Systems/server/actions/runs/38143445740) passed at exact TLS code revision `ccaf29ab1255ba7c2669128e0dbf5bb2f9af3612`: **231 Linux and189 Windows tests**, formatting/Clippy, Windows release build and actual PowerShell development fixture. The Windows TLS cases exercise explicit early refusal. [Artifact11703299972](https://github.com/Helicoid-Systems/server/actions/runs/38143445740/artifacts/11703299972) supplies the Windows x64 development server. Platform-specific successes are scoped to Unix, and portable CLI checks run on all platforms.

The previously reviewed `3656c22` baseline passed **203 Linux tests and182 native Windows tests** in [CI38139828063](https://github.com/Helicoid-Systems/server/actions/runs/38139828063), plus209 Mac tests and21 actual development-client loopback checks. The following auth report is historical evidence for that baseline. Production public auth, installed hosting, observation/control and recovery remain gated.

Owned path: `modules/server/**` only (installer adapter worker source untouched).
Product: **Helicoid** (Helicoid Systems). Organization: **Helicoid-Systems**.
Apps: **Helicoid Manager** / **Helicoid Computer**.
Build date: 11 October 2026 (auth v2 + filesystem and portability review).
Toolchain: rustc 1.99.0 / cargo 1.99.0 (`/tmp/hs-toolchain`).
Target: `/tmp/hs-build/server-target`.

## Outcome

**VERIFIED** for the bounded auth prerequisite after coordinator findings:
atomic challenge completion, deployment-bound proofs, durable bounded rate
state, explicit v1 wire/storage version split, storage caps, mandatory admin
MFA. **NOT VERIFIED / incomplete by design:** TLS, public route mounting, LAN
authority, production manager keys/signing, endpoint admission, native
installed proofs, configured operator MFA policy, media/control/file jobs,
security delegation/reset, real multi-process soak.

The coordinator reproduced 209 macOS tests, format/clippy, and all 21 native
client loopback checks. Backup output is now created privately before SQLite
writes its consistent snapshot; the existing migration regression exercises
the supported empty-file VACUUM output. Native Linux/Windows acceptance is
recorded separately after CI; Windows persisted MFA remains unavailable.

## Fresh proof commands (this turn)

```
cargo fmt -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
scripts/live-integration.sh /tmp/hs-build/server-target/debug/hs-server
```

| Command | Result |
| --- | --- |
| `cargo fmt -- --check` | **clean** |
| `cargo test --locked` | **209 passed, 0 failed** on macOS (61 lib + 24 auth_v2 + 12 http_api + 44 installer + 29 installer_adapter + 12 installer_review + 6 mfa_legacy_boundary + 21 review_findings) |
| `cargo clippy --locked --all-targets -- -D warnings` | **clean** |
| 21 client loopback checks | **21/21 passed** (dotnet ClientProof + swift ClientProof) |

### Additional coordinator review (2026-10-11)

The coordinator reproduced a legacy login bypass after genuine v2 TOTP
enrollment. MiMo V2.6 Pro repaired the shared `Service::login` boundary: MFA
factors and pending enrollment deny password-only session minting, including
HTTP and CLI callers. The final IMMEDIATE transaction also rechecks account
state, the verified password-hash snapshot and manager approval before insert.
Six regressions cover enrolled/pending/recovery MFA, approved manager identity,
mounted HTTP refusal without a token/session row and preserved legacy development
login for accounts without an MFA requirement. The coordinator tightened HTTP
status to 403 and required successful cleanup in the legacy success fixture.
No deterministic mid-call login race hook was introduced; transaction placement
was reviewed, while real multi-process authority integration remains unverified.

Native Windows migration fixtures now exercise the implemented refusal, keeping
v1/current stores byte-identical with no backup directory or sidecars. Unix
private migration success still runs. The coordinator replaced ignored sidecar
cleanup in the seed fixture with assertions that none were created. The legacy CLI fixture now parses the actual one-time-token header and runs
on every platform; token output stays captured and unprinted. Native
Linux/Windows CI must pass before the integration pin moves.

### Portability / pre-open boundary findings (2026-10-11)

| Finding | Fix | Tests |
| --- | --- | --- |
| Windows `db::open` always `NotImplemented` (legacy claim false) | Explicit legacy loopback open (`StoreCapability::PersistentUnverified`); refuses pre-existing MFA rows before schema mutation | `windows_legacy_loopback_init_and_bootstrap_still_work`, `open_refuses_preexisting_mfa_rows_when_store_is_unverified`, `windows_open_refuses_preexisting_mfa_rows` |
| Global platform bool broke in-memory auth_v2 on Windows | Db-owned `StoreCapability`; nonpersistent stores exercise real crypto; persistent unverified deny before transaction | `in_memory_store_exercises_real_crypto_on_every_platform`, `windows_persistent_denial::*` (4 API denials) |
| `set_current_dir` tests shared process cwd | Removed all chdir tests; relative-path tests use `tempdir_in(cwd)` without mutating cwd | `relative_path_resolves_against_cwd_not_root`, `relative_nested_path_resolves_against_cwd` |
| Sidecar validation after SQLite open | `symlink_metadata` classification of `-wal`/`-shm`/`-journal` **before** any open/pragma; migrate/backup same | `open_refuses_unsafe_regular_sidecar_and_preserves_state`, `open_refuses_dangling_symlink_sidecar_and_preserves_target`, `open_refuses_live_symlink_sidecar_and_preserves_target`, `migrate_refuses_dangling_symlink_sidecar_and_preserves_state` |
| `O_RDONLY` open of FIFO can hang | `O_NONBLOCK` + fd type check; shape probe refuses FIFO without opening | `fifo_store_file_is_refused_without_hang_or_write` |

### Coordinator findings disposition

| Finding | Fix | Tests |
| --- | --- | --- |
| v1 clients require `schema_version == 1` | `schema_version` = frozen wire v1; new `storage_schema_version` | `v1_health_wire_schema_version_stays_one` |
| Split transactions in complete | One final IMMEDIATE tx: recheck + consume + session | `revoked_manager_race_denies_inside_final_transaction`, `disabled_account_race_denies_inside_final_transaction`, `totp_consumption_failure_denies_without_session` |
| Proof excluded deployment | `deployment_key` in challenge + signed message (server-owned) | `wrong_deployment_proof_denies`, `proof_messages_are_domain_separated_and_deployment_bound` |
| In-memory throttle resets | Durable `challenge_throttle` + capacity caps | `durable_challenge_throttle_survives_service_recreation` |
| Unbounded challenge/TOTP rows | `MAX_AUTH_CHALLENGE_ROWS`, `MAX_TOTP_CONSUMPTIONS_PER_ACCOUNT` + prune | `auth_challenges_and_totp_rows_are_capacity_bounded` |
| MFA/recovery no sessions | Enforced + tests | `bootstrap_v2_creates_inactive_until_mfa_confirmed`, `recovery_requires_password_and_is_not_a_session` |
| Mandatory admin MFA | Documented; operator policy explicitly unavailable | `contracts/http-v2.md` MFA policy |

### Client delta (coordinator)

**None required** for `/health.schema_version` (stays `1`).
Optional additive field: `storage_schema_version` (currently `2`).

## Auth v2 summary

- **Crypto (maintained crates only):** argon2 passwords, totp-rs 5.5.1 with
  transactional time-step consumption, ed25519-dalek `verify_strict`
  deployment-bound device proofs, SHA-256-hashed single-use recovery codes.
- **Atomic completion:** crypto verify → one IMMEDIATE transaction
  (recheck account/manager/MFA/deployment binding, consume TOTP + challenge,
  insert session). Failure before commit issues no token.
- **Durable bounded rate state** and storage caps for challenges/TOTP ledger.
- **Schema v2** with explicit `migrate` + backup; startup never auto-migrates.
- **Unchanged:** v1 loopback wire shapes (schema_version stays 1);
  production media/control/file=false; loopback bind refusal; no insecure
  listener; installer adapter safety methods untouched.

Full details: `contracts/http-v1.md`, `contracts/http-v2.md`, and
`/tmp/hs-production-20261010/server-auth-report.md`.

---

# BUILD-REPORT — Helicoid `hs-server` foundation

Owned path: `modules/server/**` only.
Product: **Helicoid** (Helicoid Systems). Organization: **Helicoid-Systems**.
Apps: **Helicoid Manager** / **Helicoid Computer**.
Build date: 10 October 2026 (review-fix pass).
Toolchain: rustc 1.99.0 / cargo 1.99.0 (`/tmp/hs-toolchain`).
Dedicated target dir: `/tmp/hs-build/server-target`.

## Outcome

**VERIFIED** for the development foundation and all five coordinator review
findings (unit + integration tests + clippy/fmt + CLI refusal + loopback health).
**NOT VERIFIED:** production identity/cryptographic manager keys, LAN authority,
remote desktop, MFA, file jobs, recovery/cutover, real multi-process soak.

## Fresh proof commands (this turn)

```
cargo fmt -- --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

| Command | Result |
| --- | --- |
| `cargo fmt -- --check` | **clean** |
| `cargo test --locked` | **39 passed, 0 failed** (10 lib + 12 http_api + 17 review_findings) |
| `cargo clippy --all-targets -- -D warnings` | **clean** |

### Named tests (final guard/health pass)

| Finding | Tests |
| --- | --- |
| Latch hydration exact 0/1 | `hydrate_fails_closed_on_invalid_security_state_ok_integer`, `invalid_security_state_ok_integer_fails_closed`, `security_state_ok_one_hydrates_ok` |
| Missing deployment row latches | `missing_deployment_row_latches_and_denies_authority`, `hydrate_fails_closed_when_deployment_row_missing` |
| Health bootstrap semantics | `health_unbootstracked_is_not_accepting`, `health_accepts_only_after_bootstrap`, `health_reports_real_bootstrap_completed_when_latched` |
| Guard lock/Internal uncertainty | `internal_storage_uncertainty_fails_closed`, `required_read_failure_latches_and_denies_without_deadlock` |
| Unique tempdirs | `tempfile` dev-dependency (UUID-backed dirs); no `process::id` + `remove_file` helpers |

### Named tests (review findings)

| Finding | Tests |
| --- | --- |
| 1 Durable latch | `security_latch_survives_file_reopen`, `security_latch_survives_service_recreation_same_db`, `hydrate_fails_closed_when_deployment_row_missing`, `hydrate_fails_closed_when_trust_table_unreadable` |
| 2 Required-read guard | `required_read_failure_latches_and_denies_without_deadlock`, `health_fails_closed_when_durable_record_unreadable` |
| 3 Loopback-only bind | `refuses_non_loopback_bind_addresses`, `cli_serve_refuses_wildcard_bind`, `health_on_loopback_socket_still_works` |
| 4 Bounded throttle | `invalid_username_length_rejected_before_hash_work`, `login_throttle_locks_out_and_expires`, `login_throttle_bounded_fails_closed_when_saturated`, `throttle_prunes_expired_idle_entries` |
| 5 CI / no secret Debug | `.github/workflows/ci.yml`; `BootstrapRequest`/`LoginRequest` and CLI `Debug` removed |

Prior foundation tests (schema init, single-use bootstrap, deny-before-approval,
scoped inventory, unique claims, explicit 501 surfaces) still pass.

These include a real loopback TCP health probe and a real `hs-server` CLI
process refusal for `0.0.0.0` / `[::]`. They are **not** OS-installed platform
proof.

## Review fixes implemented

### 1. Durable Security State latch

- `Service::new` hydrates `deployment.security_state_ok` as **exact integer 0/1**
  (`2` or any non-`1` value → `Unavailable`; avoids SQLite nonzero-as-true).
- Missing row, unreadable table, or storage error → `SecurityState::Unavailable`.
- Restart / service recreation never resets a latched deployment (file reopen tested).
- Memory latch is authoritative if persisting the durable note fails.
- **Policy: never auto-recover.** Recovery is an explicit future E07/V47 procedure.

### 2. Centralized required persistence guard

- `with_conn` uses an IIFE so **lock acquisition errors** also flow through
  `finish_storage` (not an early return past the guard).
- `finish_storage` maps `AppError::Storage` **and** lock-poison/`Internal`
  uncertainty → latch + `503 security_state_unavailable`.
- Guard runs only after the Db mutex is released (no deadlock).
- Health latches on a **missing deployment row** (memory cannot stay `Ok`).
- Health reports real `bootstrap_completed` when the durable row is readable.

### 3. Loopback-only bind

- `require_loopback_bind` refuses non-loopback before listen.
- CLI `serve --bind 0.0.0.0` and `serve --bind [::]` exit non-zero (tested).
- Real `127.0.0.1` socket `/health` returns 200 (tested).
- **Wire contract shape unchanged**; health semantics documented in
  `contracts/http-v1.md` (accepting only after bootstrap).

### 4. Bounded login throttle

- Map keyed by `normalize_login_key` = `trim` + ASCII lowercase (matches DB
  `COLLATE NOCASE` for the ASCII username charset we accept).
- `LOGIN_THROTTLE_MAX_KEYS = 1024`; idle entries pruned after 15 minutes.
- Unknown keys fail closed (`429`) when saturated; existing lockout fairness kept
  (5 failures → 60s lock, success clears the key).
- Username/password length rejected **before** Argon2 work.
- Not production credential/MFA policy (still E07).

### 5. CI and hygiene

- Independent GitHub Actions: `modules/server/.github/workflows/ci.yml` runs
  `cargo fmt -- --check`, `cargo test --locked`, `cargo clippy --all-targets -- -D warnings`
  as this crate’s repository root.
- Secrets-bearing `Debug` removed from `BootstrapRequest`, `LoginRequest`, and CLI.
- Sensitive values never appear in logs or this report.

## Product decisions (confirmed by user)

- Product name **Helicoid** (Helicoid Systems); organization **Helicoid-Systems**.
- **D18:** dynamic All / fixed explicit monitoring scope.
- **D21:** file-request close retains files; replacement needs confirmation.
- Those workflows remain unimplemented in this foundation (no room/class/lesson objects).

## Explicit non-goals (unchanged)

MFA, file jobs, security recovery, authority cutover, remote control/pixels,
production LAN, TLS in-process, signed production manager identity. Manager
`public_identity` remains a **loopback development fixture**.

## API contract

`contracts/http-v1.md` remains the owned v1 wire contract. **No response shape
changes** required for these fixes. Added operational note: non-loopback binds
are refused at start (CLI), not a JSON field.

## Next actions (outside this owner)

1. B03/E07 production identities, MFA, delegation ceilings, replay fencing.
2. S01 native clients on `contracts/http-v1.md`.
3. File jobs / recovery / cutover per `docs/spec/build-map.md`.

---

# BUILD-REPORT — Windows 11 x64 development-server download

Date: 10 October 2026.
Owned paths this pass: `modules/server/.github/workflows/**`,
`modules/server/scripts/**`, `modules/server/README.md`, `modules/server/BUILD-REPORT.md`.
No Rust `src`/`tests`/`contracts`/`Cargo.lock` changes. No git/push/deletes.
Server not started on this Mac.

## Outcome

**VERIFIED (this Mac, content-level):** workflow YAML structure, script/tester
artifact paths, fixture contract text (fresh unique disposable DB, literal
loopback, no service/elevation/ExecutionPolicy bypass/firewall, password on
stdin not argv, token in memory / env not argv, fixed `dev-manager-key`, no
auto scope creation, no auto-delete of test directory).
**NOT VERIFIED (this Mac):** Windows PowerShell execution of
`start-development.ps1`, native `windows-latest` Rust build/test of this crate,
artifact download by a Windows 11 tester. **CI Windows must establish the
Windows Rust build after coordinator publishes. Do not treat that gate as
passed from Mac.**

## Fresh proof commands (this turn)

| Command | Result |
| --- | --- |
| `ls modules/server/scripts modules/server/.github/workflows` | `start-development.ps1`, `windows-tester.md`, `ci.yml` present |
| `ruby -ryaml -e "...YAML.load_file(...ci.yml)..."` | **clean parse**; jobs `verify,windows`; Linux verify steps preserved (Checkout/Toolchain/Cache/Format/Test/Clippy); windows steps Test/Build release/Stage/Upload |
| `git status --short` in `modules/server` | only `.github/workflows/ci.yml`, `README.md`, `BUILD-REPORT.md` modified + `scripts/` added; no Rust/src/tests/contracts/lock changes |
| `command -v pwsh` / `powershell` | **not installed on this Mac** — script not executed here |
| Server binary start | **not run** (explicitly out of scope on this Mac) |
| Python structural scan of `start-development.ps1` | brace/paren balance 0; required markers present (`Read-Host -AsSecureString`, `--password-stdin`, `HS_BOOTSTRAP_TOKEN`, `dev-manager-key`, `127.0.0.1:8787`, `ZeroFreeBSTR`, `serve --bind`); no `Write-Host` of password/token variables |

## Deliverables

| Path | Role |
| --- | --- |
| `.github/workflows/ci.yml` | Linux `verify` job unchanged (`fmt` / `test --locked` / `clippy`); new `windows` job: `cargo test --locked`, `cargo build --locked --release`, upload `hs-server-windows-x64-dev` |
| `scripts/start-development.ps1` | Disposable fixture launcher (Windows PowerShell 5.1+) |
| `scripts/windows-tester.md` | Tester instructions + exact manual CLI steps |
| `README.md` | Windows download section; app names set to **Helicoid Manager** / **Helicoid Computer** |
| `BUILD-REPORT.md` | This report |

CI artifact `hs-server-windows-x64-dev` stages: `hs-server.exe`,
`start-development.ps1`, `windows-tester.md`.

## Runtime fixture contract (encoded in script + docs)

| Requirement | Implementation |
| --- | --- |
| Fresh unique disposable DB directory | `helicoid-hs-server-<timestamp>-<guid8>` under temp or `-ParentDirectory`; **refuses** existing directory and any existing DB file |
| Literal loopback | `serve --bind 127.0.0.1:8787` only; server itself refuses non-loopback |
| No service / elevation / ExecutionPolicy bypass / firewall / network exposure | Script never does these; docs tell testers not to use `-ExecutionPolicy Bypass` |
| Password >= 12, prompted securely | `Read-Host -AsSecureString`; length checked before bootstrap |
| Password via stdin not argv | `--password-stdin` + pipeline; `--password` flag never used |
| Init token in memory only | Captured from `init` stdout; not printed; passed as `HS_BOOTSTRAP_TOKEN` for bootstrap only (not argv, not a file) |
| Bootstrap approves fixed `dev-manager-key` | `--manager-public-identity dev-manager-key` (same value Manager sends at login) |
| Foreground serve, Ctrl+C stops | Direct `& hs-server.exe serve` (no service) |
| User-visible address / identity / username | Printed before serve; password/token/bearer **never** logged |
| No auto-create scopes/authority | No HTTP admin calls after bootstrap; docs state inventory stays empty |
| Never delete test directory | Script leaves the disposable directory in place |

## Script syntax / tool availability / limitations (recorded)

| Item | Status |
| --- | --- |
| Target dialect | Windows PowerShell **5.1** (`#Requires -Version 5.1`); also intended for PowerShell 7+ |
| `$PSScriptRoot`, `Read-Host -AsSecureString`, `Marshal.SecureStringToBSTR` / `ZeroFreeBSTR` | Used; available in 5.1 |
| `ProcessStartInfo.ArgumentList` | **Not used** (not in .NET Framework / PS 5.1) |
| UTF-8 stdin for `--password-stdin` | `$OutputEncoding` set to UTF-8 no BOM for the bootstrap call (PS 5.1 native pipe encoding quirk) |
| Managed-string zeroization | **Not possible.** Variables cleared and `[GC]::Collect()` requested as best effort only. Report and tester doc say this explicitly — no zeroization claim |
| Local `pwsh` / `powershell` on build Mac | **Absent.** Script not syntax-executed here |
| Windows CI Rust build/test | **Pending coordinator publish.** `windows-latest` job is the proof gate |

## Manager launch flags (verified against source)

Actual Windows Helicoid Manager switches (`DevelopmentLaunchOptions.cs`):

- `--development-server` (optional `=http://127.0.0.1:8787`)
- `--development-manager-identity dev-manager-key`

Handoff prose mentioned `--development-server-address` / `--manager-public-identity`
(those names are the macOS manager surface). Tester docs use the **Windows**
switches above so sign-in actually works. Identity value remains `dev-manager-key`.

## Explicit non-goals (this pass)

Production installer/authority/remote-engine claims, LAN exposure, service
install, scope auto-grant, secret zeroization claims, starting the server on
this Mac, asserting Windows CI green from Mac.

Coordinator review changed bootstrap to a child-only environment and explicit UTF-8 stdin, preserving the calling PowerShell environment/encoding and applying a 15-second deadline. Windows CI parses the actual launcher with Windows PowerShell, calls its real init/bootstrap helpers, authenticates the Unicode password, checks caller environment preservation and refuses reused bootstrap. Results remain pending until that native job completes.

## Windows user handoff correction

The user confirmed both Windows apps launch. Their server-test video showed
Explorer opening the PowerShell source in an editor and a subsequent
PowerShell window closing before an error could be read. No sign-in success
is inferred from that video. The bundle now includes `start-development.cmd`,
which invokes the same script without elevation or policy override and pauses
after its child exits, preserving visible error diagnostics. The launcher
keeps the exact foreground loopback behavior and does not install a service.
Actual double-click behavior on the user's PC still needs their test.

## Coordinator reproduction and installer boundary

The coordinator independently reproduced all 158 runtime tests, formatting and
clippy, built the exact server binary, and passed 21 loopback integration checks
using both actual native client libraries. The three vendored v1 contracts match
SHA-256 `3e9f5de05569618cc1746513e4da70e789888bca4d42b73628864e7335a1ac02`
(12,354 bytes).

The Linux installer candidate verifies an independently pinned Ed25519 release
manifest, recomputes plan ownership, journals before mutation and bounds repair/
removal to product resources. The shared Unix atomic writer uses descriptor-
relative no-follow traversal, exclusive private temporary files, rename and
file/directory synchronization. Listener and service queries fail closed on
errors. Its 29 adapter regressions run against actual files on macOS; native
Linux installation on an occupied host is Not Verified. Windows/macOS local
service installers, encrypted backup, quarantined recovery and signed updates
remain unfinished. No resources were installed on the supplied Ubuntu VM.

### Platform-split installer adapter tests

`tests/installer_adapter.rs` is gated by real platform applicability, not by
skipping portable checks:

| Group | Count | Gate | Runs on Windows |
| --- | --- | --- | --- |
| proc-net / systemctl decode + bounds + injected faults | 19 | none (portable) | **yes** |
| `write_file_atomic` real-FS (symlink, exclusive-create, mode, world-writable parent) | 10 | `#[cfg(unix)]` | no — Unix/Linux writer only |
| **Total** | **29** | | **19 on Windows** |

The production atomic writer stays `#[cfg(unix)]` / LinuxAdapter
`#[cfg(target_os = "linux")]`. There is no Windows atomic writer and no
Windows native service installer; `run_installer` on non-Linux still returns
"installer requires a Linux host". Do not treat the Windows job as an
installed-host proof.

Historical suite total before the private-store repair was **158** (21 lib + 23 auth_v2 + 12 http_api + 44
installer + 29 installer_adapter + 12 installer_review + 17 review_findings).
The historical portability-only estimate was **148** (158 − 10); current
platform counts come from the subsequent filesystem/capability checks.
Coordinator claims native CI; this pass only gates and typechecks.
