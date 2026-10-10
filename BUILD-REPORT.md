# BUILD-REPORT — Helicoid `hs-server` foundation

Owned path: `modules/server/**` only.  
Product: **Helicoid** (Helicoid Systems). Organization: **Helicoid-Systems**.  
Working names: HS Manager / HS Computer.  
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
