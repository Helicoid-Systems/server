# Helicoid Systems Server HTTP contract — version 2 (auth)

Product: **Helicoid** (Helicoid Systems). Organization: Helicoid-Systems.
Owner: `modules/server`. Status: development foundation (auth prerequisite).
Clients integrate against this file and `contracts/http-v1.md`; do not invent
additional fields.

Transport: HTTP/1.1 JSON on the configured bind address. **Default and required
bind is literal loopback only.** TLS and public route mounting are **not** part
of this contract (following task). Production media, control, and file features
remain **false**.

## Relationship to v1

| Surface | v1 (`contracts/http-v1.md`) | v2 (this file) |
| --- | --- | --- |
| Loopback development login | `POST /v1/auth/login` (unchanged) | — |
| Bootstrap | `POST /v1/bootstrap` (dev identity fixture) | `POST /v2/bootstrap` (TOTP MFA + proven manager key) |
| MFA | status-only stub | real TOTP, recovery-only, device-key challenge |
| Sessions | opaque bearer tokens | same tokens, short-lived after v2 completion |

v1 loopback development behavior is explicitly backward compatible. Do not
open v1 foundation endpoints publicly (endpoint admission, native installed
proofs, and signing are gated separately).

## Common error envelope

Identical to v1:

```json
{
  "error": {
    "code": "bad_request",
    "message": "human-readable summary",
    "detail": "optional machine detail"
  }
}
```

| `code` | HTTP | Meaning |
| --- | --- | --- |
| `bad_request` | 400 | Invalid input |
| `unauthorized` | 401 | Missing/invalid/expired/consumed challenge or factor |
| `forbidden` | 403 | Wrong device proof, revoked manager, clock rollback, inactive account |
| `not_found` | 404 | Unknown enrollment/challenge |
| `conflict` | 409 | Single-use already consumed / expired enrollment |
| `unprocessable` | 422 | Schema/refusal condition |
| `rate_limited` | 429 | Username or challenge throttle (no account enumeration) |
| `not_implemented` | 501 | Feature explicitly unavailable in this foundation |
| `security_state_unavailable` | 503 | Trusted persistence uncertain; new authority paused |
| `internal` | 500 | Unexpected storage/processing failure |

Never log `password`, `token`, `challenge_token`, `bootstrap_token`,
`totp_secret_base32`, `recovery_codes`, `manager_signature`, or `Authorization`.

---

## Schema and migrations

Schema version is **2**. `hs-server migrate` performs an explicit
schema-versioned upgrade after a consistent pre-migration backup
(`VACUUM INTO`, WAL checkpointed). **Startup never auto-migrates** a nonempty
database: `hs-server open/serve/init` refuse an older schema and direct the
operator to `migrate`. Fresh empty databases install v2 directly.

Accounts gain state `pending_mfa` (inactive until MFA confirmation **and**
independently stored recovery material). Managers gain an optional Ed25519
`public_key` (hex, 32 bytes, unique when present).

---

## `POST /v2/bootstrap`

Local CLI or authenticated tunnel only. Transactional and single-use.
Creates the first administrator in `pending_mfa` (inactive).

Manager device key is bound **only after its Ed25519 proof** over the
deployment-bound message:

```text
hs-bootstrap-v2|deployment:<deployment_key>|token:<bootstrap_token_sha256_hex>|manager:<public_key_hex>
```

`deployment_key` is the server-owned deployment identity (persisted at install
or migration; never client-selected). An arbitrary claimed identity is refused.

```json
{
  "bootstrap_token": "<from hs-server init>",
  "username": "admin",
  "password": "at-least-12-characters",
  "manager_public_key": "<ed25519 hex 32 bytes>",
  "manager_proof": "<ed25519 hex 64 bytes>",
  "manager_friendly_name": "Optional label"
}
```

`manager_public_key` + `manager_proof` are both required to bind a device key;
both must be omitted for a keyless bootstrap.

**201** — secrets are returned **once** and must not be logged:

```json
{
  "account_id": "…",
  "username": "admin",
  "mfa_enrollment_id": "…",
  "totp_secret_base32": "…",
  "recovery_codes": ["XXXX-XXXX-XXXX-XXXX", "…"],
  "manager_public_key": "<ed25519 hex>",
  "account_state": "pending_mfa",
  "server_state": "awaiting_mfa_confirmation"
}
```

Administrator remains **inactive** until TOTP confirmation and independently
stored recovery material are both established. Pending TOTP setup cannot create
an ordinary session.

---

## `POST /v2/mfa/enroll/confirm`

Confirm a pending TOTP enrollment. Single-use and bounded (15 minutes).

```json
{
  "mfa_enrollment_id": "…",
  "totp_code": "123456",
  "recovery_material_stored": true
}
```

`recovery_material_stored` must be `true`: recovery codes must be stored
independently (offline / operator-held) before activation. The server stores
only SHA-256 hashes.

**200**

```json
{
  "account_id": "…",
  "mfa_status": "active",
  "account_state": "active"
}
```

This endpoint never issues a session token.

---

## `POST /v2/mfa/enroll/cancel`

Cancel a pending enrollment (bootstrap cancellation). Consumes the enrollment;
account is disabled if it never completed MFA.

```json
{ "mfa_enrollment_id": "…" }
```

**204** on success. Confirmation after cancel returns `409`.

---

## `POST /v2/auth/challenge`

Start a bounded durable one-use challenge. Password validation runs first;
the challenge is bound to **this deployment**, the **exact manager Ed25519
public key**, and the **intended operation**. The server derives the account
from the password-validated challenge — the client never re-supplies it at
completion.

Allowed `operation` values: `session`, `enroll_manager`, `manage_access`.

```json
{
  "username": "admin",
  "password": "…",
  "operation": "session",
  "manager_public_key": "<ed25519 hex 32 bytes>"
}
```

**201**

```json
{
  "challenge_id": "…",
  "challenge_token": "<opaque, once>",
  "operation": "session",
  "manager_public_key": "<ed25519 hex>",
  "deployment_id": "<server-owned deployment key>",
  "expires_at_unix": 1760000120
}
```

Challenge lifetime: **120 seconds**. Pending/revoked managers, inactive
accounts, and missing MFA deny. Username and challenge attempts are rate
limited with the **same** error shape for unknown and known accounts (no
enumeration).

---

## `POST /v2/auth/challenge/complete`

Prove the approved manager Ed25519 key and required TOTP factor.

The manager signs the domain-separated message, which includes the
**server-owned deployment identity** (from `deployment_id` in the begin
response / persisted challenge row — never client-selected):

```text
hs-auth-v2|deployment:<deployment_id>|challenge:<challenge_id>|operation:<operation>|manager:<manager_public_key_hex>
```

```json
{
  "challenge_id": "…",
  "challenge_token": "<from begin>",
  "manager_signature": "<ed25519 hex 64 bytes>",
  "totp_code": "123456"
}
```

**200**

```json
{
  "token": "<opaque bearer, short-lived>",
  "expires_at_unix": 1760007200,
  "account": { "…": "AccountView" },
  "manager": { "…": "ManagerView" },
  "mfa": { "required": true, "available": true, "reason": "totp_active" }
}
```

Token TTL: **2 hours** (short-lived by design).

### Atomic completion

Crypto verification runs first. Then **one final IMMEDIATE transaction**:

1. Rechecks challenge binding (account, manager key, operation, deployment)
2. Rechecks manager still `approved` and account still `active`
3. Rechecks MFA still `active`
4. Consumes the TOTP time step and the challenge
5. Inserts the session

No separate read/commit window can bypass revocation. Failure before commit
rolls back everything and issues no token.

### Denials (all fail closed)

| Condition | Result |
| --- | --- |
| Wrong / missing TOTP | `401` |
| Replayed TOTP time step | `403` (transactional consume) |
| Clock rollback beyond ±1 step | `403` |
| Wrong manager key / signature | `403` |
| Signature over a different operation | `403` |
| Signature bound to a different deployment | `403` |
| Challenge replay / double consumption | `401` |
| Pending or revoked manager (incl. race after begin) | `403` |
| Disabled account (incl. race after begin) | `403` |
| Required storage failure | `503` (security state latch) |

TOTP uses RFC 6238 (SHA-1, 6 digits, 30s step, skew ±1) via maintained
`totp-rs` 5.5.1. Time steps are consumed under a unique
`(account_id, time_step)` key inside the same transaction as challenge
consumption, so racing use of the same step fails.

Rate-limit state is **durable** (`challenge_throttle` table) and
capacity-bounded; restarts do not reset protection. Auth challenges and TOTP
consumption rows are pruned under explicit storage caps.

---

## `POST /v2/auth/recovery/begin`

Recovery-**only** factor verification. A recovery code may re-enroll the TOTP
factor; it never creates a normal session and never targets an arbitrary
account. Password is revalidated so an operator cannot use a recovery code
against someone else's login.

```json
{
  "username": "admin",
  "password": "…",
  "recovery_code": "XXXX-XXXX-XXXX-XXXX"
}
```

**201**

```json
{
  "mfa_enrollment_id": "…",
  "totp_secret_base32": "<new secret, once>",
  "account_id": "…",
  "purpose": "totp_factor_recovery_only"
}
```

Recovery codes are stored **hashed** (SHA-256 of the normalized code) and are
single-use. Normal operations and IT-chosen target logins are **not** available
through this path.

---

## `POST /v2/auth/recovery/complete`

Confirm the new TOTP secret after factor recovery. Same request/response as
`/v2/mfa/enroll/confirm`. `recovery_material_stored` must be `true` (existing
codes remain valid unless individually consumed). **No session token** is
issued.

---

## MFA policy

| Role | Policy |
| --- | --- |
| Administrator | **Mandatory MFA.** Challenge login requires active TOTP enrollment. v2 bootstrap creates `pending_mfa` until confirmation + independently stored recovery material. |
| Configured operator policy (per-account MFA optional/required settings) | **Not implemented** in this foundation — explicitly unavailable. |

Admin MFA is enforced regardless of any legacy local v1 state. v1 loopback
development login (`/v1/auth/login`) remains for local development only and is
not a public compatibility bypass.

## Unchanged unavailable surfaces

Production media, control, file jobs, and security delegation/reset remain
explicitly unavailable (`501`) and `false` in `GET /health` features. Security
delegation/reset rules stay fail-closed.

---

## Feature flags (`GET /health`)

| Feature | v2 foundation |
| --- | --- |
| `local_accounts` | `true` |
| `manager_enrollment` | `true` |
| `scoped_inventory` | `true` |
| `mfa` | `true` (TOTP + recovery-only + device-key) |
| `file_jobs` | `false` |
| `security_recovery` | `false` (delegation/reset fail-closed) |
| `remote_control` | `false` |
| `screen_observation` | `false` |
