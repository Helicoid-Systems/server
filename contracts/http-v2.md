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

Storage schema version is **3** (v2 wire contract unchanged). `hs-server migrate`
performs an explicit schema-versioned upgrade after a consistent pre-migration
backup (`VACUUM INTO`, WAL checkpointed). **Startup never auto-migrates** a
nonempty database: `hs-server open/serve/init` refuse an older schema and
direct the operator to `migrate`. Fresh empty databases install v3 directly.

v3 adds deployment `security_policy` (operator MFA policy, default
`optional`) and session `assurance` / `mfa_assured_at` (real stored
assurance/time for policy mutation freshness).

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

This endpoint never issues a session token. Confirmation installs the
verified enrollment TOTP secret into the account factor row in the same
final transaction that consumes the enrollment and activates the factor.

---

## `POST /v2/mfa/enroll/cancel`

Cancel a pending enrollment (bootstrap cancellation or pending recovery).
Consumes the enrollment (single-use).

Bounded cancellation semantics:

- **Bootstrap cancel:** the account is disabled only while it never
  completed MFA (`pending_mfa`). Pending material stays inactive.
- **Recovery cancel:** the **established account state and factor are
  preserved**. An active factor is never deactivated or replaced; an
  already-active account keeps authenticating with the original factor.
  An account that was disabled after recovery began remains disabled and
  cannot authenticate. Cancellation never reactivates an account.
- Confirmation after cancel returns `409`. Cancel after a successful
  confirm also returns `409` (the confirmed factor wins).
- `begin` / `confirm` / `cancel` of recovery never mint a session.
- Login still requires an eligible active account and active MFA factor.

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
  "expires_at_unix": 1760000120,
  "mfa_required": true
}
```

`mfa_required` is **server-derived** effective mandatory MFA for this account
at begin (administrator OR operator policy `required` OR an already-active
enrolled factor). Completion rechecks current policy, role, account state and
device approval — a challenge started under `optional` cannot finish
factor-free after policy becomes `required`. Clients that treat a missing
`mfa_required` as required are compatible; never treat absence as optional.

Challenge lifetime: **120 seconds**. Pending/revoked managers, inactive
accounts, and missing mandatory MFA deny. Username and challenge attempts are
rate limited with the **same** error shape for unknown and known accounts (no
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

`totp_code` is a JSON string for existing clients and is **optional** only for
an optional non-enrolled operator (password + approved manager signature still
required; no v1/legacy bypass). Required MFA, `required` policy, or any
already-active enrolled factor still verifies and atomically consumes genuine
TOTP. A malformed supplied factor is **refused**, never silently ignored.

**200**

```json
{
  "token": "<opaque bearer, short-lived>",
  "expires_at_unix": 1760007200,
  "account": { "…": "AccountView" },
  "manager": { "…": "ManagerView" },
  "mfa": { "required": true, "available": true, "reason": "totp_active" },
  "manager_public_key": "<ed25519 hex 32 bytes>"
}
```

`manager_public_key` is **v2 completion only** and is sourced from the final
IMMEDIATE transaction's approved device key — the exact challenge-proven
Ed25519 key. It is never client-selected and never taken from
`manager.public_identity` (bootstrap stores that display label as
`key:<hex>`). **v1 responses omit this field entirely** (frozen wire).

Token TTL: **2 hours** (short-lived by design).

### Atomic completion

Crypto verification runs first. Then **one final IMMEDIATE transaction**:

1. Rechecks challenge binding (account, manager key, operation, deployment)
2. Rechecks manager still `approved` and account still `active`
3. Rechecks current operator policy, role and factor state (effective MFA)
4. Verifies + consumes the TOTP time step when required, or accepts factor-free
   completion only under optional policy with no active factor
5. Consumes the challenge and inserts the session with real stored assurance
   (`mfa` + `mfa_assured_at`, or `password`)

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
codes remain valid unless individually consumed). The verified pending
enrollment secret is installed as the account factor in the same final
transaction (old-to-new replacement). **No session token** is issued.

---

## MFA policy

| Role | Policy |
| --- | --- |
| Administrator (`can_manage_security`) | **Mandatory MFA.** Challenge login requires active TOTP enrollment. v2 bootstrap creates `pending_mfa` until confirmation + independently stored recovery material. |
| Operator (non-administrator) | Deployment policy `optional` (default) or `required`. Effective mandatory MFA = administrator OR policy `required` OR an already-active enrolled factor. Optional policy never removes factor protection from an account that already has an active factor. |

Unknown/corrupt persisted policy and storage faults **deny authority**
(fail closed). New deployments default operator policy to `optional`.

MFA-enrolled accounts cannot use v1 password-only login. The final session
transaction rechecks the shared MFA requirement (administrator OR operator
policy `required` OR any persisted MFA material) before inserting a session.
**Required-policy operators and administrators without factors are refused v1
password login** — mandatory administrator MFA and operator policy cannot be
bypassed through the legacy route. Only non-administrator accounts with no MFA
requirement retain explicitly loopback-only v1 development login
(`/v1/auth/login`); they do not establish production MFA policy or authorize
public compatibility access.

### Manager device binding on v1

A v1 `manager_public_identity` display label **never** establishes authority
for an approved cryptographic device. Legacy login may bind only label-only
managers (`managers.public_key IS NULL`) — genuine separate development
fixtures. Key-bearing managers require an Ed25519 proof via v2 challenge
completion. The final transaction rechecks this binding (a device key added
between validation and issuance denies). v1 sessions are not device-proven.

## `GET /v2/security/operator-mfa-policy`

Bearer authentication. **Administrator only** (`can_manage_security`).

**200**

```json
{
  "policy": "optional",
  "updated_at_unix": 1760000000,
  "mfa_required_for_operators": false
}
```

Operator, legacy, or recovery-only credentials cannot read or change the
policy (`403`).

---

## `PUT /v2/security/operator-mfa-policy`

Bearer authentication. Requires **all** of:

1. Administrator (`can_manage_security`) and active account
2. A fresh successful **MFA-backed v2 session** — real stored session
   assurance `mfa` with `mfa_assured_at` age in `0..=120` seconds
   (future timestamps / clock rollback deny)
3. An approved manager device binding (still `approved` at mutation time)
4. Trusted private persistence

Missing assurance never authorizes change. Authenticate + policy mutation run
in **one IMMEDIATE transaction**.

Strict bounded DTO (`deny_unknown_fields`; policy is the enum
`optional` | `required`):

```json
{ "policy": "required" }
```

**200** — same body as GET.

Enabling `required` **invalidates factor-free operator sessions** (assurance
≠ `mfa` on non-administrator accounts). Administrator MFA-backed sessions are
not revoked by the policy change.

| Condition | Result |
| --- | --- |
| Missing/invalid bearer | `401` |
| Non-administrator | `403` |
| Factor-free or legacy session | `403` |
| Stale (`>120s`) or future assurance time | `403` |
| Unapproved / missing manager device | `403` |
| Unknown field / invalid policy value | `400`/`422` |
| Corrupt or missing stored policy | `422` |
| Storage fault | `503` (security state latch) |

---

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
