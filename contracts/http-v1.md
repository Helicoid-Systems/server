# Helicoid Systems Server HTTP contract — version 1

Product: **Helicoid** (Helicoid Systems). Organization: Helicoid-Systems.
Working names HS Manager / HS Computer.
Owner: `modules/server`. Status: development foundation. Clients integrate
against this file; do not invent additional fields.

Transport: HTTP/1.1 JSON on the configured bind address. **Default and required
bind is literal loopback only** (`127.0.0.1` / `::1`). The server **refuses**
non-loopback socket binds (for example `0.0.0.0` or `[::]`) before listening.
This build has **no** production LAN, control, media, file-job, or MFA authority.
Those surfaces return explicit unavailable errors rather than fake success.

Authentication: opaque bearer session tokens (`Authorization: Bearer <token>`).
Tokens are returned once at login/bootstrap and stored only as SHA-256 digests.
Never log `password`, `token`, `bootstrap_token`, or `Authorization`.

Manager public identities in this foundation are **loopback development identity
fixtures** (operator-chosen strings). They are not cryptographic production
identities and must not be treated as signed endpoint keys (B03/RD03 pending).

---

## Common error envelope

Every non-2xx response:

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
| `unauthorized` | 401 | Missing/invalid/expired/revoked session |
| `forbidden` | 403 | Authenticated but not permitted / out of scope / manager not approved |
| `not_found` | 404 | Unknown resource |
| `conflict` | 409 | Unique claim or lifecycle conflict |
| `unprocessable` | 422 | Schema/refusal condition |
| `rate_limited` | 429 | Sign-in throttle |
| `not_implemented` | 501 | Feature explicitly unavailable in this foundation |
| `security_state_unavailable` | 503 | Trusted persistence uncertain; new authority paused |
| `internal` | 500 | Unexpected storage/processing failure |

Example:

```json
{
  "error": {
    "code": "forbidden",
    "message": "computer is outside the account access scope"
  }
}
```

---

## `GET /health`

Unauthenticated liveness + authority readiness.

**200** — example of a ready deployment (bootstrap completed, trust state healthy):

```json
{
  "status": "ok",
  "accepting_authorized_operations": true,
  "schema_version": 1,
  "storage_schema_version": 2,
  "bootstrap_completed": true,
  "features": {
    "local_accounts": true,
    "manager_enrollment": true,
    "scoped_inventory": true,
    "mfa": true,
    "file_jobs": false,
    "security_recovery": false,
    "remote_control": false,
    "screen_observation": false
  }
}
```

**Version fields (do not conflate):**

| Field | Meaning | Value |
| --- | --- | --- |
| `schema_version` | **v1 HTTP wire contract version** | frozen at **1** — existing native clients assert `== 1`; do not change |
| `storage_schema_version` | database storage schema version | tracks `db::SCHEMA_VERSION` (currently **2**) |

Wire compatibility is explicit: v1 clients keep validating `schema_version == 1`.
Storage upgrades are independent and never alter the wire contract version.

Health semantics (fail closed):

| Condition | `status` | `accepting_authorized_operations` | `bootstrap_completed` |
| --- | --- | --- | --- |
| Trust healthy **and** bootstrap completed | `ok` | `true` | `true` |
| Bootstrap not completed (trust healthy) | `degraded` | `false` | `false` |
| Security State Unavailable (memory or durable) | `degraded` | `false` | real value if readable, else `false` |
| Deployment row missing / trust record unreadable / invalid | `degraded` | `false` | `false` unless a prior readable value is retained |

- `accepting_authorized_operations` is **never** `true` before bootstrap completes.
- POST `/v1/bootstrap` remains allowed while trust state is healthy and bootstrap
  is incomplete (`status` `degraded` is expected until first bootstrap).
- A missing deployment row **latches** Security State Unavailable (subsequent
  login/token creation return `503`); it does not merely return degraded while
  authority could still be issued.
- When the durable record is readable, `bootstrap_completed` is reported as
  stored (not fabricated).

---

## `POST /v1/bootstrap`

Single-use local bootstrap of the first administrator. Token is printed once by
`hs-server init` (stored hashed). Optional manager identity is approved only for
this verified bootstrap channel. No other pending manager is auto-approved.

```json
{
  "bootstrap_token": "<from init>",
  "username": "admin",
  "password": "at-least-12-characters",
  "manager_public_identity": "optional-dev-manager-key",
  "manager_friendly_name": "Optional label"
}
```

**201**

```json
{
  "account": {
    "id": "8f2c…",
    "username": "admin",
    "state": "active",
    "capabilities": {
      "operate": true,
      "manage_enrollment": true,
      "manage_access": true,
      "manage_accounts": true,
      "manage_security": true
    },
    "revision": 1
  },
  "manager": {
    "id": "c0a1…",
    "public_identity": "optional-dev-manager-key",
    "friendly_name": "Optional label",
    "lifecycle_state": "approved",
    "approved_at_unix": 1760000000
  },
  "server_state": "ready_for_enrollment"
}
```

Errors: `403 forbidden` (token missing/used/invalid), `409 conflict`
(already bootstrapped or unique claim), `400 bad_request` (username/password).

Bootstrap is single-use and transactional. Administration capability does **not**
imply screen observation.

---

## `POST /v1/auth/login`

Local account sign-in. Manager binding is a **separate** D20 approval check.

```json
{
  "username": "admin",
  "password": "at-least-12-characters",
  "manager_public_identity": "optional-approved-dev-manager-key"
}
```

**200**

```json
{
  "token": "<opaque bearer, returned once>",
  "expires_at_unix": 1760086400,
  "account": { "id": "8f2c…", "username": "admin", "state": "active", "capabilities": { "…": true }, "revision": 1 },
  "manager": { "id": "c0a1…", "public_identity": "optional-approved-dev-manager-key", "friendly_name": "Optional label", "lifecycle_state": "approved", "approved_at_unix": 1760000000 },
  "mfa": {
    "required": false,
    "available": false,
    "reason": "mfa_not_implemented_in_this_foundation"
  }
}
```

Errors: `401 unauthorized` (invalid credentials — no account enumeration),
`403 forbidden` (disabled account, pending/revoked/unknown manager),
`429 rate_limited`, `503 security_state_unavailable`.

---

## `POST /v1/auth/logout`

Requires bearer token. **204** on success.

---

## `GET /v1/auth/session`

Requires bearer token.

**200**

```json
{
  "account": { "id": "8f2c…", "username": "admin", "state": "active", "capabilities": { "…": true }, "revision": 1 },
  "manager": null,
  "expires_at_unix": 1760086400
}
```

---

## `GET /v1/managers`

Requires `manage_enrollment`. Pending managers cannot list or approve themselves.

**200**

```json
{
  "managers": [
    {
      "id": "c0a1…",
      "public_identity": "optional-dev-manager-key",
      "friendly_name": "Optional label",
      "lifecycle_state": "pending",
      "approved_at_unix": null
    }
  ],
  "max_page_size": 100
}
```

`lifecycle_state`: `pending` | `approved` | `revoked`.

---

## `POST /v1/managers`

Requires `manage_enrollment`. Registers a **pending** development manager
identity fixture. Never auto-approves.

```json
{
  "public_identity": "dev-manager-key",
  "friendly_name": "Mac manager lab-1"
}
```

**201** — manager object with `lifecycle_state": "pending"`.

Errors: `409 conflict` on duplicate `public_identity`, `403 forbidden` without
enrollment management.

---

## `POST /v1/managers/{id}/approve`

Requires `manage_enrollment`. Actor is the authenticated **account** session,
never the pending manager alone.

```json
{ "confirm": true }
```

**200** — manager with `lifecycle_state": "approved"`.

Errors: `404 not_found`, `409 conflict` (already approved / revoked),
`400 bad_request` (`confirm` not true).

---

## `POST /v1/managers/{id}/revoke`

Requires `manage_enrollment`. Also revokes sessions bound to that manager.

**200** — manager with `lifecycle_state": "revoked"`.

---

## `GET /v1/computers`

Bounded inventory read. Scope is resolved from the session account’s access
assignments. **Administration alone does not grant inventory.** Discovery is not
enrollment. Hard cap `max_page_size` = 100.

**200**

```json
{
  "computers": [
    {
      "id": "aa11…",
      "public_identity": "endpoint-dev-key",
      "friendly_name": "Lab Mac",
      "platform": "macos",
      "enrollment_state": "pending",
      "enrollment_epoch": 1
    }
  ],
  "scope_is_explicit": true,
  "max_page_size": 100
}
```

`platform`: `macos` | `windows` | `linux`.  
`enrollment_state`: `pending` | `enrolled` | `quarantined` | `revoked`.

An account with an empty explicit scope receives `"computers": []` (not a
hidden full inventory).

---

## `POST /v1/computers`

Requires `manage_enrollment`. Creates inventory identity in `pending` state.

```json
{
  "public_identity": "endpoint-dev-key",
  "friendly_name": "Lab Mac",
  "platform": "macos"
}
```

**201** — computer object. Errors: `409 conflict` on duplicate public identity.

---

## `GET /v1/computers/{id}`

Requires the computer to be inside the account access scope.

**200** — computer object.  
**403** `forbidden` — outside scope (message: `computer is outside the account access scope`).  
**404** `not_found` — unknown id.

---

## `GET /v1/access`

Requires `manage_access`.

**200**

```json
{
  "access_assignments": [
    {
      "id": "bb22…",
      "capability": "operate",
      "computer_scope_all": false,
      "computer_ids": ["aa11…"],
      "revision": 1
    }
  ]
}
```

`capability`: `operate` | `observe` | `install_maintain`.  
These are operation capabilities only. They do **not** produce screen pixels in
this foundation and do **not** imply administration.

---

## `POST /v1/access`

Requires `manage_access`. Explicit computer IDs or `computer_scope_all` — not
both. No guessed grants: every computer ID must already exist.

```json
{
  "account_id": "8f2c…",
  "capability": "operate",
  "computer_ids": ["aa11…"],
  "computer_scope_all": false
}
```

**201** — access assignment (replaces prior assignment for that
account+capability and bumps `revision`).

Errors: `400 bad_request` (unknown capability / empty scope / both scope forms),
`404 not_found` (account or computer missing).

---

## `GET /v1/mfa/status`

**200**

```json
{
  "required": false,
  "available": false,
  "reason": "mfa_not_implemented_in_this_foundation"
}
```

---

## `POST /v1/files/jobs`

**501**

```json
{
  "available": false,
  "reason": "file_jobs_not_implemented_in_this_foundation"
}
```

---

## `POST /v1/security/recovery`

**501**

```json
{
  "available": false,
  "reason": "security_recovery_not_implemented_in_this_foundation"
}
```

---

## Security State Unavailable

When a required storage commit/read fails, `/health` reports
`accepting_authorized_operations: false` and authority-creating calls return:

```json
{
  "error": {
    "code": "security_state_unavailable",
    "message": "required trusted persistence cannot be read or committed reliably; new authority is paused"
  }
}
```

No new grants, logins that issue sessions, enrollment approvals, or inventory
mutations are accepted while latched. Existing sessions expire on their own
deadlines. The latch is durable across restart and **never auto-recovers**.

---

## Explicit non-goals in contract v1

- No remote control / screen observation pixels (B02/B03/RD03).
- No TLS termination or certificate bypass in-process; deploy behind an
  authenticated local/SSH tunnel or a real TLS terminator. This foundation does
  not invent a signed grant format.
- No MFA factors, file jobs, security recovery, or authority cutover.
- No rooms, classes, lessons, or roster objects.
- Manager `public_identity` values are development fixtures, not production
  cryptographic identities.

D18 (inventory/monitoring scope changes) and D21 (file-request close/replacement)
are product decisions recorded in `docs/spec/decisions.md`; their workflows are
not implemented in this foundation.
