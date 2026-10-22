# Helicoid Systems Server HTTP contract — version 2 (auth)

Product: **Helicoid** (Helicoid Systems). Organization: Helicoid-Systems.
Owner: `modules/server`. Status: development foundation with authenticated
file delivery and owner-scoped file requests; endpoint observation and control
remain capability-gated.
Clients integrate against this file and `contracts/http-v1.md`; do not invent
additional fields.

Transport: HTTP/1.1 JSON. Plain HTTP and the default HTTPS listener bind to
literal loopback. `serve-tls --allow-network --bind <address>` explicitly opts
into a nonloopback TLS listener and mounts only v2 routes; all v1 development
routes are absent on that listener. The server uses the configured certificate
chain and private key. This transport option does not mean the deployment,
public routing, TURN, or installed service is verified. General file delivery
and owner-scoped request workflows are mounted on both loopback and v2-only TLS
routers. Production screen observation and remote control remain **false**
until endpoint admission, media, and input acceptance gates pass.

## Relationship to v1

| Surface | v1 (`contracts/http-v1.md`) | v2 (this file) |
| --- | --- | --- |
| Loopback development login | `POST /v1/auth/login` (unchanged) | — |
| Bootstrap | `POST /v1/bootstrap` (dev identity fixture) | `POST /v2/bootstrap` (TOTP MFA + proven manager key) |
| MFA | status-only stub | real TOTP, recovery-only, device-key challenge |
| Sessions | opaque bearer tokens | same tokens, short-lived after v2 completion |

v1 loopback development behavior is explicitly backward compatible. Network
listeners omit v1 bootstrap, login, session, inventory, and foundation routes.
Versioned sign-in, endpoint enrollment, MFA confirmation, and account routes
still enforce their documented token, proof, MFA, and capability checks.
`/v2/bootstrap` and `/v2/auth/recovery/*` are available only on literal
loopback HTTP/HTTPS listeners; a network TLS router does not expose them.

## `GET /v2/deployment`

Unauthenticated read of the server-owned deployment identity for clients to
scope independent sessions, inventory, and asynchronous callbacks. It returns
`{"deployment_id":"dep_<uuid>"}`. The identity is not accepted from client
requests and does not grant authority. Nonloopback TLS binds expose the v2-only
network router; the plain HTTP listener remains literal-loopback only.

## `GET /v2/deployment/authority`

Unauthenticated read of the deployment ID, Ed25519 grant-verification key,
and positive authority generation. The response shape is:

```json
{
  "deployment_id": "dep_<uuid>",
  "grant_signing_public_key": "<64 lowercase hexadecimal characters>",
  "authority_generation": 1
}
```

The generation is a durable checkpoint for the deployment authority. It starts
at 1 and advances with a recovered replacement identity, which remains
quarantined until cutover review is approved. Clients must pin and compare the
full deployment ID, key, and generation tuple before protected operations; a
changed tuple requires recovery review and an explicit local trust update or
endpoint re-enrollment.
The private signing key is stored in the owner-private server database.
The key is protected by the database's verified owner-only file boundary and
zeroized application-owned temporary buffers; it is not separately encrypted
or held by an HSM or KMS. The host administrator and server process therefore
remain trusted with signing authority.
The endpoint is unavailable when the persistent store cannot verify its
private-file boundary.
Encrypted database restore rotates the signing key before publishing the
restored store. The replacement is quarantined until independently reviewed
host-fencing evidence is approved. The shared Manager pins this public key
alongside the deployment ID and generation after separate out-of-band
confirmation of the ID, the SHA-256 fingerprint of the decoded 32-byte key,
and the numeric generation. This endpoint publishes verification material.
The signed observation grant exchange below uses this key; endpoints must
compare the complete authority tuple with their trusted enrollment state
before accepting a grant.

## `GET /v2/computers`

Authenticated bounded inventory read. It returns the `ComputerListResponse`
shape with at most 100 computer records and their organization group labels.
The server derives the inventory from the bearer session's access assignments;
administration capability alone does not expand inventory scope. It returns
metadata only and does not grant observation or start endpoint capture.
Network Managers use this route because the TLS router does not mount the v1
development inventory routes.

For an enrolled computer inside the account's current `observe` assignment,
each record may include an `endpoint_session` object with
`last_authenticated_at_unix`, `current_session_expires_at_unix`,
`current_session_id`, and `console_user_reported`. The first field records the
most recent endpoint key proof for the current enrollment epoch, including an
expired session. The other fields are non-null only when the latest endpoint
session remains unrevoked and unexpired; `current_session_id` is an opaque
identifier for correlating admission, and `console_user_reported` records
whether the endpoint declared an eligible signed-in console user. Other
records omit `endpoint_session`. These are authenticated session facts, not a
live-presence lease, capture readiness, or permission to receive pixels.

```json
{
  "id": "<computer-id>",
  "endpoint_session": {
    "last_authenticated_at_unix": 1792600000,
    "current_session_expires_at_unix": 1792600900,
    "current_session_id": "<opaque-session-uuid>",
    "console_user_reported": true
  }
}
```

## `POST /v2/auth/logout`

Cleanup-only bearer revocation. The server revokes the supplied session token
and returns **204**. It does not mint or refresh a session, and remains
available on the network listener so Managers can revoke their own session
before clearing local deployment state.

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

Storage schema version is **20**; the `/v2` route version is unchanged, with the
optional `endpoint_session` inventory field documented below. `hs-server migrate`
performs an explicit schema-versioned upgrade after a consistent pre-migration
backup (`VACUUM INTO`, WAL checkpointed). **Startup never auto-migrates** a
nonempty database: `hs-server open/serve/init` refuse an older schema and
direct the operator to `migrate`. Fresh empty databases install v20 directly.

v3 adds deployment `security_policy` (operator MFA policy, default
`optional`) and session `assurance` / `mfa_assured_at` (real stored
assurance/time for policy mutation freshness).

Accounts gain state `pending_mfa` (inactive until MFA confirmation **and**
independently stored recovery material). Managers gain an optional Ed25519
`public_key` (hex, 32 bytes, unique when present).

v4 adds flat `computer_groups` and `computer_group_members` tables. Names use
SQLite's `NOCASE` uniqueness (ASCII case-insensitive), and the deployment is
capped at 100 groups.
Membership is organization metadata and never creates or changes an access
assignment. Inventory adds group labels only to computer records already
inside the caller's access scope.

v7 adds bounded manager-to-endpoint file jobs. v8 binds endpoint sessions and
file targets to stable local OS user IDs; migrated rows without an identity
cannot receive files. v9 adds the signed OS account display label and stores it
on the file target for the Manager's explicit recipient confirmation. v10 adds
a server-owned 24-hour delivery expiry for unfinished file jobs.
v11 adds owner-scoped file-request drafts and explicit computer eligibility.
v12 adds OS-user-bound submissions and chunked content. v13 records per-file
content availability so authorized deletion can release storage while keeping
submission metadata. v14 records the time and manager account ID for an
authorized content deletion. Historical deletions receive a best-effort time;
the actor is unknown for those rows. v15 adds per-computer interaction
revisions and durable interaction claims for server-owned transition planning.
v17 adds one-use, 10-second observation admission grants bound to the current
Manager session, endpoint incarnation, endpoint session, and current observe
assignment. These grants are not a media transport or a network interaction
lifecycle.
v20 adds bounded metadata-only audit events and a configurable 30-day default
retention policy (1–3650 days). Required events commit with their protected
change; a missing event blocks the mutation. At 100,000 retained rows, writes
fail closed rather than dropping unexpired records.

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
After database restore, the server requires this pair from a fresh Manager
identity. Restored accounts remain disabled and quarantined, prior Managers are
revoked, and endpoint identities are quarantined until re-enrolled.

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

## `POST /v2/mfa/enroll/begin`

Start TOTP enrollment for the authenticated account itself. Requires a
current session from an approved key-bearing Manager device. This supports
delegated operators who need a factor before making fresh-MFA changes. An
active factor cannot be replaced here; use the recovery-only flow for that.
Returns a single-use 15-minute enrollment ID, TOTP secret, and recovery codes.
The client must show the material once and must not log or persist it.

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

Restore recovery quarantine remains active after this confirmation. The
fresh administrator can authenticate to review recovery state, but ordinary
privileged writes remain blocked until the explicit local release below.

---

## Restore Recovery Quarantine (loopback only)

The network-facing TLS router does not expose these routes. A freshly
bootstrapped security administrator uses the local TUI after confirming MFA.

### `GET /v2/recovery/quarantine`

Requires an active session bound to an approved Manager key and
`manage_accounts`. Returns the deployment identity and counts of retained
quarantined accounts, revoked Managers, and quarantined endpoints.

### `POST /v2/recovery/quarantine/release`

Requires a fresh MFA-backed session, an approved Manager key, and a security
administrator. Counts and deployment identity must still match the preceding
review. The exact confirmation phrase is
`release restored deployment <deployment_id>`; the request must also
acknowledge missing post-backup history and that restored authorities remain
quarantined.

```json
{
  "expected_deployment_id": "dep_<deployment identity>",
  "expected_quarantined_account_count": 1,
  "expected_revoked_manager_count": 2,
  "expected_quarantined_endpoint_count": 24,
  "acknowledge_missing_post_backup_history": true,
  "acknowledge_restored_authorities_remain_quarantined": true,
  "confirmation_phrase": "release restored deployment dep_<deployment identity>"
}
```

Release clears only the deployment-wide startup gate so a fresh authority can
continue setup. Historical accounts remain disabled and quarantined; previous
Managers remain revoked; endpoints remain quarantined and require fresh
enrollment. Restored access assignments are review hints and do not authorize
the replacement administrator or newly enrolled endpoints. Every endpoint
request also rechecks the deployment-wide quarantine in its final database
operation, so a session admitted before restore cannot continue file delivery,
observation, or other endpoint work during recovery review.

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

## `GET /v2/managers`

Returns at most 100 `ManagerView` records. Requires an active bearer session
with `manage_enrollment`; the response does not approve pending devices.

## `POST /v2/managers`

Register a new Manager device after the device proves possession of its
Ed25519 key. This endpoint requires a current bearer session whose account has
`manage_enrollment`; the session must be bound to an approved manager device.
The server creates a **pending** manager record. A separately authorized
administrator must still approve it through `POST /v2/managers/{id}/approve`.
The registration and approval actions are intentionally distinct.

The device signs the exact UTF-8 message below after trimming the friendly
name and lowercasing the 32-byte public key hex:

```text
hs-manager-enroll-v2|deployment:<deployment_id>|manager:<manager_public_key_hex>|friendly_name:<friendly_name>
```

```json
{
  "public_key": "<ed25519 hex 32 bytes>",
  "friendly_name": "Manager workstation",
  "proof": "<ed25519 hex 64 bytes>"
}
```

The server derives `public_identity` as `key:<public_key>` and derives the
deployment identity from its own trusted row. It rechecks the current session,
account permissions, manager approval, and mandatory MFA inside the same
transaction that creates the pending record. Duplicate keys are rejected by
the existing unique constraint. At most 100 manager records are retained,
matching the bounded list contract. Proof material is never logged.

**201** — the pending `ManagerView`.

## `POST /v2/managers/{id}/approve`

Approve the pending Manager named by `{id}`. Requires `manage_enrollment`, an
approved key-bearing Manager session, and fresh MFA within 120 seconds. The
server rechecks the account, Manager session, pending lifecycle state, and MFA
inside the approval transaction. Already-approved and revoked devices are
refused.

```json
{"confirm":true}
```

Returns **200** with the approved `ManagerView`.

## `POST /v2/managers/{id}/revoke`

Revoke a pending or approved Manager. Requires the same current enrollment
authority and fresh MFA. Confirmation must name the exact Manager ID shown in
the UI; all active sessions for that device are revoked in the same
transaction.

```json
{"confirm":true,"confirm_manager_id":"<same-manager-id>"}
```

Returns **200** with the revoked `ManagerView`.

---

## `GET /v2/accounts`

Returns at most 100 account records with the current state and capability
flags. `recovery_quarantined` identifies historical accounts retained from a
restored backup; they remain disabled and cannot be reactivated. Requires an
active bearer session with `manage_accounts`.

## `POST /v2/accounts`

Create an account in `pending_mfa`. This requires a `manage_accounts` session
bound to an approved Manager device and a genuine MFA assurance no more than
120 seconds old. The password is validated and hashed; it is never returned.
The pending account cannot sign in until MFA enrollment is confirmed.

```json
{
  "username": "operator.one",
  "password": "at-least-12-characters",
  "can_operate": true,
  "can_manage_enrollment": false,
  "can_manage_access": false,
  "can_manage_accounts": false,
  "can_manage_security": false
}
```

The endpoint creates a bounded TOTP enrollment and hashed recovery-code rows in
the same transaction. It returns the TOTP secret and plaintext recovery codes
once; the client must present them only to the account's intended operator and
must never log or persist them. The account remains inactive until the operator
confirms a genuine TOTP code and attests that the recovery codes were stored
independently through `POST /v2/mfa/enroll/confirm`.

```json
{
  "account": { "…": "AccountView with state pending_mfa" },
  "mfa_enrollment_id": "…",
  "totp_secret_base32": "…",
  "recovery_codes": ["…"]
}
```

Enrollment expires after 15 minutes. Cancel an abandoned enrollment through
`POST /v2/mfa/enroll/cancel`; cancellation disables an account still in
`pending_mfa`. At most 100 non-quarantined accounts can be provisioned;
restored historical records remain visible when space allows and do not consume
the current-account limit.

## Computer groups

Groups are optional flat organization labels. They organize inventory and
never grant access. `GET /v1/computers` and `GET /v2/computers` include
`groups: [{id, name}]` only for computers the caller is already authorized to
list. `GET /v2/groups`
requires `manage_enrollment` and returns group names and revisions, but no
computer membership.

`GET /v2/enrollment/computers` returns a bounded list of registered computer
metadata for the current approved, key-bearing Manager session when its
account has `manage_enrollment`. It includes computer ID, friendly name,
platform, enrollment state and epoch, and group labels. It does not return the
endpoint public identity or pixels, and it does not grant observe or operation
access. The server rechecks the current session and permission in persisted
state. Results are capped at 100 and report `max_page_size`.

### One-time endpoint enrollment

`POST /v2/enrollment/invitations` requires an active enrollment administrator,
an approved key-bearing Manager, fresh MFA (no older than 120 seconds), and
trusted private persistence. It accepts a friendly name and `macos`,
`windows`, or `linux` platform. The server creates a random 256-bit code valid
for 15 minutes and returns it only in this **201** response:

```json
{
  "id": "<invitation-uuid>",
  "deployment_id": "<server-owned-deployment-id>",
  "friendly_name": "Lab Windows",
  "platform": "windows",
  "enrollment_code": "<shown-once>",
  "created_at_unix": 1760000000,
  "expires_at_unix": 1760000900
}
```

Only the code's SHA-256 digest is stored. At most 100 unredeemed, unexpired
invitations exist at once. `GET /v2/enrollment/invitations` returns at most
100 metadata records and never returns a code or code hash.
An unredeemed invitation can be revoked through
`POST /v2/enrollment/invitations/{id}/revoke` with
`{"confirm_invitation_id":"<same-invitation-id>"}`; revocation requires fresh
MFA and invalidates the code immediately. Redeemed invitations cannot be
revoked because their computer record has its own approval and revocation
lifecycle.

The endpoint generates its Ed25519 key locally and posts its canonical
lowercase 32-byte public key, invitation ID, code, and 64-byte signature to
`POST /v2/endpoints/enroll` without a bearer credential. The signed UTF-8
message is exactly:

```text
hs-endpoint-enroll-v2|deployment:<deployment_id>|invitation:<invitation_id>|code_hash:<sha256-of-code-as-lowercase-hex>|endpoint:<public-key-as-lowercase-hex>
```

The server obtains the deployment ID from trusted storage. It verifies the
strict Ed25519 proof and atomically consumes the invitation while creating a
`pending` computer at enrollment epoch 1. Invalid, expired, revoked, or replayed
invitations return the same `401` response. Endpoint enrollment creates no
observe/operate access and returns no endpoint key.

`POST /v2/enrollment/computers/{id}/approve` and `/revoke` require the same
enrollment permission and approved key-bearing Manager, fresh MFA, and trusted
private persistence. The request must include the exact displayed computer ID
and current enrollment epoch:

```json
{"expected_enrollment_epoch":1,"confirm_computer_id":"<same-computer-id>"}
```

Approval accepts only an identity-proven pending endpoint, sets it to
`enrolled`, stores its approved incarnation identity, and increments the epoch.
Revocation also increments the epoch, fencing previously issued authority.
Stale epochs return `409`; approval is not self-approval by the endpoint.
Creating replacement identity after revocation requires a new invitation and
new computer record. Existing deployments use the explicit backed-up
`hs-server migrate` command and never migrate at startup.

## Endpoint session admission

Approval alone does not admit an endpoint to capture, input, or job workflows.
An enrolled endpoint first proves possession of its approved Ed25519 key and
receives a short-lived session fenced to its current enrollment epoch.

`POST /v2/endpoints/session/challenge` accepts an endpoint's ID, an optional
stable local identity, a fresh 32-byte lowercase-hex client nonce, the current
Unix timestamp, and a signature over the version-1 message when no local
identity is supplied:

```text
hs-endpoint-session-begin-v1|deployment:<deployment_id>|computer:<computer_id>|issued_at:<issued_at_unix>|nonce:<client_nonce>
```

The timestamp must be within 120 seconds of server time. The server obtains the
public key, deployment ID, enrollment state, and epoch from trusted storage;
pending, revoked, mismatched, and stale endpoint identities are denied. A
nonce can be used only once per computer. Accepted requests invalidate earlier
outstanding challenges for that computer. Challenge proofs are limited to 20
per computer per 15 minutes; retained nonce records are pruned after 15 minutes,
with a server-wide cap of 20,000 challenge requests per 15 minutes. Success
returns HTTP 201 with a single-use challenge ID and token, deployment ID,
computer ID, current epoch, and expiry.

For D29 file delivery with an eligible console user, clients must supply and
sign `local_user_id` and `local_user_display_name` in the challenge request.
Supported canonical IDs are `macos:uid:<nonzero decimal>` and
`linux:uid:<nonzero decimal>`, or `windows:sid:S-1-...`. The endpoint client
must derive the ID and short account label from the OS session and confirm it
is the eligible console user. The trimmed display label is at most 128 bytes,
is signed with the stable ID, and is used only for the Manager's confirmation
and job history. It cannot select or authorize a recipient. The signed begin
message is:

```text
hs-endpoint-session-begin-v3|deployment:<deployment_id>|computer:<computer_id>|local_user:<local_user_id>|local_user_display_name:<lowercase-hex-utf8>|issued_at:<issued_at_unix>|nonce:<client_nonce>
```

The version-2 message binds only `local_user_id` for compatibility. Such a
session is not eligible for new D29 jobs because it has no signed display
label. If the endpoint cannot verify an eligible console user, it may submit
the version-1 proof without either user field to replace its prior session
with an unbound session. That session cannot access file-job routes and makes
a queued recipient unavailable until the intended user is verified again.

`POST /v2/endpoints/session/complete` accepts the challenge ID and token plus
the endpoint signature over:

```text
hs-endpoint-session-v1|deployment:<deployment_id>|challenge:<challenge_id>|token_hash:<sha256-of-challenge-token-as-lowercase-hex>|computer:<computer_id>|epoch:<enrollment_epoch>|endpoint:<public-key-as-lowercase-hex>
```

The server rechecks the challenge, deployment, approved endpoint identity, and
enrollment epoch in one final transaction. A version-2 completion message is
retained for a challenge with a stable local user ID but no display label; it
binds the same user identity:

```text
hs-endpoint-session-v2|deployment:<deployment_id>|challenge:<challenge_id>|token_hash:<sha256-of-challenge-token-as-lowercase-hex>|computer:<computer_id>|epoch:<enrollment_epoch>|endpoint:<public-key-as-lowercase-hex>|local_user:<local_user_id>
```

The server consumes the challenge, revokes the endpoint's older sessions, and
issues a 15-minute opaque bearer token. The response includes the opaque
`session_id` so a peer admission grant can be checked against this exact
session; the bearer token remains separate. This endpoint returns HTTP 200
with `token`, `session_id`, `deployment_id`, `computer_id`,
`enrollment_epoch`, and `expires_at_unix`. Only the token hash is stored. The
session retains its signed local identity and, for version 3, display label.
Replays, expired challenges, wrong keys, pending endpoints, and epoch changes
are denied.

When the challenge includes both local user fields, the completion message is:

```text
hs-endpoint-session-v3|deployment:<deployment_id>|challenge:<challenge_id>|token_hash:<sha256-of-challenge-token-as-lowercase-hex>|computer:<computer_id>|epoch:<enrollment_epoch>|endpoint:<public-key-as-lowercase-hex>|local_user:<local_user_id>|local_user_display_name:<lowercase-hex-utf8>
```

`GET /v2/endpoints/self` requires that endpoint bearer token. It returns only
the authenticated computer ID, friendly name, platform, and enrollment epoch.
The server revalidates the session's expiry, revocation, current enrollment
state, approved incarnation, and epoch on each request. Endpoint tokens are
not manager credentials and do not grant any manager or operator capability.
Endpoint admission is groundwork for later media routes. It does not turn on
screen observation or remote control. The separate recipient-bound file-job
routes described below are available only through the authenticated v2 API.

## One-use observation admission

`POST /v2/admissions/observation` requires an active, approved key-bearing
Manager session, `can_operate`, current `observe` scope for the exact enrolled
computer, and a current endpoint session with a signed-in local user. The
server derives both identities from trusted rows. It returns HTTP **201** with
one signed grant. The grant expires at the earlier of 10 seconds after issue
or the current endpoint-session expiry. Managers renew by requesting a new
grant; a grant cannot be extended or replayed.

The opaque `grant_token` has this form:

```text
base64url-no-padding(canonical UTF-8 JSON claims).lowercase-hex-Ed25519-signature
```

The Ed25519 signature covers the exact payload bytes prefixed with
`hs-observation-grant-v1\0`. JSON fields are serialized in this order:

```json
{
  "version":1,
  "grant_id":"<UUID>",
  "deployment_id":"dep_<32 lowercase hex characters>",
  "account_id":"<UUID>",
  "manager_id":"<UUID>",
  "manager_public_key":"<lowercase Ed25519 public-key hex>",
  "computer_id":"<UUID>",
  "endpoint_public_key":"<lowercase Ed25519 public-key hex>",
  "endpoint_session_id":"<UUID>",
  "enrollment_epoch":2,
  "issued_at_unix":1792600000,
  "expires_at_unix":1792600010,
  "capability":"observe"
}
```

Before accepting SDP or starting capture, the endpoint creates a native peer,
exports its exact DTLS certificate PEM, and creates a fresh 32-byte
lowercase-hex nonce. It signs the following exact UTF-8 transcript with its
approved endpoint device key. The certificate digest covers the exact PEM
bytes, including line endings:

```text
hs-observation-peer-certificate-v1|deployment:<deployment_id>|grant:<grant_id>|computer:<computer_id>|endpoint_session:<endpoint_session_id>|epoch:<enrollment_epoch>|nonce:<endpoint_nonce>|role:endpoint|certificate_sha256:<lowercase-sha256-of-exact-certificate-pem>
```

The `challenge` signal carries `computer_id`, `endpoint_session_id`,
`endpoint_nonce`, `expires_at_unix`, and both `endpoint_certificate_pem` and
`endpoint_certificate_signature`. The certificate fields must appear as a
pair. The server validates their size and encoding and verifies the signature
against the endpoint public key in the signed grant before relaying the
challenge. The Manager independently verifies the grant, transcript, nonce,
and signature, then configures the exact PEM as its native expected remote
certificate before setting the remote description.

The Manager also exports its local certificate and signs the same transcript
with `role:manager`. That attestation must accompany the Manager offer; the
endpoint verifies it against the grant's Manager public key and configures the
expected certificate before accepting SDP. Carry it in one session-level SDP
attribute inserted before the first `m=` line:

```text
a=hs-observation-cert-v1:<base64url-no-padding-of-certificate-pem>.<lowercase-hex-signature>
```

The endpoint strictly decodes and verifies that attribute, removes it, pins the
verified PEM, and only then passes the remaining offer to native WebRTC. The
Qt Manager and Windows Computer sources now implement this exchange with
native peers. This is source-level integration only: the native observation
capability bits remain disabled, the Windows native DLL is absent from the
retained inventory, and neither client has an installed runtime acceptance
result.

After the peer channel is verified, both peers export the canonical
channel-binding tuple from their current native verified-channel handles. The
Manager signs these exact UTF-8 bytes with its approved device key:

```text
hs-observation-peer-proof-v2|deployment:<deployment_id>|grant:<grant_id>|computer:<computer_id>|endpoint_session:<endpoint_session_id>|epoch:<enrollment_epoch>|nonce:<endpoint_nonce>|channel_binding:<lowercase-hex-native-channel-binding>
```

The endpoint must first verify the deployment-signed grant locally, check its
own endpoint key, enrollment epoch, and endpoint-session ID, require that the
exported binding is still valid and canonical, and verify this Manager
signature locally against that same binding. It then submits the grant, nonce,
channel binding, and proof to
`POST /v2/endpoints/admissions/observation/redeem` using its current endpoint
bearer token. The server repeats the signature and current-authority checks,
validates the fixed-size WebRTC binding format, then atomically consumes the
grant. A lost response requires a newly issued grant and nonce; redemption is
never replayed as success.

The server rechecks the current endpoint session and incarnation, Manager
approval and session, account status and MFA policy, current `observe` scope,
deployment identity, exact signed token, grant expiry, and one-use state in the
consume transaction. Manager revocation, session revocation, endpoint user
change, endpoint revocation, access removal, and key rotation therefore block
new admissions. An endpoint must stop capture when the lease expires unless it
consumes a newly issued lease. This server exchange does not itself start
capture, deliver pixels, or enable remote control. The Windows endpoint and Qt
Manager sources now implement the corresponding native channel, capture,
display, and fresh-grant renewal paths; their capability bits remain disabled
until builds and installed runtime evidence pass before
`features.screen_observation` can be enabled.

After issuance, the server places a short-lived dispatch copy of the token in a
bounded process-local mailbox for the exact endpoint session in the signed
claims. `GET /v2/endpoints/admissions/observation/pending` uses that endpoint's
current bearer session and holds the request for at most 10 seconds. A response
contains up to eight grants queued for that exact session. The mailbox is
bounded to 512 grants across the deployment; a full mailbox refuses delivery
and invalidates the unexposed database grant. Polling consumes each queued
copy once. The authority database continues to store only the token hash. A
server restart drops unpolled copies; the Manager must request a fresh grant.

When `/health.features.screen_observation` is true, the Windows Computer polls
this route while enrolled, reuses its current signed-in endpoint session,
verifies each delivered grant with its enrollment pin, and sends a fresh
endpoint nonce challenge into that grant's signaling mailbox. This prepares the
exchange only; it does not start a peer, redeem the grant, or start capture.

### Observation WebRTC signaling

`POST /v2/admissions/observation/{grant_id}/signals` and
`GET /v2/admissions/observation/{grant_id}/signals?after=<cursor>` use the
Manager bearer session. The corresponding endpoint routes are
`POST /v2/endpoints/admissions/observation/{grant_id}/signals` and
`GET /v2/endpoints/admissions/observation/{grant_id}/signals?after=<cursor>`;
they require the current endpoint bearer session. Both sides recheck the grant,
the exact Manager and endpoint sessions, current endpoint incarnation, and
current `observe` scope on every request.

The endpoint may submit one `challenge` (up to 4 KiB) before the Manager may
submit one `offer`; the endpoint may then submit one `answer` and either side
may submit ICE candidates or `close`. Requests use
`{"kind":"challenge|offer|answer|ice|close","payload":"..."}`. The
challenge payload has the four required grant-binding fields above and either
zero or both certificate-attestation fields. A challenge without an
attestation is not accepted by the Manager for peer setup. The server checks
the IDs, expiry, nonce, certificate bounds, and endpoint signature.
SDP is limited to 64 KiB, an ICE value to 4 KiB, and `close` has an empty
payload. A mailbox holds
at most 128 messages and 256 KiB; the returned batch is capped at 64 messages
and contains a monotonically increasing per-grant cursor. Poll with the last
returned cursor to receive only later messages. Signaling lives in process
memory and expires with its grant, so a server restart drops pending messages.
The authority can observe SDP and ICE candidate values; clients must use the
trusted HTTPS authority connection. This relay transports signaling only and
does not prove a connected peer, verify a DTLS channel binding, authorize
capture, or deliver media.

The Windows Computer source now creates the endpoint peer before publishing a
certificate-attested challenge, verifies and pins the Manager certificate,
answers and exchanges ICE, verifies the channel-bound Manager proof, redeems
the grant, then captures and sends primary-display frames during the bounded
lease. The Manager source creates a pinned receive-only peer, relays its signed
offer, processes answer/ICE, sends channel-bound proof, and reads frames. These
paths are source-only: the native capability mask is still disabled, the
Windows DLL is not packaged in this checkout, and neither path has current
build or installed runtime proof. Keep `features.screen_observation` false
until both certificates, native pinning, redemption, denial/expiry/revocation,
desktop teardown, and frame display pass the installed-platform acceptance
gates.

## Manager-to-endpoint file delivery

The manager-to-endpoint file delivery job workflow is mounted on the
authenticated v2 TLS network router and the loopback development router.
Legacy v1 file-job routes remain unavailable. `features.file_jobs` reports
whether the v2 job workflow is available; it does not claim that installed
endpoint delivery has passed runtime or release acceptance.

### File request lifecycle foundation

`GET /v2/files/storage` returns an authenticated operator's deployment-wide
logical payload summary. It requires an active approved Manager session and
`can_operate`; it exposes aggregate byte and item counts without filenames or
account identities. `reserved_payload_bytes` is the sum of active delivery-job
payloads and uploading or retained Received request content. The response also
includes the current job/upload counts, retained Received file totals, and
`available_payload_bytes` (zero when reservations meet or exceed the limit).
This is application quota accounting, not filesystem free space or SQLite,
WAL, and backup disk usage. The current enforced 2 GiB cap and retention bounds
remain subject to E06 workload and release acceptance.

```json
{
  "payload_limit_bytes": 2147483648,
  "delivery_payload_bytes": 0,
  "request_payload_bytes": 0,
  "reserved_payload_bytes": 0,
  "available_payload_bytes": 2147483648,
  "active_file_jobs": 0,
  "active_file_job_limit": 500,
  "active_request_uploads": 0,
  "active_request_upload_limit": 100,
  "retained_received_files": 0,
  "retained_received_bytes": 0
}
```

`POST /v2/files/requests` saves a manager-owned draft. It requires an active
approved Manager session, `can_operate`, and current `operate` scope for every
eligible enrolled computer. Drafts contain a bounded title and instructions,
an explicit list of eligible computer IDs, extension rules, maximum file count
and aggregate size, a close deadline, and a replacement policy. The limits
(50 computers, 50 files, 128 MiB per request, and 30 days) are enforced by the
server. Storage reserves at most 2 GiB for payloads and 100 concurrent request
uploads. Completed content remains until an authorized operator deletes it;
scheduled retention and physical erasure are not implemented.

`GET /v2/files/requests` lists the caller's bounded request history and
`GET /v2/files/requests/{id}` returns one owner-only request. Draft creation
sends no endpoint work. `POST /v2/files/requests/{id}/publish` with
`{"expected_revision":1}` publishes the draft only after the server
rechecks the revision, enrollment and access scope for every eligible
computer. Publication advances the revision. `POST
/v2/files/requests/{id}/close` requires the same request ID in
`confirm_request_id` plus the current `expected_revision`; closure is a
one-way transition that refuses future submissions and retains completed
submissions. Deadlines close published requests automatically, advance their
revision, expire pending uploads, and remove temporary chunks.

An authenticated endpoint can call `GET /v2/endpoints/file-requests`. The
server returns only open requests whose immutable eligible-computer list
contains that endpoint's current computer identity. It requires the current
endpoint session to carry a signed local OS-user identity. This slice does not
expose request ownership or another local user's submission.

`POST /v2/endpoints/file-requests/{id}/submissions` reserves a complete
manifest for the current endpoint user. The body includes the exact request
revision, 1–50 safe file names, each file's byte size and lowercase SHA-256,
and optional `replace_submission_id` plus `confirm_replacement: true`. The
server checks the extension rules, per-user manifest count/size, current
request deadline, target computer, stable local-user ID and signed display
label in one transaction. Replacement is allowed only when the request says
so and the old Received submission belongs to the same request, computer and
OS user. The old content stays intact until the replacement verifies.

`GET /v2/endpoints/file-requests/{id}/submissions` returns only that same
computer and OS user's bounded submission history, including unfinished
uploads, so the same user can resume. New OS users cannot list, write, replace,
or retrieve those submissions. Each file uploads raw 256 KiB chunks to
`PUT /v2/endpoints/file-requests/{request_id}/submissions/{submission_id}/files/{file_id}/chunks/{index}`.
`POST .../{submission_id}/complete` verifies the whole manifest before marking
it Received. Missing chunks leave the upload resumable; mismatched size or
digest fails the submission and removes temporary chunks. The upload deadline
is at most 24 hours and never extends beyond request closure. Server-wide
request submissions share the existing file-delivery 2 GiB payload reservation
cap, with at most 100 concurrent request uploads.

The request owner may list submission metadata with
`GET /v2/files/requests/{id}/submissions` and retrieve chunks with
`GET /v2/files/requests/{request_id}/submissions/{submission_id}/files/{file_id}/chunks/{index}`.
Both operations recheck current operate scope for every affected computer.
Received content remains available after request closure. On verified
replacement, the old submission is marked Superseded and its content chunks
are removed; failed replacement leaves the prior Received content intact.
Manager and Linux TUI source clients expose draft administration, submission
review, verified download, and explicit content removal through the v2 API;
platform endpoint request and upload clients are also source-present. Runtime
acceptance remains pending and scheduled retention controls are unavailable. A request owner may explicitly delete the retained
content for a received submission with
`DELETE /v2/files/requests/{request_id}/submissions/{submission_id}` and
`{"confirm_submission_id":"<same-submission-id>"}`. The server checks the
current manager session, operate capability, request ownership, and current
operate scope for the submitting computer. It deletes the content chunks,
retains submission/file metadata, marks each file's response state `deleted`,
records `content_deleted_at_unix` and `content_deleted_by_account_id`, and
releases the bytes from the active storage quota. Repeating the same
confirmed deletion is idempotent. This is logical application deletion, not a
physical-erasure guarantee: SQLite free pages and prior database backups may
still contain old bytes. The authenticated v2 TLS routes expose this request
workflow; general file jobs use the separate authenticated routes described
above.

Before confirmation, the Manager calls
`GET /v2/files/recipients/{computer_id}`. This requires a current approved
Manager session, `can_operate`, and `operate` scope for that enrolled computer.
It returns the newest current endpoint session created within the last three
minutes, including its opaque session ID, signed OS account display label, and
verification time as `verified_at_unix`. The response fields are
`computer_id`, `session_id`, `display_name`, and `verified_at_unix`. If there
is no fresh signed-in recipient, the server returns
`409 file_recipient_unavailable`; the client must not substitute an older
session or a guessed account.

`POST /v2/files/jobs` requires an active, current, approved key-bearing Manager
session, an account with `can_operate`, a current `operate` assignment, and an
explicit recipient confirmation for every named enrolled endpoint. Each target
is bound in the creation transaction to that computer and the newest unexpired,
unrevoked session created within the last three minutes for the currently
approved enrollment. The server requires that session ID to equal the one the
Manager displayed and confirmed. If the recipient changed after confirmation,
the request returns `409 file_recipient_changed`; if no fresh signed identity
and label exists, it returns `409 file_recipient_unavailable`. It does not fall
back to an older session or guess a user or shared destination. The request is:

```json
{
  "file_name":"instructions.pdf",
  "file_size_bytes":1234,
  "sha256":"<64 lowercase hex characters>",
  "computer_ids":["<computer UUID>"],
  "expected_recipients":[
    {"computer_id":"<same computer UUID>","session_id":"<preflight session UUID>"}
  ]
}
```

The server accepts at most 128 MiB and 50 unique targets per job. Each target
has an independent durable state and result. The server stores one copy of the
payload as 256 KiB chunks in its private SQLite store. Active push jobs and
uploading or retained Received request submissions share a 2 GiB payload quota,
with at most 500 active jobs server-wide and 100 per owner. A retained request
submission releases its bytes from the active quota after authorized logical
deletion; there is no scheduled retention policy yet. Incomplete uploads expire
after 24 hours.
The current development candidate expires queued delivery 24 hours after upload
verification while waiting for the exact intended local user; E06 must freeze
this budget before file jobs can be enabled. The deadline is returned as
`delivery_expires_at_unix` in
manager and endpoint job views. The server expires pending targets and deletes
their payload chunks when that deadline passes, including during idle service
maintenance. Completed target results remain visible in a multi-target job
that expires while other targets are still waiting. Job metadata is retained
after terminal results, while payload chunks are deleted after all targets
reach a terminal state.
Both `FileJobView` and `EndpointFileJobView` include the Unix-seconds field
`delivery_expires_at_unix` so clients can show the same server-owned deadline.
Each job target returns `recipient_display_name`, the signed label shown in the
Manager confirmation. The label is informational; authorization and delivery
continue to use the stable local user ID bound to the endpoint session.

For nonempty files, the owner uploads raw bytes with
`PUT /v2/files/jobs/{id}/chunks/{index}`. The final chunk is only as long as
needed. Repeated identical chunks are idempotent; a different chunk may replace
one while the job remains `uploading`. The server verifies the assembled SHA-256
before changing the job and its targets to `queued`. A zero-byte file is queued
at creation only when its digest matches the empty-file SHA-256.

`GET /v2/files/jobs` returns the caller's bounded job history; `GET
/v2/files/jobs/{id}` returns details and all per-target outcomes to that job's
owner. No cross-server transaction is implied.

The owner may cancel an `uploading` or not-yet-leased `queued` job with
`POST /v2/files/jobs/{id}` and `{"confirm_job_id":"<same-job-id>"}`. This
marks waiting targets cancelled and releases payload chunks. Once an endpoint
leases the job as `in_progress`, cancellation returns `409`; committed delivery
continues to its per-target result.

An admitted endpoint calls `GET /v2/endpoints/jobs` with its endpoint session.
The server leases only jobs bound to that computer and exact local identity.
An identity change moves unfinished work back to queued state; the owner sees
`waiting_computer` if there is no current session, `waiting_recipient` if the
newest current session belongs to another user, or `recipient_unavailable` if
that session has no verifiable identity. Only the same identity can resume
before the job expires. `GET
/v2/endpoints/jobs/{id}/chunks/{index}` returns raw chunk bytes and the
`x-helicoid-chunk-sha256` header. Other endpoints and manager sessions cannot
read those chunks. The endpoint reports a target result with
`POST /v2/endpoints/jobs/{id}/result`:

```json
{
  "succeeded":true,
  "received_size_bytes":1234,
  "received_sha256":"<same lowercase digest>"
}
```

A successful result must match the declared full-file size and digest. Failed
results may include a bounded human-readable `detail` and omit the received
size/digest. Replayed identical terminal results are idempotent; conflicting
results are refused. The owner can observe `completed`, `failed`, or `partial`
job state and distinct results for each target.

Endpoint enrollment revocation fails that computer's waiting or in-progress
targets in the same transaction as the epoch change. Other targets continue
independently; payload chunks are released once every target is terminal.

Group writes require an active `manage_enrollment` account and an approved,
key-bearing Manager session. The server rechecks the session and permission in
the same transaction as each mutation; account or deployment MFA policy is
also enforced. Names are trimmed, 1–64 non-control Unicode characters, and
unique under SQLite's `NOCASE` collation (ASCII case-insensitive). At most 100
groups may exist.

`POST /v2/groups` creates an empty group at revision 1:

```json
{"name":"West campus"}
```

Returns **201** with `{ "id", "name", "revision": 1 }`.

`PUT /v2/groups/{id}` renames a group using its current revision:

```json
{"expected_revision":1,"name":"West"}
```

Returns **200** with the current group. A changed name increments the revision;
an unchanged name is idempotent. A stale revision returns `409`.

`PUT /v2/groups/{id}/computers/{computer_id}` sets one computer's membership:

```json
{"expected_revision":2,"included":true}
```

The computer must exist. A changed membership increments the group revision;
repeating the current desired membership returns the group unchanged. The
result does not alter `access_assignments` or make an out-of-scope computer
visible to the operator.

`DELETE /v2/groups/{id}` requires the current revision and an exact group ID
confirmation:

```json
{"expected_revision":3,"confirm_group_id":"<same-group-id>"}
```

Returns **204** and removes that group's memberships. Access assignments and
independent computer records remain unchanged.

## `GET /v2/access`

Returns at most 100 access assignments with their current revisions. Requires
an active bearer session with `manage_access`.

## `GET /v2/access/observe-scope`

Returns the authenticated account's explicit `observe` assignment scope. A
missing assignment returns `{"scope_all":false,"computer_ids":[]}`; an all
computer assignment returns `{"scope_all":true,"computer_ids":[]}`. Explicit
computer IDs are sorted and bounded to 100. Requires an active bearer session
and healthy server security state. This is advisory UI state only: it does not
authorize capture, and any future endpoint admission must independently
recheck the current assignment and computer scope.

## `POST /v2/access`

Create or replace one access assignment. Requires an active account with
`manage_access`, an approved key-bearing Manager session, fresh MFA within 120
seconds, and current authority rechecked in the assignment transaction. The
target account must be active. `computer_scope_all` and explicit `computer_ids`
are mutually exclusive; explicit identifiers must be unique and bounded to
the inventory page limit. Supported capabilities are `operate`, `observe`, and
`install_maintain`. `observe` remains metadata authority and does not itself
enable capture or provide pixels.

```json
{
  "account_id": "<server-account-id>",
  "capability": "operate",
  "computer_scope_all": false,
  "computer_ids": ["<server-computer-id>"]
}
```

Returns **201** with the current assignment and incremented revision.

## `DELETE /v2/access/{id}`

Revoke one assignment. Requires `manage_access`, an approved Manager device,
fresh MFA within 120 seconds, and an exact revision from the latest
`GET /v2/access` response. The server rechecks session authority and revision
inside the transaction; a stale revision returns `409` without deleting the
assignment. `confirm` must be `true`.

```json
{
  "expected_revision": 3,
  "confirm": true
}
```

Returns **200** with the assignment ID, account ID, capability,
`state: "revoked"`, and the revision that was revoked. Its computer-scope rows are
deleted in the same transaction.

## `PUT /v2/accounts/{id}/capabilities`

Replace an active account's capability set. Requires current account-management
authority, a key-bearing approved Manager session, and MFA within 120 seconds.
Only a security administrator may grant or revoke the security-administrator
capability. A target must already have active MFA before receiving that role,
and the last active security administrator cannot be removed. Every successful
change increments the account revision.

```json
{
  "expected_revision": 4,
  "can_operate": true,
  "can_manage_enrollment": false,
  "can_manage_access": true,
  "can_manage_accounts": false,
  "can_manage_security": false
}
```

Returns **200** with the updated `AccountView`.

## `PUT /v2/accounts/{id}/state`

Activate or disable an existing account. Requires current account-management
authority, an approved key-bearing Manager session, and fresh MFA. Pending-MFA
accounts cannot be changed through this endpoint. Disabling revokes every
session belonging to that account. Only a security administrator may disable a
security administrator, and the last active security administrator cannot be
disabled. A disabled security administrator must have active MFA before
reactivation. `expected_revision` prevents applying a stale account-table view.

```json
{
  "expected_revision": 4,
  "state": "disabled"
}
```

Returns **200** with the updated `AccountView` and incremented revision.

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
transaction (old-to-new replacement), and all existing account sessions are
revoked in that transaction. **No session token** is issued.

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

Successful policy changes are audited in the same transaction as the policy
update and any session revocations.

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

## Audit metadata and retention

Audit reads and retention changes require an active security administrator,
an approved Manager device, and a fresh MFA-backed v2 session. Responses
contain actor account and Manager IDs, an allowlisted action, opaque target
IDs, time, result, and a stable reason code. They exclude usernames, request
bodies, free-form messages, credentials, file data, and screen content.

### `GET /v2/audit/events`

Returns at most 100 events per page, newest first. `limit` defaults to 50 and
must be 1–100. Optional filters are exact `actor_account_id`, `action`, and
`target_id` values, plus inclusive `from_unix` / `to_unix` time bounds. The
server applies the configured retention window to every query. Continue with
the returned `next_cursor` as the `before_unix` and `before_id` query pair,
keeping the same filters on the next page.

```json
{
  "events": [
    {
      "id": "<event-id>",
      "actor": { "account_id": "<account-id>", "manager_id": "<manager-id>" },
      "action": "access.granted",
      "target_ids": ["<assignment-id>", "<account-id>", "<computer-id>"],
      "time_unix": 1792600000,
      "result": "succeeded",
      "reason_code": "capability_observe"
    }
  ],
  "next_cursor": null
}
```

### `GET /v2/security/audit-retention`

Returns the current retention in days and its last update time.

### `PUT /v2/security/audit-retention`

Requires a fresh MFA-backed security-admin Manager session and trusted
persistence. The strict request accepts `retention_days` from 1 through 3650.
The policy change and its audit event commit together.

```json
{ "retention_days": 30 }
```

**200**

```json
{ "retention_days": 30, "updated_at_unix": 1792600000 }
```

Current writers record successful committed changes to endpoint invitations
and enrollment decisions, Manager enrollment/approval/revocation, access
assignments, account provisioning/capabilities/state, observation grant
creation, interaction reservations, file delivery creation/upload verification/
cancellation and received-content deletion, file-request draft/publication/
closure, computer-group creation/rename/membership/deletion, restore quarantine
release, authority cutover, operator MFA policy, MFA enrollment/activation,
bootstrap, and audit retention. Denied-attempt coverage and
other security/action paths still need to join this boundary before the product
audit contract is complete.

---

## Unchanged unavailable surfaces

Production media, control, and security delegation/reset remain explicitly
unavailable (`501`) and `false` in `GET /health` features. Security
delegation/reset rules stay fail-closed.

---

## Feature flags (`GET /health`)

| Feature | v2 foundation |
| --- | --- |
| `local_accounts` | `true` |
| `manager_enrollment` | `true` |
| `scoped_inventory` | `true` |
| `mfa` | `true` (TOTP + recovery-only + device-key) |
| `file_jobs` | `true` (recipient-bound authenticated v2 job routes) |
| `security_recovery` | `false` (delegation/reset fail-closed) |
| `remote_control` | `false` |
| `screen_observation` | `false` |
