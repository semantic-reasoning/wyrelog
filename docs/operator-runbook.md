# Wyrelog Operator Runbook

This runbook closes the supported Linux production path for a packaged
Wyrelog application service deployment. It assumes the package installs
`wyrelogd`, `wyctl`, the access-control template tree, and the systemd
support files from `packaging/`.

## Installed Layout

- Binaries: `/usr/bin/wyrelogd`, `/usr/bin/wyctl`
- Templates: `/usr/share/wyrelog/access`
- Template release verifier: `/usr/share/wyrelog/tools/verify-template-release.sh`
- Daemon environment: `/etc/wyrelog/wyrelogd.env`
- System KeyProvider root: `/etc/wyrelog/system/policy.key` loaded by
  systemd as credential `wyrelog-system-policy-key`
- System policy store: `/var/lib/wyrelog/system/policy.sqlite`
- System audit store: `/var/log/wyrelog/system/audit.duckdb`
- System Datalog fact root: `/var/lib/wyrelog/system/facts`
- Service KeyProvider root: `/etc/wyrelog/service/policy.key` loaded by
  systemd as credential `wyrelog-service-policy-key`
- Service policy store: `/var/lib/wyrelog/service/policy.sqlite`
- Service audit store: `/var/log/wyrelog/service/audit.duckdb`
- Service Datalog fact root: `/var/lib/wyrelog/service/facts`
- Runtime directory: `/run/wyrelog`
- HTTP listen port: `127.0.0.1:8765` unless overridden by the service file
- Production log policy: compile release builds with
  `-Dwyrelog_log_max_level=warn`; packaged runtime defaults set
  `WYL_LOG=warn`

## Profiles

Wyrelog ships two daemon profiles:

- `system`: the authority profile for policy, keys, audit aggregation,
  and operator control.
- `service`: the application-facing profile for user decisions. It uses
  independent policy/key/audit paths and a bounded disk spool for events
  that cannot yet be forwarded to the system profile.

Packaged profile paths:

- System policy store: `/var/lib/wyrelog/system/policy.sqlite`
- System KeyProvider root: `/etc/wyrelog/system/policy.key`
- System audit store: `/var/log/wyrelog/system/audit.duckdb`
- System Datalog fact root: `/var/lib/wyrelog/system/facts`
- Service policy store: `/var/lib/wyrelog/service/policy.sqlite`
- Service KeyProvider root: `/etc/wyrelog/service/policy.key`
- Service audit store: `/var/log/wyrelog/service/audit.duckdb`
- Service Datalog fact root: `/var/lib/wyrelog/service/facts`
- Service event spool: `/var/lib/wyrelog/service/event-spool`

Inspect the resolved profile contract with:

```sh
wyrelogd --profile=system --profile-info --production
wyrelogd --profile=service --profile-info --production
```

## First Install

1. Install the package and create managed users/directories:

   ```sh
   systemd-sysusers /usr/lib/sysusers.d/wyrelog.conf
   systemd-tmpfiles --create /usr/lib/tmpfiles.d/wyrelog.conf
   ```

2. Create the production KeyProvider root once. Packaged systemd units pass
   this file through `LoadCredential=`, so `wyrelogd` reads it as
   `systemd-creds:wyrelog-system-policy-key` rather than opening the
   `/etc` file directly:

   ```sh
   install -m 0640 -o root -g wyrelog /dev/null /etc/wyrelog/system/policy.key
   python3 - <<'PY'
import os
with open("/etc/wyrelog/system/policy.key", "wb") as f:
    f.write(os.urandom(32))
PY
   chown root:wyrelog /etc/wyrelog/system/policy.key
   chmod 0640 /etc/wyrelog/system/policy.key
   ```

3. Validate package readiness before starting the daemon:

   ```sh
   wyrelogd --production \
     --profile system \
     --template-dir /usr/share/wyrelog/access \
     --policy-db /var/lib/wyrelog/system/policy.sqlite \
     --policy-keyprovider file:/etc/wyrelog/system/policy.key \
     --audit-db /var/log/wyrelog/system/audit.duckdb \
     --fact-root /var/lib/wyrelog/system/facts \
     --check
   wyrelogd --template-info --template-dir /usr/share/wyrelog/access
   wyctl key status --keyprovider /etc/wyrelog/system/policy.key
   ```

4. Start and verify service readiness:

   ```sh
   systemctl enable --now wyrelog-system.service
   systemctl enable --now wyrelog-service.service
   wyctl --daemon-url http://127.0.0.1:8765 status
   wyctl --daemon-url http://127.0.0.1:8765 status --readiness
   wyctl --daemon-url http://127.0.0.1:8766 status
   wyctl --daemon-url http://127.0.0.1:8766 status --readiness
   ```

## First-run Administrator Bootstrap

A freshly provisioned policy store has no administrator and therefore no
operator can mint a bearer token or grant any other principal a role.
The daemon exposes two flags that, together, perform the one-shot grant
that closes that gap. The grant is recorded in the encrypted policy
store as a sealed marker so a second invocation with a different
subject fails closed.

The flags are:

- `--bootstrap-admin-subject=SUBJECT` records `SUBJECT` as the initial
  `wr.system_admin` role member on the default tenant.
- `--bootstrap-admin-allow-skip-mfa` (optional) grants the same subject
  the `wr.login.skip_mfa` direct permission on the synthetic `login`
  scope so it can mint a first bearer token through `/auth/login` before an
  IdP is wired in.

Both flags are honored only on the live runtime store and are rejected
if combined with `--check` because readiness uses a scratch store that
would not persist the seal. The bootstrap is also rejected outright when
the audit subsystem is disabled so no silent grant can land.

### Linux / systemd

Drop in an override carrying the flags through `ExecStart`. Environment
variables are not consulted for these flags today, so pass them on the
command line:

```ini
# /etc/systemd/system/wyrelog-system.service.d/bootstrap.conf
[Service]
ExecStart=
ExecStart=/usr/bin/wyrelogd \
  --profile system \
  --template-dir /usr/share/wyrelog/access \
  --policy-db /var/lib/wyrelog/system/policy.sqlite \
  --policy-keyprovider systemd-creds:wyrelog-system-policy-key \
  --audit-db /var/log/wyrelog/system/audit.duckdb \
  --production \
  --bootstrap-admin-subject=alice \
  --bootstrap-admin-allow-skip-mfa
```

Apply and verify:

```sh
systemctl daemon-reload
systemctl restart wyrelog-system.service
journalctl -u wyrelog-system.service -n 50
wyctl --daemon-url http://127.0.0.1:8765 audit query \
  --filter 'action=bootstrap_admin_apply' \
  --access-token-file /run/wyrelog/operator.token
```

Once `alice` has rotated to an IdP-issued bearer, drop the
`--bootstrap-admin-allow-skip-mfa` flag from the drop-in and run
`systemctl daemon-reload && systemctl restart wyrelog-system.service`.
The marker and the existing role membership remain in place. The
persisted `wr.login.skip_mfa` direct-permission grant is **not**
removed by dropping the flag and must be revoked explicitly as
described under "Revoking bootstrap MFA bypass" below.

### Windows / Service

Pass the flags through `sc.exe config` so the service binary path
carries them as arguments:

```powershell
sc.exe config wyrelog binPath= "\"C:\Program Files\Wyrelog\wyrelogd.exe\" --profile system --template-dir \"C:\ProgramData\Wyrelog\access\" --policy-db \"C:\ProgramData\Wyrelog\system\policy.sqlite\" --policy-keyprovider file:\"C:\ProgramData\Wyrelog\system\policy.key\" --audit-db \"C:\ProgramData\Wyrelog\system\audit.duckdb\" --production --bootstrap-admin-subject=alice --bootstrap-admin-allow-skip-mfa"
sc.exe stop wyrelog
sc.exe start wyrelog
```

Verify through `wyctl.exe`:

```powershell
wyctl.exe --daemon-url http://127.0.0.1:8765 audit query ^
  --filter "action=bootstrap_admin_apply" ^
  --access-token-file C:\ProgramData\Wyrelog\operator.token
```

### Operational Notes

- The flag pair is idempotent for the same subject. Leaving the flag on
  subsequent restarts is safe and emits a no-op audit row each time
  with `deny_reason=already_sealed_same_subject`. Operators may either
  remove the flag after first success or leave it in place for explicit
  intent capture.
- A different subject after seal will fail closed with
  `bootstrap_admin: store already sealed for <other>` and a non-zero
  exit code. Rotation requires the original admin to grant a new admin
  through `wyctl policy role-grant`.
- `--bootstrap-admin-allow-skip-mfa` installs a **persisted**
  `wr.login.skip_mfa` direct-permission grant against the bootstrap
  subject on the `login` scope. The grant survives daemon restarts and the flag's
  presence/absence on subsequent boots; the flag on later boots is a
  no-op once the seal exists. The grant must be revoked explicitly
  once the operator has rotated to an IdP-issued bearer (see
  "Revoking bootstrap MFA bypass" below).
- The flag is rejected with `--check` because readiness uses a scratch
  policy store that would not persist the seal.
- Bootstrap is refused when the audit subsystem is disabled so the
  grant always leaves an audit trail.

### Revoking bootstrap MFA bypass

The `--bootstrap-admin-allow-skip-mfa` flag installs a **persisted**
`wr.login.skip_mfa` direct-permission grant against the bootstrap
subject on the `login` scope. The grant survives daemon restarts and the flag's
presence/absence on subsequent boots, so it must be revoked
explicitly once the operator has rotated to an IdP-issued bearer:

```sh
wyctl --daemon-url http://127.0.0.1:8765 policy permission-revoke \
    --subject <bootstrap-subject> \
    --perm wr.login.skip_mfa \
    --scope login \
    --access-token-file /run/wyrelog/operator.token \
    --guard-timestamp $(date +%s) \
    --guard-loc-class internal_network \
    --guard-risk low
```

Verify the revoke landed by inspecting the audit trail or the
decision-trace tool:

```sh
wyctl --daemon-url http://127.0.0.1:8765 audit query \
  --filter 'action=permission_revoke' --limit 10 \
  --access-token-file /run/wyrelog/operator.token
```

## TOTP Multi-Factor Authentication (MFA)

Wyrelog ships a built-in RFC 6238 TOTP validator so a fresh install can
reach an authenticated bearer token without an external IdP. Enrollments
live as `totp_enrollment` facts in the encrypted policy store, sealed
through the same KeyProvider as every other policy fact. There is no
separate MFA database, no shared secret leaves the policy store, and no
user-side backup codes are supported in v0 — recovery is admin reset only.

The flow assumes the policy store, KeyProvider, and audit subsystem are
already configured per the sections above.

### First-Install Bootstrap

The supported first-install path threads MFA enrollment off the
bootstrap admin grant. Start `wyrelogd` with both bootstrap flags:

```sh
wyrelogd --production \
  --profile system \
  --template-dir /usr/share/wyrelog/access \
  --policy-db /var/lib/wyrelog/system/policy.sqlite \
  --policy-keyprovider file:/etc/wyrelog/system/policy.key \
  --audit-db /var/log/wyrelog/system/audit.duckdb \
  --bootstrap-admin-subject=alice \
  --bootstrap-admin-allow-skip-mfa
```

At this point `alice` can log in through `/auth/login?…&skip_mfa=true`
because the bootstrap flag installed the `wr.login.skip_mfa` direct
permission. Enroll `alice`'s TOTP factor from an operator shell that has
read access to the bootstrap access token:

```sh
wyctl mfa enroll \
  --subject alice \
  --access-token-file /run/wyrelog/bootstrap.token
```

This is the recommended online form. It asks the running daemon to create a
short-lived, actor- and session-bound enrollment challenge, prints the
`otpauth://` URI, prompts for the current code, and confirms the enrollment
without opening the daemon-owned encrypted policy store a second time. The
access token must authorize `wr.policy.write`. Do not combine
`--access-token-file` with `--store` or `--keyprovider`.
The daemon keeps at most one pending challenge for an authenticated session,
uses a monotonic five-minute expiry, and consumes the challenge on every
confirmation attempt. A mistyped code therefore requires restarting
`wyctl mfa enroll`; this one-shot behavior prevents online guessing and replay.

For maintenance or recovery while the daemon is stopped, the offline form is
still available:

```sh
wyctl mfa enroll \
  --subject alice \
  --store /var/lib/wyrelog/system/policy.sqlite \
  --keyprovider file:/etc/wyrelog/system/policy.key
```

`wyctl mfa enroll` prints the `otpauth://` URI and the base32 secret on
stdout, then prompts on stderr for the current 6-digit code. The
operator scans the URI in an authenticator app (Google Authenticator,
Authy, 1Password, Bitwarden — all consume the same URI format) and
types the displayed code. On a valid code the enrollment fact lands,
and the `wr.login.skip_mfa` permission on the bootstrap subject is
**auto-revoked in the same transaction**. From this point on, `alice`
must present a TOTP code to log in; the bootstrap escape no longer
works for that subject.

The bootstrap auto-revoke step is intentionally one-shot. Enrolling any
non-bootstrap subject is a no-op for the revoke step because they
never held `wr.login.skip_mfa` in the first place.

### Enrolling Additional Admins

Use authenticated online enrollment for every subsequent admin. This keeps
the running daemon as the sole owner of the encrypted policy store. The
bootstrap auto-revoke branch is skipped silently for subjects that do not
hold `wr.login.skip_mfa`:

```sh
wyctl --daemon-url http://127.0.0.1:8765 mfa enroll \
  --subject bob \
  --access-token-file /run/wyrelog/admin.token
```

The subject must already have an authoritative policy identity, typically a
role membership created through `wyctl policy role-grant`. Enrollment does
not grant roles or permissions; it only attaches a TOTP factor.

### Offline Maintenance Defaults via GSettings

Direct `--store` / `--keyprovider` enrollment, including their GSettings
fallbacks, is only for maintenance or recovery while `wyrelogd` is stopped.
Never use it against the encrypted store owned by a running daemon. During a
daemon-stopped maintenance window, operators can stop repeating the paths by
setting the two GSettings keys once:

```sh
gsettings set org.wyrelog.wyctl default-policy-store /var/lib/wyrelog/policy.sqlite
gsettings set org.wyrelog.wyctl default-keyprovider systemd-creds:wyrelog-policy
```

After this, and only while the daemon is stopped,
`sudo wyctl mfa enroll --subject alice` (no `--store`, no `--keyprovider`)
resolves both paths from GSettings. `--subject` is
**not** a GSettings-backed key — it is always passed explicitly per
enrollment, because every enrollment targets exactly one principal.

Precedence is **CLI > GSettings > error**: an explicit `--store` or
`--keyprovider` on the command line still wins over the GSettings value,
and if neither is set the existing per-flag missing diagnostic fires.
The existing kill switch `WYCTL_DISABLE_GSETTINGS=1` (the literal
string `1`) disables the GSettings fallback uniformly across all wyctl
subcommands, including the mfa subcommands, restoring the pre-GSettings
"CLI-or-nothing" behaviour for incident-response or CI runs.

See the *wyctl Configuration and Token-File Safety* section below for
the full key reference and the surrounding precedence/kill-switch
machinery.

### Recovery and Reset

There are no user-side backup codes in v0. The only recovery path is
an operator with direct access to the policy store and the KeyProvider
running `wyctl mfa reset`:

```sh
wyctl mfa reset \
  --subject alice \
  --store /var/lib/wyrelog/system/policy.sqlite \
  --keyprovider file:/etc/wyrelog/system/policy.key
```

`wyctl mfa reset` deletes the existing enrollment fact and runs a fresh
enroll flow against the same subject. The new seed and otpauth URI are
emitted on stdout exactly as in the first-install case. Because the
enrollment row is replaced, the failure counter and any active lockout
state are implicitly reset.

**Abort semantics**: if the operator aborts mid-reset — EOF on the
prompt, an invalid code, or any other non-zero exit — the subject is
left **unenrolled**. The reset is not "undone" back to the previous
seed; the previous enrollment was already deleted by the first
mutation. Operators should not assume an aborted reset preserves the
old enrollment. Re-run `wyctl mfa enroll` against the same subject to
finish the recovery.

### Atomicity and Re-run Safety

`wyctl mfa enroll` wraps every mutation (enrollment fact insert,
bootstrap permission revoke, audit row) in a single policy-store
savepoint. Partial failure rolls back cleanly: if the enroll command
exits non-zero, no state changed.

`wyctl mfa reset` does **not** have that property. The reset path
deletes the prior enrollment row as its first action and commits that
delete independently, **before** the new enroll flow's savepoint
opens. This is a deliberate contract, not a UX edge case: the moment
an operator runs `wyctl mfa reset`, the prior TOTP seed is gone and
cannot be recovered. If the follow-on enroll is aborted — EOF on the
prompt, a wrong code, any non-zero exit — the subject is left
**unenrolled**, exactly as documented under "Abort semantics" above.
Operators running `wyctl mfa reset` during incident response must
treat the delete as irreversible.

The contract is:

- If `wyctl mfa enroll` exits non-zero, re-run the command. No state
  changed; the bootstrap auto-revoke step is idempotent for an
  already-revoked subject and a no-op for non-bootstrap subjects.
- If `wyctl mfa reset` exits non-zero, the prior enrollment row has
  already been deleted. The subject is unenrolled. Re-run `wyctl mfa
  enroll` against the same subject to finish the recovery.

There is no separate "rollback" command — re-running `wyctl mfa
enroll` is the recovery path for both failure modes.

### Lockout Behavior

The TOTP validator drives the existing principal FSM:

- After **5 consecutive wrong codes** the principal transitions to
  `LOCKED`. `/auth/mfa/verify` returns `429 mfa_locked` until the lock
  expires.
- After **15 minutes**, the lock auto-clears and the principal state
  returns to `UNVERIFIED`. The user must re-login from `/auth/login`
  to obtain a fresh `mfa_required` session token before retrying
  `/auth/mfa/verify`.
- `wyctl mfa reset` implicitly clears the failure counter because the
  enrollment row is replaced. Operators do not have a separate
  "unlock without reseed" command in v0.

Lockout state is durable across daemon restarts — it lives in the
policy store, not in process memory.

### HTTP API Summary

The login flow is two HTTP calls. `/auth/login` returns a short-lived
session token that cannot mint access or refresh tokens on its own;
`/auth/mfa/verify` exchanges that session token plus a current TOTP
code for the access and refresh tokens.

```
POST /auth/login?username=<subject>&tenant=<tenant>
  -> 200 { session_token, principal_state: "mfa_required" }

POST /auth/mfa/verify?session_token=<token>&code=NNNNNN
  -> 200 { access_token, refresh_token, principal_state: "authenticated" }
  -> 400 invalid_mfa_request   (malformed query)
  -> 400 tenant_sealed | tenant_invalid
                               (session's tenant no longer active)
  -> 401 mfa_auth_required     (missing or unknown session token)
  -> 401 mfa_invalid           (wrong code)
  -> 401 enrollment_required   (subject has no totp_enrollment fact)
  -> 429 mfa_locked            (5+ failures within 15 min)
  -> 500 mfa_verify_failed     (counter persistence IO error)
```

`/auth/login` does not enumerate enrolled vs unenrolled subjects: an
unenrolled but otherwise-valid subject still receives an `mfa_required`
session, and only `/auth/mfa/verify` surfaces `enrollment_required`.

**Bootstrap escape**: `POST /auth/login?…&skip_mfa=true` works **only**
for subjects holding the `wr.login.skip_mfa` permission. After the
bootstrap admin completes `wyctl mfa enroll`, that permission is
auto-revoked and the escape no longer works for the bootstrap subject.
Any other subject that has never held `wr.login.skip_mfa` is
unaffected — the escape was never a general login mode.

### Stdout Secrecy

`wyctl mfa enroll` and `wyctl mfa reset` write the `otpauth://` URI and
the base32 secret to **stdout**. The prompt for the current code and
all diagnostics go to **stderr**. Do not pipe stdout to a log file, a
journal, or a CI artifact — the seed bytes leak through that path.

A typical safe operator session keeps stdout attached to the
controlling terminal and lets the authenticator app consume the
displayed URI directly. If stdout must be captured for tooling, treat
the captured file as a sealed secret with the same handling as the
KeyProvider key file.

### otpauth URI Compatibility

The emitted URI follows the Google Authenticator key-URI format:

```
otpauth://totp/wyrelog:<subject>?secret=BASE32&issuer=wyrelog&algorithm=SHA1&digits=6&period=30
```

`algorithm=SHA1`, `digits=6`, `period=30`, ±1 step skew. The format is
consumed without modification by Google Authenticator, Authy,
1Password, Bitwarden, and any other authenticator that accepts the
Google key-URI shape. ASCII QR rendering inside `wyctl` is intentionally
out of scope — operators who want a QR can pipe the URI through
`qrencode -t ANSI` or paste it into the authenticator app's manual
import flow.

### Threat-Model Notes

- **Scope**: the built-in validator handles only the TOTP factor.
  Bearer-token issuance, storage, and revocation are unchanged from
  the rest of the daemon's auth path — access and refresh tokens are
  minted by the daemon and held in its in-memory state map. Token
  revocation is still "restart the daemon"; there is no
  per-token revoke API in v0.
- **Backup codes**: explicitly not supported in v0. The lost-device
  recovery path is a privileged operator running `wyctl mfa reset`.
  Operators should plan for that access (a second admin with store +
  KeyProvider access, or a documented break-glass procedure) before
  enrolling MFA on the only admin account.
- **Store-access privilege**: anyone with write access to the policy
  store path AND the KeyProvider can mint or reset any subject's TOTP
  enrollment. The encrypted policy store is the trust anchor for MFA;
  protect the KeyProvider key file with the same care as the bootstrap
  marker.

## Service Credential Handoff

`wyctl service-credential issue` and `wyctl service-credential rotate`
drive the loopback-only escrow handoff. Issue mints the first
credential for a service subject; rotate supersedes an existing
credential id. Both talk to the local daemon over its loopback listener
and require a live, MFA-assured human bearer session that holds
`wr.service_credential.manage`. The bearer is always authenticated in the
management resolver tenant `__wr_default`; `--tenant` independently selects
the credential target.

### Arming the service-management authority (prerequisite)

Before `service-principal create`, `service-credential issue`, or any other
service-management verb will authorize, the acting admin must first arm the two
management permissions (`wr.service_principal.manage`,
`wr.service_credential.manage`) for its own session. Arm them with a single
loopback call using the same live, MFA-assured human bearer and guard context:

```
POST /service-management-authority/arm
  Authorization: Bearer <access-token>
  ?guard-timestamp=<ts>&guard-loc-class=<class>&guard-risk=<risk>
```

Semantics:

- **Session-bound.** The authority is armed at the caller's own `session_id`
  and is inert once that session is revoked or logs out. Re-arming is required
  after a new login.
- **Self-scoped.** The armed subject is always the bearer's own actor and the
  scope is always the bearer's own `session_id`. No query, body, or header
  parameter can redirect the grant to another subject or scope.
- **MFA-gated, human-only.** The call requires the SYSTEM profile, an actual
  loopback transport, a bearer (never a session token) authenticated in
  `__wr_default`, and a live human MFA-assured session. Service tokens can
  never arm this authority.
- **Eligibility.** Only holders of the `wr.system_admin` role may self-arm; the
  role carries the `wr.service.self_authorize` permission that gates the call
  (a separation-of-duties boundary). The guard context is required and validated
  but is not the primary control — the profile, loopback, MFA-session, and role
  checks above are.

### Service-authority cleanup failures

Every service-management mutation finalizes its exclusive service-authority
WRITE lease before the daemon sends response status, headers, or body. If that
terminal cleanup detects inconsistent lock-rank, store-pin, or ownership state,
cleanup takes precedence over the route result: the daemon returns HTTP 500
with `policy_write_cleanup_failed` and refuses later service-authority WRITE
requests for the lifetime of that process.

Treat this response as an indeterminate mutation outcome. Durable work may
already have committed, and the 500 response neither rolls it back nor proves
that it did not commit. Preserve the request id, inspect the authoritative
resource or operation state with a human session, and do not retry the mutation
under a new id. The diagnostic log records only the static owner identifier,
the primary internal result when known, the primary status/error code, and the
numeric cleanup result; it intentionally omits credentials, tokens, actors,
tenants, paths, and request bodies.

There is no reset endpoint for this fail-closed latch. Health, human
authentication, and ordinary policy decisions remain available. Correct the
underlying deployment or storage problem and restart the affected daemon to
construct a fresh authority coordinator, then obtain a fresh human token,
re-arm service-management authority, and verify the authoritative state before
retrying with the original request id where that operation supports one.

```
wyctl service-credential issue \
  --tenant <tenant> \
  --subject <service-subject-id> \
  --destination <escrow-file-name> \
  --expires-at-us <epoch-microseconds> \
  [--request-id <id>] \
  --access-token-file <path>

wyctl service-credential rotate \
  --tenant <tenant> \
  --credential-id <credential-id> \
  --destination <escrow-file-name> \
  --expires-at-us <epoch-microseconds> \
  [--request-id <id>] \
  --access-token-file <path>
```

`--subject` identifies the service principal and does not encode or establish
the target tenant; rotate names the credential to supersede with
`--credential-id` instead. The daemon requires the issue body's tenant and the
selected target to match exactly. For rotate, list, revoke, status, and recover,
it derives the authoritative tenant from stored credential or operation state
and rejects a different selected target without revealing whether the object
exists. `--destination` is the escrow publication
file and `--expires-at-us` is the absolute publication expiry in epoch
microseconds and must be greater than zero. Both are mandatory. The
`--access-token-file` bearer token may instead come from `wyctl`
configuration, and the guard flags `--guard-timestamp`,
`--guard-loc-class`, and `--guard-risk` carry policy-guard context.

Service-principal management is global rather than tenant-targeted. Its
`--tenant` may be omitted or explicitly set to `__wr_default`; any other value
is rejected locally. Credential commands still require `--tenant` because it
selects the managed target, not the bearer session tenant.

Disable a service principal with an optional stable retry key:

```
wyctl service-principal disable \
  --subject <service-subject-id> \
  [--request-id <canonical-request-id>] \
  --access-token-file <path>
```

When `--request-id` is omitted, `wyctl` mints one canonical ID and sends it in
the strict request body. If the connection drops or the daemon returns 500/503,
retry with the same explicit ID; using a new ID creates a distinct authorized
attempt. HTTP 409 means that the key is already bound to a conflicting request
and must not be reused for different inputs. The response
`X-Wyrelog-Request-Id` is only per-attempt correlation and is never a substitute
for `--request-id`.

### Idempotency

`--request-id` is optional; omit it and `wyctl` mints a fresh canonical
request id. Reusing the same `--request-id` with identical inputs is a safe
retry: the daemon
returns the same operation, credential, and receipt and never mints a
second secret. Supply a stable `--request-id` when a previous invocation
may have succeeded without you observing its reply.

### Secret Secrecy

On success `wyctl` writes one `key=value` receipt line to **stdout**:

```
state=<state> request_id=<id> credential_id=<id> generation=<n> destination=<name> publication_receipt_id=<id> delivered=<yes|no>
```

This receipt line is non-secret. The one-time credential secret is
**never** printed: it is delivered out-of-band to the owner-only escrow
publication file named by `--destination` on the daemon host, and a
diagnostic to that effect goes to **stderr**. Do not pipe stdout to a
file expecting the secret there — it is not in the receipt. Protect the
escrow file as a sealed secret with the same handling as the KeyProvider
key file. `delivered=yes` appears only once the secret has been durably
published to that file.

### Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Success; receipt printed to stdout. |
| 2 | Local usage or validation error (bad flags, no server contacted). |
| 3 | Server rejected the request as invalid (HTTP 400). |
| 4 | Policy conflict or authorization denied (HTTP 409 or 403). |
| 5 | Other remote failure (HTTP 500 or 503). |
| 6 | Authentication required; missing or invalid token (HTTP 401). |

### The identity and authorization model

Service credentials introduce a second, deliberately weaker class of principal
alongside the human admins that own the deployment. Keep the pieces distinct:

- **Principal.** A service principal is a subject in a reserved, validated
  namespace: its subject id always begins with `svc:` (for example
  `svc:svc-app`). Human and service subjects cannot collide. Service principals
  are created and disabled only by a human admin (see below); they never
  bootstrap, enroll TOTP, or use the human login/refresh/skip-MFA paths.
- **Credential.** A credential is a `wlc_<KSUID>` object bound to exactly one
  principal and, through its own row, to exactly one tenant. The credential row
  is the sole tenant authority during exchange; the exchange request itself
  carries no tenant and has no default-tenant fallback. Only a versioned salted
  verifier plus lifecycle metadata persist in the encrypted policy store — never
  the 32-byte secret.
- **Session and token.** Exchanging a credential (next section) creates an
  ordinary live session and a short-TTL access token (a JWT) carrying the exact
  service auth method, credential id/generation, subject, tenant, session id,
  and `jti`. There is no workload refresh token in v1.
- **Role.** A freshly issued credential holds no role. Its token authenticates
  but is unauthorized for every protected operation until a human grants it a
  workload-safe, tenant-scoped role. Roles carrying any direct, inherited, or
  multi-hop **control-plane** authority are rejected atomically for service
  subjects — a service principal can never be granted system, policy, tenant,
  audit, security, key-management, or credential-management authority. The
  data-plane allowlist is fixed and small (`wr.stream.read`, `wr.stream.list`,
  `wr.svc.read_decision`); every other permission is control-plane by default
  (`templates/access/bootstrap.dl`, `wyrelog/policy/store.c` —
  `approved_data_plane_permissions[]`).
- **Live authorization is `/decide`.** The authoritative, real-time answer to
  "may this token do this now?" is the daemon's `/decide` endpoint, evaluated
  against the current policy. It is not cached in the token; a role change flips
  the same unexpired token immediately.

Management authority is asymmetric by design:

- **Human SYSTEM management authority.** Creating principals, issuing/rotating/
  revoking credentials, and recovering operations is available only to a live,
  MFA-assured human bearer authenticated in the management resolver tenant
  `__wr_default` under the SYSTEM profile, holding `wr.service_principal.manage`
  / `wr.service_credential.manage`. Those two permissions are not granted by any
  role; the admin arms them for its own session with the self-arm call
  documented under "Arming the service-management authority" above (the
  `POST /service-management-authority/arm` route, #729), which requires the
  `wr.system_admin` role's `wr.service.self_authorize` eligibility, a real
  loopback transport, and a live human MFA-assured session. Service tokens can
  never arm this authority.
- **Data-plane-only `svc:` identity.** A service token is confined to the
  data-plane allowlist. It cannot reach any control-plane action even
  transitively — the decision engine only mirrors an approved data-plane
  permission into a `svc:` principal's live authorization and never writes or
  reads control-plane permission state for a `svc:` subject
  (`wyrelog/wyl-decide.c`).

### Exchanging a credential for a token

A workload turns its escrow credential document into a bearer token with a
single loopback call:

```
wyctl auth service-token \
  --credential-file <escrow-doc-path> \
  --token-output <token-output-path>
```

`wyctl auth service-token` (`wyrelog/wyctl/wyctl.c`, `run_auth_service_token`)
reads the credential document, decodes the credential id and its one-time
secret, and exchanges them at the daemon's `/auth/service-token` endpoint over
the loopback listener only. The minted short-TTL JWT is written to the
`--token-output` path; it is **never** printed to stdout, and the 32-byte
secret is never placed on argv, stdout, or a query parameter. The daemon
accepts the exchange only when the exact session/jti/credential-generation/
principal/tenant registry entry is `ACTIVE`; a `PENDING`, `REVOKED`, absent, or
mismatched entry fails closed. The bearer resolver used here
(`resolve_bearer_session()`) is the same one that resolves human bearers — there
is no alternate service-only resolver.

### Live authorization and revocation

Authorization is evaluated live at `/decide`, so a zero-role token is provably
inert until a role is granted, and revoking that role makes the same token inert
again immediately.

```
# Fresh service token, no role yet: DENY.
POST /decide  { subject: svc:svc-app, action: wr.stream.read, tenant: tenant-a }
  -> decision=0 (deny)

# A human admin grants a workload-safe, tenant-scoped role.
POST /policy/roles/grant  { subject: svc:svc-app, role: <workload-safe role>,
                            scope: tenant-a }   (human __wr_default bearer,
                                                 guard context)

# Same unexpired token, re-evaluated: ALLOW.
POST /decide  { subject: svc:svc-app, action: wr.stream.read, tenant: tenant-a }
  -> decision=1 (allow)

# The human revokes the grant.
POST /policy/roles/revoke  { subject: svc:svc-app, role: <workload-safe role>,
                            scope: tenant-a }   (human __wr_default bearer,
                                                 guard context)

# Same token again: DENY. No token reissue, no cache flush.
POST /decide  ...  -> decision=0 (deny)
```

The grant/revoke flips the result of the *same* unexpired token because `/decide`
reads current policy rather than a claim baked into the token.

**Tenant isolation.** A token minted for one tenant is bound to that tenant.
Presenting a `tenant-a`-bound token against `tenant-b` is refused at the tenant
gate with HTTP 403 and error `tenant_denied` (`wyrelog/daemon/http.c`); the
credential row — not any request field — is the tenant authority.

### Incident revocation and zero-survivor

Three independent controls each leave zero usable and zero pending tokens. None
of them has a refresh path that could resurrect access.

Revoke a single credential:

```
wyctl service-credential revoke \
  --credential-id <wlc_KSUID> \
  --tenant <tenant> \
  [--request-id <id>] \
  --access-token-file <path>
# receipt: credential_id=<wlc_KSUID> state=revoked revoked_by=<actor> revoked_at_us=<ts>
```

Disable the whole principal (management is global; `--tenant` is omitted or
`__wr_default`):

```
wyctl service-principal disable \
  --subject <svc:subject-id> \
  --tenant __wr_default \
  [--request-id <id>] \
  --access-token-file <path>
```

Seal the tenant (blocks the entire tenant surface):

```
POST /tenants/seal
  Authorization: Bearer <token>
  { "version": "1", "request_id": "<canonical-request-id>" }
```

After any of these, a fresh exchange for an affected credential fails, an
already-minted token stops authenticating (HTTP 401 at the bearer gate), and a
request that carries a sealed tenant is rejected with HTTP 400 and error
`tenant_sealed` (`wyrelog/daemon/http.c`). This zero-survivor property is proven
end to end by `service-credential-zero-survivor-e2e` (Linux packaged runtime).

### Publication failure and orphan recovery (#383)

Issuing or rotating a credential is two separable steps: the daemon **commits**
the new credential in the authoritative store, and then **publishes** the
secret to the local escrow document. These are deliberately not a single
distributed transaction. If the daemon crashes or the publication fails *after*
the server commit, the server-side credential exists but no escrow document was
written — a durable, **secret-free** orphan recorded under `--operation-root`.
No secret is ever on disk in this state.

Recover it read-only. The recover verb inspects durable operation state; it
mints no secret and writes no escrow document:

```
wyctl service-credential recover \
  --request-id <R> \
  --tenant <tenant> \
  --access-token-file <path>
# receipt: request_id=<R> operation=issue state=server_committed
#          destination=<name> successor_credential_id=<wlc_KSUID> ...
```

A committed-but-unpublished orphan reports `state=server_committed` and names
the `successor_credential_id`. This durable state **survives a daemon restart**:
re-running `recover` after a restart returns the same `state=server_committed`
and the same `successor_credential_id`. Because the escrow secret was never
delivered and cannot be, the correct remediation is to revoke the successor
through the ordinary public revoke path:

```
wyctl service-credential revoke \
  --credential-id <successor_credential_id> \
  --tenant <tenant> \
  --access-token-file <path>
# receipt: ... state=revoked
```

This end-to-end flow — post-commit publication fault, `recover` reporting
`server_committed` with a successor, restart survival, revoke to
`state=revoked`, and an escrow root that holds zero files throughout — is
packaged-runtime-proven on Linux by
`service-credential-publication-fault-e2e`
(`tests/check-service-credential-publication-fault-e2e.sh`, #754).

### File custody and local-only transport

The service-credential surface is loopback-only and file-mediated:

- **Escrow documents (`0600`).** The one-time secret is delivered out-of-band to
  the owner-only escrow document named by `--destination` under
  `--credential-publication-root`, never to stdout or argv. Treat that file as a
  sealed secret with the same handling as the KeyProvider key file.

  ```
  $ ls -l /var/lib/wyrelog/system/publication/
  -rw------- 1 wyrelog wyrelog  ...  <destination>
  ```

- **Owner-only roots (`0700`).** `--credential-publication-root`,
  `--operation-root`, and the fact root are each created `0700` and must be
  mutually disjoint (and disjoint from the policy DB, audit DB, and event spool);
  overlap fails daemon startup closed.

  ```
  $ ls -ld /var/lib/wyrelog/system/publication /var/lib/wyrelog/system/operations
  drwx------ 2 wyrelog wyrelog  ...  /var/lib/wyrelog/system/publication
  drwx------ 2 wyrelog wyrelog  ...  /var/lib/wyrelog/system/operations
  ```

- **Loopback only.** Management (issue/rotate/revoke/list/status/recover,
  principal create/disable) and the `/auth/service-token` exchange are validated
  against the actual listener and peer address and accept a canonical literal
  loopback URL only. There is no remote, proxy, TLS/mTLS, or Unix-socket
  transport in v1, and the `Forwarded` / `X-Forwarded-*` headers are never
  trusted to establish the caller's address.

### Audit interpretation

The durable audit sink records service-credential activity without ever
recording secret material:

- **Lifecycle allow rows.** A successful issue or rotate leaves a durable
  authorization row for the `wr.service_credential.manage` decision, tagged with
  the acting human actor, request id, credential id, and generation. Revoke and
  the operation-handoff disposition/remediation steps are likewise recorded.
- **`last_used_at`.** Each credential carries a best-effort `last_used_at_us`
  timestamp, updated on exchange, that lets you spot dormant or still-live
  credentials during an incident.
- **Single-owner DENIED audit.** The exclusive service-authority WRITE lease is
  single-owner; a denied acquisition is recorded best-effort so contention is
  visible.
- **`service_exchange_receipt_projections` is normally empty.** This DuckDB
  table exists only as a crash-recovery projection for the exchange path
  (`wyrelog/audit/conn.c`). On a cleanly acknowledged exchange it is
  deliberately left empty — an empty projection table is the expected steady
  state, not a missing-audit finding. Note also that even this projection stores
  only a `session_fingerprint` and `jti_fingerprint`, never the raw session id
  or `jti`.
- **No secret ever appears.** No plaintext credential secret, plaintext CVK,
  JWT, `Authorization` body, session id, or `jti` is present in any audit row,
  log, error, CLI output, or recovery journal. This is proven end to end by
  `service-credential-leak-scan-e2e` (Linux packaged runtime).

## Datalog Product Flow

Wyrelog is a Datalog storage and inference engine. The packaged access-control
policy is the default policy template for the daemon, while Datalog facts live in
separate per-tenant, per-graph stores. Keep these paths physically separate:

- Policy DB: encrypted SQLite authority store, for example
  `/var/lib/wyrelog/system/policy.sqlite`.
- Audit DB: DuckDB audit sink, for example
  `/var/log/wyrelog/system/audit.duckdb`.
- Fact DBs: DuckDB files below the fact root, for example
  `/var/lib/wyrelog/system/facts/<tenant>/<graph>/facts.duckdb`.

Back up and restore those stores as separate artifacts. Do not place the policy
or audit DB under the fact root. The static packaged units rely on the daemon's
profile defaults for the fact root so the same unit files remain valid for
builds with and without fact-store support; pass `--fact-root` explicitly in
manual checks or local deployments that enable Datalog fact storage.

The commands below show a complete local product flow on the default tenant.
Replace `alice` and the paths for your deployment.

```sh
BASE_URL=http://127.0.0.1:8765
TOKEN=/run/wyrelog/operator.token
TENANT=__wr_default
GRAPH=orders

wyrelogd --production \
  --profile system \
  --template-dir /usr/share/wyrelog/access \
  --policy-db /var/lib/wyrelog/system/policy.sqlite \
  --policy-keyprovider file:/etc/wyrelog/system/policy.key \
  --audit-db /var/log/wyrelog/system/audit.duckdb \
  --fact-root /var/lib/wyrelog/system/facts \
  --bootstrap-admin-subject alice \
  --bootstrap-admin-allow-skip-mfa \
  --listen-port 8765
```

Mint the first token and arm the packaged administrator's Datalog authorities on
the tenant scope. The bootstrap role already grants these permissions; the
permission-state transition records that the operator intentionally armed them
for this scope.

```sh
python3 - <<'PY'
import json, urllib.request
url = "http://127.0.0.1:8765/auth/login?username=alice&tenant=__wr_default&skip_mfa=true"
req = urllib.request.Request(url, method="POST")
with urllib.request.urlopen(req) as response:
    token = json.load(response)["access_token"]
open("/run/wyrelog/operator.token", "w", encoding="utf-8").write(token + "\n")
PY

for perm in wr.graph.manage wr.schema.manage wr.fact.write wr.datalog.query; do
  curl -fsS -X POST \
    -H "Authorization: Bearer $(cat "$TOKEN")" \
    "$BASE_URL/policy/permissions/transition?subject=alice&perm=$perm&scope=$TENANT&event=grant&guard_timestamp=$(date +%s)&guard_loc_class=trusted&guard_risk=29"
done
```

Run the graph, schema, fact, and query commands through `wyctl`:

```sh
wyctl --daemon-url "$BASE_URL" graph create \
  --tenant "$TENANT" --graph "$GRAPH" \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29

wyctl --daemon-url "$BASE_URL" fact schema register \
  --tenant "$TENANT" --graph "$GRAPH" \
  --namespace shop --relation orders --schema-version 1 \
  --columns order_id:symbol,amount:int64 --max-rows 1000 \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29

printf 'order_id,amount\no-1,42\n' >/tmp/orders.csv
wyctl --daemon-url "$BASE_URL" fact put \
  --tenant "$TENANT" --graph "$GRAPH" \
  --namespace shop --relation orders --schema-version 1 \
  --batch-id orders-1 --idempotency-key orders-1 \
  --format csv --input /tmp/orders.csv \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29

wyctl --daemon-url "$BASE_URL" datalog query \
  --tenant "$TENANT" --graph "$GRAPH" \
  --query 'orders(O,A)' --output json --limit 10 \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29
```

Fact mutation is schema-registered: append, retract, and forget operate only on
relations registered through `fact schema register`. The daemon does not support
raw Datalog atom deletion endpoints such as `DELETE /api/facts/fact(1)` or
ad-hoc deletion of `fact(1)` without a registered relation schema. Attempts to
mutate a relation before registering its schema fail with
`fact_schema_not_found` on the schema-backed `/facts/<tenant>/<graph>/<relation>`
routes.

The following unary `fact(V)` flow shows the required contract for a registered
`fact(value:int64)` relation:

```sh
GRAPH=unary

wyctl --daemon-url "$BASE_URL" graph create \
  --tenant "$TENANT" --graph "$GRAPH" \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29

wyctl --daemon-url "$BASE_URL" fact schema register \
  --tenant "$TENANT" --graph "$GRAPH" \
  --namespace examples --relation fact --schema-version 1 \
  --columns value:int64 --max-rows 1000 \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29

printf 'value\n1\n2\n3\n' >/tmp/fact.tsv
curl -fsS -X POST \
  -H "Authorization: Bearer $(cat "$TOKEN")" \
  --data-binary @/tmp/fact.tsv \
  "$BASE_URL/facts/$TENANT/$GRAPH/fact:append?tenant=$TENANT&namespace=examples&schema_version=1&batch_id=fact-1&idempotency_key=fact-1&guard_timestamp=$(date +%s)&guard_loc_class=trusted&guard_risk=29"

wyctl --daemon-url "$BASE_URL" datalog query \
  --tenant "$TENANT" --graph "$GRAPH" \
  --query 'fact(V)' --output json --limit 10 \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29

printf 'value\n1\n' >/tmp/fact-retract.tsv
curl -fsS -X POST \
  -H "Authorization: Bearer $(cat "$TOKEN")" \
  --data-binary @/tmp/fact-retract.tsv \
  "$BASE_URL/facts/$TENANT/$GRAPH/fact:retract?tenant=$TENANT&namespace=examples&schema_version=1&batch_id=fact-r1&idempotency_key=fact-r1&guard_timestamp=$(date +%s)&guard_loc_class=trusted&guard_risk=29"

wyctl --daemon-url "$BASE_URL" datalog query \
  --tenant "$TENANT" --graph "$GRAPH" \
  --query 'fact(V)' --output json --limit 10 \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29
```

The first query returns values `1`, `2`, and `3`. The query after the retract
returns only `2` and `3`; the raw atom `fact(1)` is not deleted through a
separate `/api/facts` API.

Omit `--max-rows` during schema registration to keep the default 1000-row
Datalog query cap. Set it explicitly for larger materialized JSON queries;
accepted values are 1 through 1000000, and `wyctl datalog query --limit`
cannot exceed the registered cap.

To verify recovery, restart `wyrelogd` with the same policy DB, audit DB, key,
and fact root. Mint a fresh token after restart and run the same
`wyctl datalog query`; the fact graph is replayed from the per-graph DuckDB fact
store. Check graph health with:

```sh
curl -fsS "$BASE_URL/facts/status"
```

A single corrupted graph should report a degraded graph entry while unrelated
graphs remain queryable. Stop the daemon before repairing or replacing a damaged
`facts.duckdb`, restore only the affected `<tenant>/<graph>` fact directory,
restart, then confirm `/facts/status` returns `"status":"ready"`.

## Day-2 Operations

- Template validation from an operator shell. Use `file:` for manual checks;
  the packaged service uses `systemd-creds:` after systemd loads the
  credential:

  ```sh
  wyrelogd --template-info --template-dir /usr/share/wyrelog/access
  wyrelogd --production --template-dir /usr/share/wyrelog/access \
    --profile system \
    --policy-db /var/lib/wyrelog/system/policy.sqlite \
    --policy-keyprovider file:/etc/wyrelog/system/policy.key \
    --audit-db /var/log/wyrelog/system/audit.duckdb --check
  ```

- Policy grant/revoke:

  ```sh
  wyctl --daemon-url http://127.0.0.1:8765 policy permission-grant \
    --subject alice --permission site.policy.read --scope tenant-a \
    --access-token-file /run/wyrelog/operator.token
  wyctl --daemon-url http://127.0.0.1:8765 policy permission-revoke \
    --subject alice --permission site.policy.read --scope tenant-a \
    --access-token-file /run/wyrelog/operator.token
  ```

- Audit query:

  ```sh
  wyctl --daemon-url http://127.0.0.1:8765 audit query \
    --filter 'decision=deny' --limit 50 \
    --access-token-file /run/wyrelog/operator.token
  ```

- Restart:

  ```sh
  systemctl restart wyrelog-system.service
  systemctl restart wyrelog-service.service
  wyctl --daemon-url http://127.0.0.1:8765 status --readiness
  wyctl --daemon-url http://127.0.0.1:8766 status --readiness
  ```

  Access and refresh tokens are invalidated by daemon restart. Operators
  must obtain fresh credentials after restart.

- Profile status:

  ```sh
  curl -fsS http://127.0.0.1:8765/profile/status
  curl -fsS http://127.0.0.1:8766/profile/status
  ```

  Service-profile event forwarding targets
  `http://127.0.0.1:8765/profile/events`. If the system profile is not
  reachable, the service profile keeps its local decision path isolated
  and uses the configured event spool directory as the bounded recovery
  surface.

## Which Endpoint Reports What

`/readyz` reports whether **this process** can serve a correct query. It does
**not** reflect fact-subsystem health, and that is deliberate — see #874 for the
decision and its reasons.

`/facts/status` is the surface that reports fact health, and it is the endpoint
to watch for an outstanding erasure.

| you want to know | endpoint | what it tells you |
| --- | --- | --- |
| is the process serving | `GET /readyz` | `200` and `ready\n`, or `503` with a reason |
| is any graph degraded | `GET /readyz?format=json` | `subsystems.facts` carries `graphs_total`, `graphs_ready`, `graphs_degraded` |
| which graph, and why | `GET /facts/status` | per-graph `state` and the aggregate |

Three consequences worth knowing before you wire an alert.

**A Kubernetes readiness probe cannot see fact health.** An `httpGet` probe
reads the status code and discards the body, and no fact state changes that
code. A graph carrying an unconverged erasure is reported `degraded` by
`/facts/status` while `/readyz` stays `200`. That is not an oversight: a
readiness failure removes the pod from Service endpoints without running the
boot pass that converges the erasure, so it would withdraw a working query
surface without fixing anything.

**A single poll can still cover both.** `/readyz?format=json` carries the fact
aggregate under `subsystems.facts`, including `graphs_degraded`, regardless of
whether per-graph detail was requested. A body-matching probe can alert on a
non-zero count from that one request. Only `/facts/status` names the per-graph
state.

**The plain-text `/readyz` carries no fact information at all.** The body is
exactly `ready\n` on success. Do not parse it for anything else, and note that
the failure path returns JSON rather than plain text.

A degraded graph may still be answering queries. `/facts/status` reports
`"queryable": true` for a graph whose engine is complete and correct for the
data that is present, even while that graph is counted in `graphs_degraded`.
Read the per-graph `state` rather than inferring a cause from the aggregate,
and read the `BOOT` log lines, which name the graph and the reason directly.

## Backup And Restore

1. Stop the daemon:

   ```sh
   systemctl stop wyrelog-service.service
   systemctl stop wyrelog-system.service
   ```

2. Back up the active profile's KeyProvider root, policy store, audit
   store, event spool when present, and the output of
   `wyrelogd --template-info`.

3. Restore the files with the same ownership and modes, then run the
   production `--check` command before restarting.

## Template Upgrade

1. Install the new package without starting the daemon.
2. Verify the installed template tree against the release note values:

   ```sh
   /usr/share/wyrelog/tools/verify-template-release.sh \
     /usr/bin/wyrelogd /usr/share/wyrelog/access \
     EXPECTED_VERSION EXPECTED_SHA256 \
     EXPECTED_MIGRATIONS EXPECTED_LATEST_MIGRATION_VERSION
   ```

3. Run production `--check` against the existing policy and audit stores.
4. Restart the service.
5. If readiness fails, roll back by restoring the previous package, template
   tree, policy store, audit store, and KeyProvider backup together.

## Template Artifact Release And Replay Policy

Template artifacts are release artifacts, not runtime secrets. The private
Ed25519 signing keys are owned by the release custodian role and kept outside
the deployed Wyrelog hosts. Production hosts receive only signed template
artifacts and embedded public verification keys in `manifest.ini` and
`migrations/*.ini`.

The signing process is:

1. Build the package from a tagged release commit.
2. Generate the canonical template digest for the fixed engine load order
   documented in `templates/access/manifest.ini`.
3. Sign the digest with context `wyrelog-template-v0-sha256`.
4. Sign each migration digest with context
   `wyrelog-template-migration-v0-sha256`.
5. Publish the package with release notes that record template version,
   template SHA-256, migration count, latest migration version, and the
   signing public key fingerprints.

Signing-key rotation is a release event. Add the new public key to the next
artifact manifest or migration artifact, sign the artifact with the new
offline private key, and record the rotation in the release notes. The old
private key must be retired from signing use after the last release that
depends on it is published. If a signing key is suspected to be compromised,
stop rollout, publish a superseding release signed by a new key, and reject
the affected artifact identity in deployment automation.

Downgrade and replay policy is fail-closed by default:

- A package downgrade is unsupported as an in-place operation.
- Replaying a previously signed template with an older release identity is
  rejected by comparing `verify-template-release.sh` output against the
  release note values approved for the deployment.
- Rollback is restore-from-backup only: restore the previous package,
  template tree, policy store, audit store, and KeyProvider state as one
  consistent snapshot, then run production `--check`.
- Supersession is the supported correction path for a bad artifact: publish a
  new release with a new template identity and verify that exact identity on
  every host before restart.

Operator provenance verification:

```sh
wyrelogd --template-info --template-dir /usr/share/wyrelog/access
/usr/share/wyrelog/tools/verify-template-release.sh \
  /usr/bin/wyrelogd /usr/share/wyrelog/access \
  EXPECTED_VERSION EXPECTED_SHA256 \
  EXPECTED_MIGRATIONS EXPECTED_LATEST_MIGRATION_VERSION
```

## Key Rotation

1. Stop the daemon.
2. Back up the current key and policy store together.
3. Create the new 32-byte key file using mode `0640`, owner `root`, and group
   `wyrelog`.
4. Verify both key specs with `wyctl key status --keyprovider file:PATH`.
5. Rotate the encrypted policy store while the daemon is offline:

   ```sh
   wyctl key rotate \
     --store /var/lib/wyrelog/system/policy.sqlite \
     --from-keyprovider file:/etc/wyrelog/system/policy.key \
     --to-keyprovider file:/etc/wyrelog/system/policy.next.key
   ```

6. Move the new key into the profile's `policy.key` location, run production
   `--check`, then start the daemon.

The rotation command verifies the existing store with the current provider,
rewrites the store with the new provider through the encrypted store atomic
write protocol, and leaves the previous store usable if rotation fails before
the final rename.

The offline `wyctl key rotate` above is packaged-runtime-proven: the rotation
end-to-end suite drives it against a real packaged, encrypted store and asserts
`status=rotated`, that the credential verifier bytes are byte-identical
afterward, and that the sealed Credential Verification Key (CVK) is re-sealed
unchanged so every service credential keeps working across the root change. A
plain readiness probe of a single provider spec, `wyctl key status
--keyprovider file:PATH`, is likewise packaged-proven.

### Interrupted rotation recovery (#364)

KeyProvider root rotation is crash-recoverable, but recovery is **explicit, not
automatic**. A normal single-root store open never auto-recovers an interrupted
rotation; an operator must run the recovery verbs below with both provider roots
available. This crash-recovery classifier and its recovery actions are
**unit/library-proven** (the `policy-store-service-cvk` rotation-recovery cases,
`tests/test-policy-store-service-cvk.c`), not exercised by any packaged e2e
driver — the packaged rotation e2e drives only `key rotate`.

Classify an interrupted rotation with the recovery-status mode (selected by
`--store`):

```sh
wyctl key status \
  --store /var/lib/wyrelog/system/policy.sqlite \
  --from-keyprovider file:/etc/wyrelog/system/policy.key \
  --to-keyprovider file:/etc/wyrelog/system/policy.next.key
# state=<...>  intent-state=<...>  safe-next-action=<none|old|new|...>
# required-roots=<old|new|both>  retire-old-root=<yes|no>  ...
```

The report tells you the recovery `state`, the `intent-state`, the
`safe-next-action`, and which `required-roots` you must have on hand. Perform
the recovery with either spelling of the same verb:

```sh
wyctl key recover \
  --store /var/lib/wyrelog/system/policy.sqlite \
  --from-keyprovider file:/etc/wyrelog/system/policy.key \
  --to-keyprovider file:/etc/wyrelog/system/policy.next.key
# status=recovered store=/var/lib/wyrelog/system/policy.sqlite
```

`wyctl key resume` is an alias for the same recovery. Recovery either resumes an
OLD-root store forward to the intended NEW generation or recognizes an
already-committed NEW result and only completes durable cleanup. If the rotation
state is **AMBIGUOUS** — neither or both roots authenticate — recovery
deliberately **fails closed** without changing any canonical byte and **retains
both roots** for operator investigation (`wyctl: key recovery fail-closed:
ambiguous or contradictory rotation state; both provider roots retained`).

Three statements are authoritative for rotation incidents:

1. **Server rotation is authoritative.** The canonical rename is the
   linearization point of the rotation. There is no rollback after it: once the
   new canonical store is in place, recovery completes forward, it does not
   revert.
2. **Old file bytes may be revoked.** After a *credential* rotation the
   predecessor credential is revoked and its escrow document no longer
   exchanges. Destroy superseded escrow documents; do not keep them as a
   fallback.
3. **Replacement publication is not a distributed transaction.** Server commit
   and local escrow publication are separate steps. A post-commit publication
   failure is recovered through the operation journal, not by rolling back the
   server — see "Publication failure and orphan recovery (#383)".

## Emergency Break-Glass

Break-glass builds must be compiled with audit enabled. Before enabling
the build flag, verify that audit readiness passes and that the emergency
principal and expiry policy are documented for the deployment. Every
override must leave an audit reason code.

## Rollback

Rollback requires the previous package, template identity, policy store,
audit store, and KeyProvider state. Stop the daemon, restore the previous
artifacts, run production `--check`, start the service, and verify
readiness with `wyctl status --readiness`.

## wyrelogd Configuration File

`wyrelogd` accepts a `--config PATH` flag that points at a GLib keyfile
(INI-format) configuration. Every key the file supports has an
equivalent CLI flag; the CLI value wins when both are present, so the
config file fills in the gaps for values that are static for a given
deployment. There is intentionally no GSettings integration on the
daemon side — system services run under systemd or the Windows Service
Manager, where dconf / GSettings has no session bus and per-user
semantics are the wrong granularity. The keyfile + CLI + systemd
`EnvironmentFile=` triplet covers every legitimate daemon-config
shape.

### File Layout

A single `[daemon]` section. Booleans use the GLib `true`/`false`
literals; integers and strings are unquoted.

```ini
[daemon]
profile = system
template_dir = /usr/share/wyrelog/access
policy_db = /var/lib/wyrelog/system/policy.sqlite
policy_keyprovider = systemd-creds:wyrelog-system-policy-key
audit_db = /var/log/wyrelog/system/audit.duckdb
fact_root = /var/lib/wyrelog/system/facts
fact_store_mode = per-tenant-graph
event_spool_dir = /var/lib/wyrelog/system/event-spool
system_url = http://127.0.0.1:8765
listen_port = 8765
event_queue_limit = 1024
production = true
bootstrap_admin_subject = wr.admin
bootstrap_admin_allow_skip_mfa = false
```

### Key Reference

| Key | Type | Equivalent CLI flag | Purpose |
|-----|------|---------------------|---------|
| `profile` | string | `--profile` | `system` or `service`. Selects the profile defaults and the listen-port default (8765 vs 8766). |
| `template_dir` | string | `--template-dir` | Access policy template directory. |
| `policy_db` | string | `--policy-db` | Path to the encrypted policy authority database. |
| `policy_keyprovider` | string | `--policy-keyprovider` | KeyProvider spec for `policy_db`. `systemd-creds:NAME` or `file:PATH`. |
| `audit_db` | string | `--audit-db` | Runtime audit sink database path. |
| `fact_root` | string | `--fact-root` | Root directory for the Datalog fact store. |
| `fact_store_mode` | string | `--fact-store-mode` | Layout mode for the fact store. Currently only `per-tenant-graph`. |
| `operation_root` | string | `--operation-root` | Root directory for the service-credential operation journal (the durable, secret-free intent state described under "Publication failure and orphan recovery"). Opt-in: never auto-defaulted. When set it is created `0700` owner-only and must be disjoint from every other daemon path. |
| `credential_publication_root` | string | `--credential-publication-root` | Owner-only root under which the escrow credential documents (`--destination`) are published. Opt-in: never auto-defaulted. When set it is created `0700` owner-only and must be disjoint from every other daemon path. |
| `event_spool_dir` | string | `--event-spool-dir` | Service-profile disk spool directory. |
| `system_url` | string | `--system-url` | System-profile daemon URL the service-profile daemon forwards events to. |
| `listen_port` | int | `--listen-port` | HTTP listen port. `0` selects an ephemeral port (used by integration tests). |
| `event_queue_limit` | int | `--event-queue-limit` | Maximum pending service-profile spool files. |
| `production` | bool | `--production` | Enables the fail-closed production startup gates. CLI and conf are OR-combined; see "Production Mode Precedence". |
| `bootstrap_admin_subject` | string | `--bootstrap-admin-subject` | Grants the `wr.system_admin` role to this subject on a fresh policy store. One-shot bootstrap aid. |
| `bootstrap_admin_allow_skip_mfa` | bool | `--bootstrap-admin-allow-skip-mfa` | Grants `wr.login.skip_mfa` to the bootstrap admin so it can mint a first bearer token. |

`operation_root` and `credential_publication_root` are the two roots the
escrow service-credential handoff needs. Both are opt-in — a deployment that
leaves them unset simply reports the escrow handoff surface as unavailable and
keeps running. When either is set the daemon creates it `0700` (owner-only) and
validates at startup that it is distinct from — neither equal to nor nested
under — every other configured path (policy DB, audit DB, fact root, service
event spool) and from each other; any overlap fails startup closed. This keeps
a delivered secret or a durable operation journal from ever sharing a directory
with another store.

### Precedence

CLI flags always win. The config file fills in values that the CLI
left unset. There is no second-level merging; if you write a value
in the config file and you also pass `--foo` on the command line,
the CLI value is used as-is (the config-file value is not consulted
even as a fallback for partial overrides).

`/etc/wyrelog/wyrelogd.env` (the systemd `EnvironmentFile=`) carries
process-level environment variables (`WYL_LOG`, `WYL_CONFIG`, etc.),
not daemon-config keys. The two are complementary, not redundant:
the env file controls what the systemd-launched process sees in
its environment; the config file controls what the daemon's option
parser inflates into `WylDaemonOptions`.

### systemd Wiring

The packaged units (`wyrelog-system.service`, `wyrelog-service.service`)
thread the config file through the daemon's `--config` flag and pin
production gating with `--production`:

```ini
[Service]
Environment=WYL_LOG=warn
EnvironmentFile=-/etc/wyrelog/system.env
ExecStart=/usr/bin/wyrelogd --config /etc/wyrelog/wyrelogd.conf --production
ProtectSystem=strict
ReadOnlyPaths=/etc/wyrelog /usr/share/wyrelog
ReadOnlyPaths=/etc/wyrelog/wyrelogd.conf
```

Operator customization should edit `wyrelogd.conf` rather than redefining
the entire `ExecStart`. The `ProtectSystem=strict` and `ReadOnlyPaths=`
lines are the parent-directory defense against attacker-controlled
symlink swaps of `/etc/wyrelog/` itself — drop-ins that override
`ExecStart=` must preserve them.

### Migration Recipe

Example conf files ship under `${datadir}/wyrelog/examples/` (not in
`/etc/`) so the operator must explicitly copy them into place. The
canonical recipe for the system profile:

```sh
sudo install -d -m 0750 -o root -g wyrelog /etc/wyrelog
sudo cp /usr/share/wyrelog/examples/wyrelogd-system.conf.example \
    /etc/wyrelog/wyrelogd.conf
sudo chown root:wyrelog /etc/wyrelog/wyrelogd.conf
sudo chmod 0640 /etc/wyrelog/wyrelogd.conf
sudo systemctl restart wyrelog-system.service
```

Same for the service profile:

```sh
sudo install -d -m 0750 -o root -g wyrelog /etc/wyrelog
sudo cp /usr/share/wyrelog/examples/wyrelogd-service.conf.example \
    /etc/wyrelog/wyrelogd.conf
sudo chown root:wyrelog /etc/wyrelog/wyrelogd.conf
sudo chmod 0640 /etc/wyrelog/wyrelogd.conf
sudo systemctl restart wyrelog-service.service
```

Create the conf file **before** restarting wyrelogd. The shipped
`ExecStart=` passes `--config /etc/wyrelog/wyrelogd.conf`; the daemon
exits nonzero when that path is missing, which then drives the
systemd `Restart=` loop until the file appears. Operators who want a
different path must override `ExecStart=` via a drop-in.

### Conf File Permission Gate

`wyrelogd` opens the conf file through a TOCTOU-safe gate
(`conf_file_open_safely` in `wyrelog/daemon/options.c`) with the
following matrix:

| Condition | `--production` behavior | Non-production behavior |
|-----------|-------------------------|-------------------------|
| `S_IWGRP` or `S_IWOTH` set on conf | refuse to start, error prefix `wyrelogd: conf: refusing` | WARN with prefix `wyrelogd: conf:` (no "refusing"), continue |
| Symlink at conf path (`O_NOFOLLOW` -> `ELOOP`) | refuse to start | refuse to start |
| Conf is not a regular file (FIFO, char device) | refuse to start | refuse to start |
| Conf size > 64 KiB (`WYL_DAEMON_CONF_MAX_BYTES` in `wyrelog/daemon/options.c`) | refuse to start | refuse to start |
| I/O error during read | refuse to start | refuse to start |

Required posture: `0640 root:wyrelog`. The size cap and S_ISREG check
are hard failures regardless of `--production`. The mode check is the
only condition that downgrades to WARN outside production so dev
workflows are not broken; production deployments always reject loose
modes.

**Defense-in-depth caveat.** `O_NOFOLLOW` guards only the final path
component. A compromised packaging step that makes `/etc/wyrelog`
itself a symlink to attacker-controlled space is NOT caught by the
daemon gate alone. The packaged unit's `ProtectSystem=strict` and
`ReadOnlyPaths=/etc/wyrelog` lines provide the parent-directory
defense — preserve them in any custom drop-in.

### Production Mode Precedence

`--production` and the `production` conf key are NOT mutually
exclusive. The effective production mode is:

```
production_mode = (CLI --production) OR (conf [daemon] production = true)
```

Either source can promote the daemon into fail-closed production
mode. The conf path is wired in `wyrelog/daemon/options.c:179-184`:
when the CLI did not set `--production`, the loader reads the
boolean `production` key from the `[daemon]` section via
`g_key_file_get_boolean`. This is logical-OR, not "CLI overrides".

Operationally:

- **Explicit production boot** (current packaged default):
  pass `--production` on the unit's `ExecStart=`. Visible in
  `systemctl status` output, auditable via `journalctl`, and
  cannot be inadvertently softened by an unrelated conf edit.
- **Explicit non-production boot**: BOTH gates must be off.
  Drop `--production` from `ExecStart=` (via a drop-in) AND ensure
  the conf either omits `production=` entirely or sets
  `production=false`. Leaving `production=true` in the conf will
  re-enable fail-closed mode even when the CLI flag is absent.

Why the CLI flag is the preferred surface despite the OR-merge:
its presence is greppable in `systemctl status` and journal logs,
giving operators a single visible witness for boot intent. The
conf key exists for completeness but is the easier surface for a
conf-write attacker to flip in either direction:

- Attacker with conf-write can pin `production=true` invisibly; an
  operator following a "drop `--production` for dev WARN-downgrade"
  recipe then gets unexpected fail-closed mode.
- Conversely, a non-production host that inherits a conf with
  `production=false` (or, equivalently, the key absent and CLI flag
  absent) silently runs without fail-closed gates.

The packaged unit keeps `--production` on `ExecStart=` for that
visibility reason; do not remove it from `ExecStart=` without
auditing the conf as well.

### Diagnostic / Query Flags (Not Config-Eligible)

The following CLI flags cannot be expressed in the conf file. They
exit the daemon after printing, so they have no startup steady-state
to configure:

- `--check` — load policy templates and exit. Used by package
  pre-/post-install hooks and human dry-runs.
- `--version` — print the wyrelog version string and exit.
- `--template-version` — print the access template version and exit.
- `--template-info` — print the access template artifact identity
  (signature, hash, timestamps) and exit.
- `--profile-info` — print the resolved daemon profile configuration
  (the value of every `WylDaemonOptions` field after merging CLI, conf,
  and defaults) and exit. Also runs the bootstrap-key staleness probe
  described below.
- `--config PATH` — the path to the conf file itself. The path of the
  conf is necessarily a CLI argument.

### Bootstrap-Key Staleness WARN

When `--profile-info` runs against a conf that still carries
`bootstrap_admin_subject` or `bootstrap_admin_allow_skip_mfa=true`,
`wyrelogd` probes the policy store for any subject row
(`maybe_warn_stale_bootstrap_key` and `policy_store_probe_subjects`
in `wyrelog/daemon/wyrelogd.c`) and emits one of two greppable lines
to stderr:

```
wyrelogd: bootstrap_admin: stale-key subject=<id> allow_skip_mfa=<bool> (...)
```

emitted when the probe confirms at least one subject row exists.
The greppable stable prefix is `wyrelogd: bootstrap_admin: stale-key
subject=` — operators should anchor scripts on that token, not on
the parenthetical hint. The hint itself takes one of two concrete
shapes depending on which bootstrap keys are present:

When only `bootstrap_admin_subject` is set in the conf:

```
... (remove bootstrap_admin_subject from /etc/wyrelog/wyrelogd.conf and restart)
```

When both `bootstrap_admin_subject` and
`bootstrap_admin_allow_skip_mfa` are set:

```
... (remove bootstrap_admin_subject and bootstrap_admin_allow_skip_mfa from /etc/wyrelog/wyrelogd.conf and restart)
```

And:

```
wyrelogd: bootstrap_admin: indeterminate subject=<sanitized> allow_skip_mfa=<bool> (policy store unreadable: <reason>) -- cannot confirm bootstrap key is fresh
```

emitted when the probe cannot authoritatively answer (path unset,
sqlite open failure, schema missing, step error). The `indeterminate`
line exists so an attacker who can write the conf cannot silence the
staleness signal by also corrupting the policy store — operators get
a different greppable token instead of silence.

The subject string is sanitized through a dmesg-style hex-escape
(non-printable bytes rendered as `\xNN`) before stderr emission. The
conf file is exactly the write surface an attacker would use to plant
ANSI/CSI/OSC escape sequences; piping it verbatim through stderr at
onboarding time would let the attacker spoof terminal output.

Migration practice: delete the `bootstrap_admin_*` keys from
`/etc/wyrelog/wyrelogd.conf` after first successful boot. The
shipped example confs leave both keys commented out for exactly this
reason.

The stable greppable token discipline (anchor scripts on
`wyrelogd: bootstrap_admin: stale-key subject=` rather than on the
parenthetical remediation hint) mirrors the lesson from #331
commit 7 — false runbook claims about message wording got caught
as BLOCKERs during review there, so this runbook commits to the
stable prefix as the authoritative interface.

### Log Verbosity Is an Env Variable

There is no `log_level=` conf key. Operators set log verbosity via
the systemd unit's `Environment=` (or a drop-in). The grammar
(`wyl_log_internal_parse_spec` in `wyrelog/wyl-log.c`) is:

```
SECTION:LEVEL[,SECTION:LEVEL...]
```

Bare-level strings like `WYL_LOG=info` are **silently dropped** at
the `g_strv_length(parts) != 2` continue in `wyl-log.c:92` — they
match no section and never raise any threshold. Two correct forms:

```ini
[Service]
# Section-specific: raise boot to info, leave policy at warn
Environment=WYL_LOG=boot:info,policy:warn
```

```ini
[Service]
# Wildcard: apply one level to every section
Environment=WYL_LOG=*:info
```

Valid section tokens (case-insensitive): `boot`, `policy`, `session`,
`decision`, `audit`, `io`, `general`, plus the wildcard `*`. Valid
levels: `none`, `error`, `warn`, `info`, `debug`, `trace`. Unknown
sections are silently ignored (an operator typo must not destabilise
the daemon; documented in the K4 design note in `wyl-log.c`).

Note: the packaged unit ships `Environment=WYL_LOG=warn`. By the
grammar above this is a **no-op** — it parses to zero entries and
leaves every section at the compile-time default (which happens to
be `WARN`, set in `wyl_log_internal_parse_spec`). The value is
preserved as an explicit-intent marker and to keep the line slot
available for forward-compatible grammar extensions; operators
should not interpret its presence as evidence that any level is
actually being enforced.

### Fact-Store Defaults

`fact_root` and `fact_store_mode` are valid conf keys, but the
shipped example confs do **not** set them. The daemon defaults apply
when the keys are absent:

- `fact_root` defaults to `/var/lib/wyrelog/system/facts` (system
  profile) or `/var/lib/wyrelog/service/facts` (service profile).
- `fact_store_mode` defaults to `per-tenant-graph`.

Operators may add explicit values to the conf if they need
non-default paths or a future store layout.

### Why No GSettings on the Daemon

The wyctl client uses GSettings (see the next section) because it
runs in an operator's interactive session where dconf is available
and per-user defaults are the right granularity. The daemon faces
the opposite constraints:

- System services usually have no D-Bus session bus, so the default
  dconf backend would fail-soft to "no defaults" anyway.
- Daemon config is a deployment-level concern that wants
  configuration-management tooling (Ansible, Puppet, NixOS, Chef) to
  control. Those tools manage files in `/etc`, not dconf databases.
- The same dconf store is operator-writable by design. Trusting it
  for daemon startup would let a compromised operator session pivot
  to changing daemon behaviour on the next restart.

These trade-offs make GKeyFile + `/etc/wyrelog/wyrelogd.conf` the
right surface for `wyrelogd`. The wyctl GSettings layer below is
deliberately *not* shared with the daemon — the audit trail and the
threat model both prefer the explicit separation.

## wyctl Configuration and Token-File Safety

`wyctl` reads operator-static defaults from GSettings so common flags do
not need to be repeated on every invocation, while bearer-token bytes are
loaded only from a protected on-disk token file. Explicit CLI flags always
override GSettings. The GSettings store records only the *path* to the
token file; the bytes themselves never live in dconf, the keyfile backend,
or any other GSettings backing store. The same path-only / spec-only
discipline applies to the MFA defaults: `default-policy-store` records
the policy-store path, and `default-keyprovider` records the KeyProvider
*spec string* (e.g. `file:/etc/wyrelog/policy.key`,
`systemd-creds:wyrelog-policy`). The KeyProvider key material, the TOTP
seed bytes, and the policy-store contents never live in GSettings.

Daemon defaults live in `/etc/wyrelog/wyrelogd.conf` (see the previous
section) — wyctl and wyrelogd intentionally do **not** share a single
GSettings tree. The same value (e.g. `tenant`) lives in two places by
design because each surface answers a different question: the daemon
config decides what tenants the daemon will service, the wyctl
defaults decide which tenant the operator at this workstation routes
their CLI calls to. Keeping the two explicit makes audit-trail review
honest about which surface acted.

### Schema Overview

- Schema id: `org.wyrelog.wyctl`
- Schema path: `/org/wyrelog/wyctl/`
- Install location: `${datadir}/glib-2.0/schemas/org.wyrelog.wyctl.gschema.xml`
- After install the package runs `glib-compile-schemas` against the
  schemas directory to refresh `gschemas.compiled`. Manual installs that
  copy the schema in place must run `glib-compile-schemas
  ${datadir}/glib-2.0/schemas` afterwards or wyctl will silently fall
  back to CLI-only mode.

### Key Reference

| Key | Type | Default | Purpose |
|-----|------|---------|---------|
| `daemon-url` | `s` | `""` | URL of `wyrelogd` when `--daemon-url` is omitted. Empty = "no default; CLI must supply." |
| `default-tenant` | `s` | `""` | Tenant id used when `--tenant` is omitted (same empty-is-unset convention). |
| `default-graph` | `s` | `""` | Graph id used when `--graph` is omitted. |
| `access-token-file` | `s` | `""` | Filesystem path to the bearer token file used when `--access-token-file` is omitted. Path only. |
| `default-timeout-ms` | `u` | `2000` | Request timeout in milliseconds used when `--timeout-ms` is omitted. Re-validated by wyctl's CLI parser (`1..60000`). |
| `default-guard-loc-class` | `s` | `""` | Location class used when `--guard-loc-class` is omitted. |
| `default-guard-risk` | `i` | `-1` | Risk score (0..100) used when `--guard-risk` is omitted. `-1` is the "unset" sentinel because `0` is a real risk score. |
| `default-guard-timestamp-mode` | `s` | `"none"` | Strategy for filling `--guard-timestamp` when omitted. `"none"` preserves the historical "must be supplied" behaviour; `"now"` is reserved for a future commit that fills the current wall-clock time. |
| `default-policy-store` | `s` | `""` | Backs offline `--store` for daemon-stopped `wyctl mfa enroll|reset` maintenance or recovery. Empty = "no default; CLI must supply." |
| `default-keyprovider` | `s` | `""` | Backs offline `--keyprovider` for daemon-stopped `wyctl mfa enroll|reset` maintenance or recovery. Empty = "no default; CLI must supply." |

Example: configure the operator workstation once and let every wyctl
invocation pick up the defaults.

```sh
gsettings set org.wyrelog.wyctl daemon-url 'http://127.0.0.1:8765'
gsettings set org.wyrelog.wyctl default-tenant 'system'
gsettings set org.wyrelog.wyctl default-graph 'production'
gsettings set org.wyrelog.wyctl access-token-file "$HOME/.config/wyrelog/access-token"
gsettings set org.wyrelog.wyctl default-timeout-ms 5000
```

### Precedence Rule

For every flag covered above, the resolved value is the first non-empty
of:

1. **CLI flag** (`--daemon-url X`). An empty-string CLI value
   (`--daemon-url ""`) is treated as a deliberate operator value, not
   as absence, and falls into the existing per-flag validation paths.
2. **GSettings value** for the corresponding schema key. The schema's
   empty-string defaults encode "unset" — wyctl never fabricates a
   default URL or tenant from those.
3. **Unset** — the existing per-flag "missing" diagnostic fires
   (`wyctl: missing daemon URL`, `wyctl: missing --tenant`, etc.).

The offline, daemon-stopped forms of `wyctl mfa enroll` and
`wyctl mfa reset` participate in the same resolver pipeline: `--store` falls back to `default-policy-store`
and `--keyprovider` falls back to `default-keyprovider` under the same
precedence rule (CLI > GSettings > missing-flag diagnostic). The
`WYCTL_DISABLE_GSETTINGS=1` kill switch documented below disables the
fallback uniformly across all wyctl subcommands, mfa included.

### Kill Switch: `WYCTL_DISABLE_GSETTINGS`

Set `WYCTL_DISABLE_GSETTINGS=1` (the **literal string `1`** — `true`,
`yes`, `on` are not honoured) to skip the GSettings lookup entirely.
Useful for:

- CI containers without a dconf daemon.
- Reproducible CLI-only runs in incident-response workflows.
- Bisecting a misconfigured operator workstation.

With the kill switch set, wyctl behaves exactly as the pre-GSettings
build did: every flag is sourced from `argv` or the per-flag missing
diagnostic fires.

### Token-File Permission Requirements (POSIX)

Before any daemon request is sent, `wyctl` opens the access-token file
with `open(O_NOFOLLOW | O_CLOEXEC | O_RDONLY | O_NOCTTY)` and applies
the following checks on the resulting file descriptor (no second
path-based syscall is issued, so the safety check has no TOCTOU window
between stat and read):

1. **Regular file** — directories, devices, sockets, FIFOs are
   rejected with `wyctl: access token file is not a regular file: <path>`.
2. **Owned by the invoking user** (`st.st_uid == geteuid()`) — rejected
   with `wyctl: access token file not owned by current user: <path>`.
3. **No group/other permission bits** — the mask
   `(S_IRWXG | S_IRWXO)` must be zero. `0600` and `0400` are accepted;
   `0640`, `0604`, `0660`, etc. are rejected with
   `wyctl: access token file permissions too broad (require 0600): <path>`.
4. **Not a terminal symlink** — `O_NOFOLLOW` refuses the open and
   reports `wyctl: access token file is a symlink (refusing to follow): <path>`.
5. **Bounded read** — the token must be 65,536 bytes or less. Larger
   files fail with `wyctl: access token file too large: <path>`.

The check is the chokepoint every subcommand reaches before any
`wyl_client_*` HTTP call. Operators who see a token-file diagnostic
can be confident the daemon was never contacted.

#### Intermediate-Path Symlinks (Scope Statement)

`O_NOFOLLOW` only refuses a terminal symlink. Intermediate path
components are still resolved normally, so a setup where a parent
directory is itself a symlink — or where a non-owner can write to a
parent directory and substitute one — falls outside the safety
guarantee. **Every directory on the path to the token file must be
owned by the invoking user and not group/world-writable.** A typical
safe layout is `~/.config/wyrelog/access-token` where `~/.config` is
already operator-owned with the standard `0700` mode.

Closing the intermediate-component window would require
Linux-only `openat2(RESOLVE_BENEATH)`. That is explicitly out of scope
for the GA hardening pass.

### Token-File Permission Requirements (Windows)

On Windows wyctl applies a smaller but still fail-closed check:

1. `FILE_ATTRIBUTE_REPARSE_POINT` must NOT be set on the file — that
   covers symbolic links, directory junctions, and any third-party
   reparse target. Rejected with
   `wyctl: access token file is a symlink (refusing to follow): <path>`.
2. `FILE_ATTRIBUTE_READONLY` must be set — operators mark the file
   read-only via `attrib +R <path>` to opt into the check. Rejected
   with `wyctl: access token file not marked read-only: <path>`.

Full ACL validation is reserved for a future hardening pass; the
diagnostic `wyctl: access token file ACL validation unavailable: <path>`
is allocated for that landing and is **not emitted** by the current
binary.

### Diagnostic Message Catalog

When the token-file safety check refuses the file, exactly one of the
following lines is written to stderr. Each diagnostic is greppable as
a literal substring so operator tooling can route automatically.

| Failure | Diagnostic (stderr) |
|---------|--------------------|
| Missing path or `--access-token-file=""` | `wyctl: missing --access-token-file` |
| File not found | `wyctl: access token file not found: <path>` |
| Terminal symlink (POSIX) or reparse point (Windows) | `wyctl: access token file is a symlink (refusing to follow): <path>` |
| Non-regular file (FIFO, device, socket, directory) | `wyctl: access token file is not a regular file: <path>` |
| Owned by another user | `wyctl: access token file not owned by current user: <path>` |
| Group or other permission bits set | `wyctl: access token file permissions too broad (require 0600): <path>` |
| Read failed for another reason | `wyctl: unable to read access token file: <path>` |
| File is zero bytes | `wyctl: empty access token file: <path>` |
| File contains an embedded NUL or fails normalization | `wyctl: invalid access token file: <path>` |
| File exceeds the 64 KiB cap | `wyctl: access token file too large: <path>` |
| Read-only attribute missing (Windows) | `wyctl: access token file not marked read-only: <path>` |

For each failure the process exits with status `2` and **no HTTP
request is sent** to the daemon — the contract is enforced by both
unit tests and end-to-end integration tests that assert the absence
of `daemon unavailable` / `<op> failed` diagnostics under unsafe
token configurations.

### Operator Setup Recipe (POSIX)

```sh
# Create the per-user wyrelog config directory.
install -d -m 0700 "$HOME/.config/wyrelog"

# Write the bearer token. Use install + redirect rather than echo
# to avoid the token landing in shell history.
install -m 0600 /dev/null "$HOME/.config/wyrelog/access-token"
printf '%s' "$WYRELOG_TOKEN" > "$HOME/.config/wyrelog/access-token"

# Point GSettings at the file.
gsettings set org.wyrelog.wyctl access-token-file \
  "$HOME/.config/wyrelog/access-token"

# Verify wyctl can read it.
wyctl status

# Remove the env var so the token is no longer in memory.
unset WYRELOG_TOKEN
```

### Operator Setup Recipe (Windows)

```pwsh
$WyrelogDir = "$Env:USERPROFILE\.config\wyrelog"
New-Item -ItemType Directory -Force -Path $WyrelogDir | Out-Null

# Write the bearer token (PowerShell will not echo it back).
Set-Content -Path "$WyrelogDir\access-token" -Value $Env:WYRELOG_TOKEN -NoNewline

# Mark the file read-only — required by the Windows safety check.
attrib +R "$WyrelogDir\access-token"

# Point GSettings at the file.
gsettings set org.wyrelog.wyctl access-token-file "$WyrelogDir\access-token"

# Verify wyctl can read it.
wyctl status

# Remove the env var so the token is no longer in memory.
Remove-Item Env:WYRELOG_TOKEN
```
