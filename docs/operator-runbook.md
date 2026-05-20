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
read access to the policy store and the KeyProvider:

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

Use the same command for every subsequent admin. The bootstrap
auto-revoke branch is skipped silently for subjects that do not hold
`wr.login.skip_mfa`:

```sh
wyctl mfa enroll \
  --subject bob \
  --store /var/lib/wyrelog/system/policy.sqlite \
  --keyprovider file:/etc/wyrelog/system/policy.key
```

The subject must already exist as a principal in the policy store
(typically through `wyctl policy role-grant`). Enrollment does not
create principals — it only attaches a TOTP factor to one.

### Setting defaults via GSettings

Operators who enroll multiple subjects against the same policy store and
KeyProvider can stop repeating `--store` and `--keyprovider` on every
invocation by setting the two GSettings keys once:

```sh
gsettings set org.wyrelog.wyctl default-policy-store /var/lib/wyrelog/policy.sqlite
gsettings set org.wyrelog.wyctl default-keyprovider systemd-creds:wyrelog-policy
```

After this, `sudo wyctl mfa enroll --subject alice` (no `--store`, no
`--keyprovider`) resolves both paths from GSettings. `--subject` is
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
| `event_spool_dir` | string | `--event-spool-dir` | Service-profile disk spool directory. |
| `system_url` | string | `--system-url` | System-profile daemon URL the service-profile daemon forwards events to. |
| `listen_port` | int | `--listen-port` | HTTP listen port. `0` selects an ephemeral port (used by integration tests). |
| `event_queue_limit` | int | `--event-queue-limit` | Maximum pending service-profile spool files. |
| `production` | bool | `--production` | Enables the fail-closed production startup gates. |
| `bootstrap_admin_subject` | string | `--bootstrap-admin-subject` | Grants the `wr.system_admin` role to this subject on a fresh policy store. One-shot bootstrap aid. |
| `bootstrap_admin_allow_skip_mfa` | bool | `--bootstrap-admin-allow-skip-mfa` | Grants `wr.login.skip_mfa` to the bootstrap admin so it can mint a first bearer token. |

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

A typical service unit threads the config file through the daemon's
`--config` flag:

```ini
[Service]
EnvironmentFile=/etc/wyrelog/wyrelogd.env
ExecStart=/usr/bin/wyrelogd --config /etc/wyrelog/wyrelogd.conf --production
```

The packaged unit ships with this shape; operator customization should
edit `wyrelogd.conf` rather than redefining the entire `ExecStart`.

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
| `default-policy-store` | `s` | `""` | Backs `--store` for `wyctl mfa enroll|reset`. Policy-store path (SQLite file). Empty = "no default; CLI must supply." |
| `default-keyprovider` | `s` | `""` | Backs `--keyprovider` for `wyctl mfa enroll|reset`. KeyProvider spec (e.g. `file:/etc/wyrelog/policy.key`). Empty = "no default; CLI must supply." |

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

The `wyctl mfa enroll` and `wyctl mfa reset` subcommands participate in
the same resolver pipeline: `--store` falls back to `default-policy-store`
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
