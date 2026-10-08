# Wyrelog Operator Runbook

This runbook closes the supported Linux production path for a packaged
Wyrelog application service deployment. It assumes the package installs
`wyrelogd`, `wyctl`, the access-control template tree, and the systemd
support files from `packaging/`.

## HTTP request body limits

The local daemon bounds request bodies before authentication. Append, retract,
and schema registration accept at most 1 MiB; Datalog queries and service-token
exchange accept 16 KiB; fact forget, MFA enrollment, service-principal creation,
credential issue/rotation and operation recovery/reconciliation accept 4 KiB.
Profile events, tenant sealing, principal disabling and credential revocation
accept 1 KiB. Other routes have a 1 MiB transport ceiling.

An oversized declared Content-Length is rejected before reading the body.
Chunked requests are rejected as soon as received bytes exceed the limit,
without waiting for the final chunk. The response is HTTP 413 with
`{"error":"request_body_too_large"}`, a server-generated
`X-Wyrelog-Request-Id`, and `Connection: close`. Malformed bodies within the
limit retain the endpoint's normal validation response. If the peer cannot
receive the error or the socket write fails, the daemon closes the connection
without waiting; clients may then observe a transport error instead of 413.
An eager upload can also cause a TCP reset when the connection closes with
unread inbound data, even after the error was written. Clients that need the
early HTTP response should use `Expect: 100-continue` and wait before uploading.

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

## Linux Runtime Dependencies and Product Install

The Linux release package profile is verified by
`tools/stage-product-install.py` against a fresh `DESTDIR`. Configure it with
`-Dproduct_install=true` and force the pinned Wirelog and libchronoid
fallbacks. The staging helper runs `meson install` and prunes only the
developer artifacts listed in `packaging/linux-product-install.json`, then
checks the final tree and ELF runtime closure. This preserves the runtime
shared libraries while omitting subproject headers, static archives,
pkg-config files, man pages, and developer CLIs. Do not use
`--skip-subprojects`: the product uses the installed Wirelog, nanoarrow,
xxhash, and libchronoid shared libraries at runtime.

Packagers must also provide the external DuckDB runtime library
`libduckdb.so` at exactly version 1.5.5. The Meson prebuilt dependency is pinned
to the upstream v1.5.5 Linux archive; the installed product does not vendor
DuckDB. The libchronoid 1.2.0 shared library is installed from the pinned
fallback. Standard system runtime dependencies include GLib/GIO, libsoup 3,
libsodium, SQLite, the C runtime, and (when TPM is enabled) tss2-esys. Package
metadata must declare these runtime requirements; a successful build or an
`ldd` resolution against the build host is not evidence that the package is
self-contained.

CI configures the canonical product profile with every release-sensitive
option explicit, builds the daemon and CLI, installs into an empty staging
directory with the staging helper, and checks every staged ELF
dependency against the staged library set or the explicit external/system
allowlists. For external DuckDB, it checks the version reported by the exact
pinned build artifact as well as the subproject version and wrap hash; it does
not treat runner-wide library resolution as proof of package runtime closure.
The check also verifies the product path manifest, required template/service
assets, and symlink containment.

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

Run these commands as root for a clean installation. For an existing deployment,
use [Migration Recipe](#migration-recipe) and preserve existing keys and settings.

1. Install the package and create managed users/directories:

   ```sh
   systemd-sysusers /usr/lib/sysusers.d/wyrelog.conf
   systemd-tmpfiles --create /usr/lib/tmpfiles.d/wyrelog.conf
   ```

2. Install a separate configuration for each profile, as `root:wyrelog 0640`:

   ```sh
   test ! -e /etc/wyrelog/system.conf && \
     install -m 0640 -o root -g wyrelog \
       /usr/share/wyrelog/examples/wyrelogd-system.conf.example \
       /etc/wyrelog/system.conf
   test ! -e /etc/wyrelog/service.conf && \
     install -m 0640 -o root -g wyrelog \
       /usr/share/wyrelog/examples/wyrelogd-service.conf.example \
       /etc/wyrelog/service.conf
   ```

   If either destination already exists, stop and follow the migration recipe.
   Review both files before starting either unit. Keep their profiles, stores,
   credentials, and listener ports separate: system uses port 8765 and service
   uses port 8766.

3. Create a distinct production KeyProvider root for each profile. This
   refuses to replace an existing key. The units pass the files through
   `LoadCredential=` as `wyrelog-system-policy-key` and
   `wyrelog-service-policy-key`, respectively:

   ```sh
   python3 - <<'PY_KEYS'
import os
for profile in ("system", "service"):
    path = f"/etc/wyrelog/{profile}/policy.key"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    with os.fdopen(fd, "wb") as key:
        key.write(os.urandom(32))
PY_KEYS
   chown root:wyrelog /etc/wyrelog/system/policy.key /etc/wyrelog/service/policy.key
   chmod 0640 /etc/wyrelog/system/policy.key /etc/wyrelog/service/policy.key
   ```

4. Validate both installed configurations before starting the daemons. Outside
   systemd, override only the credential provider with the corresponding key
   file because `LoadCredential=` has not populated a credentials directory:

   ```sh
   wyrelogd --config /etc/wyrelog/system.conf --production \
     --policy-keyprovider file:/etc/wyrelog/system/policy.key --check
   wyrelogd --config /etc/wyrelog/service.conf --production \
     --policy-keyprovider file:/etc/wyrelog/service/policy.key --check
   wyrelogd --template-info --template-dir /usr/share/wyrelog/access
   wyctl key status --keyprovider /etc/wyrelog/system/policy.key
   ```

   If you customized a key location, use that location for the check and the
   unit's `LoadCredential=`. Stop and correct any failed check before continuing.

5. Start and verify both profiles. The legacy `wyrelog.service` is mutually
   exclusive with the profile units and must stay disabled:

   ```sh
   systemctl daemon-reload
   systemctl disable --now wyrelog.service
   systemctl enable --now wyrelog-system.service wyrelog-service.service
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
  `wr.system_admin` role member on tenant `__wr_default`.
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
  --access-token-file /run/wyrelog/auditor.token \
  --guard-timestamp "$(date +%s)" \
  --guard-loc-class trusted --guard-risk 29
```

Audit queries require a separately provisioned, MFA-authenticated auditor;
the `wr.system_admin` operator token is deliberately not allowed to read the
audit stream. See [Day-2 Operations](#day-2-operations) before using this check.

Once `alice` has rotated to an IdP-issued bearer, drop the
`--bootstrap-admin-allow-skip-mfa` flag from the drop-in and run
`systemctl daemon-reload && systemctl restart wyrelog-system.service`.
The marker and the existing role membership remain in place. The
persisted `wr.login.skip_mfa` direct-permission grant is **not**
removed by dropping the flag and must be revoked explicitly as
described under "Revoking bootstrap MFA bypass" below.

### Obtain the bootstrap token

The bootstrap flags grant the role; they do not create an access-token file.
For the built-in first-install path, `--bootstrap-admin-allow-skip-mfa` lets
the bootstrap subject obtain a temporary bearer before TOTP enrollment. After
the service is running, create the token file with restrictive permissions:

```sh
umask 077
python3 - /run/wyrelog/bootstrap.token <<'PY'
import json
import os
import sys
import urllib.request

token_path = sys.argv[1]
url = ("http://127.0.0.1:8765/auth/login?username=alice"
       "&tenant=__wr_default&skip_mfa=true")
request = urllib.request.Request(url, method="POST")
with urllib.request.urlopen(request) as response:
    token = json.load(response)["access_token"]
fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    output.write(token + "\n")
PY
```

Use this temporary token only to enroll the bootstrap administrator's TOTP
factor. Successful enrollment revokes the skip-MFA permission. Then perform a
fresh normal login, verify the TOTP code, and replace the token file with the
new MFA-assured access token before arming permissions or running guarded
operator commands. The [Datalog product flow](#datalog-product-flow) contains
the complete login, verification, and token-file replacement example. The
actual default tenant identifier is `__wr_default` (not `default`). Verify
the bootstrap audit record only after replacing the temporary token with the
MFA-assured token.

### Windows / Service

Pass the flags through `sc.exe config` so the service binary path
carries them as arguments:

```powershell
sc.exe config wyrelog binPath= "\"C:\Program Files\Wyrelog\wyrelogd.exe\" --profile system --template-dir \"C:\ProgramData\Wyrelog\access\" --policy-db \"C:\ProgramData\Wyrelog\system\policy.sqlite\" --policy-keyprovider file:\"C:\ProgramData\Wyrelog\system\policy.key\" --audit-db \"C:\ProgramData\Wyrelog\system\audit.duckdb\" --production --bootstrap-admin-subject=alice --bootstrap-admin-allow-skip-mfa"
sc.exe stop wyrelog
sc.exe start wyrelog
```

After the daemon starts, obtain the temporary bootstrap token and protect its
file before writing the secret:

```powershell
$loginUrl = "http://127.0.0.1:8765/auth/login?username=alice&tenant=__wr_default&skip_mfa=true"
$login = Invoke-RestMethod -Method Post -Uri $loginUrl
$tokenPath = "C:\ProgramData\Wyrelog\bootstrap.token"
New-Item -ItemType File -Path $tokenPath | Out-Null
icacls $tokenPath /inheritance:r /grant:r "$($env:USERNAME):(R,W)" "SYSTEM:(F)"
[IO.File]::WriteAllText($tokenPath, $login.access_token + "`n", [Text.Encoding]::ASCII)
```

Use this token only to enroll TOTP. Then repeat the normal `/auth/login` and
`/auth/mfa/verify` flow and replace the file with the newly issued
MFA-assured access token before guarded permission transitions.

After provisioning a separate MFA-authenticated auditor at `__wr_default` as
described under [Day-2 Operations](#day-2-operations),
verify through `wyctl.exe` with the auditor's token (not the system operator's):

```powershell
wyctl.exe --daemon-url http://127.0.0.1:8765 audit query `
  --filter "action=bootstrap_admin_apply" `
  --access-token-file "C:\ProgramData\Wyrelog\auditor.token" `
  --guard-timestamp "$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())" `
  --guard-loc-class trusted --guard-risk 29
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
explicitly once the operator has rotated to an IdP-issued bearer. The revoke is
authorized at `__wr_default`: the token must belong to an MFA-assured system
administrator holding an armed `wr.policy.write` there, even though the grant
itself lives at `login`. The bypass cannot be granted again after bootstrap; a
grant at `login` is refused with `policy_denied`.

```sh
wyctl --daemon-url http://127.0.0.1:8765 policy permission-revoke \
    --subject <bootstrap-subject> \
    --perm wr.login.skip_mfa \
    --scope login \
    --access-token-file /run/wyrelog/operator.token \
    --guard-timestamp "$(date +%s)" \
    --guard-loc-class trusted \
    --guard-risk 10
```

Verify the revoke landed by inspecting the audit trail or the
decision-trace tool:

```sh
wyctl --daemon-url http://127.0.0.1:8765 audit query \
  --filter 'action=permission_revoke' --limit 10 \
  --access-token-file /run/wyrelog/auditor.token \
  --guard-timestamp "$(date +%s)" \
  --guard-loc-class trusted --guard-risk 29
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

At this point `alice` can request an MFA-bypassed login because the bootstrap
flag installed the `wr.login.skip_mfa` direct permission. Create protected
access and refresh token files, then enroll `alice`'s TOTP factor:

```sh
wyctl --daemon-url "$BASE_URL" auth login \
  --subject alice --tenant __wr_default --skip-mfa \
  --token-output /run/wyrelog/bootstrap.token \
  --refresh-token-output /run/wyrelog/bootstrap.refresh
```

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

Both requests are bounded by `--timeout-ms` (or `default-timeout-ms`). When
one gets no answer in time, or the connection fails, wyctl exits 1 and says
what to do:

- **No answer to the start request** (`no enrollment secret was received`).
  At most a pending challenge was created, and nothing was written. Re-run
  the same command; the new challenge replaces the old one for this session,
  and an unconfirmed challenge expires on its own.
- **No answer to the confirmation** (`the enrollment outcome is unknown`).
  The daemon may have enrolled the factor from this run. Keep this run's
  authenticator entry and re-run the same command, adding the new secret as
  a second entry to get a code. If the confirmation is refused with
  `HTTP 409` and `mfa_already_enrolled`, the first run's factor is enrolled:
  delete the new entry and keep the first. If it prints `status=enrolled`,
  the first run did not enroll: delete the first entry and keep the new one.

A refusal the daemon did answer, such as a wrong code, changes nothing and
carries no such line; re-run the command.

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

The subject must already have an authoritative policy identity: a role
membership created through `wyctl policy role-grant`, or a direct permission
granted through `wyctl policy permission-grant`. A subject with neither is
refused with `mfa_enroll_subject_not_found`, and service principals (`svc:`)
are never enrollable. A login attempt does not count: `/auth/login` accepts any
username without authentication, so a subject that has only logged in is still
refused. Enrollment does not grant roles or permissions; it only
attaches a TOTP factor.

### Deactivating a User

There is no user record to delete and no `wyctl` command that disables a human
subject. A user's authority is the set of role memberships and direct
permissions held by the subject, so deactivation means taking each of them
away. Run every step with an MFA-assured administrator token.

1. Establish what the subject holds. Neither `wyctl` nor the daemon lists a
   subject's roles or direct permissions, and the audit trail does not record
   who received a grant: a `role_grant` or `permission_grant` event stores the
   granting administrator in `subject_id`, the scope in `resource_id` and the
   role or permission in `deny_origin`. Keep your own record of grants;
   deactivation can only revoke what you can name.

2. Disarm each permission you armed for the subject. Revoking a grant does not
   clear its armed state, so if the same grant is made again later it is
   immediately effective, without the MFA-assured arming step. Disarming first
   means a later re-grant stays dormant until it is armed again:

   ```sh
   wyctl --daemon-url http://127.0.0.1:8765 policy permission-transition \
     --subject bob --perm wr.datalog.query --scope acme --event revoke \
     --access-token-file /run/wyrelog/admin.token \
     --guard-timestamp "$(date +%s)" \
     --guard-loc-class trusted --guard-risk 29
   ```

   Exit status 3 with `invalid_policy_mutation` means the permission was not
   armed at that scope; continue. This step does not apply to the
   guard-catalogue permissions, such as `wr.audit.read` and `wr.sys.admin`:
   they have no armed state, the daemon refuses to arm or disarm them (exit
   3, `permission_not_armable`), and only revoking the role that carries one
   withdraws it.

3. Revoke every role membership and every direct permission, including
   `wr.login.skip_mfa` if the subject still holds it (see "Revoking bootstrap
   MFA bypass"):

   ```sh
   wyctl --daemon-url http://127.0.0.1:8765 policy role-revoke \
     --subject bob --role wr.viewer --scope acme \
     --access-token-file /run/wyrelog/admin.token \
     --guard-timestamp "$(date +%s)" \
     --guard-loc-class trusted --guard-risk 29
   wyctl --daemon-url http://127.0.0.1:8765 policy permission-revoke \
     --subject bob --perm wr.datalog.query --scope acme \
     --access-token-file /run/wyrelog/admin.token \
     --guard-timestamp "$(date +%s)" \
     --guard-loc-class trusted --guard-risk 29
   ```

   Both commands print `ok` whether or not the subject held the grant, so
   `ok` does not confirm that the grant existed.

Revocation takes effect on the subject's next request. Tokens already issued
to the subject stay valid but are evaluated against the updated policy, so a
request that the revoked grant authorized is now denied; a request already
authorized when the revocation commits may still finish.

An administrator cannot confirm the result with `policy explain`: a decision
about another human subject is refused with `decide_denied`. The subject's own
`policy explain` prints `deny` for a revoked permission.

Deactivation does not stop the subject from authenticating. The TOTP
enrollment remains, so the subject can still log in and verify a code, and
receives a token that carries no authority. `wyctl mfa enroll` refuses the
subject with `409 mfa_already_enrolled`; the enrollment can only be replaced
with the offline `wyctl mfa reset` (see "Recovery and Reset"). To reactivate
the subject, grant the roles or permissions again and arm the ones you
disarmed; the existing enrollment is reused.

### Offline Maintenance Defaults via GSettings

Direct `--store` / `--keyprovider` enrollment, including their GSettings
fallbacks, is only for maintenance or recovery while `wyrelogd` is stopped.
Never use it against the encrypted store owned by a running daemon.

For privileged maintenance, the supported recipe is to pass the store and
KeyProvider explicitly. Use the paths for the stopped daemon's profile; for
example, with the system profile's file-backed KeyProvider:

```sh
sudo wyctl mfa enroll \
  --subject alice \
  --store /var/lib/wyrelog/system/policy.sqlite \
  --keyprovider file:/etc/wyrelog/system/policy.key
```

Use the same explicit options for privileged `wyctl mfa reset`.
This recipe does not depend on root's GSettings defaults or on preserving
the invoking user's environment.

GSettings can still save repeated paths when `gsettings` and `wyctl` run
as the **same account with the same settings-backend environment**, and
that account already has access to the store and KeyProvider. For that
same-account, daemon-stopped case:

```sh
gsettings set org.wyrelog.wyctl default-policy-store /var/lib/wyrelog/system/policy.sqlite
gsettings set org.wyrelog.wyctl default-keyprovider file:/etc/wyrelog/system/policy.key
wyctl mfa enroll --subject alice
```

Do not add `sudo` only to the final command and expect it to inherit the
operator's saved defaults. See [whose settings wyctl reads under sudo](#when-wyctl-ignores-a-value-gsettings-get-returns)
below. `--subject` is **not** a GSettings-backed key; always pass it
explicitly because each enrollment targets one principal.

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
  already-revoked subject and a no-op for non-bootstrap subjects. The
  exception is an online confirmation that got no answer: wyctl then says
  the outcome is unknown, and the re-run is decided as described under
  "First-Install Bootstrap".
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

POST /auth/mfa/verify
Content-Type: application/json
{"session_token":"<token>","code":"NNNNNN"}
  -> 200 { access_token, expires_in, refresh_token, refresh_expires_in,
           principal_state: "authenticated" }
  -> 400 invalid_mfa_request   (malformed body or any query parameters)
  -> 400 tenant_sealed | tenant_invalid
                               (session's tenant no longer active)
  -> 401 mfa_auth_required     (missing or unknown session token)
  -> 401 mfa_invalid           (wrong code)
  -> 401 enrollment_required   (subject has no totp_enrollment fact)
  -> 429 mfa_locked            (5+ failures within 15 min)
  -> 500 mfa_verify_failed     (counter persistence IO error)
```

Any response in this flow that carries tokens also reports their issued
lifetimes, so a client that treats the access token as opaque -- the correct
default for a bearer it does not verify -- can schedule a refresh without
decoding the JWT:
`expires_in` beside `access_token` (900 seconds) and `refresh_expires_in`
beside `refresh_token` (86400). This holds for `/auth/login`,
`/auth/mfa/verify` and `/auth/refresh`. Both are the lifetimes the token was
issued with, not the remaining life of one already in hand: `/auth/refresh`
answers a retried request by rebuilding the original response, so a decaying
value there would make a replay differ from what it replays. The service
token response does not carry `expires_in`; its lifetime is 300 seconds.

`wyctl` provides the human login and local token lifecycle. Query-form MFA
verification is no longer accepted; older callers must send the session token
and code in the JSON body shown above. `wyctl` prompts without echo on a TTY;
when stdin is redirected, provide one six-digit code line through stdin. Token
values are never accepted as command-line arguments or printed:

```sh
wyctl --daemon-url "$BASE_URL" auth login \
  --subject alice --tenant __wr_default \
  --token-output "$TOKEN" --refresh-token-output "$REFRESH_TOKEN"

wyctl --daemon-url "$BASE_URL" auth refresh \
  --tenant __wr_default --token-file "$TOKEN" \
  --refresh-token-file "$REFRESH_TOKEN"

wyctl --daemon-url "$BASE_URL" auth logout \
  --tenant __wr_default --token-file "$TOKEN" \
  --refresh-token-file "$REFRESH_TOKEN"
```

The two output files must be different protected paths. Refresh serializes
with logout through a persistent sidecar lock. It replaces the refresh file
first; if access-token replacement fails afterward, the prior access token
remains usable and another refresh can recover the pair. A durability-uncertain
refresh-file replacement requires a new login rather than an automatic retry.
On Windows, `MOVEFILE_WRITE_THROUGH` is used for replacement; the filesystem
may provide weaker parent-directory metadata durability than POSIX `fsync`.

A 401 from a route that takes a bearer carries an RFC 6750 challenge, so a
client can tell a credential it should refresh from one it never sent:

```
WWW-Authenticate: Bearer realm="wyrelog"
WWW-Authenticate: Bearer realm="wyrelog", error="invalid_token"
```

The `error="invalid_token"` form means a bearer was presented and refused --
expired, revoked, or not verifying. Refresh once and retry; a second such 401
is terminal. The bare form means no usable bearer reached the route, which
covers a missing `Authorization` header and also a header in another scheme,
such as `Basic`: the daemon cannot report a token as invalid when none was
sent, and the bare challenge names the scheme the route wants. Re-authenticate
rather than refresh.

Expiry and a bad signature deliberately answer alike. Both are `invalid_token`,
which RFC 6750 defines to cover each, and the client's response to them is the
same. The distinction the client needs -- and previously could not make, since
every one of these conditions returned a bare `401` with no header at all -- is
between a credential worth refreshing and one that was never usable.

`/auth/refresh` takes the token in the request body:

```
POST /auth/refresh
  {"refresh_token": "<token>"}
  -> 200 { access_token, expires_in, refresh_token, refresh_expires_in, … }
  -> 400 invalid_refresh_request
  -> 401 refresh_auth_required
```

The older `POST /auth/refresh?refresh_token=<token>` form is **retained for
compatibility** and answers identically. It is not scheduled for removal, but
prefer the body: a token in a URL reaches shell history, `/proc/<pid>/cmdline`
for any process that can read another's arguments, and any proxy or client
log, and the refresh token is the longest-lived credential the human login
path issues. The bundled client sends the body form only.

Sending the token in both channels at once is refused with `400
invalid_refresh_request` rather than resolved in favour of one. If a proxy
logged the query token while the daemon honoured the body token, the log would
name a credential the daemon never used. A request body that is present but
does not parse is likewise refused, rather than being treated as absent and
falling back to the query parameter.

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

Credential issue and rotation require the daemon to be running with
`--production` and an initialized policy key provider configured with
`--policy-keyprovider`; passing a provider path without `--production` does
not activate it. The daemon also needs both `--operation-root` and
`--credential-publication-root` configured. Without an effective provider, a
fresh handoff is refused with HTTP 503 `service_credential_unavailable` before
it creates an operation journal or credential state. `WYL_LOG=policy:debug`
records the static reason `effective-provider-unavailable`. The requesting
human must have a live MFA-assured session and the armed
`wr.service_credential.manage` permission described below.

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
the strict request body. On any failure the daemon could have seen, `wyctl`
prints `service-principal disable request_id=<id>` with the ID it sent. If the
connection drops or the daemon returns 500/503, retry with that ID; using a
new ID creates a distinct authorized attempt. HTTP 409 means that the key is already bound to a conflicting request
and must not be reused for different inputs. The response
`X-Wyrelog-Request-Id` is only per-attempt correlation and is never a substitute
for `--request-id`.

### Idempotency

`--request-id` is optional; omit it and `wyctl` mints a fresh canonical
request id. Issue, rotate and revoke print `<command> request_id=<id>` with the
id they sent on any failure the daemon could have seen, so a minted id is never
lost. Reusing the same `--request-id` with identical inputs is a safe
retry: the daemon
returns the same operation, credential, and receipt and never mints a
second secret. Supply a stable `--request-id` when a previous invocation
may have succeeded without you observing its reply.

For service-credential issue and rotation, HTTP 403
`service_credential_denied` means the live caller/session/management authority
was refused; it is not a request-id conflict. HTTP 409
`service_credential_conflict` means the request id is already bound to different
immutable operation inputs, or its operation has been retired and the id remains
reserved. Do not mint a replacement id to get around either response. HTTP
500/503 can occur after the credential mutation has committed
but before escrow publication or delivery finishes; keep the original request
id, inspect `service-credential status`/`recover`, and retry only with that id.
After a timeout or a server error, `wyctl` names `service-credential recover
--request-id <id> --tenant <tenant>`, which only reports what the daemon
recorded for that id (see "Publication failure and orphan recovery"); if it
finds no such operation, or the daemon offers no `recover`, re-run the same
command with that id.
The daemon emits a static, secret-free policy diagnostic naming the refusal
check when `WYL_LOG=policy:debug` is enabled.

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
  and `jti`. A service access token lives 300 seconds and its response carries
  no `expires_in`; the human lifetimes and how they are reported are described
  with the login example above. There is no workload refresh token in v1.
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

  **The `session_token` query parameter carries the policy scope, not a session
  token.** The name is legacy and the value is used only as the resource the
  decision is evaluated against; the caller is authenticated by the `Bearer`
  header. Pass the tenant -- for a service request, the credential tenant:

  ```
  POST /decide?user=alice&perm=wr.datalog.query&tenant=__wr_default     &session_token=__wr_default          -> {"decision":1}
  ```

  Passing an actual session token there asks about a scope no grant is written
  at, so it answers a confident `{"decision":0}` for a permission the daemon
  will honour on the very next request. `docs/developer-lifecycle.md` states
  the rule; it is repeated here because this page is the one an operator reads
  while debugging a denial, and reading only this page was enough to
  misdiagnose `/decide` as broken (#1034).

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
again immediately. A human administrator holding
`wr.service_principal.manage` may also inspect a same-tenant `svc:` subject;
service bearers remain self-subject only, and other cross-subject requests are
denied. The legacy `session_token` query parameter carries the policy scope (the
tenant), not the bearer token.

```
# Fresh service token, no role yet: DENY. An admin can inspect this subject too.
POST /decide?user=svc:svc-app&perm=wr.stream.read&tenant=tenant-a&session_token=tenant-a
  Authorization: Bearer <service-or-authorized-admin-token>
  -> decision=0 (deny)

# A human admin grants a workload-safe, tenant-scoped role.
POST /policy/roles/grant  { subject: svc:svc-app, role: <workload-safe role>,
                            scope: tenant-a }   (human __wr_default bearer,
                                                 guard context)

# Same unexpired token, re-evaluated: ALLOW.
POST /decide?user=svc:svc-app&perm=wr.stream.read&tenant=tenant-a&session_token=tenant-a
  Authorization: Bearer <service-or-authorized-admin-token>
  -> decision=1 (allow)

# The human revokes the grant.
POST /policy/roles/revoke  { subject: svc:svc-app, role: <workload-safe role>,
                            scope: tenant-a }   (human __wr_default bearer,
                                                 guard context)

# Same token again: DENY. No token reissue, no cache flush.
POST /decide?user=svc:svc-app&perm=wr.stream.read&tenant=tenant-a&session_token=tenant-a
  Authorization: Bearer <service-or-authorized-admin-token>
  -> decision=0 (deny)
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

Seal the tenant (blocks the entire tenant surface; see "Tenants"):

```
wyctl tenant seal \
  --name <tenant> --confirm \
  [--request-id <id>] \
  --access-token-file <path>
# receipt: tenant=<tenant> changed=true request_id=<id>
```

After any of these, a fresh exchange for an affected credential fails and an
already-minted token stops being accepted. The status depends on which action
was taken: a credential revoke or a principal disable leaves the token unable
to resolve at all, so the bearer gate answers HTTP 401; a tenant seal leaves
the credential resolving against a closed tenant, so the bearer gate answers
HTTP 409 `tenant_sealed` (#1032). A request that merely names a sealed tenant
is rejected earlier, with HTTP 400 and error `tenant_sealed`
(`wyrelog/daemon/http.c`). This zero-survivor property is proven end to end by
`service-credential-zero-survivor-e2e` (Linux packaged runtime), which
exercises the two 401 cases and the 400 case.

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
- **Human session ids are shown as handles.** That guarantee is about
  service credentials. A human login's session id is also its
  `session_token`, which `?session_token=` accepts on every guarded route,
  and the stored audit rows do record it: as the subject of `session_state`
  and `session_fired_delta_*` rows, and in any column of a row written for a
  session-scoped request. `/audit/events` and `wyctl audit query` therefore
  show `session#` followed by 16 hex digits in its place. A handle is stable
  for the life of one daemon process, so a session's rows still correlate,
  but it is not a credential and does not match as a filter value. The
  subject of those two row kinds is always replaced; in every other column
  only the id of a session still live when the log is read is, and the id of
  a session that has ended, which no longer authenticates, appears as
  stored. The raw ids remain in the on-disk policy and audit stores, which
  the file permissions of those stores protect.

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
REFRESH_TOKEN=/run/wyrelog/operator.refresh
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

Use the bootstrap bypass only to enroll the administrator's TOTP factor. A
successful enrollment atomically revokes `wr.login.skip_mfa`; it does not mint
the MFA-assured session needed to arm permissions. After enrollment, perform a
fresh normal login. `wyctl` prompts for TOTP without echo and writes the
MFA-assured access and refresh tokens to protected files:
The enrollment-confirmation code cannot be replayed for login; if the current
30-second TOTP code was just used to enroll, wait for the next code before
completing the fresh login below.

```sh
wyctl --daemon-url "$BASE_URL" auth login \
  --subject alice --tenant __wr_default --skip-mfa \
  --token-output /run/wyrelog/bootstrap.token \
  --refresh-token-output /run/wyrelog/bootstrap.refresh

wyctl --daemon-url "$BASE_URL" mfa enroll \
  --subject alice \
  --access-token-file /run/wyrelog/bootstrap.token

wyctl --daemon-url "$BASE_URL" auth login \
  --subject alice --tenant __wr_default \
  --token-output "$TOKEN" --refresh-token-output "$REFRESH_TOKEN"

wyctl --daemon-url "$BASE_URL" audit query \
  --filter 'action=bootstrap_admin_apply' --limit 10 \
  --access-token-file "$TOKEN" \
  --guard-timestamp "$(date +%s)" \
  --guard-loc-class trusted --guard-risk 29

for perm in wr.graph.manage wr.schema.manage wr.fact.write wr.datalog.query; do
  wyctl --daemon-url "$BASE_URL" policy permission-transition \
    --subject alice --perm "$perm" --scope "$TENANT" --event grant \
    --access-token-file "$TOKEN" \
    --guard-timestamp "$(date +%s)" --guard-loc-class trusted --guard-risk 29
done
```

`auth login` checks both token output paths before contacting the daemon. If
either path already exists, it exits 2 and names that path; use distinct,
unused filenames for another tenant. An output can still appear after this
check. In that case protected publication refuses to replace it, attempts
server logout, and reports which file collided. If publication reports
uncertain durability, inspect both token files before another login.

A granted permission is dormant until it is armed. Before the loop above,
`wyctl --daemon-url "$BASE_URL" policy explain --user alice --permission
wr.graph.manage --resource "$TENANT" --access-token-file "$TOKEN"` prints
`deny` with `reason=not_armed`; afterwards it prints `allow`. The arming
events, `grant` and `reset`, need the MFA-assured token: the bootstrap token
is refused with exit 4 and `policy_denied`. A transition the state
machine refuses, such as arming an already armed permission when the loop is
re-run, exits 3 with `invalid_policy_mutation`; `policy explain` shows the
current state.

Graph-count admission can be bounded independently of fact bytes and rows. Only
a principal holding the `wr.sys.admin` permission on the tenant (the packaged
`wr.system_admin` role carries it) may read or change a tenant's quota.
Configure a limit and inspect its usage before creating graphs:

```sh
wyctl --daemon-url "$BASE_URL" fact quota configure \
  --tenant "$TENANT" --limit 100 \
  --access-token-file "$TOKEN" \
  --guard-timestamp "$(date +%s)" --guard-loc-class trusted --guard-risk 29

wyctl --daemon-url "$BASE_URL" fact quota status \
  --tenant "$TENANT" \
  --access-token-file "$TOKEN" \
  --guard-timestamp "$(date +%s)" --guard-loc-class trusted --guard-risk 29
```

The status reports `limit`, `committed`, and `pending`; secure provisioning
rows and fallback graph-create reservations count as pending against the same
limit and remain reserved across daemon restarts. Retrying the identical graph
create resumes its durable operation. The retry must use the same fact root;
the policy store binds to one root, so restore the original daemon root if it
was changed while a reservation is pending. A limit of `0` denies all new
graph creates. A requested limit below current committed-plus-pending usage is
refused with HTTP `409` and
`error=fact_quota_limit_below_usage`; existing graphs are never removed. At
capacity, `POST /graphs/create` returns HTTP `429` with
`error=fact_quota_exceeded`, `dimension=graph_count`, `limit`, and `observed`,
before graph artifacts are created. Graph count is one of six tenant quota
dimensions; the others, the refusal and committed-but-reconciling contracts,
and the operation-status route are described in the Tenant Resource
Quotas section below.

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

printf 'order_id\tamount\no-1\t42\n' >/tmp/orders-retract.tsv
wyctl --daemon-url "$BASE_URL" fact retract \
  --tenant "$TENANT" --graph "$GRAPH" \
  --namespace shop --relation orders --schema-version 1 \
  --batch-id orders-retract --idempotency-key orders-retract \
  --format tsv --input /tmp/orders-retract.tsv \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29

wyctl --daemon-url "$BASE_URL" datalog query \
  --tenant "$TENANT" --graph "$GRAPH" \
  --query 'orders(O,A)' --output json --limit 10 \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29
```

Both commands print a key/value batch receipt. For example:

```text
action=put batch_id=orders-1 operation_id=orders-1 replay=false mutation_class=committed_ready effect=unknown
action=retract batch_id=orders-retract operation_id=orders-retract replay=false mutation_class=committed_ready effect=unknown
```

`replay=false` means this idempotency key recorded a new batch;
`replay=true` means the previously recorded batch was replayed. The output
format replaces the old single-word `inserted`/`duplicate` output, so scripts
that parse the old text must be updated. The `effect=unknown` field is
deliberate: batch acceptance does not report whether the fact relation changed.
A retract is a blind tombstone write, so a no-match retract has the same receipt
as one that matched. The final query must no longer contain `o-1, 42`; query
results are the proof that the row was removed, rather than the batch receipt
or HTTP status alone.

There is no update command. Changing a row is a `fact retract` of the old
value followed by a `fact put` of the new one: two batches with separate
idempotency keys, not one atomic change. If the second batch fails (a quota
refusal, an expired token, a daemon restart), the relation is left without
the row, and neither command reports the half-applied change. Recover by
re-running the failed `fact put` with the same `--batch-id`,
`--idempotency-key` and input file; a batch that was in fact recorded answers
`replay=true` instead of writing twice, and different rows under the same keys
answer `409 fact_batch_conflict`. Renew an expired token with `auth refresh`
or `auth login` first. A quota refusal repeats until the quota is raised with
`fact quota configure` or usage drops. Then confirm the row with
`datalog query`.

### Erasing a batch

A retract only hides a row behind a tombstone; the batch that wrote the row
stays in the fact store. `wyctl fact forget` erases every row of one committed
batch, for example to honour an erasure request. It cannot be undone, so it
requires `--confirm` and a `--tenant` and `--graph` typed on the command line;
the configured default tenant and graph are never used as its target. The
caller needs `wr.fact.write` in the tenant.

```sh
wyctl --daemon-url "$BASE_URL" --timeout-ms 30000 fact forget \
  --tenant "$TENANT" --graph "$GRAPH" \
  --namespace shop --relation orders --schema-version 1 \
  --batch-id orders-1 --operator ops-oncall --reason 'erasure request 17' \
  --confirm --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29
```

It prints `action=forget batch_id=orders-1 rows_purged=1
mutation_class=committed_ready reconcile=false`. `--operator` and `--reason`
are recorded with the erase as annotations; the audited actor is the subject
of the access token. Erasing a retract batch removes its tombstones, so the
rows it hid become visible again; erase the batch that wrote a row to remove
the row itself.

- Exit 4 with `graph_sealed`: the graph is sealed and nothing was erased.
- Exit 5 with `fact_batch_not_found`: no batch with that id was recorded for
  that namespace, relation and schema version. A batch recorded for another
  relation is left untouched.
- Exit 5 with `graph_not_found` or `fact_schema_not_found`: the graph, or the
  relation schema, does not exist.
- Exit 5 with `fact_forget_audit_failed`: the rows **were** erased but the
  audit record was not written. wyctl prints `purged=true audit=failed` and
  `do not retry`; record the erase by hand from that output.
- No response (a timeout or a dropped connection), an unreadable answer, or
  any other 5xx: the outcome is unknown, since the daemon records the erase
  before it runs and can fail after it commits. wyctl says so. Re-run the same
  command; `fact_batch_not_found` on the re-run means the batch is already
  erased, or never existed.

Public schema registration is currently a one-time operation for each
tenant/graph/namespace/relation. The positive `--schema-version` identifies
that relation's initial schema and may be any positive version. Every later
public registration, including an exact repeat, returns HTTP 409
`schema_already_registered`, whether or not facts have been appended. The
policy store contains internal version-activation machinery, but the public
daemon/CLI does not yet provide the staged migration workflow needed to use it
safely.

Fact mutation is schema-registered: append, retract, and forget operate only on
relations registered through `fact schema register`. The daemon does not support
raw Datalog atom deletion endpoints such as `DELETE /api/facts/fact(1)` or
ad-hoc deletion of `fact(1)` without a registered relation schema. Attempts to
mutate a relation before registering its schema fail with
`fact_schema_not_found` on the schema-backed `/facts/<tenant>/<graph>/<relation>`
routes.

### Repairing rows left by an old wrong-relation forget

An older forget implementation could remove a batch and its events while
leaving rows in the batch's actual relation projection. With a bearer granted
`wr.fact.read`, call `GET /facts/verify?tenant=<tenant>&graph=<graph>` with the
normal guard context. The response includes
`orphan_repair_candidate_batches` and `orphan_repair_candidate_rows` across
registered relation schemas. These are conservative repair candidates, not a
count of every orphan: a candidate must have no batch or event row, exactly one
completed zero-purge forget intent targeting another projection, and exactly
one matching forget audit record. Ambiguous history is excluded.

For each affected batch whose actual relation, namespace, and schema version
are known, use an MFA-assured bearer granted `wr.fact.write` and send
`POST /facts/<tenant>/<graph>/<actual-relation>:repair` with query parameters
`tenant`, `namespace=<actual-namespace>`, `schema_version=<actual-version>`,
and the normal guard context. The JSON body contains `batch_id`, `operator`,
and `reason`, as for forget. The graph must be unsealed. The daemon rechecks
the evidence under its write lease, deletes only that batch's rows from the
actual projection, and commits a `fact_orphan_repair_audit` record with the
original forget operation ID, authenticated actor, request ID, reason, and row
count in the same transaction. A missing, ambiguous, or already repaired
candidate returns HTTP 404; a sealed graph returns 409. Verify again after
repair. A refresh failure after the durable repair is reported as a committed
degraded mutation, so the runtime may need reconciliation even when the rows
are gone.

A sealed graph refuses all three: append, retract and forget each return `409`
`graph_sealed`. Sealing a graph is irreversible -- there is no graph unseal
operation, tenant unseal does not clear the graph flag, and `graph create`
refuses an existing or sealed graph -- so an erasure request that arrives for
an already-sealed graph has no in-product remedy. Seal only after any pending
erasure work is complete.

List a tenant's graphs, and whether each is sealed, with `wyctl graph list`,
which needs `wr.graph.manage`:

```sh
wyctl --daemon-url "$BASE_URL" graph list \
  --tenant "$TENANT" --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29
```

It prints one `graph=<graph> sealed=<bool> schema_version=<n>` line per graph.
Seal a graph with `wyctl graph seal`, which needs the same permission. Because
the seal cannot be undone, it
requires `--confirm` and a `--tenant` and `--graph` typed on the command line;
the configured defaults are never its target.

```sh
wyctl --daemon-url "$BASE_URL" graph seal \
  --tenant "$TENANT" --graph "$GRAPH" --confirm \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29
```

It prints `tenant=<tenant> graph=<graph> sealed=true`, also when the graph
was already sealed, so a re-run is safe. Exit 5 with
`graph_not_found` means no such graph. On no response or another 5xx the
outcome is unknown, and wyctl says so; `wyctl graph list` then shows whether
the graph is sealed.

One case is recoverable, and it is worth distinguishing from the above. A forget
is durable in two steps: a PENDING intent, then the deletion and its completion.
If the daemon dies between them, the intent survives and nothing in the request
path resumes it -- and after the graph is sealed, no request can. Starting the
daemon converges it: every graph's pending forget intents are driven to
completion before that graph's engine is built, sealed graphs included, because
sealing blocks admission of new data rather than erasure of data already stored.
So a forget that was already in flight when the graph was sealed will finish on
the next start; only an erasure request that arrives after the seal is stranded.

Boot convergence is best-effort by design: a graph whose forget cannot be
converged is logged and skipped, never allowed to stop the daemon starting.

Since #869 the daemon asks this question read-only first. It opens each graph's
fact store without requesting write access, counts pending intents, and takes a
write lease only when something is actually pending. A boot with nothing to
converge -- the overwhelmingly common case -- now takes no write lease on any
graph, and a store reached through a mis-pointed path -- once it has anything
pending -- is refused at the probe rather than after a lease it would then
decline.

Three distinct lines appear in the `BOOT` section:

- `could not open the fact store of tenant <t> graph <g> to look for a pending
  forget` (warning) -- the store would not open at all, so its forget ledger
  was never read and nothing is known about any erasure for that graph. The
  graph is normally reported degraded too, because the engine build makes the
  same read-only open and fails for the same reason. Since the probe and the
  engine build now request identical access, a graph that reports *ready* while
  emitting this warning is not the write-lease case it used to be -- that
  combination is the anomaly the third line below reports.
- `a pending fact forget recorded for tenant <t> graph <g> could not be
  converged` (error) -- an intent was found and did not complete. Personal data
  that was accepted for deletion is still present in that graph. Investigate
  before returning the graph to service. That graph also reports
  `forget_incomplete` on `/facts/status` (`wyctl fact status` prints
  `state=forget_incomplete` on that graph's line), so this case is visible
  without reading logs; the warning above is not.

  This line now also covers the case the previous revision of this runbook told
  you to watch for separately. A write lease is requested only after the
  read-only probe has counted a pending intent, so a graph refused that lease
  is a graph we know has an outstanding erasure: it lands here, as an error,
  with `forget_incomplete` on `/facts/status`. It no longer reports `ready`
  over an unreconciled ledger.
- `the fact store of tenant <t> graph <g> refused the forget probe with rc=<n>
  but served the engine build moments later` (error) -- the probe and the
  engine build make the same call with the same arguments, and they disagreed.
  Nothing is known about that graph's erasure state; no `/facts/status` verdict
  is written for it, because "we could not establish it" is not the same as
  "an erasure is outstanding".

  Read the `rc` before concluding anything. Under the secure bridge this can be
  a lost race for the shared reader guard, which is transient and clears on its
  own. But any transient resource failure that clears between the two opens
  produces the same line -- an exhausted descriptor table is the obvious one,
  and is not bridge-specific. A recurring instance of this line on the same
  graph is worth investigating; a single one with an `rc` that indicates
  resource exhaustion is a capacity problem, not a lease problem.

Note that at `wyrelog_log_max_level=error`, which the option's own description
recommends for production builds, the warning is compiled out entirely. Both
errors survive.

That gap is narrower than it was. The case this runbook previously singled out
-- a bridge graph refused a *write* handle while still serving reads, reporting
`ready` with only a compiled-out warning to tell you -- cannot occur now: no
write lease is taken unless a pending intent has already been counted, and a
refusal at that point is an error, not a warning. What remains behind the
`error` threshold is the first bullet: a store that would not open at all,
which in nearly every case also shows up as a degraded graph. Collecting `BOOT`
output at `warn` at least once after a configuration change is still worthwhile
for that reason.

Fact append/retract and schema registration use TSV with LF or CRLF record
terminators. Only the terminator is removed: spaces and other field whitespace
are preserved, including a lone CR on an unterminated final record. One final
terminator is optional. Empty records (including leading/interior blank lines
and repeated final terminators) are rejected, not skipped. A whitespace-only
string record is data. Schema boolean/type tokens must match their accepted
spelling; trailing whitespace is not silently trimmed.

The exact first record matching the relation's column names is reserved header
syntax. To write those names as a data row, send the header followed by the same
record again; later matching records are data. The schema header
`column_name<TAB>column_type<TAB>nullable<TAB>visible` is likewise optional only
in the first record. There is no quoting or backslash escape syntax: tabs delimit
fields and LF delimits records, so tab/LF-containing field values cannot be
represented. Embedded NUL bytes are rejected before text parsing.

Nullable `string`/`symbol` fields cannot encode an empty string or the literal
`NULL`: both are rejected with HTTP 400 `invalid_fact_payload`, not converted to
SQL NULL. Non-nullable text fields retain literal `NULL` and empty cells in
multi-column records; a wholly empty record is still rejected. Other nullable
types retain their existing NULL-token parsing and store validation. Invalid
TSV rejects the whole batch before persistence, including any preceding valid
rows. Invalid schema TSV returns HTTP 400 `invalid_schema_payload`.

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
wyctl --daemon-url "$BASE_URL" fact put \
  --tenant "$TENANT" --graph "$GRAPH" \
  --namespace examples --relation fact --schema-version 1 \
  --batch-id fact-1 --idempotency-key fact-1 \
  --format tsv --input /tmp/fact.tsv \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29

wyctl --daemon-url "$BASE_URL" datalog query \
  --tenant "$TENANT" --graph "$GRAPH" \
  --query 'fact(V)' --output json --limit 10 \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29

printf 'value\n1\n' >/tmp/fact-retract.tsv
wyctl --daemon-url "$BASE_URL" fact retract \
  --tenant "$TENANT" --graph "$GRAPH" \
  --namespace examples --relation fact --schema-version 1 \
  --batch-id fact-r1 --idempotency-key fact-r1 \
  --format tsv --input /tmp/fact-retract.tsv \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29

wyctl --daemon-url "$BASE_URL" datalog query \
  --tenant "$TENANT" --graph "$GRAPH" \
  --query 'fact(V)' --output json --limit 10 \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29
```

The first query returns values `1`, `2`, and `3`. The query after the retract
returns only `2` and `3`; the raw atom `fact(1)` is not deleted through a
separate `/api/facts` API.

`wyctl fact put` and `wyctl fact retract` print a one-line receipt,
`action=<put|retract> batch_id=... operation_id=... replay=<true|false>
mutation_class=... effect=unknown`, or a `committed-reconciling` line when the
commit is still reconciling. `replay=true` is the route's `"inserted":false`.
The JSON responses below are the HTTP route's body, which also carries the
deltas that the receipt omits.

A retract that matches nothing answers exactly like one that matched. Retract
`9`, which was never appended, and the response is (elided to the fields
that matter here; for this response the route also returns `batch_id`,
`queryable`, `reconcile` and `engine_generation`, plus `degraded_class` when
`mutation_class` is `committed_degraded`):

```
{"ok":true,"inserted":true,"committed":true,
 "mutation_class":"committed_ready",
 "committed_row_delta":1,"logical_byte_delta":8}
```

The query afterwards still returns `2` and `3`.

Whether a resend repeats that response or is refused depends on both identity
keys together, not on either one alone:

- a fresh `batch_id` **and** a fresh `idempotency_key` append another
  tombstone: `"inserted":true` and positive deltas, exactly as above;
- reusing **both**, with every other recorded field and the row content
  unchanged, is the idempotent replay: HTTP 200 with `"inserted":false` and
  the deltas the original commit charged, restated from the batch's durable
  row rather than reported as `0` (#1013). A client that sums deltas across
  retries must therefore key on `"inserted"`, or it charges the same batch
  once per attempt. A `logical_byte_delta` of `-1` means the batch was
  committed before the cost was stored and cannot be recovered; it is an
  explicit unknown, never a credit and never a charge of zero;
- reusing only one of the two, or reusing both while anything else recorded
  for the batch differs, fails to match the stored batch and answers
  `409 fact_batch_conflict`.

So a retry loop that mints a fresh `batch_id` *and* a fresh
`idempotency_key` each attempt is not replaying -- it is appending a new
tombstone every time, and each one is charged. (Minting only one of the two
does not append at all; by the rule above it is refused `409`.) The graph-count
quota described above does not cap fact rows, bytes, or mutation batches; the
`logical_bytes` quota in the Tenant Resource Quotas section does.

`logical_byte_delta` measures the request, not the effect. It sizes each value
by that value's own type, so it is not a byte count of the payload: fixed-width
scalars charge their natural width (`int64` and `compound_ref` 8, `bool` 1),
and `symbol` and `string` charge their UTF-8 byte length. A NULL is never
priced at all. The tuple format cannot represent one, so the daemon refuses any
batch containing a NULL -- even in a column registered `nullable` -- with
`400 invalid_fact_payload`, before the request reaches the code that prices it.

**Blind retract is intended, and no receipt reports matched rows.** A retract
is an append of a tombstone: the write path records the batch and never reads
the relation, so it does not know whether the value shadowed a live row. Do not
read `effect=unknown`, `"inserted":true` or a positive
`committed_row_delta` as "a row was removed" -- they report no matching-row
count. `"committed":true` carries even less: it is a constant on this path,
not a result.

That is also why nothing matching raises no error and returns no matched-row
count: the write path has neither to give.

If you need to know whether a value was present, query for it before
retracting. Treat that answer as advisory rather than as a precondition: it is
a separate request, and another writer can append or retract the value between
it and your retract.

Omit `--max-rows` during schema registration to keep the default 1000-row
Datalog query cap. Set it explicitly for larger materialized JSON queries;
accepted values are 1 through 1000000, and `wyctl datalog query --limit`
cannot exceed the registered cap.

To verify recovery, restart `wyrelogd` with the same policy DB, audit DB, key,
and fact root. Mint a fresh token after restart and run the same
`wyctl datalog query`; the fact graph is replayed from the per-graph DuckDB fact
store. Check graph health with:

```sh
wyctl --daemon-url "$BASE_URL" fact status \
  --tenant "$TENANT" --access-token-file "$TOKEN"
```

It prints `scope=tenant tenant=<tenant> status=<status>` and the aggregate
counts, then one `graph=<graph> state=<state> queryable=<bool>
engine_generation=<n> reason=<class>` line per graph. Without `--tenant` and `--access-token-file`
the request is anonymous and prints `scope=anonymous` with the counts alone.
Add `--graph <graph>` to print that graph's line only. `wyctl fact status`
exits 0 when the status is `ready` (with `--graph`, when that graph is
queryable), 1 when it is degraded or disabled or the graph is absent or not
queryable, 2 when its arguments, credentials or proxy settings are invalid,
and 3 when the daemon's answer is invalid or reports a status this wyctl does
not know, as a newer daemon can.
Like the endpoint, it only talks to the daemon's loopback listener.

The per-graph rows name a tenant and a graph, so they are returned only to an
authenticated caller and only for that caller's own tenant; `tenant` must name
it explicitly, because the request tenant otherwise defaults to
`__wr_default`. A caller that presents no credential still receives the
aggregate (`status` and the four counts) with no `graphs` array, which is the
same shape `/readyz?format=json` publishes. A request for a tenant the caller
is not in is refused with `tenant_denied`, and a credential that fails to
resolve is refused with `401` rather than quietly falling back to the
anonymous body.

The authenticated response narrows the four counts to the same tenant, so
`graphs_degraded` read this way counts that tenant's graphs alone. The
top-level `status` verdict is derived from those counts and narrows with
them: an authenticated `/facts/status` reports `ready` while another tenant is
degraded. Alert on `/readyz?format=json` when you want the deployment-wide
figure.

A single corrupted graph should report a degraded graph entry while unrelated
graphs remain queryable. Stop the daemon before repairing or replacing a damaged
`facts.duckdb`, restore only the affected `<tenant>/<graph>` fact directory,
restart, then confirm `/facts/status` returns `"status":"ready"`
(`wyctl fact status` exits 0). To check one graph's store against the policy
store without changing anything, which needs `wr.fact.read`:

```sh
wyctl --daemon-url "$BASE_URL" fact verify \
  --tenant "$TENANT" --graph "$GRAPH" --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29
```

It prints `verified=true` and exits 0 when the graph's path, identity and
schema match. It exits 1 with `verified=false` when the daemon finds a
mismatch (`fact_graph_verification_failed`), and 5 when the graph does not
exist or the check could not run.

### A graph reporting `forget_incomplete`

A graph whose boot forget reconciliation did not converge reports
`"state":"forget_incomplete"` and counts toward `graphs_degraded`, so the
aggregate `"status"` is `degraded` rather than `ready`. It means an erasure this
graph accepted has not completed, and the data is still present.

Two things about that entry are deliberate and worth knowing before acting on
it:

- **The graph is still serving queries.** Its entry reports
  `"queryable":true`. This is a health signal, not a barrier -- the daemon does
  not refuse reads on a graph with an outstanding erasure, because the engine
  is complete and correct for the data that is there.
- **This is the first degraded state with no replay failure behind it.** A
  graph that is counted in `graphs_degraded` while still serving queries is
  not new -- a post-mutation refresh that fails while the previous engine
  survives leaves the graph queryable and degraded, and its reason code says
  which replay step failed. What is new is a graph that replayed *perfectly*
  and is degraded anyway, because it owes an erasure. Check `"state"` rather
  than inferring a cause from the aggregate.

A graph that is both unreplayable and owes an erasure reports the replay reason
(`store_unavailable`, `schema_mismatch`, `replay_failed`), not
`forget_incomplete`. The replay failure is the more actionable of the two and
must be cleared first; the erasure state reappears once the graph replays.

A **sealed** graph is the exception, and it is the one that matters most. Boot
reconciliation deliberately converges a sealed graph's pending forget -- sealing
blocks admission of new data, not erasure of data already stored, and after the
seal there is no request path left, so startup is the only remedy. A sealed
graph is never given an engine, so its `forget_incomplete` is masked -- the
population most likely to strand an erasure is the one that cannot display the
state.

A sealed graph reports `"state":"sealed"`, `"queryable":false`, and a null
`last_error_class`. It is counted in `graphs_sealed`, in neither
`graphs_ready` nor `graphs_degraded`, and it does not move the aggregate
`"status"`. Sealing is your own decision, so it is neither a fault to alert on
nor evidence of health. **If you alert on `graphs_degraded`, that alert does
not cover sealed graphs; add `graphs_sealed` if you want to see them.**

Earlier releases reported `"state":"schema_mismatch"` here, because refusing an
engine to a sealed graph returns a policy error and the replay classifier maps
policy errors to a schema mismatch. If you are reading a daemon that still does
that, the schema is not the problem -- read the `BOOT` error line, which names
the graph and the reason directly.

Two consequences of the sealed state are worth knowing before you act on it.

- **A stranded erasure on a sealed graph is not visible in the aggregate.** The
  status mapping consults the erasure axis only where replay health would
  report ready, and sealed outranks both, so a graph that is sealed *and* owes
  an unconverged forget reports `sealed` and nothing else. It no longer flips
  the aggregate to `degraded` the way the old `schema_mismatch` misreport
  happened to. The `BOOT` line still names it; alert on that, not on the
  aggregate.
- **`queryable` means different things in two places, deliberately.** On
  `/facts/status` it answers "can I read this graph", so a sealed graph reports
  `false`. In a mutation response body it answers "did my write's engine
  survive", which the barrier does not change. The first describes the
  barrier; the second describes the engine behind it. Today the two cannot
  disagree in practice, because every mutation route refuses a sealed graph
  before it gets that far. They will once a graph can be closed to admission
  without being durably sealed -- either graph unseal, or the seal route
  driving the runtime sequencer, which closes admission before it commits the
  durable bit. Whichever arrives first is enough.

The state is a startup snapshot. It is written by the full replay that runs when
the daemon opens its handle, and in a running daemon that happens exactly once
-- an append, a retract, or any other targeted refresh does not read the forget
ledger and so leaves the state alone. So a graph converges out of
`forget_incomplete` on the next restart, not during the run, and if it persists
across restarts the intent cannot converge on its own and needs investigation;
the `BOOT` error line above names the reason code.

The same snapshot property has a quieter consequence. A graph whose store could
not be opened at startup gets no verdict at all, and carries none for the rest
of the process even if the store later becomes readable and the graph returns to
`ready` after an append. Such a graph reports `ready` with a forget ledger that
was never reconciled. Restart re-probes it. This is not a state the daemon can
detect while running, which is why the startup `BOOT` lines are worth
collecting.

## Tenants

Tenant management runs as a `__wr_default` session and needs
`wr.tenant.manage` there, armed. Every command below takes the usual guard
options.

```sh
wyctl --daemon-url "$BASE_URL" tenant list \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29

wyctl --daemon-url "$BASE_URL" tenant create --name acme \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29
```

`tenant list` prints one `tenant=<tenant> sealed=<bool>` line per tenant.
`tenant create` prints `tenant=<tenant> changed=<bool>`; creating a tenant that
already exists succeeds with `changed=false`. Creating a tenant grants the
caller the `wr.system_admin` role in it and records the caller as the tenant's
owner.

Sealing closes the whole tenant: every request that names it is refused, and
its service credentials stop working (see "Incident revocation and
zero-survivor"). It needs `--confirm`:

```sh
wyctl --daemon-url "$BASE_URL" tenant seal --name acme --confirm \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29
```

It prints `tenant=<tenant> changed=<bool> request_id=<id>`. Every seal carries
a request id, which wyctl mints unless `--request-id` names one, and a failed
seal always prints it (`wyctl: tenant seal request_id=<id>`). When the outcome
is unknown (no answer, an unreadable answer or a 5xx), repeat the seal with
`--request-id <id>`, not a new id, so the daemon completes or confirms that
same seal. `409 tenant_seal_superseded` or `tenant_seal_conflict` means that
id can no longer apply: the tenant changed after the seal was recorded, or the
id belongs to another request. Check `wyctl tenant list`, and if the tenant
still needs sealing, seal it again without `--request-id`.

A create, seal or unseal that fails after the daemon committed it leaves a
pending repair, and the daemon holds one for all tenants. Until the same
command is repeated -- a seal with the same `--request-id` -- the daemon
answers every tenant create, seal and unseal, for any tenant, with `503
tenant_mutation_unavailable`, and wyctl says so. The failed command may be the
one that just got that answer: a seal that fails after its own commit installs
the repair and answers the same way. The same answer can also mean the daemon
was momentarily busy, so repeating is safe either way. Create and unseal are
safe to repeat: once done they answer `changed=false`. So after a 5xx or no
answer, repeat the same command before anything else. A seal can also answer
`503 tenant_lifecycle_coordination_required`; repeat it the same way.

Unsealing reopens the tenant; it does not unseal its graphs:

```sh
wyctl --daemon-url "$BASE_URL" tenant unseal --name acme \
  --access-token-file "$TOKEN" \
  --guard-timestamp $(date +%s) --guard-loc-class trusted --guard-risk 29
```

Tenants cannot be deleted (`/tenants/delete` answers `501`); seal one to
retire it.

### Tenant owners

Every tenant has exactly one recorded owner. A tenant created through
`tenant create` is owned by the subject that created it. The built-in tenant
`__wr_default` is owned by the reserved system owner `wr.system`, never by a
person, and bootstrapping an administrator does not change that. No subject
may use the reserved `wr.` namespace, and a `svc:` subject cannot own a
tenant. The store refuses any tenant without a valid owner, and an owner
cannot be changed.

Stores created before tenants recorded an owner are migrated the first time
the upgraded daemon opens them. `__wr_default` gets
`wr.system`. Every other tenant gets the subject of its earliest
`wr.system_admin` grant on that tenant, which is the grant tenant creation
writes for its creator. A tenant without such a grant, or whose creator cannot
own a tenant, is never guessed at. The migration names each one in a warning
and fails, and the store keeps its previous shape:

```
tenant owner migration: no owner can be resolved for tenant 'acme'; name one
with `wyctl tenant assign-owner`
```

Name an owner for each such tenant with the daemon stopped, then start the
daemon again:

```sh
wyctl tenant assign-owner   --store /var/lib/wyrelog/system/policy.sqlite   --keyprovider file:/var/lib/wyrelog/system/policy.key   --assign acme=alice --assign beta=bob
```

`--store` and `--keyprovider` fall back to the `default-policy-store` and
`default-keyprovider` GSettings keys, as for the other offline commands. With a
KeyProvider the store is taken maintenance-exclusive, so the command refuses
to run while a daemon holds it. Each `--assign` names a tenant once and a
valid human owner; built-in tenants cannot be named. The command runs the
migration with those owners. An assignment wins over an inferred creator for
a tenant the migration has not yet given an owner. The command prints one
line per assignment:

- `tenant=<tenant> owner=<subject> assigned=yes`: the migration applied it.
- `tenant=<tenant> owner=<current> assigned=no reason=already_owned`: the tenant
  already had an owner, which is never changed.
- `tenant=<tenant> assigned=no reason=unknown_tenant`: no such tenant.

It exits `0` only when every assignment was applied. It exits `1` when any was
not, when the migration still fails (another tenant remains unresolved; the
warnings name it, and nothing was changed), or when the store could not be
persisted. It exits `2` for an invalid request.

## Tenant Resource Quotas

A tenant is the admission boundary for shared resources. Six per-tenant quota
dimensions are enforced at the HTTP daemon, which is the only entry point
to them: `wyctl` reaches every quota through the daemon and has no local
quota path. Each dimension is read and configured through one route,
`GET|POST /facts/quota?tenant=<tenant>&dimension=<dimension>`, and one
command pair, `wyctl fact quota status|configure --tenant <tenant>
--dimension <dimension>`. Both require a principal holding the `wr.sys.admin`
permission on that tenant; the packaged `wr.system_admin` role carries it.

The policy store and the graph DuckDB files do not share a transaction, so
quota accounting follows ADR 0004: an operation reserves capacity in the
policy store before it mutates a graph, settles the reservation from the
committed outcome, and converges by retrying the identical request. ADR 0008
describes the durable open reservations behind the `concurrent_opens`
dimension.

### Dimensions

| dimension | enforced at | configure | status fields |
| --- | --- | --- | --- |
| `graph_count` | `POST /graphs/create` | `--limit N` | `limit`, `committed`, `pending` |
| `schema_count` | `POST /facts/schema/register` | `--limit N` | `limit`, `registered` |
| `write_rate` | every fact append and retract | `--rate-per-second N --burst N` | `rate_per_second`, `burst` |
| `concurrent_opens` | every physical fact-store open a request performs | `--limit N` | `limit`, `pending`, `active`, `acquiring`, `cleanup_pending`, `charged` |
| `logical_bytes` | every fact append and retract | `--row-limit N --limit BYTES` | `row_limit`, `limit`, `committed_rows`, `committed_bytes`, `pending_rows`, `pending_bytes` |
| `physical_bytes` | artifact growth during a fact mutation commit | `--limit BYTES` | `limit`, `committed_bytes`, `pending_bytes`, `reconciling_bytes` |

`wyctl fact quota status` prints one line per call in the form
`tenant=<tenant> dimension=<dimension> <field>=<value> ...` with the fields
above; a dimension with no limit prints `unlimited`. For `logical_bytes` the
byte limit is printed as `byte_limit=`. `wyctl fact quota configure` prints
the same line after the change is durable.

Configuration rules that apply to every dimension:

- A tenant with no configured limit for a dimension is unlimited in it.
- A configured limit cannot be removed; raise it instead.
- `limit`, `--row-limit`, `--rate-per-second` and `--burst` take integers;
  `rate_per_second` and `burst` must be positive, the others may be `0`.
  Malformed or mismatched parameters return HTTP `400`
  `invalid_fact_quota_request`, and `wyctl` refuses them locally with exit
  code `2` before sending anything.
- A tenant the caller is not authorized in answers `403` (`tenant_denied`
  or `fact_quota_denied`); an authorized tenant that has no registry row
  answers `404 tenant_invalid`; a method other than `GET` or `POST` returns
  `405`.
- A limit below current usage is refused with `409
  fact_quota_limit_below_usage` for `graph_count` (committed plus pending),
  `schema_count` (registered) and `physical_bytes` (committed plus pending
  plus reconciling). The other three dimensions accept any limit: a
  `concurrent_opens` or `logical_bytes` limit below current usage refuses
  new work until usage drains, and `write_rate` has no stored usage.

### Refusals

A request that would exceed a limit is refused before anything is committed,
with HTTP `429` and a JSON body of the form

```json
{"error":"fact_quota_exceeded","dimension":"graph_count",
 "limit":100,"observed":100}
```

- `graph_count`, `schema_count`, `concurrent_opens` and `physical_bytes`
  carry `limit` and `observed`. `observed` is committed plus pending graphs,
  registered schemas, charged open reservations, or committed plus pending
  plus reconciling bytes respectively.
- `write_rate` carries `dimension` only and adds a `Retry-After` header in
  whole seconds, rounded up, when the bucket reports a wait.
- `logical_bytes` carries `dimension` only, because one reservation covers
  both the row and the byte limit of the paired dimension.

A refusal commits nothing: no graph artifacts (`graph_count`), no schema row
(`schema_count`), no batch and no logical operation (`write_rate`,
`concurrent_opens`), and no store commit (`logical_bytes`, `physical_bytes`). A
write refused by `write_rate` consumes no token. A refusal at commit
(`physical_bytes`, or a store error) leaves the request's logical operation
`cancelled` and visible in `/facts/quota/operation-status`; the identical retry
reopens it.

### Per-dimension notes

**graph_count.** `pending` counts graphs still provisioning and fallback
graph-create reservations; both survive a daemon restart and retrying the
identical create resumes its durable operation. The retry must use the same
fact root; the policy store binds to one root, so restore the original
daemon root if it was changed while a reservation is pending. A limit of `0`
denies all new graph creates. Existing graphs are never removed by a quota
change.

**schema_count.** `registered` is the number of relation schema versions
registered for the tenant across all of its graphs. A limit of `0` denies all
new registrations.

**write_rate.** A token bucket per tenant: it starts full at `burst`, refills
at `rate_per_second`, and never holds more than `burst`. Each admitted append
or retract takes one token; `forget` is not rate-admitted. Changing either
value resets the bucket to the new `burst`.

**concurrent_opens.** Every fact append, retract and forget opens the graph's
store for the request and reserves one durable slot before the open, released
when the request's handle closes. `charged` is the number of reservations in
the `pending`, `acquiring`, `active` or `cleanup_pending` states, and the
open is refused when `charged` has reached the limit, so a limit of `0`
refuses every open. A reservation whose owner crashed is reclaimed by the
lease protocol in ADR 0008; a `cleanup_pending` row is still charged until
that happens.

**logical_bytes.** The row and byte limits are one paired dimension and are
always configured together. An append or retract reserves the rows and logical
bytes of the batch it carries before the store commits, and is refused when
committed plus pending plus requested would exceed either limit. Logical bytes
are the sum over the batch's schema columns of each value's size: the UTF-8
length of a symbol or string, `8` for an int64 or a compound_ref, `1` for a
bool. Two consequences follow. A retract that matches no live row is charged for
the rows and bytes it supplied, exactly like one that removed rows, because
pricing measures the request, not the projection. A replay of the same
`batch_id` and `idempotency_key` with identical content is deduplicated: it
reports the stored cost and is not charged again, while reusing either key with
different content is refused with `409 fact_batch_conflict`.

**physical_bytes.** Admission measures the graph's artifact set through the
bounded evidence of the artifact inventory and fails closed: when evidence
cannot be taken, the mutation is an error, never an admission. A mutation is
refused when committed plus pending plus reconciling bytes have reached the
limit, or when the bytes the evidence bounds for it exceed the remaining
headroom, and it settles from the size observed after the commit. When the
post-commit observation cannot be taken, the reservation's bytes move to
`reconciling_bytes`, which keeps counting against the limit and is never
lowered by unverified evidence. This dimension is enforced only by builds
with the secure DuckDB bridge; other builds accept the configuration and
report it, but never refuse on it.

### Committed but reconciling

When a fact append or retract has committed but its logical settlement could
not be recorded, the daemon answers HTTP `202` instead of `200`:

```json
{"ok":true,"committed":true,"reconcile":true,"quota_state":"reconciling",
 "operation_id":"orders-1","batch_id":"orders-1",
 "payload_digest":"<64 hex characters>","inserted":true,
 "mutation_class":"committed","queryable":true,
 "committed_row_delta":1,"logical_byte_delta":11,"engine_generation":7}
```

The data is durable, and `queryable`, `mutation_class` and the deltas mean
exactly what they mean on a `200`; a `202` is never a refusal. `wyctl fact put`
and `wyctl fact retract` print `committed-reconciling operation_id=<key>
batch_id=<id> payload_digest=<hex>` for it; a non-empty `payload_digest` marks
the quota `202`, because the same line with an empty `operation_id` and
`payload_digest` reports a `200` whose runtime needs a reconcile. `operation_id`
is the request's idempotency key, and `payload_digest` is the daemon's digest of
the batch content. Retain the digest: it is returned only on the `202`, and it
completes the identity the status route below requires. Retrying the identical
request converges the operation without repeating the digest: while the
operation is `pending`, the retry deduplicates the batch, settles the
reservation, and answers `200` with `duplicate`.

A mutation refused at commit, for example by a `physical_bytes` `429`, a `409
fact_batch_conflict`, or a store error, cancels its logical reservation and
leaves the operation `cancelled`. The identical request later reopens that
reservation under the same limit check and, once the cause has cleared, commits
and settles it, so the retry answers `200` and is charged exactly once; a cause
that has not cleared refuses and cancels it again, and if the reservation no
longer fits, the retry answers `429` for `logical_bytes` and commits nothing.

Convergence of a logical operation is retry-driven. There is no startup sweep
of pending logical operations and no route or command that cancels one. If
the daemon stops between the reservation and its settlement, the pending row
keeps charging `pending_rows` and `pending_bytes` until the identical request
is retried; the operator remedy is to retry that request, or to raise the
limit. This fails closed and does not weaken enforcement.

### Inspecting one operation

`GET /facts/quota/operation-status` takes `tenant`, `graph`, `batch_id`,
`operation_id` and `payload_digest` (64 hex characters); the complete
identity is required so a reused operation id cannot disclose another
operation's status. It requires the same `wr.sys.admin` permission as the
quota routes. A missing or malformed parameter is `400
invalid_fact_quota_operation_request`, an unknown operation is `404
fact_quota_operation_not_found`, and a known operation id under a different
identity is `409 fact_quota_operation_conflict`. The body reports
`state` (`pending`, `settled`, `reconciling`, or `cancelled`, which means the
commit failed and an identical retry reopens the reservation), `replay`,
`requested_rows`, `requested_bytes`, `applied_rows` and `applied_bytes`;
`applied_bytes` is `-1` while the applied bytes are unknown.

```sh
wyctl --daemon-url "$BASE_URL" fact quota operation-status \
  --tenant "$TENANT" --graph "$GRAPH" \
  --batch-id orders-1 --operation-id orders-1 \
  --payload-digest "$DIGEST" \
  --access-token-file "$TOKEN" \
  --guard-timestamp "$(date +%s)" --guard-loc-class trusted --guard-risk 29
```

The command prints one line,
`tenant=<tenant> graph=<graph> batch_id=<id> operation_id=<key>
state=<state> replay=<true|false> requested_rows=N requested_bytes=N
applied_rows=N applied_bytes=N`, and exits `0`. It exits `2` for a missing
target option or a digest that is not 64 hex characters, `3` when the daemon
rejects the request as malformed, `4` when the daemon denies the caller
(`403 fact_quota_denied`), `5` when the operation is not found or the
identity conflicts, and `6` when no valid access token is presented (`401`).
The daemon's error code is printed on stderr for every remote failure.

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

- Policy grant, arm and revoke. A grant alone leaves the permission dormant
  (`policy explain` reports `reason=not_armed`); arm it with
  `permission-transition --event grant` from an MFA-assured session. `grant`
  and `reset` both arm and both need MFA; a transition the state machine
  refuses exits 3. Arming applies only outside the guard catalogue in
  `wyrelog/wyl-permission-scope.c`, whose twelve permissions are
  `wr.sys.admin`, `wr.sys.key_rotate`, `wr.sys.merkle_seal`,
  `wr.policy.write`, `wr.policy.grant_role`, `wr.svc.freeze`,
  `wr.svc.unfreeze`, `wr.svc.grant_role`, `wr.service.self_authorize`,
  `wr.audit.read`, `wr.audit.explain` and `wr.stream.write_reserved`. Those
  are decided by the holder's grants and the request guard, and a transition
  for one exits 3 with `permission_not_armable`:

  ```sh
  wyctl --daemon-url http://127.0.0.1:8765 policy permission-grant \
    --subject alice --perm site.policy.read --scope tenant-a \
    --access-token-file /run/wyrelog/operator.token \
    --guard-timestamp "$(date +%s)" \
    --guard-loc-class trusted --guard-risk 10
  wyctl --daemon-url http://127.0.0.1:8765 policy permission-transition \
    --subject alice --perm site.policy.read --scope tenant-a --event grant \
    --access-token-file /run/wyrelog/operator.token \
    --guard-timestamp "$(date +%s)" \
    --guard-loc-class trusted --guard-risk 10
  wyctl --daemon-url http://127.0.0.1:8765 policy permission-revoke \
    --subject alice --perm site.policy.read --scope tenant-a \
    --access-token-file /run/wyrelog/operator.token \
    --guard-timestamp "$(date +%s)" \
    --guard-loc-class trusted --guard-risk 10
  ```

- Grant a role or list service principals. Both operations require a live
  MFA-assured operator token and guard context:

  ```sh
  wyctl --daemon-url http://127.0.0.1:8765 policy role-grant \
    --subject alice --role wr.system_admin --scope __wr_default \
    --access-token-file /run/wyrelog/operator.token \
    --guard-timestamp "$(date +%s)" \
    --guard-loc-class trusted --guard-risk 10
  wyctl --daemon-url http://127.0.0.1:8765 service-principal list \
    --tenant __wr_default \
    --access-token-file /run/wyrelog/operator.token \
    --guard-timestamp "$(date +%s)" \
    --guard-loc-class trusted --guard-risk 10
  ```

- Audit query:

  The audit database is profile-wide: an auditor can read events from every
  tenant in this daemon profile. Grant `wr.auditor` only at the reserved
  system scope `__wr_default`; a grant at an application-tenant scope does
  not authorize this endpoint. The auditor must be a separate principal from
  anyone with control or mutation authority at any scope. This includes
  direct or inherited `wr.sys.*` administration, policy writes and role
  grants, tenant management or MFA bypass, service/security operations,
  service-principal or credential management, graph/schema/fact writes,
  reserved-stream writes, and audit writes. Read-only permissions such as
  `wr.policy.read`, `wr.fact.read`, and `wr.datalog.query` alone do not
  disqualify an auditor. These boundaries apply across tenants because the
  audit endpoint returns the whole profile stream. A policy decision uses the
  published policy snapshot; a request already authorized may finish if the
  auditor grant is revoked while that request is in flight, while subsequent
  requests use the updated policy.
  Enroll the auditor in MFA and log in through `/auth/login` followed by
  `/auth/mfa/verify` as described in [the HTTP login flow](#http-api-summary).
  `wr.audit.read` is guarded: each query must supply an acceptable guard
  context, and risk must be below 70. It is a guard-catalogue permission, so
  the role grant and that guard decide it; there is no arming step. For
  example, an existing MFA-authenticated operator can grant the role with:

  ```sh
  wyctl --daemon-url http://127.0.0.1:8765 policy role-grant \
    --subject auditor --role wr.auditor --scope __wr_default \
    --access-token-file /run/wyrelog/operator.token \
    --guard-timestamp "$(date +%s)" \
    --guard-loc-class trusted --guard-risk 29
  ```

  The role takes effect at once. A `permission-transition` for
  `wr.audit.read`, or for any other guard-catalogue permission, is refused
  with exit status 3 and `permission_not_armable`, because no decision reads
  an armed state for these permissions; to withdraw it, revoke `wr.auditor`.
  To check the grant, pass the same guard to `policy explain`; without one it
  reports `reason=guard_unsatisfied` rather than the real outcome:

  ```sh
  wyctl --daemon-url http://127.0.0.1:8765 policy explain \
    --user auditor --permission wr.audit.read --resource __wr_default \
    --access-token-file /run/wyrelog/auditor.token \
    --guard-timestamp "$(date +%s)" \
    --guard-loc-class trusted --guard-risk 29
  ```

  Then use the auditor's MFA-issued token, not the operator token:

  ```sh
  wyctl --daemon-url http://127.0.0.1:8765 audit query \
    --filter 'decision=deny' --limit 50 \
    --access-token-file /run/wyrelog/auditor.token \
    --guard-timestamp "$(date +%s)" \
    --guard-loc-class trusted --guard-risk 29
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
  wyctl --daemon-url http://127.0.0.1:8765 profile status
  wyctl --daemon-url http://127.0.0.1:8766 profile status
  ```

  Each prints `profile=<system|service> system_url=<url|none>
  event_spool_dir=<path|none> event_queue_limit=<n>`. The route needs no
  credential; wyctl exits 1 when the daemon is unavailable or answers with an
  error.

  Service-profile event forwarding targets
  `http://127.0.0.1:8765/profile/events`. If the system profile is not
  reachable, the service profile keeps its local decision path isolated
  and uses the configured event spool directory as the bounded recovery
  surface.

## Routes Without a wyctl Command

Almost every daemon route an operator uses has a `wyctl` command.
The `check-wyctl-route-coverage` test fails the test suite when a route has
neither a command nor a recorded reason. To print the routes below and any
command still being added, run from the source tree:

```sh
python3 tools/check-wyctl-route-coverage.py . --list
```

These routes are reached only over HTTP:

- `/facts/{tenant}/{graph}/{relation}:repair`: repairs rows left by an old
  wrong-relation forget (see "Repairing rows left by an old wrong-relation
  forget"). There is no `wyctl` command for it yet (#1280).
- `/profile/events`: event forwarding from the service profile to the system
  profile. It is traffic between the two daemons, not an operator action.
- `/service-management-authority/arm`: arms the service-management authority
  for the caller's session (see "Arming the service-management authority").
  There is no `wyctl` command for it yet (#1269).
- `/service-credential-operations/reconcile`: reconciles a stalled
  service-credential operation. The client library exposes it; `wyctl` does
  not yet (#1270).

`/service-principals` and `/service-credentials` each serve several
operations, chosen by method and path. The gate counts each of them as one
route, covered by the `wyctl service-principal` and
`wyctl service-credential` commands, so an operation added inside either one
is not detected.

### Unsupported by the daemon

- `/tenants/delete`: the daemon answers every valid request with
  `501 tenant_delete_unsupported`. Tenants cannot be deleted; retire one by
  sealing it.

## Which Endpoint Reports What

`/readyz` reports whether **this process** can serve a correct query. It does
**not** reflect fact-subsystem health, and that is deliberate — see #874 for the
decision and its reasons.

`/facts/status` is the surface that reports fact health, and it is the endpoint
to watch for an outstanding erasure.

The typed C client exposes the current aggregate and per-graph fields through
`wyl_client_fact_status()`. The per-graph rows report tenant and graph
identifiers, so the daemon returns them only to an authenticated caller and
only for that caller's own tenant; pass the access token together with the
tenant it authenticates. Called with `NULL` for both, the client requests the
response anonymously and receives the aggregate counts alone. Use this API
only through the daemon's local listener and do not expose it through a remote
proxy: the C client rejects non-loopback daemon URLs for it. Future status
names are retained as wire strings
and map to the client's `UNKNOWN` enum value until that client is updated.
The decoder rejects snapshots larger than 4 MiB, more than 16,384 graphs, or
status/reason names longer than 64 bytes; it never returns a truncated list.

### Bounded replay scheduling

Startup, mutation refresh, unseal, and explicit reconciliation share one
tenant-fair replay scheduler. Work is FIFO within a tenant and round-robin
between ready tenants; the per-tenant concurrency and queue limits reserve
capacity so one tenant cannot occupy every worker or pending slot. Defaults
are 4 global workers, 1 worker per tenant, 1,024 global pending jobs, 64 pending
jobs per tenant, 1,000,000 materialized rows per replay, and 120 seconds per
replay. Tune them with `--fact-replay-global-concurrency`,
`--fact-replay-tenant-concurrency`, `--fact-replay-global-queue-limit`,
`--fact-replay-tenant-queue-limit`, `--fact-replay-row-limit`, and
`--fact-replay-time-limit-ms`. Tenant limits must remain below global limits;
invalid or zero explicit values stop startup.

Queue saturation rejects new replay work as busy. A row limit or timeout marks
only that graph degraded/retryable and retains its previous published engine;
no partial candidate becomes queryable. Shutdown closes scheduler admission,
cancels queued and active jobs, then waits for workers before closing the
policy store.

Unseal and explicit reconciliation acquire their scheduler admission token
before acquiring the thread-affine service-auth write lease. Queue waits
therefore hold neither that lease nor policy/runtime publication locks.
Startup enumerates graph identities, releases its startup policy pin, and only
then submits jobs. After admission, each worker captures that graph's authority,
materialization, activation, and schema in one policy read snapshot and releases
the SQLite transaction before opening DuckDB or entering runtime publication.
Targeted refresh uses the same immutable per-graph view. Unseal and explicit
reconciliation capture the view inside their already-open lifecycle publication
fence; that outer transaction remains held through atomic lifecycle/runtime
publication and is released by the fence owner. No policy generation is retained
while queued.

`/facts/status` exposes global, identifier-free counters in the stable
`replay_resources` object: active and queued jobs, replay-owned active store
reservations, completed work, rows,
runtime and queue delay, cancellations, timeouts, row-limit failures, and
queue/quota rejections. These fields contain no tenant IDs, graph IDs, paths,
or facts and therefore remain bounded-cardinality even in an authenticated
tenant-scoped response. The typed client returns a caller-sized snapshot from
`wyl_client_fact_replay_resources()` without changing `WylClientFactStatus`'s
ABI.

The typed C client also exposes the non-mutating graph verification endpoint
through `wyl_client_fact_graph_verify()`. It requires credentials bound to the
target tenant and returns only the verified tenant and graph identifiers; it
never returns a physical path or a raw verification error.

These are typed read-only status and verification APIs. They do not yet provide
typed reconciliation or `wyctl` fact status/verification/reconciliation
commands; those remain in the open #550 scope. Quota operation status is
separate: it has a typed route and a `wyctl` command, described in the
Tenant Resource Quotas section above.

| you want to know | endpoint | what it tells you |
| --- | --- | --- |
| is the process serving | `GET /readyz` | `200` and `ready\n`, or `503` with a reason |
| is any graph degraded | `GET /readyz?format=json` | `subsystems.facts` carries `graphs_total`, `graphs_ready`, `graphs_degraded`, `graphs_sealed` |
| did an audit record go missing | `GET /readyz?format=json` | `audit_errors`, monotonic; non-zero means at least one emission failed |
| which graph, and why | `GET /facts/status` | per-graph `state` and the aggregate; the per-graph rows require a credential and are scoped to the caller's tenant, so an anonymous caller receives the aggregate alone |
| what a tenant may still consume | `GET /facts/quota?tenant=..&dimension=..` | one quota dimension's configured limit and its usage fields; `POST` with the same query configures it |
| did a reconciling mutation settle | `GET /facts/quota/operation-status` | one logical quota operation's `state` and applied rows and bytes, addressed by its complete identity including the `payload_digest` from the `202` |

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

`graphs_sealed` is counted separately and is not part of `graphs_degraded`, so
a probe watching only the degraded count will not see a sealed graph. That is
the intended default -- a seal is your own decision -- but it means a sealed
graph that also owes an unconverged erasure raises nothing here. The `BOOT`
line is what names that.

### A lost audit record shows up as a count, not as a status

`audit_degraded` on `/readyz` means the audit store rejected a read or a write.
It converges: the endpoint re-probes the store on every request and returns to
`ready` once the store is healthy again, with no restart. If it reports
`audit_degraded` while you believe the store is healthy, the store is not
healthy *from this process* -- check the file's permissions and its WAL, then
poll again.

**Recovery is not amnesia, and for a single lost record it is the only signal
you get.** `audit_errors` in the `/readyz?format=json` body is monotonic and
never cleared. A one-shot emission failure -- one mutation whose audit row
could not be written, against a store that is fine a moment later -- never
shows a 503 at all, because the next probe finds the store healthy and clears
the flag. That is deliberate: losing one record should not withdraw the
process from service. It does mean **a probe watching only `status` will not
see it.** Alert on `audit_errors` being non-zero if you want to know.

Whatever the status says, a non-zero `audit_errors` means at least one audit
emission failed and its record is gone. Investigate that from the `AUDIT` log
lines, which name the error, and from the 5xx responses the affected clients
received -- not from `/readyz`, which by then reports `ready` truthfully.

**The plain-text `/readyz` carries no fact information at all.** The body is
exactly `ready\n` on success. Do not parse it for anything else, and note that
the failure path returns JSON rather than plain text.

A degraded graph may still be answering queries. `/facts/status` reports
`"queryable": true` for a graph whose engine is complete and correct for the
data that is present, even while that graph is counted in `graphs_degraded`. A
**sealed** graph is the one case where that does not follow: it reports
`"queryable": false`, because the barrier refuses reads whatever the engine
behind it looks like.
Read the per-graph `state` rather than inferring a cause from the aggregate,
and read the `BOOT` log lines, which name the graph and the reason directly.

## Backup And Restore

1. Stop the daemon:

   ```sh
   systemctl stop wyrelog-service.service
   systemctl stop wyrelog-system.service
   ```

2. While both units are stopped, take one offline backup set for each enabled
   profile. The policy store and the profile's complete Datalog fact root are
   a pair: the policy store is bound to that fact root, so capture and restore
   them from the same point in time and at the same paths. Include the entire
   fact root tree, not only selected `facts.duckdb` files.

   Packaged paths are:

   | Profile | Policy store | Fact root |
   | --- | --- | --- |
   | `system` | `/var/lib/wyrelog/system/policy.sqlite` | `/var/lib/wyrelog/system/facts` |
   | `service` | `/var/lib/wyrelog/service/policy.sqlite` | `/var/lib/wyrelog/service/facts` |

   Include each profile's KeyProvider root and audit store in the same backup
   set, plus the service event spool when present and the output of
   `wyrelogd --template-info`. Record the package and template release identity
   needed to restore the matching software and templates.

3. Keep both daemons stopped while restoring a backup set. Restore the policy
   store and its matching complete fact root together to their original paths,
   along with the matching KeyProvider, audit store, event spool when present,
   and template artifacts. Preserve owner, group, and mode throughout the
   restored trees. In particular, each packaged fact root must remain
   `0700 wyrelog:wyrelog` as defined by
   `packaging/tmpfiles.d/wyrelog.conf`; preserve the existing metadata of
   subordinate directories and files as well.

4. Before restarting, run the production `--check` command for each enabled
   profile with its restored policy store, KeyProvider, audit store, and
   fact root. Verify that each profile config resolves to those restored paths;
   set `fact_root` explicitly if it differs from the profile default. Both
   profile check commands are shown in [First Install](#first-install).
   This checks production startup/readiness requirements;
   it does not replace the post-start graph health checks below.

5. Start the profile units and verify each profile's fact health. Query
   `/facts/status?tenant=$TENANT` with a fresh authenticated token for every
   tenant whose graph stores were restored; inspect the returned graph states.
   Also query `/readyz?format=json` on each profile listener and check the
   `subsystems.facts` totals, ready, degraded, and sealed counts against the
   expected graph inventory. `/facts/status` supplies tenant-scoped graph
   detail; `/readyz?format=json` supplies process-wide aggregate counts.

This is an offline file-level recovery procedure. Validated staged restore and
publication are future work tracked by [#552](https://github.com/semantic-reasoning/wyrelog/issues/552).

## Template Upgrade

1. Stop both profile units and create the paired profile backups described in
   [Backup And Restore](#backup-and-restore) before changing the package or
   templates. Keep the previous package, installed template tree, and each
   profile's policy-store/fact-root pair available as one rollback set.

2. Install the new package without starting either daemon. Verify the
   installed template tree against the release note values:

   ```sh
   /usr/share/wyrelog/tools/verify-template-release.sh \
     /usr/bin/wyrelogd /usr/share/wyrelog/access \
     EXPECTED_VERSION EXPECTED_SHA256 \
     EXPECTED_MIGRATIONS EXPECTED_LATEST_MIGRATION_VERSION
   ```

3. Run production `--check` for each profile against its existing policy,
   audit, KeyProvider, and fact-root paths.
4. Start the profile units. Check `/readyz?format=json` for aggregate fact
   health and use authenticated `/facts/status?tenant=$TENANT` requests to
   inspect each restored tenant's graph states.
5. If verification fails, stop both units and roll back the package and
   template tree together with the matching policy-store/fact-root pair,
   KeyProvider, audit store, and event spool backup when present. Preserve
   ownership and modes, rerun production `--check` for both profiles, then
   restart and repeat the health checks.

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

`/etc/wyrelog/system.env` and `/etc/wyrelog/service.env` (the profile
units' `EnvironmentFile=` entries) carry
process-level environment variables (`WYL_LOG`, `WYL_CONFIG`, etc.),
not daemon-config keys. The two are complementary, not redundant:
the env file controls what the systemd-launched process sees in
its environment; the config file controls what the daemon's option
parser inflates into `WylDaemonOptions`.

### systemd Wiring

The packaged units (`wyrelog-system.service`, `wyrelog-service.service`)
thread separate profile configs through the daemon's `--config` flag and pin
production gating with `--production`. The legacy `wyrelog.service` is
mutually exclusive with both profile units; the system and service profile
units are designed to run together:

```ini
[Service]
Environment=WYL_LOG=warn
EnvironmentFile=-/etc/wyrelog/system.env
ExecStart=/usr/bin/wyrelogd --config /etc/wyrelog/system.conf --production
ProtectSystem=strict
ReadOnlyPaths=/etc/wyrelog /usr/share/wyrelog
ReadOnlyPaths=/etc/wyrelog/system.conf
```

For the service profile, use `/etc/wyrelog/service.conf` in both `ExecStart=`
and `ReadOnlyPaths=`. Operator customization should edit the corresponding
profile config rather than redefining the entire `ExecStart`. The
`ProtectSystem=strict` and `ReadOnlyPaths=`
lines are the parent-directory defense against attacker-controlled
symlink swaps of `/etc/wyrelog/` itself — drop-ins that override
`ExecStart=` must preserve them.

### Migration Recipe

The packaged units now read `/etc/wyrelog/system.conf` and
`/etc/wyrelog/service.conf`. The old shared `/etc/wyrelog/wyrelogd.conf` is
no longer read by either profile unit. Complete this migration before
restarting upgraded units. Run the following commands as root.

1. Stop both profiles and disable the legacy unit before changing configuration:

   ```sh
   systemctl stop wyrelog-service.service wyrelog-system.service
   systemctl disable --now wyrelog.service
   ```

   The legacy unit remains installed for compatibility but is mutually exclusive
   with both profile units. Conflicts and stop/start ordering prevent overlap
   with the legacy daemon; the two profile units can run together.

2. Back up existing configuration and systemd drop-ins. If the shared
   `/etc/wyrelog/wyrelogd.conf` exists, inspect `profile` in its `[daemon]`
   section and preserve its contents. A missing, invalid, or ambiguous profile
   requires manual resolution before proceeding. Transfer its site-specific
   settings only to the matching profile; never copy it to both destinations.
   Preserve the existing policy keys, databases, fact roots, and event spool.
   Do not repeat the fresh-install key generation for an existing profile.

3. Install examples only for missing destination files:

   ```sh
   install -d -m 0750 -o root -g wyrelog /etc/wyrelog
   if [ ! -e /etc/wyrelog/system.conf ]; then
     install -m 0640 -o root -g wyrelog \
       /usr/share/wyrelog/examples/wyrelogd-system.conf.example \
       /etc/wyrelog/system.conf
   fi
   if [ ! -e /etc/wyrelog/service.conf ]; then
     install -m 0640 -o root -g wyrelog \
       /usr/share/wyrelog/examples/wyrelogd-service.conf.example \
       /etc/wyrelog/service.conf
   fi
   ```

   Merge the saved settings into the matching destination manually, preserving
   any existing destination customizations. Review both files: `profile=system`
   and port 8765 belong in `system.conf`; `profile=service` and port 8766 belong
   in `service.conf`. Keep policy, audit, fact, key, and spool paths separate.
   If adding a previously unused profile, provision its own key and directories
   using the corresponding steps in [First Install](#first-install).

4. Review local systemd drop-ins that override `ExecStart=` or credentials.
   Remove obsolete shared-config overrides or change them to the matching
   profile path. Preserve `--production`, `ReadOnlyPaths=`, and the correct
   `LoadCredential=`. Then set config permissions and check both configs:

   ```sh
   chown root:wyrelog /etc/wyrelog/system.conf /etc/wyrelog/service.conf
   chmod 0640 /etc/wyrelog/system.conf /etc/wyrelog/service.conf
   wyrelogd --config /etc/wyrelog/system.conf --production \
     --policy-keyprovider file:/etc/wyrelog/system/policy.key --check
   wyrelogd --config /etc/wyrelog/service.conf --production \
     --policy-keyprovider file:/etc/wyrelog/service/policy.key --check
   ```

   Substitute existing site-specific key paths when needed. Resolve any failed
   check before continuing. These commands use the installed configs, with a
   file KeyProvider override because they run outside systemd credentials.

5. Only after both configs and keys are ready, reload and start the pair:

   ```sh
   systemctl daemon-reload
   systemctl enable --now wyrelog-system.service wyrelog-service.service
   ```

   Verify both listeners using the status commands in
   [First Install](#first-install). Retain the old shared config backup until
   migration succeeds. A missing config makes the daemon exit and systemd
   retry it; create both files before enabling either unit. For a custom config
   path, update both `ExecStart=` and its `ReadOnlyPaths=` pin.

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
... (remove bootstrap_admin_subject from the active profile config and restart)
```

When both `bootstrap_admin_subject` and
`bootstrap_admin_allow_skip_mfa` are set:

```
... (remove bootstrap_admin_subject and bootstrap_admin_allow_skip_mfa from the active profile config and restart)
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

Migration practice: delete the `bootstrap_admin_*` keys from the active
profile config (`/etc/wyrelog/system.conf` or `/etc/wyrelog/service.conf`)
after first successful boot. The shipped example confs leave both keys
commented out for exactly this reason.

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

These trade-offs make GKeyFile + profile-specific `/etc/wyrelog/*.conf` files
the right surface for `wyrelogd`. The wyctl GSettings layer below is
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

Packaged daemon profiles read `/etc/wyrelog/system.conf` and
`/etc/wyrelog/service.conf` (see the previous section); custom deployments
may pass another path with `--config`. wyctl and wyrelogd intentionally do **not** share a single
GSettings tree. The same value (e.g. `tenant`) lives in two places by
design because each surface answers a different question: the daemon
config decides what tenants the daemon will service, the wyctl
defaults decide which tenant the operator at this workstation routes
their CLI calls to. Keeping the two explicit makes audit-trail review
honest about which surface acted.

### HTTP Proxy Schemas

When the GNOME GIO proxy resolver is installed, HTTP commands check that
`org.gnome.system.proxy` and its HTTP, HTTPS, FTP, and SOCKS child schemas
are reachable before creating a client. Missing schemas produce a `wyctl:`
diagnostic and a normal nonzero exit instead of a GLib abort. Restore the
system schema directory in `XDG_DATA_DIRS` (usually `/usr/share`) or point
`GSETTINGS_SCHEMA_DIR` at a directory containing the compiled GNOME schemas.
A nonempty `XDG_DATA_DIRS` replaces the system search path.

If direct access is intended, explicitly set `GIO_USE_PROXY_RESOLVER=dummy`;
this disables proxy use. wyctl never selects this setting automatically.
With missing schemas and the GNOME backend installed, other explicit
resolver selections are conservatively rejected too: unavailable or
unsupported selections can fall back to GNOME. Systems without that backend
have no GNOME schema requirement. Normal proxy selection is unchanged when
all required schemas are visible.

`WYCTL_DISABLE_GSETTINGS=1` disables wyctl's configuration defaults only;
it does not disable GIO proxy settings. Help, version, offline operations,
and validation failures reached before HTTP client construction remain usable.

### Schema Overview

- Schema id: `org.wyrelog.wyctl`
- Schema path: `/org/wyrelog/wyctl/`
- Install location: `${datadir}/glib-2.0/schemas/org.wyrelog.wyctl.gschema.xml`
- After install the package runs `glib-compile-schemas` against the
  schemas directory to refresh `gschemas.compiled`. Manual installs that
  copy the schema in place must run `glib-compile-schemas
  ${datadir}/glib-2.0/schemas` afterwards. If the schema is unavailable,
  wyctl still accepts CLI options and diagnoses the first attempted
  GSettings fallback.

### When wyctl ignores a value `gsettings get` returns

First check for a `wyctl: GSettings fallback unavailable:` message on
stderr. wyctl emits at most one such diagnostic per invocation, when an
option actually needs a fallback that cannot be read. It distinguishes:

- `schema not found`: `org.wyrelog.wyctl` is not reachable.
- `untrusted schema source`: a source that could be changed by a non-root
  user was ignored. A protected lower-priority source may still provide the
  selected schema and value.
- `missing key`: the selected schema lacks the requested key.
- `expected type`: the key exists but has an incompatible type. The message
  gives the actual and expected types (`s` for strings, `u` for unsigned
  32-bit values).

Install the schema matching the wyctl version, run `glib-compile-schemas`
for its directory, and check `GSETTINGS_SCHEMA_DIR`, `XDG_DATA_HOME`, and
`XDG_DATA_DIRS`. An older schema earlier in the search path can shadow the
installed one. Explicit CLI options let the command proceed without those
fallbacks. The diagnostic contains schema/key names and types, never stored
values or credentials.

Only the first unusable fallback is reported; other affected options still
resolve as unset. The command keeps its existing missing-option messages
and exit status. Opening settings alone, help/version, explicit CLI values,
valid empty defaults, and intentional `WYCTL_DISABLE_GSETTINGS=1` do not
produce this diagnostic. A command that succeeds using an internal default
may still print it for an unavailable fallback it attempted.

When the effective UID is root, wyctl builds a separate schema-source chain
and accepts only root-owned schema directories and regular `gschemas.compiled`
files that are not group- or other-writable. It checks every directory and
symlink in the path, including resolved symlink targets. On Linux, a
root-owned sticky ancestor such as `/tmp` is allowed when the next path entry
is itself protected. On macOS, extended ACLs that grant mutation access are
rejected. Linux also requires each directory and the opened cache to reside on
XFS, ext2/ext3/ext4, Btrfs, tmpfs, or ramfs; unknown filesystems and inspection
errors are rejected. This intentionally excludes overlayfs, network
filesystems, and FUSE mounts, including many container installations. Other
Unix systems disable root's schema fallback because wyctl cannot verify their
permission model. Unsupported or unverifiable permissions make that source
unavailable. The chain keeps GLib's precedence among accepted locations:
`GSETTINGS_SCHEMA_DIR`, the user data directory, then system data directories.
There are no path-prefix exceptions: a protected custom prefix works, while
a user-owned Homebrew or profile tree is ignored when running as root.

Set-ID or secure-execution processes do not use wyctl's GSettings defaults.
Explicit CLI options remain available. Opening settings alone is quiet; if a
command actually needs a fallback, wyctl reports once that an unsafe source
was ignored, even when a trusted lower-priority source supplied the value.

This check protects schema defaults from unprivileged filesystem writers. It
does not establish trust in values loaded from a GSettings backend selected by
preserved environment variables, and it does not defend against root, mount
administrators, or a filesystem that lies about ownership and permission
metadata. For privileged invocations, use a controlled target-account
environment and explicit CLI options as described in
[offline maintenance](#offline-maintenance-defaults-via-gsettings).

Schema visibility and account-specific settings are separate problems:

**The schema wyctl could reach.** wyctl once consulted only the first
schema source in GLib's chain rather than walking it, so a correctly
installed schema was invisible to wyctl while `gsettings` found it. Any
other directory carrying compiled schemas ahead of wyrelog's was enough,
and with `GSETTINGS_SCHEMA_DIR` unset that includes
`$XDG_DATA_HOME/glib-2.0/schemas`, which outranks every `XDG_DATA_DIRS`
entry. Fixed in the release carrying issue #1190; wyctl now walks the
chain. If you are on an older build, upgrading resolves it.

**Whose settings wyctl reads under `sudo`.** GSettings values belong to
the account and backend environment in which they were written. Under a
usual `sudo` environment-reset policy, `HOME` becomes `/root` and
`sudo wyctl` reads the target account's settings rather than the invoking
operator's. Making the same schema available to both commands does not
copy the operator's saved values. `gsettings get` run as yourself therefore
does not establish what a privileged wyctl will read.

The supported privileged workflow is to pass the needed CLI options
explicitly, as in [offline maintenance](#offline-maintenance-defaults-via-gsettings)
above. This also works when root has no configured GSettings defaults.
Do not use `sudo -E` or add a `sudoers` `env_keep` rule just to make this
recipe work; forwarding the operator's settings environment is not part
of the supported recipe. GSettings remains available for same-account
invocations, including a separately configured target-account backend,
but this runbook does not require provisioning root's settings or a
system-wide defaults layer.

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

`--timeout-ms`, or `default-timeout-ms` when it is omitted, bounds every
daemon request a command sends: connecting, uploading the request (a fact
batch included), and reading the answer. The default is 2000 ms and the
limit is 60000 ms, so wyctl cannot wait for an operation that takes longer
than a minute; raise the value for large fact batches, heavy queries, or
long erasures, as the forget example above does. A request that runs out of
time exits like any other transport failure, and the daemon may still have
completed it. For policy grants, revokes and transitions, fact put and
retract, fact forget, fact schema register, fact quota configure, graph
create and seal, tenant create, seal and unseal, service-principal create
and disable, and service-credential issue, rotate and revoke, wyctl adds a
line saying that the outcome is unknown and how to find out; the online
`mfa enroll` says whether a re-run is safe (see "First-Install Bootstrap");
other commands, such as `auth logout`, report only the failure, so check the
daemon's state before repeating them.

Example: configure the operator workstation once and let wyctl invocations
in that same account and settings-backend environment pick up the defaults.
These per-user values are not automatically inherited by `sudo wyctl`.

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

### CLI daemon error diagnostics

When a daemon request fails, `wyctl` includes the daemon's bounded JSON
`error` code in stderr, for example `decide_denied`, `audit_denied`, or
`service_token_denied`. Malformed error envelopes use a command-specific
fallback. Response bodies and credentials are not printed.

`policy check`, `policy explain`, `audit query`, and `auth service-token`
use exit 2 for local invalid input, 3 for daemon-invalid input or malformed
success responses, 4 for policy refusal, 5 for transport/server failures,
and 6 for authentication failures. A successful policy check whose decision
is `deny` still prints `deny` and exits 1; `policy explain` exits 0 for a
successfully retrieved decision. Human login, refresh, logout, and status
retain their existing exit codes and include the daemon error code when present.

`policy permission-grant`, `permission-revoke`, `permission-transition`,
`role-grant`, and `role-revoke` also print the daemon's error code. The code
is what separates refusals that share an exit status. For example, exit 4
may come with `policy_denied` (the caller lacks the authority, or the
MFA-assured session, that the operation needs at that scope),
`tenant_denied`, or `policy_mutation_denied` (the policy store refused the
change). These are examples, not a complete list, and one code can appear
with more than one exit status. When the response carries no code, these
commands fall back to `invalid_policy_mutation` (exit 3),
`policy_mutation_denied` (exit 4), `policy_mutation_failed` (exit 5), or
`policy_auth_required` (exit 6). When no readable answer arrived, or the
daemon reported a server error, they add a line saying the outcome is unknown
and whether repeating the command is safe. Unlike the commands above, they
print `ok` for any successful response without reading its body, and a
request the client refuses before sending it exits 3, not 2. As with every
command, `wyctl`'s own argument errors exit 2.
