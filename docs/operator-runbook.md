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
- Service KeyProvider root: `/etc/wyrelog/service/policy.key` loaded by
  systemd as credential `wyrelog-service-policy-key`
- Service policy store: `/var/lib/wyrelog/service/policy.sqlite`
- Service audit store: `/var/log/wyrelog/service/audit.duckdb`
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
- Service policy store: `/var/lib/wyrelog/service/policy.sqlite`
- Service KeyProvider root: `/etc/wyrelog/service/policy.key`
- Service audit store: `/var/log/wyrelog/service/audit.duckdb`
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
  the `wr.login.skip_mfa` direct permission so it can mint a first
  bearer token through `/auth/login` before an IdP is wired in.

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
  subject. The grant survives daemon restarts and the flag's
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
subject. The grant survives daemon restarts and the flag's
presence/absence on subsequent boots, so it must be revoked
explicitly once the operator has rotated to an IdP-issued bearer:

```sh
wyctl --daemon-url http://127.0.0.1:8765 policy permission-revoke \
    --subject <bootstrap-subject> \
    --perm wr.login.skip_mfa \
    --scope __wr_default \
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
