# Wyrelog Operator Runbook

This runbook closes the supported Linux production path for a packaged
Wyrelog application service deployment. It assumes the package installs
`wyrelogd`, `wyctl`, the access-control template tree, and the systemd
support files from `packaging/`.

## Installed Layout

- Binaries: `/usr/bin/wyrelogd`, `/usr/bin/wyctl`
- Templates: `/usr/share/wyrelog/access`
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
2. Run `wyrelogd --template-info` and record version, hash, migration
   count, and latest migration version.
3. Run production `--check` against the existing policy and audit stores.
4. Restart the service.
5. If readiness fails, roll back the package and restore the previous
   template tree and policy store backup.

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
