# Wyrelog Operator Runbook

This runbook closes the supported Linux production path for a packaged
Wyrelog application service deployment. It assumes the package installs
`wyrelogd`, `wyctl`, the access-control template tree, and the systemd
support files from `packaging/`.

## Installed Layout

- Binaries: `/usr/bin/wyrelogd`, `/usr/bin/wyctl`
- Templates: `/usr/share/wyrelog/access`
- Daemon environment: `/etc/wyrelog/wyrelogd.env`
- Policy KeyProvider state: `/etc/wyrelog/policy.key`
- Policy store: `/var/lib/wyrelog/policy.sqlite`
- Audit store: `/var/log/wyrelog/audit.duckdb`
- Runtime directory: `/run/wyrelog`
- HTTP listen port: `127.0.0.1:8765` unless overridden by the service file
- Production log policy: compile release builds with
  `-Dwyrelog_log_max_level=warn`; packaged runtime defaults set
  `WYL_LOG=warn`

## First Install

1. Install the package and create managed users/directories:

   ```sh
   systemd-sysusers /usr/lib/sysusers.d/wyrelog.conf
   systemd-tmpfiles --create /usr/lib/tmpfiles.d/wyrelog.conf
   ```

2. Create the production KeyProvider state once:

   ```sh
   install -m 0640 -o root -g wyrelog /dev/null /etc/wyrelog/policy.key
   python3 - <<'PY'
import os
with open("/etc/wyrelog/policy.key", "wb") as f:
    f.write(os.urandom(32))
PY
   chown root:wyrelog /etc/wyrelog/policy.key
   chmod 0640 /etc/wyrelog/policy.key
   ```

3. Validate package readiness before starting the daemon:

   ```sh
   wyrelogd --production \
     --template-dir /usr/share/wyrelog/access \
     --policy-db /var/lib/wyrelog/policy.sqlite \
     --policy-keyprovider /etc/wyrelog/policy.key \
     --audit-db /var/log/wyrelog/audit.duckdb \
     --check
   wyrelogd --template-info --template-dir /usr/share/wyrelog/access
   wyctl key status --keyprovider /etc/wyrelog/policy.key
   ```

4. Start and verify service readiness:

   ```sh
   systemctl enable --now wyrelog.service
   wyctl --daemon-url http://127.0.0.1:8765 status
   wyctl --daemon-url http://127.0.0.1:8765 status --readiness
   ```

## Day-2 Operations

- Template validation:

  ```sh
  wyrelogd --template-info --template-dir /usr/share/wyrelog/access
  wyrelogd --production --template-dir /usr/share/wyrelog/access \
    --policy-db /var/lib/wyrelog/policy.sqlite \
    --policy-keyprovider /etc/wyrelog/policy.key \
    --audit-db /var/log/wyrelog/audit.duckdb --check
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
  systemctl restart wyrelog.service
  wyctl --daemon-url http://127.0.0.1:8765 status --readiness
  ```

  Access and refresh tokens are invalidated by daemon restart. Operators
  must obtain fresh credentials after restart.

## Backup And Restore

1. Stop the daemon:

   ```sh
   systemctl stop wyrelog.service
   ```

2. Back up `/etc/wyrelog/policy.key`,
   `/var/lib/wyrelog/policy.sqlite`, `/var/log/wyrelog/audit.duckdb`,
   and the output of `wyrelogd --template-info`.

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
3. Replace `/etc/wyrelog/policy.key` with a new 32-byte file using mode
   `0640`, owner `root`, and group `wyrelog`.
4. Run `wyctl key status --keyprovider /etc/wyrelog/policy.key`.
5. Run production `--check`, then start the daemon.

Changing the KeyProvider root invalidates sealed policy-store material
that was written under the previous root. Perform root rotation only with
a coordinated restore or migration plan.

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
