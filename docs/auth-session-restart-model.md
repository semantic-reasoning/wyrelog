# LoBAC Auth Restart and JWT Key Model

LoBAC v0 uses a restart-invalidates-all auth/session model.

## Restart Semantics

Daemon restart invalidates every in-memory HTTP session, access token,
refresh token, refresh successor, refresh reuse marker, and logout tombstone.
Clients must treat any authentication failure after restart as a full
reauthentication requirement.

Stable wire errors after restart:

- Bearer-protected endpoints return their existing `*_auth_required` code.
- `/auth/refresh` returns `refresh_auth_required`.
- Tenant mismatch remains fail-closed through `tenant_invalid` or
  `tenant_denied` before endpoint-specific authorization continues.

This model intentionally does not persist refresh-token state. A restart
cannot resurrect a logged-out session or revoked refresh token because no
previous token state is reloaded.

## JWT Signing Key Custody

Production JWT signing key material is rooted in the configured production
KeyProvider path. On each daemon boot, the daemon derives a JWT root secret
from the KeyProvider and mixes in a random boot epoch before issuing tokens.
The boot epoch is reflected in the JWT `kid`, so tokens from a previous
process epoch fail the key-id gate before they can bind to live token state.

Non-production mode continues to use process-local random JWT key material.

## Rotation Behavior

JWT signing-key rotation is epoch rotation. Rotating the epoch clears active
access-token and refresh-token state and changes the JWT `kid`. Existing
session handles remain in memory, but clients must login again because old
access and refresh tokens no longer authenticate.

Operator runbook:

1. Rotate the production KeyProvider material if the root must change.
2. Restart the daemon to create a new boot epoch.
3. Expect all clients to receive `*_auth_required` or
   `refresh_auth_required` and perform a fresh login.
4. Confirm `/readyz` returns ready before admitting traffic.
