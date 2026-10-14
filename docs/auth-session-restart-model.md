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

## Session Credentials and Internal Identity

Human login returns an opaque `session_token`: `wst_` followed by 64 lowercase
hexadecimal characters encoding 32 random bytes. It is independent of the
internal UUID session ID. The daemon retains only a SHA-256 digest for credential
lookup; JWT claims, session state, policy scopes, and revocation
markers use the internal ID. Neither that ID nor the digest authenticates as a
session token. Service sessions do not have a human session credential.

MFA verification returns the same session token. Refresh responses, including
idempotent replays, omit `session_token`: they rotate access/refresh tokens and
do not recover or replace the original secret. Clients must retain the secret
from login if they need session-token authentication. The C client preserves it
on ordinary refresh; replacing its refresh token explicitly clears the old
session secret, so restoring only a refresh token yields bearer-only state.
External clients that required `session_token` in refresh responses must adapt.
Login and MFA responses still include it.

The legacy `/decide` parameter named `session_token` also accepts policy scopes.
A live `wst_` credential is translated to its internal ID before evaluation;
an unresolved value with that reserved prefix is rejected, including a logged-out
token. Other policy scope values retain their existing meaning.

New session-related audit fields store `session#` followed by 64 lowercase hex
characters: SHA-256 of `wyrelog.audit.session.v1:` followed by the internal ID.
This deterministic correlation handle is not a credential or a policy scope.
Session-state and session-event subjects always use it; decision resources and
permission/membership scopes use it only for known session identities. Other
resources, including unrelated UUIDs, retain their original representation.

A handle-local digest set classifies identities before session publication and
retains them through logout for delayed removal events. This set grants no
access and does not track liveness. Startup rebuilds it from persisted
session lifecycle events before loading policy facts; it does not classify ordinary tenant
scopes. HTTP service sessions register their identity before publication.

Existing hash-chained audit rows are not rewritten. Legacy read-time structural
and live-ID redaction remains in place, using process-local keyed handles with
16 hex digits. Newly stored 64-digit handles pass through unchanged. A restart
invalidates old credentials, including those that once doubled as internal IDs;
historical files still require their existing protections.

## JWT Signing Key Custody

Production JWT signing key material is rooted in the configured production
KeyProvider spec. Packaged Linux services use `systemd-creds:NAME`, where
systemd exposes the credential under `$CREDENTIALS_DIRECTORY`; manual
operator checks may use `file:PATH`. On each daemon boot, the daemon derives a
JWT root secret from the KeyProvider and mixes in a random boot epoch before
issuing tokens.
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
