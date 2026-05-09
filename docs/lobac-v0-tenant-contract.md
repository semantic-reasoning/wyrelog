# LoBAC v0 Single-Tenant Contract

## Overview

LoBAC v0 ships as a **single-tenant** access-intelligence runtime. The
public wire surface, the public C API, and the bootstrap policy template
all share one canonical tenant identity. Multi-tenant capabilities
described in the parent design (#5) and the profile-separation work (#2)
are deferred to v1.

## Canonical tenant

The only accepted tenant value is the literal:

```
__wr_default
```

This value is exposed internally as the `WYL_TENANT_DEFAULT` constant
(`wyrelog/wyl-common-private.h`) and is the only value the daemon and
client library will accept across every surface that takes a tenant:

- `wyl_session_login` (and the libwyrelog session minting path)
- `POST /auth/login` (HTTP login surface)
- `POST /decide` (decision surface)
- `GET  /policy` (policy read surface)
- `GET  /audit` (audit query surface)
- JWT bearer-token `claims.tenant`
- `wyl_client_tenant_select` (C API tenant selector)

Any other literal — including the empty string, an unknown identifier,
or a foreign-looking literal such as `evil-co` — is rejected.

## Wire-format error codes

The HTTP gate emits two stable string codes scoped exclusively to the
tenant check. These are defined in `wyrelog/daemon/http.c` as
`WYL_DAEMON_ERR_TENANT_INVALID` and `WYL_DAEMON_ERR_TENANT_DENIED`:

| Code              | HTTP status | Meaning                                                                                                  |
|-------------------|-------------|----------------------------------------------------------------------------------------------------------|
| `tenant_invalid`  | 400         | The request declares a tenant value the daemon does not recognise. In v0 anything other than `__wr_default` is unknown. |
| `tenant_denied`   | 403         | The authenticated principal's tenant does not match the tenant declared on the request.                  |

`tenant_invalid` is also emitted with HTTP 401 by the bearer-token
verifier when a JWT carries a `claims.tenant` the daemon does not
recognise. Status differs because the failure surfaces during auth, not
on a malformed request body.

The two codes are wire strings only; the existing `wyrelog_error_t`
enum is unchanged. Clients keying on these codes can distinguish a
malformed-tenant request from a credential/tenant mismatch without
relying on handler-specific generic shape codes.

## Defense in depth

The bearer-token verifier enforces `claims.tenant == __wr_default`
**directly**, independent of the transitive session check. Verification
order in `resolve_bearer_session`:

1. Verify JWT signature.
2. Resolve the live session referenced by the token.
3. **Direct check**: `wyl_daemon_tenant_is_known(claims.tenant)` —
   reject with `tenant_invalid` (HTTP 401) on any non-canonical value.
4. Equality check: `claims.tenant == session.tenant`.

The direct check is redundant with the session-mint gate today, but it
stops a future relaxation upstream (for example, a multi-tenant prep
change to `login_tenant_is_valid`) from silently relaxing JWT
acceptance. The session-token auth path does not carry a per-token
tenant claim and is gated by `ensure_auth_context_request_tenant`
through the request query parameter, so no analogous check is needed
there.

## Public API surface

The following public symbols exist and remain stable across v0 → v1
for forward compatibility, but in v0 they reject any non-canonical
value with `WYRELOG_E_INVALID`:

- `wyl_client_tenant_select` (`wyrelog/client.h`)
- `wyl_client_dup_tenant`     (`wyrelog/client.h`)
- `wyl_login_req_set_tenant`  (`wyrelog/session.h`)
- `wyl_login_req_get_tenant`  (`wyrelog/session.h`)
- `wyl_session_dup_tenant`    (`wyrelog/session.h`)

Callers written against the v0 wire contract will keep compiling once
the multi-tenant widening lands; only the runtime accept-set widens.

## What is NOT shipped in v0

The following are explicitly out of scope for v0 and tracked as
follow-up work against the parent multi-tenant design (#5) and the
profile-separation issue (#2):

- Tenant registry storage (no per-tenant rows in the policy store).
- Tenant CRUD admin API (no `POST /tenants`, no listing surface).
- Per-tenant data-encryption keys / TPM-sealed scope per tenant.
- Cross-tenant isolation regression suite.
- Audit-row tenant column and per-tenant audit partitioning.

A v0 deployment that needs a second tenant must wait for v1; there is
no supported workaround through configuration, environment, or runtime
flag.

## SemVer note

Single-tenant is a **pre-1.0 contract**. Widening the runtime
accept-set to admit additional tenants is an API/wire behavior change
and requires a major-version bump (v1). Until then, both the bootstrap
DL template (`templates/access/bootstrap.dl`) and the daemon's
`wyl_daemon_tenant_is_known` predicate are the source of truth for the
single accepted value.
