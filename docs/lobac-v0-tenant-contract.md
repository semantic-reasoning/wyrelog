# LoBAC Tenant Lifecycle Contract

## Overview

LoBAC keeps `__wr_default` as the built-in tenant for compatibility, and
adds an explicit tenant registry in the policy store for additional
tenants. A tenant must be present and unsealed in that registry before
the daemon accepts login, decision, policy mutation, or authenticated
audit requests for it.

The lower-level session API validates tenant syntax and binds the
selected tenant into the session. The HTTP daemon remains authoritative
for registry membership, sealed state, and cross-tenant isolation.

## Default Tenant

The default tenant literal is:

```
__wr_default
```

It is exposed internally as `WYL_TENANT_DEFAULT`
(`wyrelog/wyl-common-private.h`) and is seeded during policy-store schema
creation and bootstrap template installation. The default tenant cannot
be sealed.

## Tenant Lifecycle

Tenant rows live in the policy store `tenants` table. The HTTP tenant
lifecycle surface is guarded by the `wr.tenant.manage` permission on the
default tenant.

| Method | Path              | Target parameter | Result |
|--------|-------------------|------------------|--------|
| `GET`  | `/tenants`        | none             | Lists known tenants and sealed state. |
| `POST` | `/tenants/create` | `name`           | Creates a tenant idempotently. |
| `POST` | `/tenants/seal`   | `name`           | Marks a tenant inactive. |
| `POST` | `/tenants/unseal` | `name`           | Reactivates a sealed tenant. |
| `POST` | `/tenants/delete` | `name`           | Returns `501 tenant_delete_unsupported`; deletion semantics are intentionally unsupported. |

`tenant=` in query strings remains the request/auth tenant. Lifecycle
targets use `name=` so target selection cannot be confused with the
credential tenant.

`POST /tenants/seal` additionally requires a strict JSON body no larger than
1024 bytes:

```json
{"version":"1","request_id":"<canonical 27-character KSUID>"}
```

The body request ID is the caller's durable idempotency key and is separate
from the per-attempt `X-Wyrelog-Request-Id` response header. An exact authorized
retry returns the original `changed` result without another audit, receipt,
authority transition, or service-session invalidation. A fresh key against an
already stable sealed tenant is an audited no-op with `changed:false`.

Tenant lifecycle state is also decision state. Every registered tenant is
projected into the policy engine's `session_state(scope, state)` input: an
unsealed tenant projects `active`, and a sealed tenant projects `closed`.
Create, seal, and unseal publish a complete durable snapshot before returning
success, so subsequent decisions observe the new state without a daemon
restart or manual policy reload. If a legacy human-session row uses the same
textual identifier as a tenant, the tenant row is authoritative for that
scope; the human row and its event history remain durable and become visible
again only if that identifier is no longer owned by the tenant registry.

Private templates that omit `session_state` remain compatible only with the
pristine built-in `__wr_default` tenant and no durable human session states.
Once another tenant or human state exists, opening such a template fails
closed. A declared `session_state` relation must have exactly two non-compound
symbol columns.

Tenant seal does not perform the graph-drain lifecycle owned by #549.
`active`, `sealing`, or `unsealing` therefore returns
`503 tenant_lifecycle_coordination_required` without mutation. If an earlier
seal receipt is no longer authoritative after unseal/reseal or another
lifecycle transition, the old key returns `409 tenant_seal_superseded` and the
body includes `recorded_lifecycle_generation`,
`recorded_sealed_generation`, `current_lifecycle_generation`, and
`current_sealed_generation`. Other key collisions return
`409 tenant_seal_conflict`; authority unavailability returns 503, and durable
receipt/audit/terminal-row corruption returns 500.

## Wire-Format Error Codes

The HTTP gate emits stable string codes in the JSON `error` field:

| Code              | HTTP status | Meaning |
|-------------------|-------------|---------|
| `tenant_invalid`  | 400 or 401  | The request or credential names a syntactically invalid or unknown tenant. |
| `tenant_sealed`   | 400 or 401  | The tenant exists but is sealed and cannot accept new authenticated work. |
| `tenant_denied`   | 403         | The authenticated principal's tenant does not match the tenant declared on the request, or a non-default tenant attempts to mutate another tenant's scope. |

The status is 401 when the failure is detected while resolving
credentials, and 400/403 when it is detected while validating the
request body or query parameters.

## Isolation Rules

Sessions, JWT bearer credentials, refresh-token rotation, decisions,
audit queries, and policy mutations carry a tenant binding. The daemon
fails closed before mutation or decision when:

- the request tenant is unknown or syntactically invalid;
- the tenant exists but is sealed;
- a live session or JWT claim is bound to a different tenant;
- a non-default tenant attempts to mutate policy for a different scope.

The default tenant retains legacy administration behavior and may manage
other tenant scopes through the guarded policy-mutation APIs.

## Public API Surface

The public tenant symbols remain stable:

- `wyl_client_tenant_select` (`wyrelog/client.h`)
- `wyl_client_dup_tenant` (`wyrelog/client.h`)
- `wyl_login_req_set_tenant` (`wyrelog/session.h`)
- `wyl_login_req_get_tenant` (`wyrelog/session.h`)
- `wyl_session_dup_tenant` (`wyrelog/session.h`)

These APIs accept syntactically valid tenant identifiers. Registry
membership and sealed-state checks are enforced by the daemon and policy
store paths that perform authenticated work.
