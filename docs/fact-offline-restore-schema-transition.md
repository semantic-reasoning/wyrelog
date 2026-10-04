# Offline restore schema transitions

Generated backup manifests record the active schema digest and the selected
version of every relation in each graph. A restore may select those versions on
the destination even when its currently active digest differs. The destination
must already contain matching definitions for every selected version before it
is sealed. The manifest records the selected versions, but does not carry
schema definitions. Registering a missing definition during BEGIN or PREPARE is
not part of this operation.

Query aliases are unique per tenant and graph across registered schema
versions. A visible alternate version must use a distinct alias, such as
`items_v2`; attempting to register a second visible version with the same
default alias is rejected by the policy store.

Run dry-run before BEGIN. `schema_transition_required` means the authenticated
backup selects a different policy schema. BEGIN checks the selected versions
against the destination's registered definitions and pins both the old active
digest and the backup's desired digest in the durable restore journal. PREPARE
replays the staged file using the selected versions while the old schema remains
active. A missing version, conflicting definition, changed old activation, or
changed selected definition stops the operation before publication.

Rollback before COMMIT leaves the old activation in place. At the final policy
publication step, the selected versions, restore journal, provisioning state,
and lifecycle transition are committed in one policy transaction. A restart
uses the journal's old and desired digests to distinguish a pending restore
from one whose selected schema was published. The target remains sealed while
file replacement is in progress; it becomes active only with the selected
schema. Same-schema restores follow the same checks and remain idempotent.

Legacy manifests without a relation-version selection can be restored only
when the destination's active schema digest already matches the backup.
