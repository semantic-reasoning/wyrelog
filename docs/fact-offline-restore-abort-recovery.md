# Offline restore abort recovery

An operator may abort a confirmed restore whose durable journal is in BEGIN
or PREPARE with no decision. Recovery starts from its operation UUID. The
recovery entry point reloads the claim and journal, selects tenant or graph
scope, and uses the durable revision for a compare and swap. A COMMIT decision
requires the separate commit resume path.

The first successful rollback decision forbids restore resume. Tenant abort
then processes graphs in journal order. It removes a stage only when the
journal's recorded identity, sealed policy, main identity, provisioning pair,
root lease, and closed graph runtime all agree. A graph with no recorded stage
identity is checked for stage absence; an operation-named orphan is left for
inspection. A foreign or replaced stage, missing claim, changed policy, stale
revision, or busy runtime stops recovery without adopting the artifact. Graphs
already marked ABANDONED are rechecked on each retry. A partial tenant abort
keeps its claim and journal, so a later process can continue by UUID.

Completion of rollback retains the claim and journal. Call the verified
release entry point only after all selected graphs are ABANDONED. It holds one
root writer lease and closed-runtime tokens for every graph while rechecking
stage absence, main identities, policy, and journal before atomically removing
the claim and journal. A failure or ambiguous response requires a fresh read
by UUID. If release committed, the UUID is no longer present and retry returns
`NOT_FOUND`; this result alone is not proof that an earlier release succeeded.
Inspect the destination and policy when the response was ambiguous.
