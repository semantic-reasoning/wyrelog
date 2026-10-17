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
identity is checked for stage absence.

An import that fails after finalizing its stage but before the journal records
the stage identity leaves an operation-named orphan that `prepare` cannot
replace (#1407). Abort admits such a stage only after proving it is this
operation's: the exact operation-derived name, opened without following links,
a regular file with one link, owned by the restoring user with mode exactly
0600, no sidecar, and the manifest's size and SHA-256 for that graph, all while
the root writer lease is held. The proof is recorded first: one journal revision
binds the identity and decides ROLLBACK (or, after another graph already
decided, reopens the graph that was abandoned unbound). Only then does the
ordinary retire path remove the stage, so a crash on either side of that
revision is finished by the next abort. An admitted identity can only be
retired, never committed. A stage that fails any check, including a partially
written one, is left untouched and abort stops; no code path removes it, so the
operator inspects and removes it by hand before retrying. In tenant scope the
graphs before it may already be rolled back and the refused graph recorded
ABANDONED, so the journal can read complete while that stage exists; release
rechecks stage absence and refuses until it is gone.

A foreign or replaced stage, missing claim, changed policy, stale revision, or
busy runtime stops recovery without adopting the artifact. Graphs already
marked ABANDONED are rechecked on each retry. A partial tenant abort keeps its
claim and journal, so a later process can continue by UUID.

Completion of rollback retains the claim and journal. Call the verified
release entry point only after all selected graphs are ABANDONED. It holds one
root writer lease and closed-runtime tokens for every graph while rechecking
stage absence, main identities, policy, and journal before atomically removing
the claim and journal. A failure or ambiguous response requires a fresh read
by UUID. If release committed, the UUID is no longer present and retry returns
`NOT_FOUND`; this result alone is not proof that an earlier release succeeded.
Inspect the destination and policy when the response was ambiguous.
