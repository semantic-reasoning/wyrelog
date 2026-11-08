# Pre-recursion rule-pack reader fixture

The four files under `fact/` are byte-exact copies from Wyrelog commit
`6201ee46a3cfd5199e694e35d279741c9fd94103`, before #1504. The manifest records
original paths, SHA-256 checksums and Git blob IDs. The provenance test checks
both hashes without network access or a local Git history dependency. Do not
update these copies when changing the production compiler.

`test-fact-rule-pack-legacy-reader` compiles these sources with this include
root first and links GLib, SQLite and the selected Wirelog provider directly;
it does not link the current Wyrelog library/compiler. The adapter opens an
actual policy SQLite backup read-only, checks the original ordered v1
count/digest layout, and calls the frozen compiler with the fixture's declared
schemas. Tests compare the database bytes before and after execution.

This proves the historical language reader's positive-cycle refusal and
acyclic acceptance. The SQL adapter is new and Wirelog dependencies are
current: it is **not** execution of a complete historical daemon or proof of
every historical loader behavior. Separate current production replay and
restore tests establish graph-local refusal and nonactivation. The snapshot
contains no test entry point and its C/H files remain formatter fixed points.
