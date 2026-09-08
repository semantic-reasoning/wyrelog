# Fact graph admission enum evolution

This map is the change contract for adding a third value to
`WylFactGraphAdmission`. The enum is intentionally still two-valued today:
`OPEN` admits work and `CLOSED` refuses it. The entries below are the complete
set of deciders and reporters that must be reviewed together.

| ID | Location | Kind | Current form | Rule for a third value |
| --- | --- | --- | --- | --- |
| A1 | `wyrelog/fact/runtime-private.c` `manager_refresh_gated` | decider | `entry->admission == refuse_when` | Keep the caller-specific refusal contract explicit; `refresh` must refuse every non-serving phase before reporters are widened. |
| A2 | `wyrelog/fact/runtime-private.c` `manager_refresh_gated` | decider | `entry->admission == WYL_FACT_GRAPH_ADMISSION_OPEN` | The drain re-test must reject every phase that cannot admit work. |
| A3 | `wyrelog/fact/runtime-private.c` `manager_refresh_gated` | decider | `entry->admission == WYL_FACT_GRAPH_ADMISSION_OPEN` | The closed-entry eviction gate must reject every phase that is not safely evictable. |
| A4 | `wyrelog/fact/runtime-private.c` `wyl_fact_graph_runtime_manager_acquire_snapshot` | decider | `entry->admission == WYL_FACT_GRAPH_ADMISSION_CLOSED` | Snapshot serving must be gated by the single serving value, `OPEN`. |
| A5 | `wyrelog/wyl-handle.c` `wyl_handle_commit_fact_mutation` | reporter | `status.admission == WYL_FACT_GRAPH_ADMISSION_CLOSED` | Widen only after A1/A2 make the new phase non-admitting; preserve degraded classification for real replay failures. |
| A6 | `wyrelog/wyl-handle.c` `legacy_fact_graph_state` | reporter | `status->admission != WYL_FACT_GRAPH_ADMISSION_OPEN` | Keep all non-serving phases stronger than replay health in the projection. |
| A7 | `wyrelog/wyl-handle.c` `fact_graph_runtime_status_cb` | reporter | `runtime_status->admission == WYL_FACT_GRAPH_ADMISSION_OPEN` | Queryability must remain explicitly tied to the sole serving phase. |
| A8 | `wyrelog/daemon/http.c` `facts_route_handler` | reporter | `status.admission == WYL_FACT_GRAPH_ADMISSION_CLOSED` | Widen only with the matching decider and retain the committed-barrier/degraded distinction. |
| A9 | `wyrelog/fact/graph-seal-private.c` `wyl_fact_graph_unseal` | reporter | `out_outcome->status.admission == WYL_FACT_GRAPH_ADMISSION_CLOSED` | Derive the barrier outcome from the admission contract, not from an assumed two-value sentinel. |

The order is deliberate: A1–A4 decide whether work can happen; A5–A9 only
describe the result. A reporter must not be converted independently of its
decider. The static guard in
`tests/test-fact-graph-status-boundary.py` checks that all nine locations stay
represented in this map and that their current source anchors remain present.

No behavioural change is claimed by this document. Any future enum extension
must convert the deciders first, then the reporters, and add an enum value plus
behavioural tests in that same change.
