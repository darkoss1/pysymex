# POLAR

POLAR is the runtime frontier layer used by the default path manager. It stores live queued work,
records low-cost scheduling features, and can compact or spill frontier entries when exact
checkpoint material is available.

## Method

1. A path manager assigns each queued state a deterministic integer ID.
2. The frontier work store records the live payload.
3. Cheap features are collected for scheduling: pending constraints, detector obligations, branch
   degree, and resident-size estimate.
4. The priority queue ranks live IDs deterministically.
5. Materialization returns an executable `VMState` from a resident state, checkpoint, or spill file.
6. Shadow capsules and checkpoints support diagnostics and exact CEGIS evidence.

## Runtime Modes

| Mode | Behavior |
| --- | --- |
| `polar_cegis_shadow` | Emits POLAR/CEGIS shadow telemetry. It does not enable certificate pruning. |
| `polar_cegis_runtime` | Enables exact certificate-based frontier removal. Compact queueing is still disabled. |

Both modes expose shadow telemetry. Runtime mode is the default execution configuration.

## Checkpoints And Capsules

Capsules summarize detector obligations, constraint footprints, unsupported or havoc markers, and
resident-size estimates. Checkpoints can reconstruct a state exactly when the stored snapshot still
matches the capsule digest.

Compaction replaces a resident queued state with an exact in-memory checkpoint. Spill can move a
checkpoint to external storage when policy allows it. Failed reconstruction and digest mismatches
are counted for diagnostics.

## Scheduling Signal

The constraint interaction graph tracks branch program counters and connects branches that share
variables. POLAR uses branch degree as a scheduling signal. The graph is not a proof object.

## Evidence In Source

- Runtime modes: `pysymex/execution/frontier/modes.py`
- Work store and entries: `pysymex/execution/frontier`
- Path manager: `pysymex/execution/strategies/manager/path.py`
- Constraint interaction graph: `pysymex/core/graph/cig.py`
- Tests: `tests/unit/execution/frontier`, `tests/unit/execution/strategies`

## Limits

POLAR may choose and compact work. It does not decide solver truth, detector confidence, or target
safety. Removing live work requires CEGIS evidence described in [CEGIS.md](CEGIS.md).
