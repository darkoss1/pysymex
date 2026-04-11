# SMT Slicing and Incremental Execution Architecture

This document describes the current SMT-performance architecture in PySymEx, with explicit status labels for what is implemented today versus what remains future work.

## Scope and Guarantees

The goals are:

- Reduce Python-to-Z3 overhead on branch-heavy execution.
- Preserve soundness (never prune feasible states due to accelerator/backend issues).
- Keep acceleration optional and safely degradable when unavailable.

PySymEx currently prioritizes soundness over peak speed when there is any conflict.

## Implementation Status Matrix

| Area | Status | Primary Components |
|---|---|---|
| True incremental prefix synchronization | Implemented | `IncrementalSolver._active_path`, `_sync_path`, `is_sat(..., known_sat_prefix_len=...)` |
| Chronological constraint chain iteration | Implemented | `ConstraintChain.__iter__`, `ConstraintChain.newest`, `ConstraintChain.__reversed__` |
| CHTD hardware acceleration (GPU/CPU backend selection) | Implemented | `executor_core._get_chtd_solver`, `h_acceleration.chtd_solver` |
| Hardware-acceleration integrity guard on UNSAT prune | Implemented | `SymbolicExecutor._validate_chtd_unsat` |
| Constraint hash shortcut directly from `ConstraintChain.hash_value()` in solver cache discriminator | Implemented | `IncrementalSolver` cache key/discriminator now use `hash_value()` fast-path when available |
| Backward AST data-flow slicing of ambient constraints | Implemented | `IncrementalSolver.is_sat(..., known_sat_prefix_len=...)` slices ambient prefix constraints against suffix query variables |
| Cube-and-conquer search-space splitting in portfolio path | Partial | `PortfolioSolver` exists; no full production cube orchestrator integrated in main executor loop |

## 1. True Incremental Z3 Solving

### Problem
Without synchronization, each branch check can reassert long path prefixes into temporary scopes, increasing FFI and solver setup overhead.

### Current Architecture
`IncrementalSolver` tracks an ambient synchronized path in `_active_path` and aligns it with incoming constraints:

1. Compute longest common prefix with `_common_prefix_len`.
2. `pop()` only the divergent suffix.
3. `push()` and add only the missing suffix.
4. For `known_sat_prefix_len`, solve only the delta constraints in a temporary scope.

### Result
For prefix-heavy workloads, this provides substantial speedup while preserving exact SAT semantics.

## 2. Chronological Copy-On-Write Chains

### Problem
Prefix synchronization requires consistent chronological ordering. Newest-first iteration can break common-prefix detection.

### Current Architecture
`ConstraintChain` now iterates oldest-first, and exposes explicit newest-first access via:

- `ConstraintChain.newest()` for O(1) tail access.
- `reversed(chain)` for newest-first traversal.

This keeps persistent structural sharing while enabling correct prefix synchronization.

## 3. CHTD and Hardware Acceleration

### Problem
CHTD pruning can reduce search work, but backend complexity (GPU/CPU/reference) must never compromise correctness.

### Current Architecture
The executor:

- Builds a constraint interaction graph.
- Runs CHTD message propagation at adaptive intervals.
- Chooses backend dynamically:
  - GPU-preferred when enabled and branch set is large enough.
  - CPU/reference fallback when GPU is unavailable.
- Tracks detailed CHTD telemetry in solver stats.

## 4. UNSAT Integrity Guard for Accelerator Paths

### Problem
A false UNSAT from any accelerated path would be catastrophic if used directly for pruning.

### Current Architecture
Before pruning forked states on CHTD UNSAT, PySymEx now runs a deterministic incremental Z3 validation over the candidate branch states.

- If incremental Z3 finds any SAT candidate, pruning is canceled.
- A mismatch counter is incremented and logged.
- Telemetry fields:
  - `unsat_hits`
  - `unsat_validations`
  - `unsat_mismatches`

This ensures hardware acceleration can speed execution without weakening soundness.

## 5. What Is Not Yet Implemented (and Should Not Be Overclaimed)

The following optimizations are still roadmap items and are not currently active in the core SAT path:

- End-to-end production cube-and-conquer splitting integrated into the default executor SAT pipeline.

## 6. Operational Guidance

For best speed with integrity:

- Keep incremental solving enabled.
- Keep CHTD enabled for branch-heavy workloads.
- Enable hardware acceleration when available, relying on automatic fallback and UNSAT validation.
- Use bounded benchmark runs to compare workloads, since benefit depends on branch structure and treewidth.

## 7. References

- `pysymex/core/solver.py`
- `pysymex/core/copy_on_write.py`
- `pysymex/execution/executor_core.py`
- `pysymex/accel/chtd_solver.py`
- `tests/unit/core/solver/test_engine.py`
- `tests/unit/core/solver/test_constraints.py`
- `tests/unit/accel/test_chtd.py`

