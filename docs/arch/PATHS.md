# Paths

Path exploration controls the order and amount of symbolic work. Scheduling may prioritize paths,
but it must not silently discard feasible paths unless an explicit limit or exact proof supports
that decision.

## Method

1. Execution seeds a path manager with the initial `VMState`.
2. The worklist loop pops the next state until the queue is empty or a limit stops it.
3. Each step dispatches one opcode and may return continuation, branch, exception, or terminal
   states.
4. Feasibility checks prune only established UNSAT children.
5. SAT and UNKNOWN paths may remain explorable.
6. Resource limits record degraded-pass labels and fallback events.

## Scheduling

The default adaptive manager is the POLAR path manager. It uses deterministic queue ordering,
program-counter branch degree from the constraint interaction graph, resident-size estimates, and
detector-obligation features. CEGIS can select detector-obligation states for execution and can
remove work only through exact certificate gates.

## Path Explosion Controls

Path growth is exponential in the worst case. PySyMex uses bounded controls rather than pretending
to explore everything:

- maximum paths,
- maximum depth,
- maximum iterations,
- timeout,
- loop limits and widening where supported,
- state-merging options,
- solver caches and SMT slicing,
- frontier compaction and spill support.

When a limit stops analysis, the result should show degraded coverage. It should not look like a
complete safety proof.

## Evidence In Source

- Worklist loop: `pysymex/_internal/execution/engine/worklist.py`
- Path manager creation: `pysymex/_internal/execution/scheduling`
- POLAR path manager: `pysymex/_internal/execution/strategies/manager`
- Resource handling: `pysymex/_internal/execution/resources`, `pysymex/_internal/limits`
- Tests: `tests/unit/execution/strategies`, `tests/unit/execution/scheduling`

## Limits

Scheduling heuristics are performance tools. They may change which path runs next, but not the
truth of a path. Solver `UNKNOWN`, timeout, incomplete modeling, or unsupported behavior must stay
inconclusive.
