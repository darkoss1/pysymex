# Adaptive Exploration

Status: implemented for host exploration, loops, recursion, and identified representation caps.

## Problem Statement

PySyMex historically used fixed host limits for paths, symbolic step depth, total VM iterations,
wall-clock time, loop iterations, call depth, and selected representation operations. Automatic
mode now replaces those stops with optional user limits, exact recurrence checks, well-founded
descent proofs, lazy exact representations, and explicit inconclusive fallback.

Path explosion and termination are undecidable in general. Removing numeric stops therefore does
not make arbitrary symbolic execution complete. The replacement must improve autonomous progress
without turning solver uncertainty, widening, unsupported behavior, or abandoned work into a
successful verification result.

## Desired Invariant

In automatic mode, host exploration does not discard feasible work because of an implicit path,
depth, iteration, or wall-time count. Work leaves the frontier only when it executes, is proven
infeasible or exactly subsumed, is represented by an explicitly marked approximation, or an
elective user limit stops the run and records an inconclusive result.

Sandbox limits remain mandatory security boundaries. Per-query solver limits remain explicit
sources of `UNKNOWN` until an adaptive solver policy can replace them without allowing one query
to block the engine indefinitely.

## Scope

This project classifies limits by semantic effect:

| Class | Examples | Policy |
| --- | --- | --- |
| Elective host stops | paths, symbolic depth, VM iterations, analysis timeout | Disabled in automatic mode; positive CLI/API values remain supported. |
| Convergence policy | loop recurrence, widening, exact duplicate/subsumption | Replace fixed loop cutoffs with evidence-driven convergence. |
| Resource adaptation | frontier compaction, spill, cache eviction, batching | Adaptive thresholds may remain because they preserve queued work. |
| Representation limits | modeled string/list/array truncation | Use exact lazy representations where available; otherwise expose unsupported/precision loss. |
| Security boundary | sandbox CPU, memory, process, file, output, payload limits | Retain and test. |

Display truncation, cache capacity, compaction batch size, and telemetry retention are not analysis
hard stops when they do not discard semantic work or alter result meaning.

## Proposed Design

1. Represent each host stop as an elective value. Absence means automatic exploration; a positive
   value means the user explicitly requested a bound.
2. Keep `pysymex._internal.limits` as the sole owner of host-limit representation and enforcement.
3. Let the POLAR/CEGIS frontier prioritize detector obligations, novel control flow, low solver
   pressure, and low resident cost without heuristically deleting feasible states.
4. Preserve exact-only CEGIS removal, state subsumption, compaction, and spill behavior.
5. Replace fixed loop iteration pruning with this evidence order:
   - execute concrete finite iterators to their exact end;
   - terminate exact repeated states as structural recurrence;
   - widen changing abstract state when a safe loop exit exists;
   - report no-exit structural loops as issues;
   - mark unsupported or non-convergent approximation as inconclusive.
6. Treat user-configured limits as overrides, not defaults. A reached override records a stable
   `resource_limit_*` degradation and never supports a safety claim.
7. Recheck affine loop and recursion descent evidence at each recurrence instead of deriving a
   hidden numeric fuse.
8. Switch large concrete ranges and sequence repetitions from eager materialization to exact lazy
   symbolic views.
9. Run hard-theory literal/witness preprocessing first, then ask the configured solver regardless
   of formula length; only solver `UNKNOWN` remains inconclusive.

The scheduler may alter order and storage. It may not silently drop feasible work based on cost,
novelty, age, solver timeout, or low detector relevance.

## Rejected Alternatives

- Setting very large defaults: still a hidden hard stop and makes behavior machine-dependent.
- Dropping low-score paths: can create false negatives without exact coverage evidence.
- Treating solver timeout or `UNKNOWN` as infeasible: unsound.
- Keeping a hidden emergency iteration fuse: violates the automatic-mode contract and hides
  incomplete exploration.
- Removing all limits before convergence handling exists: can make ordinary scans non-terminating.

## Impact

- CPython semantics: unchanged; execution ordering must not alter opcode behavior.
- Solver: SAT/UNSAT/UNKNOWN meanings remain unchanged. Solver call count may increase.
- Detectors: potential false negatives from implicit host stops should fall; no new definite issue
  may be emitted from widened or unknown-only evidence.
- Path growth: remains exponential in the worst case. Exact subsumption and convergence reduce
  repeated work but do not prove general polynomial behavior.
- Memory: automatic mode depends on compaction, cache eviction, lazy representations, and spill
  rather than a default host-memory stop.
- Native isolation: unchanged.
- API/CLI: limit options remain available; omitted values select automatic mode.

## Migration And Rollback

Migrate one owner at a time: host limit types and tracker, worklist deadline handling, scanner/API
defaults, loop convergence, then representation limits. Each stage keeps positive explicit limits
working. A stage can be rolled back independently by restoring the previous defaults without
changing result schemas.

## Test Plan

- Explicit path, depth, iteration, and timeout limits still stop with degradation.
- Automatic host limits do not stop finite runs at former defaults.
- Worklist automatic mode installs no total solver deadline.
- Concrete finite loops execute completely beyond the former loop count.
- Exact recurrent loops terminate deterministically without a numeric cutoff.
- Widened loop exits expose precision loss and do not produce definite issues without feasible
  evidence.
- Precision matrix remains `TP=24`, `FP=0`, `TN=24`, `FN=0`.
- Focused tests, full pytest, Ruff, Pyright, package build, and diff hygiene pass.

## Residual Risk

Symbolic loops and recursion outside the modeled abstract domains, plus hard SMT theories, can still
fail to converge or return `UNKNOWN`. Unsupported recurrence is terminated as explicit
inconclusive/precision-loss output rather than by a hidden numeric count. Per-query solver deadlines
remain because one undecidable query must not block the whole engine; timeout remains `UNKNOWN`,
never infeasible or verified. This design does not claim complete analysis of arbitrary Python
programs.
