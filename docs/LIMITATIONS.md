# Limitations

PySyMex is an alpha symbolic execution and formal-verification research engine. It is useful for
studying supported symbolic execution paths and detector behavior. It is not a complete Python
semantics, security audit replacement, or proof that a target program is safe.

## Result Interpretation

| Result state | Meaning |
| --- | --- |
| Definite finding | A detector or runtime failure was reached on a path the engine considered feasible. |
| No finding | No definite finding was emitted for explored supported paths. |
| Unsupported | The target used behavior outside the implemented semantic model. |
| UNKNOWN | Solver or engine evidence did not establish SAT or UNSAT. |
| Timeout | A resource or solver deadline interrupted analysis. |
| Inconclusive | The engine could not justify a definite answer. |
| Blocked | Sandbox, import, filesystem, policy, or environment constraints prevented execution. |
| Degraded | A pass completed only partially or stopped because of a limit or precision boundary. |

Always inspect scanner `error`, `degraded_passes`, solver stats, and report metadata before
interpreting a clean result.

## Python Semantics

PySyMex executes supported CPython bytecode for Python 3.11 through 3.13 families. Unsupported or
partially modeled areas can include:

- dynamic imports and import-time side effects,
- native extensions and C-backed runtime behavior,
- reflection-heavy code,
- metaclass and descriptor edge cases not covered by current models,
- complex generators, coroutines, and async runtime behavior,
- concurrency interleavings beyond implemented models,
- filesystem, network, environment, and subprocess behavior outside sandbox/model support,
- standard-library calls without precise models.

When precision matters, unsupported behavior should remain visible instead of being silently
concretized.

## Symbolic Execution Limits

Symbolic execution is bounded by configuration:

- path limits,
- depth limits,
- VM iteration limits,
- loop unrolling limits,
- resource limits,
- timeouts,
- scanner file and directory limits.

Path explosion can leave reachable behavior unexplored. State merging, caching, scheduling, and
frontier optimizations may reduce cost, but they do not make bounded exploration complete.

## Solver Limits

Z3 can return SAT, UNSAT, or UNKNOWN. Timeouts, malformed constraints, unsupported encodings, and
solver failures are inconclusive. A model is evidence for the active encoding; it is not evidence
that every Python runtime behavior was modeled precisely.

Callers that need proof-level distinctions should use structured solver outcomes instead of boolean
helpers that intentionally collapse some cases for compatibility.

## Detector Limits

Detectors depend on the symbolic state, modeled operations, path constraints, and scanner passes
available at the point of detection. False negatives are possible when behavior is unsupported,
unexplored, imprecisely modeled, or blocked. False positives should be treated as bugs unless the
report explicitly marks uncertainty or degradation.

## Sandbox and Safety Limits

PySyMex uses native isolation-facing backends where available: Linux namespaces, Windows
AppContainer, or WASM. If no strong backend is available, sandbox setup can fail. Sandbox denial or
setup failure is a blocked state, not evidence that the target is safe.

Sandboxing reduces risk during target loading and execution, but it does not make arbitrary target
code harmless in every environment. Treat untrusted code carefully and keep backend capabilities
visible in diagnostics.

## Contract and Termination Limits

Contract-aware execution is available through `verify` and `VerifiedExecutor`, but CLI verify is
preview behavior and the sandboxed command path currently requires `--function`.

The public `prove_termination` wrapper currently returns an UNKNOWN termination proof placeholder.
Do not describe termination proof as implemented through that wrapper until it returns real proof
evidence.
