# Detectors

Detectors turn execution evidence into issue records. A definite issue needs feasible-path evidence
for the active modeled behavior.

## Method

1. The executor builds detector dispatch tables from the active registry and config.
2. Universal detectors run on every instruction; opcode-specific detectors run only on their
   relevant opcodes.
3. Each detector receives the current `VMState`, instruction, and a SAT callback.
4. Detector queries use the active solver and preserve inconclusive-prefix information.
5. Issues caught by modeled exception handlers are suppressed.
6. Dynamic context-manager cases can defer or replace issues to match cleanup semantics.
7. Scanner issue sinks normalize, deduplicate, and retain counterexample-backed variants.

## Issue Records

`Issue` records contain kind, message, constraints, model or counterexample, bytecode offset, source
location, confidence, severity, and optional suppression reason. Scanner output converts these into
JSON-safe issue dictionaries.

## Evidence Rules

The detector path follows the shared soundness contract:

- SAT with a model or verified concrete witness can support a definite issue.
- UNSAT prevents a definite issue on that path.
- UNKNOWN, timeout, callback failure, missing model, unsupported semantics, or precision loss must
  remain inconclusive or degraded.
- Low-confidence degraded issues are allowed only when the result says why evidence is incomplete.

## Detector Families

| Family | Examples |
| --- | --- |
| Runtime | division by zero, index/key/type/attribute/value errors, assertions, user exceptions |
| Specialized | format strings, use-after-free, null dereference, unreachable code |
| Logical | local contradictions, multivariable impossibilities, path-level constraints |
| Formal | property and oracle validation helpers |

## Evidence In Source

- Issue and registry types: `pysymex/analysis/detectors/detector`
- Runtime invocation: `pysymex/execution/detectors/invocation.py`
- Feasibility helpers: `pysymex/analysis/detectors/feasibility.py`
- Scanner issue sink: `pysymex/scanner/issue_sink.py`
- Tests: `tests/unit/analysis/detectors`, `tests/unit/execution/detectors`, `tests/unit/scanner`

## Limits

Detector confidence depends on the execution and solver evidence it receives. Detectors must not
upgrade unsupported or inconclusive paths into confirmed bugs merely because a syntactic pattern
looks suspicious.
