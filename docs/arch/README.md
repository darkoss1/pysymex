# Architecture

These pages describe the implemented PySyMex architecture. They are written for maintainers who
need to understand the current engine without reading every package first.

The central rule is explicit uncertainty. Unsupported behavior, solver `UNKNOWN`, timeouts,
sandbox denial, path limits, and degraded analysis must remain visible. A clean run means no
definite issue was reported for the explored supported behavior. It is not a global proof of
target safety.

## Read Order

| Document | Use it for |
| --- | --- |
| [OVERVIEW.md](OVERVIEW.md) | End-to-end system shape and trust boundary. |
| [SCANNING.md](SCANNING.md) | File discovery, compile-only loading, sandbox bytecode extraction, and scan results. |
| [SANDBOX.md](SANDBOX.md) | Native isolation, capability checks, staged paths, and sandbox result states. |
| [FLOW.md](FLOW.md) | Symbolic VM loop, `VMState`, opcode dispatch, and execution results. |
| [MODELS.md](MODELS.md) | Builtin, container, stdlib, numeric, object, and concurrency models. |
| [SOLVER.md](SOLVER.md) | Z3 query flow, SAT/UNSAT/UNKNOWN results, models, and proof checks. |
| [SMT_SLICING.md](SMT_SLICING.md) | Constraint slicing, validated slice caches, and exact UNSAT reuse. |
| [PATHS.md](PATHS.md) | Worklist scheduling, limits, and path-explosion controls. |
| [POLAR.md](POLAR.md) | Frontier storage, scheduling features, checkpoints, and compaction. |
| [CEGIS.md](CEGIS.md) | Evidence bids, exact certificates, and no-false-prune removal gates. |
| [DETECTORS.md](DETECTORS.md) | Issue kinds, detector invocation, feasibility evidence, and scanner issue records. |
| [CONTRACTS.md](CONTRACTS.md) | Contract IR, verified execution, arithmetic checks, and current unsupported cases. |
| [REPORTS.md](REPORTS.md) | Text, JSON, HTML, SARIF, realtime, and CLI presentation boundaries. |
| [LIMITS.md](LIMITS.md) | Host analysis limits, sandbox limits, degraded-pass labels, and result meaning. |

## Source Areas

| Area | Main packages |
| --- | --- |
| Public entry points | `pysymex.api`, `pysymex.cli` |
| Scanning | `pysymex.scanner`, `pysymex.analysis.scan` |
| Execution | `pysymex.execution`, `pysymex.core.state` |
| Solver and symbolic data | `pysymex.core.solver`, `pysymex.core.types`, `pysymex.core.memory` |
| Runtime models | `pysymex.models` |
| Detectors and analyses | `pysymex.analysis` |
| Native isolation | `pysymex.sandbox` |
| Contracts | `pysymex.contracts`, `pysymex.execution.executors.verified` |
| Reports and diagnostics | `pysymex.reporting`, `pysymex.cli.formatters`, `pysymex.logger` |
| Resource limits | `pysymex.resources`, `pysymex.execution.resources` |

`pyproject.toml` contains import-linter contracts for the most important dependency boundaries.
The practical rule is simple: lower layers produce evidence, upper layers present it.
