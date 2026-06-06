# PySyMex Documentation

This directory is the source-grounded documentation set for PySyMex. It focuses on the
current repository: public workflows, architecture, uncertainty semantics, and maintenance rules.

## Read Order

| Document | Use it for |
| --- | --- |
| [CLI.md](CLI.md) | Command-line commands, flags, examples, output, and exit behavior. |
| [API.md](API.md) | Public Python entrypoints, result objects, and API stability boundaries. |
| [LIMITATIONS.md](LIMITATIONS.md) | Supported scope, known limits, and uncertainty policy. |
| [arch/README.md](arch/README.md) | Architecture index and source-area map. |
| [GLOSSARY.md](GLOSSARY.md) | Short definitions for terms used across the docs. |

For a new contributor, start with [LIMITATIONS.md](LIMITATIONS.md), then read
[arch/OVERVIEW.md](arch/OVERVIEW.md), [arch/FLOW.md](arch/FLOW.md), and the interface document
that matches your task.

## Architecture Documents

| Document | Scope |
| --- | --- |
| [arch/OVERVIEW.md](arch/OVERVIEW.md) | End-to-end system shape and trust boundary. |
| [arch/SCANNING.md](arch/SCANNING.md) | Target discovery, compile-only loading, sandbox bytecode extraction, and scan results. |
| [arch/SANDBOX.md](arch/SANDBOX.md) | Native isolation, capability checks, staged paths, and sandbox result states. |
| [arch/FLOW.md](arch/FLOW.md) | Symbolic VM loop, `VMState`, opcode dispatch, and execution results. |
| [arch/MODELS.md](arch/MODELS.md) | Runtime model families and their interaction with execution. |
| [arch/SOLVER.md](arch/SOLVER.md) | Solver query flow, SAT/UNSAT/UNKNOWN handling, and model extraction. |
| [arch/SMT_SLICING.md](arch/SMT_SLICING.md) | Constraint slicing, cache safety, and exact UNSAT reuse. |
| [arch/PATHS.md](arch/PATHS.md) | Worklist behavior, path limits, and scheduling strategy. |
| [arch/POLAR.md](arch/POLAR.md) | Frontier storage, CIG scheduling signal, checkpoints, and compaction. |
| [arch/CEGIS.md](arch/CEGIS.md) | Evidence bids, exact certificates, and no-false-prune removal gates. |
| [arch/DETECTORS.md](arch/DETECTORS.md) | Detector emission, feasibility evidence, and scanner issue records. |
| [arch/CONTRACTS.md](arch/CONTRACTS.md) | Contract decorators, verified execution, arithmetic checks, and verification limits. |
| [arch/REPORTS.md](arch/REPORTS.md) | Report formatters, diagnostics, SARIF/HTML/realtime output, and CLI boundaries. |
| [arch/LIMITS.md](arch/LIMITS.md) | Host resource tracking, sandbox limits, and degraded-result semantics. |

## Documentation Rules

Documentation should describe implemented behavior. Do not list unimplemented ideas as
architecture.
Do not treat a clean run as proof that a target is safe when the run may have hit unsupported
semantics, solver uncertainty, path limits, sandbox denial, or degraded analysis passes.
