# Overview

PySyMex analyzes Python by compiling source, extracting code objects, executing supported CPython
bytecode with symbolic values, asking Z3 about path feasibility, and reporting findings only when
the active evidence supports them.

## System Shape

```mermaid
flowchart TD
    User["User or CI"] --> CLI["CLI"]
    User --> API["Python API"]
    CLI --> Scanner["Scanner"]
    API --> Scanner
    API --> Executor["Symbolic executor"]
    Scanner --> Sandbox["Sandbox bytecode bridge"]
    Scanner --> Executor
    Sandbox --> Scanner
    Executor --> State["Symbolic state and memory"]
    Executor --> Models["Runtime models"]
    Executor --> Solver["Z3 solver"]
    Executor --> Detectors["Detectors"]
    Executor --> Contracts["Contract checks"]
    Detectors --> Reports["Reports"]
    Contracts --> Reports
    Scanner --> Reports
    Reports --> User
```

## Layered View

```mermaid
flowchart TB
    Interface["CLI, API, reports"]
    Analysis["Scanning, detectors, contracts"]
    Runtime["Symbolic VM, paths, scheduling"]
    Semantics["State, memory, runtime models"]
    Reasoning["SMT solver, slicing, caches"]
    Guardrails["Sandbox and resource limits"]

    Interface --> Analysis
    Analysis --> Runtime
    Runtime --> Semantics
    Runtime --> Reasoning
    Analysis --> Guardrails
    Runtime --> Guardrails
    Reasoning --> Analysis
```

Upper layers decide what to analyze and how to present evidence. Lower layers create the evidence:
bytecode paths, symbolic state, model outcomes, solver answers, sandbox results, and limit states.

## Method

1. The CLI or API receives a file, directory, function, or code snippet.
2. The scanner discovers target code objects and source-level scan paths.
3. Sandbox-backed extraction compiles target source inside isolation when sandboxing is enabled.
4. The symbolic executor creates `VMState` paths and dispatches version-specific opcode handlers.
5. Runtime models cover supported builtins, containers, objects, and standard-library calls.
6. Branches and issue conditions become Z3 constraints.
7. Solver results stay structured as SAT, UNSAT, or UNKNOWN.
8. Worklist scheduling chooses the next path to explore.
9. Resource limits, unsupported behavior, and degraded passes are recorded.
10. Detectors and contract checks emit findings only when they have evidence for the active path.
11. Reporting layers serialize the evidence without inventing new verification meaning.

## Trust Boundary

PySyMex is bounded and model-driven. A clean result means no definite issue was reported for the
explored supported behavior. It does not prove that every feasible runtime behavior was modeled,
that every path was explored, or that native isolation proved the target harmless.

The main invariant is explicit uncertainty. Solver `UNKNOWN`, timeout, unsupported bytecode,
modeling gaps, sandbox denial, path limits, and degraded passes must stay visible to callers and
reports.

## Evidence In Source

- Scanning: `pysymex/_internal/scanner`, `pysymex/_internal/analysis/scan`
- Execution: `pysymex/_internal/execution`, `pysymex/_internal/core/state`
- Solver: `pysymex/_internal/core/solver`
- Models: `pysymex/_internal/models`
- Detectors: `pysymex/_internal/analysis/detectors`
- Sandbox: `pysymex/_internal/sandbox`
- Reports: `pysymex/_internal/reporting`, `pysymex/_internal/cli/formatters`

## Related Pages

Read [SCANNING.md](SCANNING.md), [FLOW.md](FLOW.md), and [SOLVER.md](SOLVER.md) for the main
pipeline. Read [SANDBOX.md](SANDBOX.md), [POLAR.md](POLAR.md), [CEGIS.md](CEGIS.md), and
[LIMITS.md](LIMITS.md) for the high-risk boundaries.
