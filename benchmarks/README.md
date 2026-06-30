# Benchmark System

PySyMex benchmark code lives in `pysymex/benchmarks/suite/`. This directory keeps
release notes and local baseline artifacts only.

The benchmark suite is organized around the same concerns as the engine:

- `workload/execution.py`: symbolic executor and path-exploration costs.
- `workload/solver.py`: Z3 and solver-wrapper costs.
- `workload/analysis.py`: detector and contract-analysis costs.
- `workload/models.py`: builtin, container, and string model dispatch costs.
- `workload/reporting.py`: JSON, Markdown, HTML, and SARIF formatter overhead.
- `workload/sandbox.py`: native sandbox setup, execution, and bridge overhead.
- `workload/cli.py`: real user-facing `pysymex scan` and same-target scanner behavior.
- `core.py`, `types.py`, `runner.py`, `reporting.py`, `comparison.py`: shared
  benchmark metadata, execution, live progress, export, and regression comparison.

## Running

```bash
# Fast local loop. Streams progress and prints a summary.
pysymex benchmark

# Broader normal suite.
pysymex benchmark --mode full

# Explicitly expensive cases.
pysymex benchmark --mode stress

# Complete inventory across quick, full, and stress registrations.
pysymex benchmark --mode all

# Focus one subsystem or one case.
pysymex benchmark --category solving
pysymex benchmark --category models
pysymex benchmark --category reporting
pysymex benchmark --case cli_scan

# Machine-readable output for automation or baselines.
pysymex benchmark --format json -o benchmarks/baseline.json
pysymex benchmark --baseline benchmarks/baseline.json --threshold 15

# Inspect available cases without running them.
pysymex benchmark --list
```

Unfiltered runs default to quick mode so `pysymex benchmark` does not accidentally
run the heaviest solver, sandbox, or stress workloads. Focused filters such as
`--category sandbox` include all registered cases in that category unless an
explicit `--mode` is also supplied. Use `--mode full` for regular performance
investigations, `--mode stress` for intentionally expensive cases, and
`--mode all` when a release or audit needs every registered benchmark.
Historical long case names are still accepted by `--case` as compatibility
aliases, but `--list` and reports use the short canonical names.

## Live Output and Metrics

Text and Markdown/JSON runs stream live progress while each benchmark executes.
Iteration progress reports real measured wall time. Final results include:

- elapsed, min, max, mean, and standard deviation time;
- peak traced Python memory;
- instruction-like workload count where available;
- paths explored and paths per second where available;
- solver call and SAT/UNSAT/UNKNOWN counts where the engine exposes them;
- issue counts for detector, scanner, CLI, and reporting workloads;
- explicit status, failure detail, tags, and stability notes.

JSON output is suitable for future automation. Baseline comparison flags cases
whose mean runtime exceeds the configured threshold.

## Adding a Benchmark

1. Put the workload in the module that owns the measured concern.
2. Return a `dict[str, int]` with real metrics such as `instructions`, `paths`,
   `solver_calls`, `solver_sat`, `solver_unsat`, or `solver_unknown`.
3. Register it in `workload/registry.py` with a category, modes, tags, and a
   stability note if it is platform- or machine-dependent.
4. Keep quick-mode cases short and deterministic. Put heavy/path-explosive cases
   in full or stress mode.
5. Do not disable solver checks, detectors, scanner behavior, or sandboxing to
   improve numbers. If a metric is missing, expose it cleanly or document the gap.
6. Add a focused unit test under `tests/unit/benchmarks/`.

## Current Coverage

Covered areas:

- symbolic executor function and branching workloads;
- solver arithmetic, branch, loop, linear-constraint, incremental, and hashing
  workloads;
- VM state forking memory pressure;
- sandbox setup, execution, and module extraction;
- scanner-driven runtime detector issue production;
- concurrency race-detection and contract verification analysis;
- direct isolated scalar-carrier construction plus string, container, and builtin model dispatch;
- JSON, Markdown, HTML, and SARIF reporting-format overhead;
- default CLI scan subprocess behavior and same-target in-process scanner behavior.

Known gaps:

- detector-family breakdowns below the current runtime-detector scan workload;
- stdlib-specific model benchmarks outside strings, containers, and core builtins;
- stable cross-machine memory regression thresholds;
- explicit timeout classification separate from generic benchmark failure status;
- direct model-dispatch counters separate from executor path and solver work.

Historical release result files in this directory are local-machine artifacts and
should be treated as directional, not proof of absolute performance.

Latest local result:

- `v0.1.1a2-results.md` - complete all-mode run on Windows 11, CPython 3.13.13,
  Z3 4.16.0.
