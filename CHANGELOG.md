# Changelog

All notable changes to pysymex are documented here.


## v0.1.1a2

### Major Structural Changes

- Refocused the public engine around the symbolic-execution scanner. CLI and API
  entry points now route through file discovery, sandbox bytecode extraction,
  symbolic execution, runtime detectors, contracts, and reporting as one primary
  pipeline.
- Introduced `pysymex/limits` as the single owner for host analysis limits,
  telemetry, and `resource_limit_*` degradation labels. Config, execution,
  scanner, and API layers consume that package instead of scattered resource-limit
  code.
- Expanded `pysymex/config` into the configuration root for execution, sandbox,
  solver, logging, analysis profiles, and coercion defaults.
- Added `pysymex/profiling` as a first-class scan diagnostics package with separate
  schema, aggregation, frame classification, diagnosis, baseline comparison, and
  rendering owners.
- Modularized the CLI under a command registry with split scan, contracts,
  benchmark, and trace-analyze command packages plus shared parser validation.
- Separated scanner presentation from scan execution. Issue publication, replay
  confirmation, honest `result_level` classification, and injectable
  `ScanReporter` progress callbacks are owned by `pysymex/scanner`.
- Reorganized `pysymex/analysis` around scan orchestration, evidence collection,
  and runtime detectors. Standalone static-analysis, domain-analyzer, logical, and
  formal detector trees are no longer part of the supported package layout.
- Grouped runtime detectors into focused families under
  `pysymex/analysis/detectors/runtime/` with slimmer registry surfaces.
- Moved adaptive loop convergence, widening, and interprocedural recursion policy
  into dedicated execution owners under `execution/scheduling/loop/bounds/` and
  `execution/calls/interprocedural/`.
- Limited sandbox backends to native OS isolation on Linux namespaces and Windows
  AppContainer.
- Enforced cross-package boundaries with import-linter contracts across core,
  execution, analysis, scanner, contracts, models, reporting, sandbox, and
  benchmarks.

### Adaptive Exploration

- Host path, symbolic depth, VM iteration, analysis timeout, and host memory limits
  are now elective. Omitted CLI, API, and config values select automatic mode with no
  implicit numeric stop; positive user limits still record `resource_limit_*`
  degradation when reached.
- Replaced fixed loop iteration cutoffs with evidence-driven convergence: exact finite
  iterators, exact state recurrence, affine countdown proofs, symbolic iterator upper
  bounds, and explicit widening or inconclusive fallback when convergence is not
  provable.
- Replaced hidden representation caps for large concrete `range` values and repeated
  list/tuple materialization with exact lazy symbolic views.
- Hard-theory literal and witness preprocessing always runs before the configured
  solver decides SAT/UNSAT/UNKNOWN, regardless of constraint count.
- Added `docs/arch/ADAPTIVE_EXPLORATION.md` with the automatic-mode invariant,
  limit classification, migration plan, and residual undecidability risk. Updated
  `docs/arch/LIMITS.md`, `docs/CLI.md`, and `docs/API.md` for automatic defaults.
- Sandbox security limits, per-query solver deadlines, cache capacities, and telemetry
  truncation remain explicit boundaries and are unchanged.

### CLI and Profiling

- Added `--profile`, `--profile-output-dir`, and `--profile-baseline` for developer
  profiling during `pysymex scan`; writes cProfile output plus schema-v2 JSON summary
  artifacts with Python/platform metadata, frame-origin classification, subsystem
  phase accounting, solver and detector cache reuse, and baseline comparison against a
  prior profile artifact.
- Added `pysymex trace-analyze` for streaming JSONL execution-trace filtering,
  summarization, and diagnostic projection over `pysymex scan --trace` output.
- Reject malformed numeric limits and invalid symbolic argument hints at parse
  time before target loading or execution starts.

### Scanning and Reporting

- Scanner results now expose honest top-level `result_level` values:
  `confirmed_issue`, `possible_issue`, `degraded`, `inconclusive`, and `safe`.
- Added opt-in native-sandbox replay confirmation: when isolated CPython reproduces a
  reported exception at the reported line, the issue upgrades to `confirmed_issue`;
  replay failures remain `possible_issue` with a bounded `replay_status` field.

### Symbolic Execution and Models

- Added fixed-tuple scan input modeling: annotations such as `tuple[int, str]` preserve
  arity and element input types through hint normalization and initial symbolic state
  construction.
- Fixed symbolic tuple indexing so feasible out-of-bounds branches report
  `INDEX_ERROR` while preserving reachable success successors.
- Improved symbolic string handling, symbolic input type checking, and container index
  error reporting.
- Enhanced loop and iterator exit handling, including iteration cleanup and reraise
  preparation at unwind boundaries.
- Improved KeyError detection and counterexample extraction for container access
  paths.
- Added bounded equality-derived short-string concrete preflight for fully pinned
  short-string witnesses before symbolic reporting.
- Refactored `SymbolicString` to construct a direct symbolic string carrier, improving efficiency in symbolic value handling.
- Enhanced equality comparisons for symbolic values in `LoopWidening` to reflect true structural equality more accurately.

### Solver and Evidence

- Replaced repeated AST constant collection in witness probing with the one-pass
  `WitnessConstants` owner from `analysis.evidence.cache`.
- Changed witness-variable cache identity from transient Python wrapper identity to
  validated Z3 context/AST identity with a bounded entry cap.
- Improved witness-constants caching and formula handling in the solver pipeline.
- Optimized path constraint handling in `VMStatePathMixin` to return immediately if the constraint is true, simplifying mutation logic.
- Added sequence-linear branch feasibility checks in `branching.py` for cheaper pruning of constraints.
- Refactored the witness extraction process in `feasibility.py` and `hard.py` to prioritize float and string witnesses before integer and boolean ones, enhancing feasibility detection clarity and speed.

### Developer Workflow

- Updated dependency pins and CI/architecture constraint checks.
- Added import-linter enforcement to pre-commit alongside existing formatting
  hooks.
- Default pytest runs now exclude `@pytest.mark.slow` tests unless selected with
  `-m slow`.
- Added `basedpyright` to development dependencies and expanded strict type-check
  coverage.
- Standardized `frozenset` initializations across the codebase to consistently use parentheses `()` instead of curly braces `{}`.
- Enhanced type hinting and safety by replacing string annotations with actual types, using `Mapping` instead of `dict` in `classes.py`, and refining parameter lists for satisfiability check functions.
- Reorganized and cleaned up imports across multiple modules (e.g. `passes.py`, `file.py`, `parallel.py`, `sequential.py`, `types.py`, and `splitting.py`) to enforce consistent usage of `TYPE_CHECKING`.
- Improved error messaging by formatting exception messages before raising them (in `__init__.py`, `analyze.py`, and `inputs.py`), and eliminated backward-compatible monkeypatching of `PathSatisfiability.result`.

### Known Limits

- Automatic exploration does not prove termination or completeness for arbitrary
  Python; unsupported recurrence, hard SMT theories, and per-query solver `UNKNOWN`
  still yield inconclusive or precision-loss output rather than definite safety.
- Per-query solver timeouts remain explicit `UNKNOWN` boundaries and are not treated
  as infeasible paths.
- Bounded termination evidence is not a general ranking-function or liveness proof.
- Sandbox setup still fails closed when no supported native backend is available.
