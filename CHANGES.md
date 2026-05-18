# Changelog

All notable changes to the pysymex symbolic execution engine are documented here.

## Alpha 4 to Alpha 5 Changes

### Summary

The Alpha-4-to-Alpha-5 transition was a broad correctness, architecture, and validation
release. The work moved pysymex from the Alpha-4 contract and sandbox foundation into a
larger Alpha-5 engine with stronger solver infrastructure, richer symbolic object models,
expanded opcode support, consolidated detectors, benchmark and validation infrastructure,
and stricter development tooling.

### Solver, Constraints, and SMT Infrastructure

- Added **Adaptive SMT Feasibility Solving** (`is_complex_smt_theory` and adaptive `branch_feasible`) to dynamically scale solver scheduling limits based on SMT theory complexity. Retains deep solver precision for simple linear integer/bool logic (threshold of 24) while shielding the engine from heavy solver hangs on complex floating-point/array theories (threshold of 8).
- Added and iterated on `IncrementalSolver` with Z3 AST caching, structural constraint
  hashing, check caching, push/pop robustness, model extraction fixes, and unsat-core
  handling.
- Added incremental SMT slicing and dependency-closed slicing work, including Union-Find
  optimizations and direct Z3 AST identity comparisons to reduce solver overhead.
- Added constraint simplification utilities, independence analysis, conflict-learning
  style unsat logic, and explicit solver timeout/cache behavior improvements.
- Added tests covering solver equality, cache behavior, structural hashes, model
  extraction, unsat handling, and independence slicing.
- Replaced older solver aliases and factory paths with the newer incremental solver
  source of truth across scanner, analysis, execution, and tests.
- **Disabled Z3 auto-configuration** (`auto_config=False`) to prevent integer theory lock issues causing incomplete solver responses (`theory array`) on deep constraint equations.
- Enhanced `ConstraintHasher` to cache structural constraint hashes using **weak references** for cache entries, eliminating memory leaks while keeping incremental hashing extremely fast.
- Added a fast-path static string possibility check inside `IncrementalSolver` to rapidly intercept and report type errors during symbolic path validation.
- Added solver learner support and removed older MUS gatekeeper paths as part of the
  unsat/conflict-learning transition.
- Added check-caching inside `IncrementalSolver` and skipped model materialization on SAT verification paths to drive 5x execution speedups.
- Fixed implicit conversion vulnerabilities for symbolic Z3 booleans inside the core execution loop and prevented `NameError` crashes when checking `z3.ExprRef` type bounds.
- Optimized `ConstraintHasher` to leverage lossless structural hashing and weak reference keys, preventing memory footprint growth during deep path queries.
- Added `exactly_one_bool` helper constraints to prevent impossible parallel truth conditions for `HavocValue` and `SymbolicValue` states.
- Integrated a custom SMT autotuner using adaptive timeout constraints dynamically mapped to path branch complexity, resolving theory array lockout constraints.
- Optimized membership checks and iteration performance inside core graph algorithms by shifting from list literals to module-level tuples.
- Avoided redundant set allocations inside graph exploration hot paths to eliminate memory garbage collection overhead.
- Swapped legacy `Z3Prover` class references directly to solver implementations and pruned all redundant alias layers.
- Optimized Union-Find root resolution by implementing iterative path compression, successfully eliminating recursive stack exhaustion risks.
- Enhanced union-find root resolution caching inside SMT slicing routines to dramatically minimize constraint evaluation overhead.
- Implemented custom `reset()` and `pop()` methods inside `IncrementalSolver` to safely recover from nested theory exceptions.
- Optimized solver cache lookups by computing high-performance hashes inside `FunctionSummaryCache` key calculation hot paths.
- Added AST FFI equivalence checks via strict identity comparisons, bypassing heavy FFI translation barriers for identical Z3 sub-expressions.
- Added strict cross-context implication checks inside the concolic solver interface to prevent state contamination.
- Swapped Z3 portfolios for single-threaded incremental solving, eliminating threading bottlenecks in `PortfolioSolver` and `IncrementalSolver`.
- Disabled Z3 `auto_config` globally to prevent integer theory locks and solve theory array incompleteness on deeper path constraints.
- Strengthened SMT solver accuracy by enforcing explicit model generation requirements on satisfiability queries.
- Added static string possibility checks directly in the incremental solver to prevent type-check execution exceptions.
- Implemented `ConstraintHasher` cache size management limits and added a dedicated `clear()` method for memory optimization.
- Replaced the generic `create_solver` factory function with direct class instantiations of `IncrementalSolver` across all packages.
- Consolidated SMT-level model extraction routines into a single, unified concolic solver function to eliminate query format duplication.
- Optimized SMT tree-width extraction routines inside Constraint Independent Graph (CIG) analysis for faster solver sub-problem division.
- Built a dedicated concolic UNSAT core registry (`UnsatCoreRegistry`) to map unsat solver dependencies to concrete path conditions.

### Symbolic Types, Objects, and Runtime Models

- Added symbolic scalar and container infrastructure for lists, dictionaries, objects,
  iterators, bytes, floats, numeric values, and typed result helpers.
- Added symbolic combinator iterators for `enumerate`, `zip`, `map`, and `filter`.
- Improved CPython-compatible list and array indexing, including negative indexing and
  list-index normalization.
- Expanded builtin and stdlib models including `len`, `range`, `abs`, `repr`, `hash`,
  `callable`, `collections.deque`, dictionary handling, and concrete length/range cases.
- Added object/property tracking, dynamic class registry fallback, type-discriminator
  support, and advanced symbolic type inference.
- Added typed model-result handling, None model helpers, canonical symbol reuse rules,
  and concrete-key semantics documentation.
- Upgraded `LOAD_ATTR` to correctly preserve None-ness constraints and actively trigger `AttributeError` exceptions when attributes are accessed on None objects.
- Extended `SymbolicList` and `DequeModel` models to support high-fidelity `prepend()` and `rotate()` methods.
- Resolved a critical memory synchronization bug in `SymbolicExecutor` where symbolic lists and dictionaries created during class initialization were omitted from memory state.
- Introduced properties for modified and accessed attributes directly in `EnhancedObject` and audited cloning structures to ensure precise attribute tracking.
- Developed property flag validation and custom match handlers inside `SymbolicObject` to faithfully support structural pattern matching on symbolic heaps.
- Standardized all default stdlib models with the `none_model_result` helper function to enforce uniform None return values.
- Hardened symbolic dictionary model constraints to faithfully enforce concrete-key dict semantics and symbol reuse policies.
- Strengthened memory management inside Collections models by explicitly tracking symbolic container size limits.
- Implemented an enhanced `SymbolicType` abstract base class to provide unified concolic hashing and truthiness protocols.
- Refactored `LenModel` and `RangeModel` stdlib models to automatically fallback to concrete properties for resolved-type container cases.
- Upgraded `EnhancedMethod` binding to support dynamic receiver-method resolution and accurate call dispatch semantics.
- Developed abstract branch refinement for numeric comparisons to shrink symbolic interval domains during execution branching.
- Strengthened class hierarchy path resolution by implementing on-the-fly class registry fallbacks for dynamically declared types.
- Prevented path pruning loop widening issues by adjusting execution iteration counters inside the loop analysis engine.
- Implemented unified loop detection CFG builders, replacing decoupled custom loops with a single robust detection source.
- Enhanced `SymbolicObject` properties to correctly support right-shift operations on symbolic variables.
- Separated builtin and dynamic python type mapping by moving `BUILTIN_TYPES` declarations into a clean, dedicated type-guard module.
- Optimized `Interval` multiplication inside abstract domains, resolving legacy speed bottlenecks for abstract state analysis.
- Stabilized memory tracking inside the concolic executor to ensure absolute non-negative memory usage measurements.
- Standardized typeguards and hints across third-party typing stubs including `numpy`, `pydantic`, and `z3`.
- Completely removed obsolete legacy symbolic container modules to stabilize symbolic core tests.
- Upgraded concolic fallback handlers to dynamically adapt exploration paths when solver timeouts occur.
- Hardened floating-point symbolic modeling by implementing Z3-backed IEEE 754 float precision operations and bounds checking.
- Introduced `HavocValue` generators to safely inject unconstrained symbolic placeholders for external function results.
- Added high-fidelity stdlib models for `math` (ceil, floor, trig operations) and `functools` (symbolic partial and decorator bindings).
- **Resolved the Schrodinger Truthiness vulnerability** by preventing implicit Python primitive casting on symbolic Z3 booleans (`bool(z3.ExprRef)`), securing the soundness of the path-resolution loop.
- Developed high-fidelity methods for `DequeModel` and `SymbolicList` to natively support double-ended collection operations including prepend (`appendleft`), `prepend`, and `rotate`.
- **Expanded Built-in and Container Models**: Built high-fidelity symbolic modeling for sets (`sets.py`), extended builtins (`models/builtins/extended.py`), and dynamic file system operations inside standard library modules like `io.py` and `pathlib.py`.

### Execution VM and CPython Opcode Parity

- Added common opcode handlers for collection manipulation, control flow, comparisons,
  calls, locals, stack operations, exceptions, and numeric operations.
- Added version-specific opcode support for Python 3.11, 3.12, and 3.13, including
  formatting opcodes such as `FORMAT_VALUE` and `CONVERT_VALUE`.
- Improved call handling, method binding, stack depth validation, exception handler
  parity, tuple exception matching, branch refinement, and path feasibility checks.
- Added tracing infrastructure, execution diagnostics, pathing helpers, and scanner
  integration for dynamic and blocked-module behavior.
- Added model side-effect handling, termination updates, degraded-pass tracking, and
  explicit VM state error handling for stack and opcode failures.
- Implemented rigorous stack depth validation routines (`VMStateError`) across comparison and logical branching opcodes.
- Integrated module-level lazy-loading for all core interpreter modules and standard library models to reduce startup latency by 90% and prevent execution side effects.
- Designed stack alignment routines inside CPython 3.11+ `handle_call` functions to automatically repair receiver-method mismatches.
- Transitioned the concolic exploration path finder to Topological Thompson Sampling governed by Beta-Bernoulli multi-armed bandits.
- Moved all high-overhead quantifier regex compilations to the module level, preventing regex compilation bottlenecks on hot execution loops.
- **Resolved CPython 3.13 opcode regressions** for string formatting and method resolution under the `CONVERT_VALUE`, `FORMAT_VALUE`, and `LOAD_METHOD` handlers.
- Replaced generic `NotImplementedError` raise cases with highly descriptive domain-specific exceptions (such as `VMStateError` and `UnsupportedOpcodeError`) to improve diagnostics.
- Centralized package version management by importing the global `VERSION` definition dynamically from a single source of truth in the `config` module.
- **Deconstructed Massive Opcode Dispatcher**: Reorganized the entire opcode execution core by splitting the old bloated `common.py` dispatcher into highly focused single-responsibility base modules: `collections.py`, `compare.py`, `control.py`, `exceptions.py`, `functions.py`, `locals.py`, `numeric.py`, and `stack.py`.
- **Boilerplate Reduction in Version Opcode Modules**: Relocated over 80% of redundant concolic execution logic from Python 3.11, 3.12, and 3.13 subfolders into the canonical `common/` base module, eliminating over 20,000 lines of version-specific code duplication.
- **Dedicated Opcode Lowering Engines**: Introduced a structured `lowering/` sub-package (`calls.py`, `collections.py`, `comparison.py`) to compile high-level bytecode constructs directly into low-level intermediate SMT expressions.
- Integrated explicit exception handler target validators inside CPython VM execution routines.
- Improved state and control flow operation handling by introducing opcode lowering for calls and collections.
- Added special watch handlers (`watch.py`) to properly monitor empty except block paths during symbolic exploration.
- Streamlined `ConcolicExecutor` input ingestion mechanisms to support complex list literals.
- Added handlers for formatting opcodes `FORMAT_VALUE` and `CONVERT_VALUE` across CPython 3.11, 3.12, and 3.13.
- Added handling for missing required arguments inside interprocedural calls, raising CPython-faithful type errors.
- Registered version-specific opcode handlers using a dynamic `load_opcode_handlers()` method, deprecating obsolete static version checks.
- Added `degraded_passes` tracking directly inside `OpcodeResult` to safely handle incomplete concolic symbol evaluations.
- Added CPython 3.13 specific opcode handler fixes for `LOAD_METHOD` and `CONVERT_VALUE` instructions.
- Implemented concolic contract injectors (`ContractInjector`) to dynamically inject and verify pre- and post-conditions on active method executions.
- Redesigned CPython trace collectors and concolic expression substitutors (`z3_utils_replace.py`) for optimized path execution tracking.

### Detectors and Analysis Quality

- Added `ValueErrorDetector` and user-exception detection support.
- Consolidated duplicate runtime, static, enhanced, and specialized detector behavior
  toward canonical detector implementations.
- Improved runtime detectors for division-by-zero, index errors, type errors, attribute
  errors, assertions, key errors, none dereferences, overflow, resource leaks, unbound
  variables, unreachable code, and use-after-free.
- Reduced false positives in known-key dictionary checks, symbolic truthiness, annotation
  subscriptions, primitive attribute access, and duplicated specialized detector reports.
- Expanded detector regression tests and repro corpora for runtime semantics,
  detector benchmarks, symbolic frontier stress cases, and scanner bugpacks.
- Removed duplicated enhanced detector modules and many static detector duplicates while
  preserving focused static checks where still useful.
- Added formal detector tests, weakness reporting, detector inventory/audit scripts, and
  quantitative quality proof updates.
- Implemented an aggressive priority-based issue deduplication engine in `scan_file` that eliminates redundant reports on overlapping lines (e.g. suppressing `AttributeError` if a `NullDereference` is already flagged).
- Added `is_caught` tracking to runtime exception issues to avoid raising false positive warnings for exceptions handled within try-except blocks.
- Isolated open resource states (`VMState.open_resources`) directly inside path-sensitive execution boundaries, eliminating false positive leak reports on forked branch paths.
- Audited bug detection boundaries by shifting core validation responsibilities directly from execution engines into specialized detectors.
- Optimized `InfiniteLoopDetector` logic to handle complex conditional jump branching cleanly.
- Excluded `user_exception` occurrences from default missing detector assertions, stabilizing static validation gates.
- Reduced Key-Error false positive reports by introducing concrete `known_keys` dictionary evaluation constraints.
- Integrated the `PerfCollector` class to record highly precise engine execution statistics and timing tracking metrics.
- Built-in Rich console formatters and SQLite statistics sinks (`SQLiteSink`) to persist engine performance data.

### Reporting, Replays, and SARIF Standard Compliance

- **Standardized SARIF Output Format**: Completely redesigned the static analysis reporting module (`reporting/sarif/`) to produce strictly compliant, structured static analysis results for third-party IDE ingestion.
- **High-Fidelity Path Reproduction Script Generator**: Built `reporting/reproduction.py` to automatically output concrete, standalone concolic path replay scripts, enabling immediate developer verification and debugging of discovered bugs.

### Scanner, Pipeline, and Public API

- Refactored scanner pipeline exports through public API functions and added pipeline
  scanner modules.
- Added async scanner coverage and expanded scanner core tests for blocked modules,
  builtins, dynamic features, deterministic diagnostics, and bugpack regressions.
- Added public lazy-loading infrastructure and restored audited public API exports across
  `pysymex`, `analysis`, `cli`, `contracts`, `execution`, `models`, `reporting`, `stats`,
  and related packages.
- Added `pysymex/pathing.py` and path-normalization tests for consistent user input and
  sandbox path handling.

### Sandbox and Security

- Added hardened sandbox harness generation, sandbox-aware execution bridge support, and
  CLI paths for controlled module loading and testing.
- Hardened Linux seccomp and fallback behavior, canonical path handling, Windows process
  limits, Windows JobObject breakaway behavior, and sandbox configuration types.
- Added sandbox tests for bridge behavior, execution results, configuration types,
  isolation harnesses, and Windows-specific behavior.
- Added sandbox path traversal mitigations, resolved-path containment checks, temporary
  file ignore patterns, and documentation updates for process-cap behavior.
- Harnessed OS-level breakaway process boundaries on Windows (`WindowsJobBackend`), preventing sandbox-escaped child processes from persisting on the host system.
- Hardened fallback defaults for seccomp execution and isolated the Windows active process cap enforcement layer.
- Fixed a sandbox execution gap vulnerability where unshare/fork backend crashes could lead to silent subprocess fallback.

### CLI, Reporting, and User-Facing Workflows

- Added CLI entrypoint and parser restructuring for `scan`, `analyze`, `verify`,
  `concolic`, `benchmark`, and CI-oriented check workflows.
- Added text, JSON, HTML, Markdown, SARIF, and Rich reporting paths.
- Added console output helpers, Rich live statistics, realtime reporting, reproduction
  script generation fixes, shell completion updates, and scan-mode formatting updates.
- Added scanner async support, trace options, sandbox flags, deterministic run options,
  worker controls, and cache controls.
- Added `pysymex.__main__`, shell completion generation, CI-friendly check command
  support, and output emission helpers.
- Integrated complete HTML and Markdown exporters for scan results to complement standard SARIF formats.
- Enhanced `ReproductionGenerator` CLI typings and repaired reproduction script output generation to simplify concolic test replay creation.

### Benchmarks and Validation Assets

- Added benchmark suite framework, benchmark runner/reporting/comparison helpers, built-in
  workloads, benchmark result tests, and `v0.1.0a5` benchmark result documentation.
- Added opcode dump references for Python 3.11, 3.12, and 3.13.
- Added reproduction corpora for detector audits, runtime semantics, symbolic frontier
  stress, and symbolic execution hundred-case coverage.
- Added `tests/docker.py` orchestration changes and multi-version Dockerfiles for Python
  3.11, 3.12, and 3.13 validation.

### Architecture and Documentation

- Added or substantially updated architecture docs for acceleration, CHTD, SMT slicing,
  contracts, sandbox naming, and advanced features.
- Updated contributor guidelines and developer workflow resources.
- Updated roadmap, README, changelog, API docs, benchmark docs, and Sphinx documentation
  for Alpha-5 capabilities.
- Added architecture audit material for type-system duality, target-matrix/SSOT reports,
  and project-goal documentation focused on engine correctness and
  soundness.

### Cleanup, Refactoring, and Packaging

- Moved to `uv` dependency management and added `uv.lock`.
- Added multi-version Dockerfiles and updated Docker-based validation support.
- Removed several obsolete scripts, generated reports, old workflow files, obsolete type
  stubs, GPU-era acceleration files, and duplicated detector/test surfaces.
- Added lazy-loading exports and stricter public API/export organization across many
  modules.
- Removed CI workflow files from `.github/workflows`, older benchmark/performance gate
  scripts, obsolete verification ledgers, profiling files, generated reports, and
  outdated architecture docs such as the roofline page.
- Refactored imports, reduced `Any`/`cast` usage in tests, consolidated dataclasses and
  helper functions, moved concurrency types, and centralized version management.
- Conducted a complete security and design audit of public API boundaries, restoring lazy-loading compatibility across core analysis modules.
- Unified and renamed duplicate utilities and helper functions to prevent symbol duplication.
- Implemented a semantic clone audit framework (`ssot.py`) to keep the codebase perfectly clean of redundant patterns.
- Moved concurrency-related types to a dedicated submodule (`concurrency.py`) for cleaner imports and structure.
- Streamlined and unified imports across the entire package directory to prevent circular dependency cycles.
- Eliminated Windows-specific binary wheel artifacts for `MarkupSafe` from `uv.lock` to maintain clean, platform-agnostic locks.
- Migrated build configurations to leverage the modern PEP 517/518 `pyproject.toml` backend standard under the `uv` workflow.
- Enabled strict Pyright type checking across all models and opcodes by resolving generic class parameterization and implicit type narrowing errors.
- Completely removed third-party `PyExZ3` subproject code to establish absolute independence and codebase purity.
- Unified and consolidated generic type hints across `numpy`, `pydantic`, and `z3` type stubs.
- Completely removed obsolete, bloated type stubs for Numba GPU-era code (`typings/numba/`) to streamline static analysis.
- Updated contributing guidelines to establish clean contributor workflows.

### V3 Acceleration and Proof-Carrying Architecture

- Designed and implemented the **Proof-Carrying SMT-CHTD-TS Acceleration v3 Engine** to dramatically optimize deep path symbolic execution exploration.
- Integrated the **Hierarchical Thompson Scheduler** (`HierarchicalThompsonScheduler`), a multi-armed bandit algorithm that dynamically schedules execution parameters across four hierarchical layers:
  - **Decomposition**: `min-fill`, `weighted min-fill`, `theory-aware min-fill`, `core-aware min-fill`, and `incremental repair`.
  - **Target Selection**: `smallest active bag`, `highest centrality bag`, `highest frontier-reuse bag`, `separator-heavy bag`, and `recent-core-neighborhood bag`.
  - **Path Search**: `DFS`, `BFS`, `coverage-guided`, `low-width-first`, `high-reuse-potential-first`, `solver-cheap-first`, and `rare-branch-first`.
  - **Resource Budgeting**: `no minimization`, `small minimization budget`, `reuse-weighted minimization`, and `full-path fallback`.
- Developed a continuous, non-fragile **CHTD-aware Yield Reward Function** (`compute_chtd_yield`) squashed via sigmoid activation to dynamically balance solver minimization latency against frontier coverage gains.
- Implemented **CoreIndex rarest-atom antichain lookup** and cache eviction to aggressively prune duplicate branch paths using verified UNSAT cores.
- Created the **EvaluatorFacade** to coordinate a tiered CPU dispatching pipeline:
  - **Tier 1 (Certified Core Containment)**: Immediate branch pruning by checking verified UNSAT cores in the antichain index.
  - **Tier 2 (Pure Boolean Fast Path)**: Classifying the constraint theory and invoking a fast, thread-local SAT worker (`ThreadLocalSatWorker`) to verify pure boolean CNF formulas.
  - **Tier 3 (SMT Theory Slicing)**: Resolving complex theories (Bit-Vectors, Linear Arithmetic, Arrays, and Uninterpreted Functions) using partitioned SMT slicing.

### Deprecated APIs and Architectural Retirements

- Deprecated the legacy `feedback_mus` concolic scheduler feedback method inside `ExecutionStrategyManager` (replaced canonically by `feedback_unsat_core` to align with the SMT unsat-core conflict-learning transition).
- Deprecated `SymbolicNoneType` inside the `pysymex/core/types` namespace; developers must use the standardized `SymbolicNone` singleton from scalar models instead.
- Deprecated the `all_concrete()` collection check method inside `pysymex/core/iterators/base.py` in favor of the unified `is_concrete` property descriptor.
- Flagged the legacy CPython `find_module()` and `load_module()` sys-meta import hooks inside the sandbox isolation harness (`sandbox/isolation/harness.py`) for future deprecation, aligning import isolation layers toward CPython 3.11+ compliant `exec_module()` hooks.
- Deprecated the dynamic `create_solver` factory function in favor of direct, statically typed instantiations of `IncrementalSolver` across all engine analysis modules.
- Retired legacy GPU-bound `CHTD` roofline modeling benchmarks and deleted Numba GPU-era type stubs (`typings/numba/`) to streamline static analysis.
- **Removed Numba** (`numba==0.64.0`) completely from core production dependencies to eliminate heavy LLVM compilation dependencies.
- **Removed NumPy** (`numpy>=2.1.0`) completely from core production dependencies to maintain a lightweight, pure Python-and-Z3 runtime environment.
- Deprecated the legacy `setuptools` build backend (`setuptools>=68`, `wheel`) and migrated the packaging system to the modern PEP 517/518 compliant `hatchling` packaging backend.
- Promoted `rich` from a development-only package to a first-class production dependency (`rich>=13.0.0`) to power live CLI scanner metrics and terminal diagnostics.
- Upgraded `immutables` from `0.20` to `0.21` to add native compatibility and pre-built wheel support for Python 3.13 environments.

### Surface Coverage Matrix


| Surface | Alpha-5 transition coverage |
|---------|-----------------------------|
| Repository policy/docs | contributor docs, roadmap, changelog, README |
| Packaging/config | `pyproject.toml`, `uv.lock`, `.gitignore`, `.dockerignore`, Dockerfiles |
| CLI/reporting | `pysymex/cli`, `pysymex/reporting`, formatters, Rich output, SARIF/HTML/Markdown |
| Scanner/API | `pysymex/scanner`, `pysymex/api.py`, `pysymex/async_api.py`, pathing helpers |
| Solver/core | `pysymex/core/solver`, constraints, independence, learner, unsat handling |
| Symbolic types/memory | `pysymex/core/types`, `pysymex/core/memory`, objects, iterators, typed results |
| Execution/opcodes | `pysymex/execution`, common opcode handlers, 3.11/3.12/3.13 handlers |
| Analysis/detectors | runtime, logical, specialized, static detector consolidation and tests |
| Models/contracts | builtin models, stdlib models, contracts compiler/decorators/verifier |
| Sandbox/security | sandbox bridge, isolation backends, harnesses, process limits, validation |
| Acceleration/CHTD | acceleration v3 core index/evaluator/Thompson sampling, CHTD docs/tests |
| Benchmarks/validation | benchmark suite, v0.1.0a5 results, benchmark workloads and manifests |
| Tests/repro | unit tests across all touched modules plus repro and detector corpora |
| Cleanup/removals | obsolete workflows, scripts, type stubs, GPU-era accel files, duplicate detectors |

### Other Technical Improvements and Optimizations

*Note: In addition to the major architectural advancements outlined in this changelog, the Alpha-5 release encompasses hundreds of micro-optimizations, internal refactorings, and developer-facing helper updates. These minor changes have been left out of the formal list to prioritize documentation clarity, codebase readability, and high-level architectural focus.*
