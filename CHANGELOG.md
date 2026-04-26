# Changelog

All notable changes to pysymex will be documented in this file.


## [0.1.0-alpha.4] - 2026-04-26

### v2 Core Graduation & Experimental Contracts: Architectural Maturity & Formal Verification

- **v2 Architecture Graduation**: Finalized the transition to the **Constraint Interaction Graph (CIG)** foundation. This release replaces the legacy message-passing logic from `a1` with precise **Activation-Literal MUS Extraction**, enabling the engine to operate as a true "structural hunter" that targets localized constraint bags with mathematical exactness.
- **Tiered CPU Solver Dispatcher**: Introduced an intelligent routing layer that automatically selects the optimal solver backend (Thread-Local SAT for pure boolean logic, Z3 CDCL for mixed arithmetic, or Reference for ground-truth validation).
- **Activation-Literal MUS Extraction**: Replaced legacy message-passing with precise structural contradiction detection using Z3's activation literals. This extracts the exact Minimal Unsatisfiable Subset (MUS) in a single query, significantly improving pruning precision.
- **Asynchronous Core Learning**: Introduced background MUS extraction to prevent "solver stall." The engine now continues optimistic execution on likely feasible paths while a background worker proves structural UNSAT, pruning the search tree asynchronously upon discovery.
- **Topological Thompson Sampling**: Integrated the Topological Information Yield ($\mathcal{Y}_{\text{topo}}$) equation into the Adaptive Path Manager, allowing the engine to actively hunt for structural bottlenecks and prune redundant paths based on graph-theoretic yield.
- **Sparse Bitset State Optimization**: Implemented memory-safe structural pruning using Run-Length Encoded (RLE) sparse bitsets (Roaring Bitmaps), allowing sub-millisecond containment checks even for massive program branch counts.
- **Incremental SMT Slicing**: Introduced true incremental prefix synchronization and chronological Copy-on-Write (COW) chains to minimize Python-to-Z3 FFI overhead.

### Breaking Changes ⚠️
- **Massive Architectural Refactor**: Reorganized the entire `pysymex` package into a modular sub-package structure. Core modules in `analysis`, `core`, `execution`, `models`, `reporting`, and `sandbox` have been moved into granular sub-directories to improve maintainability.
- **Removal of GPU Acceleration**: The `h_acceleration` module and CuPy/GPU offloading have been removed due to PCIe latency limitations and state fragmentation. Replaced entirely by the thread-local CPU SAT approach in the `accel` module.
- **Taint Tracking Removal**: The explicit taint tracking system and related detectors have been removed. Flow-based taint analysis will be handled by abstract interpretation in future versions.
- **Contract System Overhaul**: Removed the legacy `ContractAnalyzer` and `ContractVerificationExecutor`. Functional verification is now handled through a modernized modular contract system (`compiler`, `decorators`, `injector`, `verifier`) integrated into the `VerifiedExecutor`.
- **CLI Consolidation**: Removed `pysymex-verify` and `pysymex-trace-analyze` entry points. All functionality is now unified under the main `pysymex` CLI.
- **Dependency Pinning**: Transitioned to strict pinning for core dependencies (`z3-solver==4.15.3.0`, `pydantic==2.12.5`, `immutables==0.20`, `numba==0.64.0`) to ensure deterministic and stable execution environments.
- **Optional Dependencies Cleanup**: Removed several legacy optional dependency groups including `accel-cpu`, `accel-gpu`, `accelerate`, `gpu`, and `gpu-cuda`.

### Added ✨
- **Experimental: Full Formal Verification Lifecycle**: Version `a4` graduates the contract system from basic quantifiers to a complete formal verification engine in `pysymex.contracts`.
    - **Hoare-Logic-Based Verifier**: Uses Z3 to prove validity of postconditions and satisfiability of preconditions against path constraints.
    - **Inductive Loop Invariants**: Supports formal verification of loop properties via base-case and inductive-step checks.
    - **Symbolic Contract Compiler**: A thread-safe, caching compiler that translates Python lambdas into Z3 formulas using specialized combinators (`And_`, `Or_`, `Not_`, `Implies_`) to bypass Python's short-circuiting keywords.
    - **Decorator-Driven API**: High-level `@requires`, `@ensures`, and `@invariant` decorators for seamless specification of function and loop properties.
- **Docker Multi-Version Testing Infrastructure**: Introduced a complete Docker-based testing suite in the `docker/` directory.
    - **Dedicated Environments**: Includes pre-configured `Dockerfile`s for Python 3.11, 3.12, and 3.13.
    - **Automated Validation**: Integrated a new `tests/docker.py` orchestration script to run the full test suite in parallel across all supported Python versions in isolated containers, ensuring clean-state validation before pushing changes.
    - **Persistent Development**: Containers are optimized for persistent use with volume mounts for live code editing.
- **New Mirrored Test Architecture**: Overhauled the `tests/` directory to mirror the `pysymex/` package structure exactly. This provides 1:1 parity between source modules and their corresponding test suites, significantly improving discoverability and maintaining 100% code coverage.

- **New Acceleration Module (`accel`)**: Introduced a high-performance, thread-local CPU-based SAT solver backend (using CaDiCaL fast-path) to replace GPU offloading, providing lower latency and better state management.
- **Version-Specific Opcode Handlers**: Added dedicated handlers for Python 3.11, 3.12, and 3.13 in `pysymex.execution.opcodes`, ensuring precise symbolic execution across different Python versions.
- **Metrics Subsystem (`stats`)**: Added a comprehensive statistics collection and reporting module for tracking performance and execution metrics.
- **Shared Utilities (`utils`)**: Introduced a `pysymex.utils` package for common helper functions and mathematical primitives.
- **Immutables Integration**: Integrated the `immutables` library for persistent VM state management, significantly reducing memory pressure during path forking.
- **New Bug Detectors**:
    - Added `enhanced_index_error` and `enhanced_type_error` detectors with improved diagnostic context.
    - Added `resource_leak` and `unbound_variable` detectors.
    - Added `assertion_error` detector to both runtime and static analysis phases.
- **Fix Suggestions**: `Issue` objects now include a `fix_suggestion` field, providing actionable advice for identified bugs.
- **Rich Console Support**: Integrated `rich` for improved CLI formatting and diagnostic reporting.

### Changed 🔄
- **VM State Optimization**: Refactored `State` and `VM` logic to leverage persistent data structures and efficient copy-on-write patterns.
- **Detector Modularization**: Reorganized all detectors into `logical`, `runtime`, `specialized`, and `static` sub-packages.
- **Sandbox Modernization**: Refactored sandbox isolation backends into a robust unified harness system.
- **License Header Standardization**: Standardized all source file headers to use the exact GPL license header format across the entire codebase.
- **Dev Dependencies**: Updated development tools, adding `psutil` and `rich` while removing `black` and `mypy` from the core dev list.

### Fixed 🐛
- Fixed a race condition in global opcode handler registration by adding `clear_global_handlers` to `OpcodeDispatcher`.
- Improved precision of `None` dereference and division-by-zero detection by categorizing them into runtime and static analysis phases.
- Standardized path sanitization logic across all sandbox backends to prevent edge-case host escapes.
- **And 100+ other minor improvements, internal refactorings, and stability fixes** to ensure the most robust alpha release to date.

## [0.1.0-alpha.3] - 2026-04-02

### Sandbox Hardening & Isolation

- **Core Sandbox Integration**: Promoted sandbox hardening as a core release feature across the isolation stack.
- **Strict Path Validation**: Added strict `extra_files` path sanitization for absolute paths, drive-prefixed paths, traversal segments, and dangerous leading dash segments.
- **Resolved-path Containment**: Enforced resolved-path checks before writes in sandbox isolation backends to prevent host escapes.
- **Windows Job Object limits**: Hardened Windows startup and Job handling with safer fallback behavior and memory-limit enforcement.

### Security and Verification

- **Adversarial Resiliency**: Expanded adversarial sandbox escape regression tests.
- **Formal Strictness Gates**: Added strictness-gate coverage and formal checks across solver, resources, integration, patterns, and loops.

### Release Hygiene

- **Documentation Updates**: Updated documentation, architecture pages, and roadmap for the 0.1.0-alpha.3 release.

### Bug Fixes

- 12 bug fixes implemented across core soundness and adversarial edge cases.


## [0.1.0-alpha.2] - 2026-03-20

### Hardware Acceleration (h_acceleration)

- **New Hardware Acceleration Pipeline**: Introduced the `h_acceleration` module to evaluate Boolean constraints near theoretical hardware limits, drastically accelerating CHTD bag solving.
- **CuPy / NVRTC GPU Backend (`gpu.py`)**: Added a high-performance GPU backend using CuPy and NVRTC. It generates and compiles pure CUDA C++ dynamically on the fly, eliminating Python overhead.
- **Numba CPU Backend (`cpu.py`)**: Added a highly optimized, multi-threaded CPU fallback using Numba's JIT compilation for environments without NVIDIA GPUs.
- **Architectural Separation of Concerns**: Cleanly separated backends so users without NVIDIA GPUs do not need to install the heavy CUDA toolkit.
- **16-byte Instruction Alignment**: Designed the internal ISA (`INSTRUCTION_DTYPE`) to use `uint16` structures padded to exactly 16 bytes. This prevents register overflow on complex expressions (supporting up to 8,192 variables) and perfectly aligns cache fetches for both modern CPUs (128-bit SSE/AVX vectors) and NVIDIA SMs (coalesced 128-bit loads).
- **Advanced JIT Optimizations**: 
    - *Thread Coarsening / ILP*: Manually unrolls evaluation loops inside the CuPy kernel to expose massive instruction-level parallelism, hiding register latency.
    - *Hardware Popcount & Warp Reduction*: Leverages `__popcll` and `__shfl_down_sync` to perform cross-warp summation in single clock cycles.
    - *Direct GPU Projection*: `evaluate_bag_projected` executes CHTD variable projection purely in GPU registers, emitting only the minimal output array to avoid PCIe transfer bottlenecks.
- **Advanced Bytecode Compiler (`bytecode_optimizer.py`)**: 
    - *Register Compaction & Renaming*: Recalculates variables backward to squeeze memory requirements into as few active registers as possible.
    - *Structural CSE & Memoization*: Common Subexpression Elimination uses AST hashing to prevent duplicate logic. DAG traversals are fully memoized to prevent exponential compile-time hangs.
    - *Aggressive Copy Prop / DCE*: Prunes unused operations strictly before JIT generation.

### Bug Fixes & Stability Improvements

Multiple correctness and stability fixes across the core engine, including:

- Fixed `core/types.py` floor division and modulo to match Python semantics exactly (previously used C-style rounding)
- Fixed `core/floats.py` missing `__floordiv__` on `SymbolicFloat` and incomplete IEEE-754 rounding mode support
- Fixed `execution/executor_core.py` `register_hook` silently dropping plugin handlers for execution hooks (`pre_step`, `post_step`, `on_fork`, `on_prune`, `on_issue`)
- Fixed `execution/executor_core.py` taint tracker not wired into initial execution state — taint tracking was initialized but never attached to the first path
- Fixed `core/solver.py` LRU cache using O(N) string conversion for keys — now uses structural hash O(1)
- Fixed `core/types_containers.py` `SymbolicList` allowing negative length and missing negative index resolution
- Fixed `execution/executor_core.py` `deduplicate_issues` and `filter_issues` called but not imported — caused `NameError` on any execution that found issues
- Fixed `analysis/cross_function/core.py` summary cache using unhashable types as dict keys in edge cases
- Fixed `core/types.py` `_merge_taint` crashing on `None` inputs from untainted operands
- Fixed `plugins/base.py` `register_hook` silently ignoring registrations for undeclared hook names

### Test Suite
- **5,702 tests passing** (up from 2,723), 0 failures
-

## [0.1.0-alpha.1] - 2026-03-15

### Path Explosion Mitigation (CHTD)

- **Constraint Interaction Graph & Treewidth Decomposition**: New `core/treewidth.py` module implements CHTD (Constraint Hypergraph Treewidth Decomposition) — builds a primal graph of variable-sharing between branches, computes tree decompositions via min-degree elimination, and extracts skeleton branch sets. Reduces path exploration from O(2^B) to O(N*2^w) for bounded-treewidth programs.
- **Constraint Independence Optimization**: KLEE-style constraint slicing in `core/constraint_independence.py` partitions path constraints into independent clusters via Union-Find, enabling per-cluster caching and 60-90% solver query reduction.
- **Adaptive Path Manager (Thompson Sampling)**: New `AdaptivePathManager` in `analysis/path_manager.py` uses a Beta-Bernoulli multi-armed bandit to dynamically balance DFS, coverage-guided, and random exploration strategies based on reward feedback. Removed legacy `HybridPathManager`.
- **Theory-Aware Solver Dispatch**: `IncrementalSolver` in `core/solver.py` now auto-detects dominant constraint theories (QF_LIA, QF_S, QF_BV, nonlinear) and tunes Z3 solver parameters per query for optimal performance. Auto-escalates to portfolio solver on mixed-theory queries.
- **Exception Forking**: Arithmetic operations inside try/except blocks now fork into dual paths (normal + exception) using Python 3.12+ exception table entries via `dis.Bytecode(func).exception_entries`. Implemented in `execution/opcodes/arithmetic.py` and `execution/dispatcher.py`.
- **Branch Affinity Fast Path**: `get_truthy_expr()` in `execution/opcodes/control.py` bypasses full disjunctive encoding when `affinity_type` is known, emitting single-sort Z3 expressions that reduce treewidth in the constraint interaction graph.
- **Interaction Graph Wired in Executor**: `execution/executor_core.py` feeds branch conditions into the constraint interaction graph and pipes treewidth/solver stats into `ExecutionResult`.

### Bug Fixes (13 pre-existing)

- Fixed infinite recursion in `plugins/base.py` `enabled` property (missing `_enabled` backing field)
- Fixed `plugins/base.py` `initialize()` requiring positional `api` argument (now optional)
- Fixed missing `constraint_discriminator` default in `core/parallel_types.py` `StateSignature`
- Fixed missing `max_queue_size` field in `core/parallel_types.py` `ExplorationConfig`
- Fixed `execution/opcodes/functions.py` `_dispatch_call` passing string to `_apply_model` instead of `func_obj` (root cause of SimpleNamespace test failures)
- Fixed `execution/opcodes/functions.py` `LOAD_ATTR` missing `CowDict` in isinstance check
- Fixed taint label propagation in `core/types.py` comparison operators (`__lt__`, `__le__`, `__gt__`, `__ge__`)
- Added missing `with_taint()`, `length()`, `substring()` methods to `core/types.py` `SymbolicString`
- Fixed `SymbolicString.__add__` using wrong field names (`z3_str` -> `_z3_str`, `z3_len` -> `_z3_len`)
- Fixed `SymbolicString.conditional_merge` returning wrong type (now returns `SymbolicValue`)
- Fixed positional argument order in `execution/opcodes/collections.py` `_format_value_symbolic`
- Fixed off-by-one in `resources.py` `check_all_limits` (`>` -> `>=`)
- Added `SymbolicFloat` handling to `tests/test_function_models.py` `get_concrete()` helper

### Test Suite

- **2,723 tests passing** (up from 2,583), 0 failures
- Added standalone integration tests (`verify_features.py`) covering treewidth, adaptive path manager, theory-aware solver, taint propagation, and full pipeline
- Added extreme stress tests (`stress_test.py`) with 12 path-explosion scenarios up to 2^13 theoretical paths

## [0.1.0-alpha] - 2026-03-01

### Initial Release

First public alpha release of pysymex (Python Symbolic Execution Engine).

#### Core Engine
- **Symbolic Execution Engine**: Full CPython 3.11–3.13 bytecode-level analysis
  - 100+ opcode handlers including Python 3.13 paired instructions (`STORE_FAST_STORE_FAST`, `LOAD_FAST_LOAD_FAST`, etc.)
  - Precision-guided exception handling with `SETUP_FINALLY` block tracking
  - Path exploration strategies: DFS, BFS, coverage-guided
- **Z3 SMT Solver Integration**: Incremental solver with push/pop scope management, caching, and portfolio solving
- **Symbolic Types**: `SymbolicValue`, `SymbolicString`, `SymbolicList`, `SymbolicDict`, `SymbolicNone` with full Z3 constraint modeling
- **VM State Management**: Copy-on-write state forking, structural constraint hashing, atomic path IDs

#### Analysis
- **12+ Bug Detectors**: Division by zero, modulo by zero, negative shift, index errors, key errors, None dereference, type errors, attribute errors, assertion failures, unreachable code, taint violations, integer overflow
- **Interprocedural Analysis**: Call graph construction, function summaries, cross-function return type inference
- **Taint Tracking**: Source-to-sink taint propagation with implicit flow tracking
- **Abstract Interpretation**: Interval, Sign, Parity, and Null lattice domains with product domain, widening, narrowing, and loop fixpoint computation
- **False Positive Reduction**: Dataclass awareness, context-sensitive exception analysis, known-crashy API allowlists, finding deduplication, and confidence scoring

#### Infrastructure
- **CLI**: `pysymex scan`, `pysymex analyze`, `pysymex verify`, `pysymex concolic`, `pysymex benchmark`
- **Output Formats**: Text, JSON, HTML, SARIF 2.1.0
- **Watch Mode**: Incremental re-analysis on file changes
- **Parallel Scanning**: Multi-process file verification
- **100+ stdlib models**: `pathlib`, `operator`, `copy`, `io`, `heapq`, `bisect`, `enum`, `dataclasses`, `collections`, `itertools`, `functools`, and more
- **Plugin System**: Custom detector registration
- **2583 tests**: Comprehensive test suite with stress tests for core components

#### Known Limitations
- State deduplication uses constraint count heuristic (can merge states with different constraints but same count)
- `lru_cache` with Z3 expressions as keys (theoretical hash collision risk, extremely unlikely in practice)
- Heap modeling is approximate — complex object attribute tracking may produce false positives
- UNKNOWN solver results treated as UNSAT (conservative, may miss some bugs)
