# PySyMex Test Architecture Blueprint

This document defines the **Shadow Tree** strategy for the PySyMex test suite. It transforms the test suite into a structural duplicate of the source code, ensuring that coverage is visually verifiable, maintenance is atomic, and the developer experience is seamless.

---

## Goals

- **1:1 Mirroring**: Every logic file in `pysymex/` has a corresponding `test_*.py` file in `tests/unit/`.
- **Eliminate Junk Drawers**: No more dumping unrelated tests into `tests/ci/` or `tests/analysis/`.
- **Predictable Discovery**: The test for `pysymex/path/to/file.py` is ALWAYS at `tests/unit/path/to/test_file.py`.
- **Atomic Maintenance**: Failures in specific paths immediately identify the broken subsystem.

---

## Target Blueprint

The following structure mirrors the reorganized source tree defined in `architecture_blueprint.md`.

```text
tests/
│
├── unit/                               # THE SHADOW TREE
│   ├── core/                           # Semantic Foundation
│   │   ├── types/
│   │   │   ├── test_base.py            # pysymex/core/types/base.py
│   │   │   ├── test_scalars.py         # pysymex/core/types/scalars.py
│   │   │   ├── test_containers.py      # pysymex/core/types/containers.py
│   │   │   ├── test_numeric.py         # pysymex/core/types/numeric.py
│   │   │   ├── test_floats.py          # pysymex/core/types/floats.py
│   │   │   ├── test_checks.py          # pysymex/core/types/checks.py
│   │   │   └── test_havoc.py           # pysymex/core/types/havoc.py
│   │   │
│   │   ├── memory/
│   │   │   ├── test_heap.py            # pysymex/core/memory/heap.py
│   │   │   ├── test_types.py           # pysymex/core/memory/types.py
│   │   │   ├── test_addressing.py      # pysymex/core/memory/addressing.py
│   │   │   ├── test_cow.py             # pysymex/core/memory/cow.py
│   │   │   └── collections/
│   │   │       ├── test_lists.py       # pysymex/core/memory/collections/lists.py
│   │   │       └── test_mappings.py    # pysymex/core/memory/collections/mappings.py
│   │   │
│   │   ├── objects/
│   │   │   ├── test_model.py           # pysymex/core/objects/model.py
│   │   │   ├── test_types.py           # pysymex/core/objects/types.py
│   │   │   └── test_oop.py             # pysymex/core/objects/oop.py
│   │   │
│   │   ├── solver/
│   │   │   ├── test_engine.py          # pysymex/core/solver/engine.py
│   │   │   ├── test_constraints.py     # pysymex/core/solver/constraints.py
│   │   │   ├── test_independence.py    # pysymex/core/solver/independence.py
│   │   │   └── test_unsat.py           # pysymex/core/solver/unsat.py
│   │   │
│   │   ├── graph/
│   │   │   └── test_treewidth.py       # pysymex/core/graph/treewidth.py
│   │   │
│   │   ├── iterators/
│   │   │   ├── test_base.py            # pysymex/core/iterators/base.py
│   │   │   └── test_combinators.py     # pysymex/core/iterators/combinators.py
│   │   │
│   │   ├── exceptions/
│   │   │   ├── test_types.py           # pysymex/core/exceptions/types.py
│   │   │   └── test_analyzer.py        # pysymex/core/exceptions/analyzer.py
│   │   │
│   │   ├── parallel/
│   │   │   ├── test_core.py            # pysymex/core/parallel/core.py
│   │   │   └── test_types.py           # pysymex/core/parallel/types.py
│   │   │
│   │   ├── test_optimization.py        # pysymex/core/optimization.py
│   │   ├── test_state.py               # pysymex/core/state.py
│   │   ├── test_cache.py               # pysymex/core/cache.py
│   │   └── test_shutdown.py            # pysymex/core/shutdown.py
│   │
│   ├── execution/                      # Bytecode Mechanics
│   │   ├── test_vm.py                  # pysymex/execution/vm.py
│   │   ├── test_dispatcher.py          # pysymex/execution/dispatcher.py
│   │   ├── test_types.py               # pysymex/execution/types.py
│   │   ├── test_protocols.py           # pysymex/execution/protocols.py
│   │   ├── test_termination.py         # pysymex/execution/termination.py
│   │   │
│   │   ├── executors/
│   │   │   ├── test_core.py            # pysymex/execution/executors/core.py
│   │   │   ├── test_facade.py          # pysymex/execution/executors/facade.py
│   │   │   ├── test_async_exec.py      # pysymex/execution/executors/async_exec.py
│   │   │   ├── test_concurrent.py      # pysymex/execution/executors/concurrent.py
│   │   │   └── test_verified.py        # pysymex/execution/executors/verified.py
│   │   │
│   │   ├── opcodes/
│   │   │   └── base/
│   │   │       ├── test_arithmetic.py  # pysymex/execution/opcodes/base/arithmetic.py
│   │   │       ├── test_collections.py # pysymex/execution/opcodes/base/collections.py
│   │   │       ├── test_compare.py     # pysymex/execution/opcodes/base/compare.py
│   │   │       ├── test_control.py     # pysymex/execution/opcodes/base/control.py
│   │   │       ├── test_exceptions.py  # pysymex/execution/opcodes/base/exceptions.py
│   │   │       ├── test_functions.py   # pysymex/execution/opcodes/base/functions.py
│   │   │       ├── test_locals.py      # pysymex/execution/opcodes/base/locals.py
│   │   │       ├── test_stack.py       # pysymex/execution/opcodes/base/stack.py
│   │   │       └── test_async_ops.py   # pysymex/execution/opcodes/base/async_ops.py
│   │   │
│   │   └── strategies/
│   │       ├── test_manager.py         # pysymex/execution/strategies/manager.py
│   │       └── test_merger.py          # pysymex/execution/strategies/merger.py
│   │
│   ├── models/                         # Environment Simulation
│   │   ├── builtins/
│   │   │   ├── test_base.py            # pysymex/models/builtins/base.py
│   │   │   ├── test_core.py            # pysymex/models/builtins/core.py
│   │   │   ├── test_extended.py        # pysymex/models/builtins/extended.py
│   │   │   ├── test_analysis.py        # pysymex/models/builtins/analysis.py
│   │   │   ├── test_functions.py       # pysymex/models/builtins/functions.py
│   │   │   └── test_methods.py         # pysymex/models/builtins/methods.py
│   │   │
│   │   ├── containers/
│   │   │   ├── test_lists.py           # pysymex/models/containers/lists.py
│   │   │   ├── test_dicts.py           # pysymex/models/containers/dicts.py
│   │   │   ├── test_sets.py            # pysymex/models/containers/sets.py
│   │   │   ├── test_tuples.py          # pysymex/models/containers/tuples.py
│   │   │   ├── test_strings.py         # pysymex/models/containers/strings.py
│   │   │   ├── test_bytes.py           # pysymex/models/containers/bytes.py
│   │   │   └── test_frozensets.py      # pysymex/models/containers/frozensets.py
│   │   │
│   │   ├── stdlib/
│   │   │   ├── test_math.py            # pysymex/models/stdlib/math.py
│   │   │   ├── test_io.py              # pysymex/models/stdlib/io.py
│   │   │   ├── test_data.py            # pysymex/models/stdlib/data.py
│   │   │   ├── test_system.py          # pysymex/models/stdlib/system.py
│   │   │   ├── test_collections.py     # pysymex/models/stdlib/collections.py
│   │   │   ├── test_pathlib.py         # pysymex/models/stdlib/pathlib.py
│   │   │   ├── test_regex.py           # pysymex/models/stdlib/regex.py
│   │   │   ├── test_dataclasses.py     # pysymex/models/stdlib/dataclasses.py
│   │   │   ├── test_functools.py       # pysymex/models/stdlib/functools.py
│   │   │   ├── test_itertools.py       # pysymex/models/stdlib/itertools.py
│   │   │   └── test_contextlib.py      # pysymex/models/stdlib/contextlib.py
│   │   │
│   │   ├── concurrency/
│   │   │   ├── test_asyncio.py         # pysymex/models/concurrency/asyncio.py
│   │   │   └── test_threading.py       # pysymex/models/concurrency/threading.py
│   │   │
│   │   ├── test_numeric.py             # pysymex/models/numeric.py
│   │   └── test_objects.py             # pysymex/models/objects.py
│   │
│   ├── analysis/                       # Observation & Detection
│   │   ├── detectors/
│   │   │   ├── test_base.py            # pysymex/analysis/detectors/base.py
│   │   │   ├── test_static.py          # pysymex/analysis/detectors/static.py
│   │   │   ├── test_specialized.py     # pysymex/analysis/detectors/specialized.py
│   │   │   ├── test_formal.py          # pysymex/analysis/detectors/formal.py
│   │   │   ├── test_protocols.py       # pysymex/analysis/detectors/protocols.py
│   │   │   └── test_filter.py          # pysymex/analysis/detectors/filter.py
│   │   │
│   │   ├── taint/
│   │   │   ├── test_core.py            # pysymex/analysis/taint/core.py
│   │   │   ├── test_checker.py         # pysymex/analysis/taint/checker.py
│   │   │   └── test_types.py           # pysymex/analysis/taint/types.py
│   │   │
│   │   ├── contracts/
│   │   │   ├── test_compiler.py        # pysymex/analysis/contracts/compiler.py
│   │   │   ├── test_decorators.py      # pysymex/analysis/contracts/decorators.py
│   │   │   ├── test_quantifiers.py     # pysymex/analysis/contracts/quantifiers.py
│   │   │   └── test_types.py           # pysymex/analysis/contracts/types.py
│   │   │
│   │   ├── dataflow/
│   │   │   ├── test_core.py            # pysymex/analysis/dataflow/core.py
│   │   │   └── test_types.py           # pysymex/analysis/dataflow/types.py
│   │   │
│   │   ├── abstract/
│   │   │   ├── test_domains.py         # pysymex/analysis/abstract/domains.py
│   │   │   ├── test_interpreter.py     # pysymex/analysis/abstract/interpreter.py
│   │   │   └── test_types.py           # pysymex/analysis/abstract/types.py
│   │   │
│   │   ├── types/
│   │   │   ├── test_inference.py       # pysymex/analysis/types/inference.py
│   │   │   ├── test_environment.py     # pysymex/analysis/types/environment.py
│   │   │   ├── test_kinds.py           # pysymex/analysis/types/kinds.py
│   │   │   ├── test_patterns.py        # pysymex/analysis/types/patterns.py
│   │   │   ├── test_constraints.py     # pysymex/analysis/types/constraints.py
│   │   │   └── test_stubs.py           # pysymex/analysis/types/stubs.py
│   │   │
│   │   ├── interprocedural/
│   │   │   ├── test_callgraph.py       # pysymex/analysis/interprocedural/callgraph.py
│   │   │   ├── test_summaries.py       # pysymex/analysis/interprocedural/summaries.py
│   │   │   ├── test_cross_function.py  # pysymex/analysis/interprocedural/cross_function.py
│   │   │   └── test_types.py           # pysymex/analysis/interprocedural/types.py
│   │   │
│   │   ├── control/
│   │   │   ├── test_cfg.py             # pysymex/analysis/control/cfg.py
│   │   │   ├── test_loops.py           # pysymex/analysis/control/loops.py
│   │   │   ├── test_dead_code.py       # pysymex/analysis/control/dead_code.py
│   │   │   └── test_types.py           # pysymex/analysis/control/types.py
│   │   │
│   │   ├── specialized/
│   │   │   ├── test_arithmetic.py      # pysymex/analysis/specialized/arithmetic.py
│   │   │   ├── test_bounds.py          # pysymex/analysis/specialized/bounds.py
│   │   │   ├── test_strings.py         # pysymex/analysis/specialized/strings.py
│   │   │   ├── test_none.py            # pysymex/analysis/specialized/none.py
│   │   │   ├── test_ranges.py          # pysymex/analysis/specialized/ranges.py
│   │   │   ├── test_escape.py          # pysymex/analysis/specialized/escape.py
│   │   │   ├── test_assertions.py      # pysymex/analysis/specialized/assertions.py
│   │   │   ├── test_invariants.py      # pysymex/analysis/specialized/invariants.py
│   │   │   └── test_flow.py            # pysymex/analysis/specialized/flow.py
│   │   │
│   │   ├── resources/
│   │   │   ├── test_lifecycle.py       # pysymex/analysis/resources/lifecycle.py
│   │   │   └── test_types.py           # pysymex/analysis/resources/types.py
│   │   │
│   │   ├── concurrency/
│   │   │   ├── test_core.py            # pysymex/analysis/concurrency/core.py
│   │   │   └── test_interleaving.py    # pysymex/analysis/concurrency/interleaving.py
│   │   │
│   │   ├── pipeline/
│   │   │   ├── test_phases.py          # pysymex/analysis/pipeline/phases.py
│   │   │   └── test_types.py           # pysymex/analysis/pipeline/types.py
│   │   │
│   │   ├── cache/
│   │   │   ├── test_core.py            # pysymex/analysis/cache/core.py
│   │   │   └── test_invalidation.py    # pysymex/analysis/cache/invalidation.py
│   │   │
│   │   ├── integration/
│   │   │   ├── test_core.py            # pysymex/analysis/integration/core.py
│   │   │   └── test_formal.py          # pysymex/analysis/integration/formal.py
│   │   │
│   │   ├── test_concolic.py            # pysymex/analysis/concolic.py
│   │   ├── test_autotuner.py           # pysymex/analysis/autotuner.py
│   │   └── test_protocols.py           # pysymex/analysis/protocols.py
│   │
│   ├── sandbox/                        # Security Isolation
│   │   ├── test_runner.py              # pysymex/sandbox/runner.py
│   │   ├── test_bridge.py              # pysymex/sandbox/bridge.py
│   │   ├── test_execution.py           # pysymex/sandbox/execution.py
│   │   ├── test_validation.py          # pysymex/sandbox/validation.py
│   │   ├── test_types.py               # pysymex/sandbox/types.py
│   │   ├── test_errors.py              # pysymex/sandbox/errors.py
│   │   └── isolation/
│   │       ├── test_linux.py           # pysymex/sandbox/isolation/linux.py
│   │       ├── test_windows.py         # pysymex/sandbox/isolation/windows.py
│   │       ├── test_subprocess.py      # pysymex/sandbox/isolation/subprocess.py
│   │       ├── test_wasm.py            # pysymex/sandbox/isolation/wasm.py
│   │       └── test_harness.py         # pysymex/sandbox/isolation/harness.py
│   │
│   ├── accel/                          # Hardware Acceleration
│   │   ├── test_dispatcher.py          # pysymex/accel/dispatcher.py
│   │   ├── test_bytecode.py            # pysymex/accel/bytecode.py
│   │   ├── test_optimizer.py           # pysymex/accel/optimizer.py
│   │   ├── test_sampling.py            # pysymex/accel/sampling.py
│   │   ├── test_memory.py              # pysymex/accel/memory.py
│   │   ├── test_chtd.py                # pysymex/accel/chtd.py
│   │   ├── test_async_exec.py          # pysymex/accel/async_exec.py
│   │   ├── test_benchmark.py           # pysymex/accel/benchmark.py
│   │   └── backends/
│   │       ├── test_cpu.py             # pysymex/accel/backends/cpu.py
│   │       ├── test_gpu.py             # pysymex/accel/backends/gpu.py
│   │       └── test_reference.py       # pysymex/accel/backends/reference.py
│   │
│   ├── cli/                            # User Interface
│   │   ├── test_commands.py            # pysymex/cli/commands.py
│   │   ├── test_parser.py              # pysymex/cli/parser.py
│   │   ├── test_scan.py                # pysymex/cli/scan.py
│   │   └── test_reporter.py            # pysymex/cli/reporter.py
│   │
│   ├── scanner/                        # Discovery
│   │   ├── test_core.py                # pysymex/scanner/core.py
│   │   ├── test_async_scanner.py       # pysymex/scanner/async_scanner.py
│   │   └── test_types.py               # pysymex/scanner/types.py
│   │
│   ├── reporting/                      # Output
│   │   ├── test_formatters.py          # pysymex/reporting/formatters.py
│   │   ├── test_html.py                # pysymex/reporting/html.py
│   │   ├── test_realtime.py            # pysymex/reporting/realtime.py
│   │   ├── test_reproduction.py        # pysymex/reporting/reproduction.py
│   │   └── sarif/
│   │       ├── test_core.py            # pysymex/reporting/sarif/core.py
│   │       └── test_types.py           # pysymex/reporting/sarif/types.py
│   │
│   ├── tracing/                        # SUPPORT: Tracing
│   │   ├── test_tracer.py              # pysymex/tracing/tracer.py
│   │   ├── test_analyzer.py            # pysymex/tracing/analyzer.py
│   │   ├── test_hooks.py               # pysymex/tracing/hooks.py
│   │   ├── test_schemas.py             # pysymex/tracing/schemas.py
│   │   └── test_z3_utils.py            # pysymex/tracing/z3_utils.py
│   │
│   ├── contracts/                      # SUPPORT: Quantifiers
│   │   └── quantifiers/
│   │       ├── test_core.py            # pysymex/contracts/quantifiers/core.py
│   │       └── test_types.py           # pysymex/contracts/quantifiers/types.py
│   │
│   ├── plugins/                        # SUPPORT: Plugins
│   │   └── test_base.py                # pysymex/plugins/base.py
│   │
│   ├── testing/                        # SUPPORT: Dev testing
│   │   ├── test_fuzzing.py             # pysymex/testing/fuzzing.py
│   │   └── test_soundness.py           # pysymex/testing/soundness.py
│   │
│   ├── benchmarks/                     # SUPPORT: Benchmarks
│   │   └── suite/
│   │       ├── test_core.py            # pysymex/benchmarks/suite/core.py
│   │       └── test_types.py           # pysymex/benchmarks/suite/types.py
│   │
│   ├── ci/                             # SUPPORT: CI/CD
│   │   ├── test_core.py                # pysymex/ci/core.py
│   │   └── test_types.py               # pysymex/ci/types.py
│   │
│   ├── test_api.py                     # pysymex/api.py
│   ├── test_async_api.py               # pysymex/async_api.py
│   ├── test_config.py                  # pysymex/config.py
│   ├── test_logging.py                 # pysymex/logging.py
│   ├── test_resources.py               # pysymex/resources.py
│   ├── test_watch.py                   # pysymex/watch.py
│   └── test_verify_cli.py              # pysymex/verify_cli.py
│
├── integration/                        # Multi-subsystem Scenarios
│   ├── test_full_project_scan.py       # E2E scan of large repos
│   ├── test_z3_heavy_solve.py          # Stress test for Z3 backend
│   └── test_cli_interactive.py         # Terminal UI/Progress checks
│
├── repro/                              # Bug Reproductions
│   ├── issue_123_aliasing.py           # Regression from tracker
│   └── issue_45_stack_overflow.py
│
├── fixtures/                           # Static Test Data
│   ├── buggy_snippets/                 # Code for detectors to find
│   └── mock_projects/                  # Directories for scanner
│
├── conftest.py                         # Global Pytest fixtures
└── helpers.py                          # Test-only utilities
```

---

## Why Each Tree Exists

### unit/ — The Shadow Tree
Tests "The Thing" (Logic). It has a strict 1:1 relationship with the source. If you change a line in `core/solver/engine.py`, the test you must run is `tests/unit/core/solver/test_engine.py`.

### integration/ — Behavioral Testing
Tests "The System" (Interaction). These don't mirror the source. They represent real-world use cases, like scanning a full directory or verifying a complex multi-file contract.

### repro/ — The History
Tests "The Regressions" (Historical Bugs). When a bug is fixed, a minimal reproduction script goes here to ensure it never returns.

---

## Discovery & Maintenance Strategy

To ensure this architecture is strictly followed and maintains long-term structural integrity, a `tests/README.md` must be maintained as the "Source of Truth" for the test suite's organization.

- **The Primary Directive**: "If you modify `pysymex/path/to/module.py`, the corresponding unit test MUST be at `tests/unit/path/to/test_module.py`."
- **Deterministic Discovery**: This 1:1 mapping ensures that any developer or automated analysis tool can deterministically locate the relevant verification logic for any source file without heuristic searching.

---

## Migration Plan

1. **Scaffolding**: Create the `tests/unit/` directory and replicate the `pysymex/` tiered folder structure.
2. **The "CI" Purge**: Move all unit tests currently hiding in `tests/ci/` (like `test_config.py`, `test_logging.py`) to the root of `tests/unit/`.
3. **Domain Realignment**: Move existing flat tests into their tiered homes (e.g., `tests/core/test_treewidth.py` → `tests/unit/core/graph/test_treewidth.py`).
4. **Collision Handling**: Ensure `pytest.ini` is set to `importmode = importlib` to allow multiple test files with the same name (e.g., `test_core.py`) in different directories.
5. **Documentation**: Update `tests/README.md` with the strict mirroring rules and directory roles to act as a permanent instruction for contributors and automated tooling.
6. **Shim cleanup**: Remove old test folders once the shadow tree is verified.
