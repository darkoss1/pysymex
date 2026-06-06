# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Registration of built-in benchmark workloads."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.benchmarks.suite.types import BenchmarkCategory
from pysymex.benchmarks.suite.types import BenchmarkMode
from pysymex.benchmarks.suite.workload.analysis import (
    bench_contract_verification,
    bench_race_detection,
    bench_runtime_detector_scan,
)
from pysymex.benchmarks.suite.workload.cli import (
    bench_cli_default_scan,
    bench_scanner_default_scan,
)
from pysymex.benchmarks.suite.workload.execution import (
    bench_bytecode_exception_entries_cache_hits,
    bench_bytecode_line_mapping_cache_hits,
    bench_executor_core_branching,
    bench_executor_core_function,
    bench_executor_path_explosion_native_cap,
    bench_state_forking,
)
from pysymex.benchmarks.suite.workload.frontier import (
    bench_frontier_runtime_compacted_admission,
    bench_frontier_runtime_native_admission,
    bench_frontier_shadow_cegis_preview_execute,
    bench_frontier_shadow_cegis_preview_unsat,
    bench_frontier_shadow_checkpoint_admission,
)
from pysymex.benchmarks.suite.workload.frontier.runtime.registry import (
    add_frontier_runtime_benchmarks,
)
from pysymex.benchmarks.suite.workload.models import (
    bench_container_model_dispatch,
    bench_string_model_dispatch,
)
from pysymex.benchmarks.suite.workload.reporting import bench_reporting_formatters
from pysymex.benchmarks.suite.workload.sandbox import (
    bench_sandbox_extract_module_cached,
    bench_sandbox_extract_module_cold,
    bench_sandbox_strong_execute_noop,
    bench_sandbox_strong_setup,
)
from pysymex.benchmarks.suite.workload.solver import (
    bench_branching,
    bench_constraint_hashing,
    bench_incremental_solver,
    bench_linear_constraints,
    bench_loop_unrolling,
    bench_simple_arithmetic,
    bench_solver_exact_literal_cache_hits,
    bench_solver_sat_cache_hits,
    bench_solver_unsat_subset_cache_hits,
)

if TYPE_CHECKING:
    from pysymex.benchmarks.suite.core import BenchmarkSuite


def create_builtin_benchmarks() -> "BenchmarkSuite":
    """Create the built-in benchmark suite with real Z3 workloads."""
    from pysymex.benchmarks.suite.core import Benchmark, BenchmarkSuite

    suite = BenchmarkSuite(
        name="pysymex_builtin",
        description="Built-in pysymex benchmarks (real solver workloads)",
    )
    suite.add(
        Benchmark(
            name="exec_core",
            func=bench_executor_core_function,
            category=BenchmarkCategory.END_TO_END,
            description="Engine-level symbolic execution via SymbolicExecutor.execute_code",
            modes=frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("execution", "symbolic-executor"),
            aliases=("executor_core_function",),
        )
    )
    suite.add(
        Benchmark(
            name="exec_branch",
            func=bench_executor_core_branching,
            category=BenchmarkCategory.END_TO_END,
            description="Branch-heavy engine execution via SymbolicExecutor.execute_code",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("execution", "path-exploration"),
            aliases=("executor_core_branching",),
        )
    )
    suite.add(
        Benchmark(
            name="path_cap",
            func=bench_executor_path_explosion_native_cap,
            category=BenchmarkCategory.PATHS,
            description="Capped branch explosion through default POLAR runtime ordering",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("execution", "path-exploration", "polar", "runtime"),
            aliases=("executor_path_explosion_native_cap",),
        )
    )
    suite.add(
        Benchmark(
            name="cli_scan",
            func=bench_cli_default_scan,
            category=BenchmarkCategory.CLI,
            description="Default user-facing pysymex scan subprocess path",
            modes=frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL)),
            tags=("cli", "scan", "subprocess"),
            stability="machine-dependent",
            aliases=("cli_default_scan",),
        )
    )
    suite.add(
        Benchmark(
            name="scanner_scan",
            func=bench_scanner_default_scan,
            category=BenchmarkCategory.END_TO_END,
            description="Same default scan target through the in-process scanner",
            modes=frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL)),
            tags=("scanner", "scan", "filesystem"),
            stability="machine-dependent",
            aliases=("scanner_default_scan",),
        )
    )
    suite.add(
        Benchmark(
            name="arith_solver",
            func=bench_simple_arithmetic,
            category=BenchmarkCategory.OPCODES,
            description="Basic arithmetic operations with Z3",
            modes=frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("solver", "arithmetic"),
            aliases=("simple_arithmetic",),
        )
    )
    suite.add(
        Benchmark(
            name="line_cache",
            func=bench_bytecode_line_mapping_cache_hits,
            category=BenchmarkCategory.OPCODES,
            description="Cached bytecode PC-to-line metadata during execution preparation",
            modes=frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("bytecode", "cache", "line-mapping"),
            aliases=("bytecode_line_mapping_cache_hits",),
        )
    )
    suite.add(
        Benchmark(
            name="except_cache",
            func=bench_bytecode_exception_entries_cache_hits,
            category=BenchmarkCategory.OPCODES,
            description="Cached CPython exception-table metadata extraction",
            modes=frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("bytecode", "cache", "exceptions"),
            aliases=("bytecode_exception_entries_cache_hits",),
        )
    )
    suite.add(
        Benchmark(
            name="branch_solver",
            func=bench_branching,
            category=BenchmarkCategory.PATHS,
            description="Path exploration with 20-way branch explosion",
            modes=frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("solver", "path-exploration"),
            aliases=("branching",),
        )
    )
    suite.add(
        Benchmark(
            name="loop_solver",
            func=bench_loop_unrolling,
            category=BenchmarkCategory.PATHS,
            description="Loop handling with constraint accumulation",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("solver", "loops"),
            aliases=("loop_unrolling",),
        )
    )
    suite.add(
        Benchmark(
            name="linear_solver",
            func=bench_linear_constraints,
            category=BenchmarkCategory.SOLVING,
            description="100 linear integer constraints",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("solver", "linear-constraints"),
            aliases=("linear_constraints",),
        )
    )
    suite.add(
        Benchmark(
            name="incremental",
            func=bench_incremental_solver,
            category=BenchmarkCategory.SOLVING,
            description="Incremental solver push/pop performance",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("solver", "incremental"),
            aliases=("incremental_solver",),
        )
    )
    suite.add(
        Benchmark(
            name="sat_cache",
            func=bench_solver_sat_cache_hits,
            category=BenchmarkCategory.SOLVING,
            description="Definitive SAT query cache-hit workload",
            modes=frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("solver", "cache", "sat"),
            aliases=("solver_sat_cache_hits",),
        )
    )
    suite.add(
        Benchmark(
            name="literal_cache",
            func=bench_solver_exact_literal_cache_hits,
            category=BenchmarkCategory.SOLVING,
            description="Exact Boolean literal cache-hit workload across Z3 wrappers",
            modes=frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("solver", "cache", "literals"),
            aliases=("solver_exact_literal_cache_hits",),
        )
    )
    suite.add(
        Benchmark(
            name="unsat_cache",
            func=bench_solver_unsat_subset_cache_hits,
            category=BenchmarkCategory.SOLVING,
            description="Definitive UNSAT subset cache-hit workload",
            modes=frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("solver", "cache", "unsat-subset"),
            aliases=("solver_unsat_subset_cache_hits",),
        )
    )
    suite.add(
        Benchmark(
            name="state_fork",
            func=bench_state_forking,
            category=BenchmarkCategory.MEMORY,
            description="VMState CoW fork performance",
            modes=frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("memory", "state-forking"),
            aliases=("state_forking",),
        )
    )
    suite.add(
        Benchmark(
            name="shadow_admit",
            func=bench_frontier_shadow_checkpoint_admission,
            category=BenchmarkCategory.MEMORY,
            description="Frontier admission with phase-0 POLAR shadow capsules",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("memory", "frontier", "polar", "capsule"),
            aliases=("frontier_shadow_checkpoint_admission",),
        )
    )
    suite.add(
        Benchmark(
            name="runtime_admit",
            func=bench_frontier_runtime_native_admission,
            category=BenchmarkCategory.MEMORY,
            description="Default POLAR runtime frontier admission with lazy capsules",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("memory", "frontier", "polar", "runtime"),
            aliases=("frontier_runtime_native_admission",),
        )
    )
    suite.add(
        Benchmark(
            name="compact_admit",
            func=bench_frontier_runtime_compacted_admission,
            category=BenchmarkCategory.MEMORY,
            description="POLAR runtime frontier admission plus exact checkpoint compaction",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("memory", "frontier", "polar", "runtime", "compaction"),
            aliases=("frontier_runtime_compacted_admission",),
        )
    )
    suite.add(
        Benchmark(
            name="preview_exec",
            func=bench_frontier_shadow_cegis_preview_execute,
            category=BenchmarkCategory.MEMORY,
            description="Shadow CEGIS live-frontier preview with solver-free execute bids",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("memory", "frontier", "cegis", "preview"),
            aliases=("frontier_shadow_cegis_preview_execute",),
        )
    )
    suite.add(
        Benchmark(
            name="preview_unsat",
            func=bench_frontier_shadow_cegis_preview_unsat,
            category=BenchmarkCategory.SOLVING,
            description="Shadow CEGIS live-frontier preview with solver UNSAT owner evidence",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("solver", "frontier", "cegis", "preview"),
            aliases=("frontier_shadow_cegis_preview_unsat",),
        )
    )
    add_frontier_runtime_benchmarks(suite)
    suite.add(
        Benchmark(
            name="string_models",
            func=bench_string_model_dispatch,
            category=BenchmarkCategory.MODELS,
            description="Symbolic string startswith, endswith, count and rfind models",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("models", "strings", "symbolic-executor"),
            aliases=("string_model_dispatch",),
        )
    )
    suite.add(
        Benchmark(
            name="container_models",
            func=bench_container_model_dispatch,
            category=BenchmarkCategory.MODELS,
            description="List, tuple, membership, len, sum, min and indexing model dispatch",
            modes=frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("models", "containers", "builtins"),
            aliases=("container_model_dispatch",),
        )
    )
    suite.add(
        Benchmark(
            name="formatters",
            func=bench_reporting_formatters,
            category=BenchmarkCategory.REPORTING,
            description="JSON, Markdown, HTML and SARIF scan report formatting overhead",
            modes=frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("reporting", "formatters"),
            aliases=("reporting_formatters",),
        )
    )
    suite.add(
        Benchmark(
            name="sandbox_setup",
            func=bench_sandbox_strong_setup,
            category=BenchmarkCategory.SANDBOX,
            description="Strong sandbox context setup and cleanup overhead",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("sandbox", "setup"),
            stability="platform-dependent",
            aliases=("sandbox_strong_setup",),
        )
    )
    suite.add(
        Benchmark(
            name="sandbox_noop",
            func=bench_sandbox_strong_execute_noop,
            category=BenchmarkCategory.SANDBOX,
            description="Strong sandbox setup plus tiny code execution overhead",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("sandbox", "execution"),
            stability="platform-dependent",
            aliases=("sandbox_strong_execute_noop",),
        )
    )
    suite.add(
        Benchmark(
            name="extract_cold",
            func=bench_sandbox_extract_module_cold,
            category=BenchmarkCategory.SANDBOX,
            description="Cold sandbox bridge module extraction overhead",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("sandbox", "module-extraction"),
            stability="platform-dependent",
            aliases=("sandbox_extract_module_cold",),
        )
    )
    suite.add(
        Benchmark(
            name="extract_cached",
            func=bench_sandbox_extract_module_cached,
            category=BenchmarkCategory.SANDBOX,
            description="Process-local sandbox bridge module extraction cache-hit overhead",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("sandbox", "module-extraction", "cache"),
            stability="platform-dependent",
            aliases=("sandbox_extract_module_cached",),
        )
    )
    suite.add(
        Benchmark(
            name="constraint_hash",
            func=bench_constraint_hashing,
            category=BenchmarkCategory.SOLVING,
            description="Structural constraint hashing performance",
            modes=frozenset((BenchmarkMode.STRESS,)),
            tags=("solver", "hashing", "stress"),
            aliases=("constraint_hashing",),
        )
    )
    suite.add(
        Benchmark(
            name="race_detect",
            func=bench_race_detection,
            category=BenchmarkCategory.CONCURRENCY,
            description="Race detection with 10 operations",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("analysis", "concurrency"),
            aliases=("concurrency_race_detection",),
        )
    )
    suite.add(
        Benchmark(
            name="detector_scan",
            func=bench_runtime_detector_scan,
            category=BenchmarkCategory.ANALYSIS,
            description="Scanner-driven runtime detector workload with guarded controls",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("analysis", "detectors", "scanner"),
            aliases=("runtime_detector_scan",),
        )
    )
    suite.add(
        Benchmark(
            name="contracts",
            func=bench_contract_verification,
            category=BenchmarkCategory.ANALYSIS,
            description="ContractVerifier proving preconditions, postconditions and loop invariants",
            modes=frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS)),
            tags=("analysis", "contracts"),
            aliases=("contract_verification",),
        )
    )
    return suite
