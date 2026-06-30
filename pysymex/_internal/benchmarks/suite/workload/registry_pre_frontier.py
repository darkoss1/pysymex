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

"""Built-in benchmark metadata registered before runtime frontier cases."""

from __future__ import annotations

from pysymex._internal.benchmarks.suite.types import BenchmarkCategory
from pysymex._internal.benchmarks.suite.workload.cli import (
    bench_cli_default_scan,
    bench_scanner_default_scan,
)
from pysymex._internal.benchmarks.suite.workload.execution import (
    bench_bytecode_exception_entries_cache_hits,
    bench_bytecode_line_mapping_cache_hits,
    bench_executor_core_branching,
    bench_executor_core_function,
    bench_executor_path_explosion_native_cap,
    bench_state_forking,
)
from pysymex._internal.benchmarks.suite.workload.frontier.benchmarks import (
    bench_frontier_runtime_compacted_admission,
    bench_frontier_runtime_native_admission,
    bench_frontier_shadow_cegis_preview_execute,
    bench_frontier_shadow_cegis_preview_unsat,
    bench_frontier_shadow_checkpoint_admission,
)
from pysymex._internal.benchmarks.suite.workload.registry_specs import (
    FULL_STRESS,
    QUICK_FULL,
    QUICK_FULL_STRESS,
    BenchmarkSpec,
)
from pysymex._internal.benchmarks.suite.workload.solver import (
    bench_branching,
    bench_exact_literal_cache_hits,
    bench_incremental_solver,
    bench_linear_constraints,
    bench_loop_unrolling,
    bench_sat_cache_hits,
    bench_simple_arithmetic,
    bench_unsat_subset_cache_hits,
)

PRE_FRONTIER_BENCHMARK_SPECS = (
    BenchmarkSpec(
        name="exec_core",
        func=bench_executor_core_function,
        category=BenchmarkCategory.END_TO_END,
        description="Engine-level symbolic execution via SymbolicExecutor.execute_code",
        modes=QUICK_FULL_STRESS,
        tags=("execution", "symbolic-executor"),
    ),
    BenchmarkSpec(
        name="exec_branch",
        func=bench_executor_core_branching,
        category=BenchmarkCategory.END_TO_END,
        description="Branch-heavy engine execution via SymbolicExecutor.execute_code",
        modes=FULL_STRESS,
        tags=("execution", "path-exploration"),
    ),
    BenchmarkSpec(
        name="path_cap",
        func=bench_executor_path_explosion_native_cap,
        category=BenchmarkCategory.PATHS,
        description="Capped branch explosion through default POLAR runtime ordering",
        modes=FULL_STRESS,
        tags=("execution", "path-exploration", "polar", "runtime"),
    ),
    BenchmarkSpec(
        name="cli_scan",
        func=bench_cli_default_scan,
        category=BenchmarkCategory.CLI,
        description="Default user-facing pysymex scan subprocess path",
        modes=QUICK_FULL,
        tags=("cli", "scan", "subprocess"),
        stability="machine-dependent",
    ),
    BenchmarkSpec(
        name="scanner_scan",
        func=bench_scanner_default_scan,
        category=BenchmarkCategory.END_TO_END,
        description="Same default scan target through the in-process scanner",
        modes=QUICK_FULL,
        tags=("scanner", "scan", "filesystem"),
        stability="machine-dependent",
    ),
    BenchmarkSpec(
        name="arith_solver",
        func=bench_simple_arithmetic,
        category=BenchmarkCategory.OPCODES,
        description="Basic arithmetic operations with Z3",
        modes=QUICK_FULL_STRESS,
        tags=("solver", "arithmetic"),
    ),
    BenchmarkSpec(
        name="line_cache",
        func=bench_bytecode_line_mapping_cache_hits,
        category=BenchmarkCategory.OPCODES,
        description="Cached bytecode PC-to-line metadata during execution preparation",
        modes=QUICK_FULL_STRESS,
        tags=("bytecode", "cache", "line-mapping"),
    ),
    BenchmarkSpec(
        name="except_cache",
        func=bench_bytecode_exception_entries_cache_hits,
        category=BenchmarkCategory.OPCODES,
        description="Cached CPython exception-table metadata extraction",
        modes=QUICK_FULL_STRESS,
        tags=("bytecode", "cache", "exceptions"),
    ),
    BenchmarkSpec(
        name="branch_solver",
        func=bench_branching,
        category=BenchmarkCategory.PATHS,
        description="Path exploration with 20-way branch explosion",
        modes=QUICK_FULL_STRESS,
        tags=("solver", "path-exploration"),
    ),
    BenchmarkSpec(
        name="loop_solver",
        func=bench_loop_unrolling,
        category=BenchmarkCategory.PATHS,
        description="Loop handling with constraint accumulation",
        modes=FULL_STRESS,
        tags=("solver", "loops"),
    ),
    BenchmarkSpec(
        name="linear_solver",
        func=bench_linear_constraints,
        category=BenchmarkCategory.SOLVING,
        description="100 linear integer constraints",
        modes=FULL_STRESS,
        tags=("solver", "linear-constraints"),
    ),
    BenchmarkSpec(
        name="incremental",
        func=bench_incremental_solver,
        category=BenchmarkCategory.SOLVING,
        description="Incremental solver push/pop performance",
        modes=FULL_STRESS,
        tags=("solver", "incremental"),
    ),
    BenchmarkSpec(
        name="sat_cache",
        func=bench_sat_cache_hits,
        category=BenchmarkCategory.SOLVING,
        description="Definitive SAT query cache-hit workload",
        modes=QUICK_FULL_STRESS,
        tags=("solver", "cache", "sat"),
    ),
    BenchmarkSpec(
        name="literal_cache",
        func=bench_exact_literal_cache_hits,
        category=BenchmarkCategory.SOLVING,
        description="Exact Boolean literal cache-hit workload across Z3 wrappers",
        modes=QUICK_FULL_STRESS,
        tags=("solver", "cache", "literals"),
    ),
    BenchmarkSpec(
        name="unsat_cache",
        func=bench_unsat_subset_cache_hits,
        category=BenchmarkCategory.SOLVING,
        description="Definitive UNSAT subset cache-hit workload",
        modes=QUICK_FULL_STRESS,
        tags=("solver", "cache", "unsat-subset"),
    ),
    BenchmarkSpec(
        name="state_fork",
        func=bench_state_forking,
        category=BenchmarkCategory.MEMORY,
        description="VMState CoW fork performance",
        modes=QUICK_FULL_STRESS,
        tags=("memory", "state-forking"),
    ),
    BenchmarkSpec(
        name="shadow_admit",
        func=bench_frontier_shadow_checkpoint_admission,
        category=BenchmarkCategory.MEMORY,
        description="Frontier admission with phase-0 POLAR shadow capsules",
        modes=FULL_STRESS,
        tags=("memory", "frontier", "polar", "capsule"),
    ),
    BenchmarkSpec(
        name="runtime_admit",
        func=bench_frontier_runtime_native_admission,
        category=BenchmarkCategory.MEMORY,
        description="Default POLAR runtime frontier admission with lazy capsules",
        modes=FULL_STRESS,
        tags=("memory", "frontier", "polar", "runtime"),
    ),
    BenchmarkSpec(
        name="compact_admit",
        func=bench_frontier_runtime_compacted_admission,
        category=BenchmarkCategory.MEMORY,
        description="POLAR runtime frontier admission plus exact checkpoint compaction",
        modes=FULL_STRESS,
        tags=("memory", "frontier", "polar", "runtime", "compaction"),
    ),
    BenchmarkSpec(
        name="preview_exec",
        func=bench_frontier_shadow_cegis_preview_execute,
        category=BenchmarkCategory.MEMORY,
        description="Shadow CEGIS live-frontier preview with solver-free execute bids",
        modes=FULL_STRESS,
        tags=("memory", "frontier", "cegis", "preview"),
    ),
    BenchmarkSpec(
        name="preview_unsat",
        func=bench_frontier_shadow_cegis_preview_unsat,
        category=BenchmarkCategory.SOLVING,
        description="Shadow CEGIS live-frontier preview with solver UNSAT owner evidence",
        modes=FULL_STRESS,
        tags=("solver", "frontier", "cegis", "preview"),
    ),
)
