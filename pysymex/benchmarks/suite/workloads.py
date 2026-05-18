# pysymex: Python Symbolic Execution & Formal Verification
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

"""Built-in benchmark workloads for pysymex."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import z3

    from pysymex.benchmarks.suite.core import BenchmarkSuite

from pysymex.benchmarks.suite.types import BenchmarkCategory

_LoopUnrollingWorkload = tuple[list["z3.BoolRef"], list["z3.BoolRef"]]
_LinearConstraintsWorkload = list["z3.BoolRef"]
_IncrementalSolverWorkload = list[list["z3.BoolRef"]]

_loop_unrolling_workload_cache: _LoopUnrollingWorkload | None = None
_linear_constraints_workload_cache: _LinearConstraintsWorkload | None = None
_incremental_solver_workload_cache: _IncrementalSolverWorkload | None = None


def _loop_unrolling_workload() -> _LoopUnrollingWorkload:
    """Return prebuilt linear constraints for the loop-unrolling solver benchmark."""
    global _loop_unrolling_workload_cache
    if _loop_unrolling_workload_cache is None:
        import z3

        x = z3.Int("x")
        base_constraints = [x >= 0, x < 1000]
        suffix_constraints = [x > i * 10 for i in range(50)]
        _loop_unrolling_workload_cache = (base_constraints, suffix_constraints)
    return _loop_unrolling_workload_cache


def _linear_constraints_workload() -> _LinearConstraintsWorkload:
    """Return prebuilt linear constraints for the bulk-solver benchmark."""
    global _linear_constraints_workload_cache
    if _linear_constraints_workload_cache is None:
        import z3

        vars_ = [z3.Int(f"v{i}") for i in range(100)]
        constraints = [vars_[i] + 1 <= vars_[i + 1] for i in range(99)]
        constraints.append(vars_[0] >= 0)
        constraints.append(vars_[99] <= 1000)
        _linear_constraints_workload_cache = constraints
    return _linear_constraints_workload_cache


def _incremental_solver_workload() -> _IncrementalSolverWorkload:
    """Return prebuilt per-scope constraints for the incremental solver benchmark."""
    global _incremental_solver_workload_cache
    if _incremental_solver_workload_cache is None:
        import z3

        x, y = z3.Ints("x y")
        _incremental_solver_workload_cache = [
            [x > i, y > i, x + y < i * 3 + 10] for i in range(100)
        ]
    return _incremental_solver_workload_cache


def create_builtin_benchmarks() -> BenchmarkSuite:
    """Create the built-in benchmark suite with real Z3 workloads.

    Returns:
        A :class:`BenchmarkSuite` containing all standard benchmarks.
    """
    from pysymex.benchmarks.suite.core import Benchmark, BenchmarkSuite

    suite = BenchmarkSuite(
        name="pysymex_builtin",
        description="Built-in pysymex benchmarks (real solver workloads)",
    )
    suite.add(
        Benchmark(
            name="executor_core_function",
            func=bench_executor_core_function,
            category=BenchmarkCategory.END_TO_END,
            description="Engine-level symbolic execution via SymbolicExecutor.execute_code",
        )
    )
    suite.add(
        Benchmark(
            name="executor_core_branching",
            func=bench_executor_core_branching,
            category=BenchmarkCategory.END_TO_END,
            description="Branch-heavy engine execution via SymbolicExecutor.execute_code",
        )
    )
    suite.add(
        Benchmark(
            name="simple_arithmetic",
            func=bench_simple_arithmetic,
            category=BenchmarkCategory.OPCODES,
            description="Basic arithmetic operations with Z3",
        )
    )
    suite.add(
        Benchmark(
            name="branching",
            func=bench_branching,
            category=BenchmarkCategory.PATHS,
            description="Path exploration with 20-way branch explosion",
        )
    )
    suite.add(
        Benchmark(
            name="loop_unrolling",
            func=bench_loop_unrolling,
            category=BenchmarkCategory.PATHS,
            description="Loop handling with constraint accumulation",
        )
    )
    suite.add(
        Benchmark(
            name="linear_constraints",
            func=bench_linear_constraints,
            category=BenchmarkCategory.SOLVING,
            description="100 linear integer constraints",
        )
    )
    suite.add(
        Benchmark(
            name="incremental_solver",
            func=bench_incremental_solver,
            category=BenchmarkCategory.SOLVING,
            description="Incremental solver push/pop performance",
        )
    )
    suite.add(
        Benchmark(
            name="state_forking",
            func=bench_state_forking,
            category=BenchmarkCategory.MEMORY,
            description="VMState CoW fork performance",
        )
    )
    suite.add(
        Benchmark(
            name="constraint_hashing",
            func=bench_constraint_hashing,
            category=BenchmarkCategory.SOLVING,
            description="Structural constraint hashing performance",
        )
    )
    suite.add(
        Benchmark(
            name="concurrency_race_detection",
            func=bench_race_detection,
            category=BenchmarkCategory.CONCURRENCY,
            description="Race detection with 10 operations",
        )
    )
    suite.add(
        Benchmark(
            name="contract_verification",
            func=bench_contract_verification,
            category=BenchmarkCategory.ANALYSIS,
            description="ContractVerifier proving preconditions, postconditions and loop invariants",
        )
    )
    return suite


def bench_simple_arithmetic() -> dict[str, int]:
    """Benchmark: IncrementalSolver arithmetic constraint solving."""
    import z3

    from pysymex.core.solver.engine import IncrementalSolver

    solver = IncrementalSolver(timeout_ms=5000)
    x, y, z = z3.Ints("x y z")
    constraints = [
        x + y == 10,
        x > 0,
        y > 0,
        x * y > 15,
        z == x - y,
        z < 5,
        z > -5,
        x + z > 2,
        y - z < 15,
        x * 2 + y * 3 == 35,
        x % 2 == 0,
        y % 2 != 0,
        z + 10 > x,
        x + y + z < 30,
        x > y,
        y > z,
        x * x > 10,
        y * y > 10,
        z * z < 100,
        x + y + z >= 5,
    ]
    solver.check_sat_cached(constraints)

    return {"instructions": len(constraints), "paths": 1, "solver_calls": 1}


def _solver_queries_from_stats(stats: dict[str, object]) -> int:
    """Extract solver query count from execution result stats."""
    queries = stats.get("queries", 0)
    if isinstance(queries, int):
        return queries
    return 0


def _coverage_count(coverage: set[int]) -> int:
    """Return the concrete number of covered instructions."""
    return len(coverage)


def bench_executor_core_function() -> dict[str, int]:
    """Benchmark: SymbolicExecutor core on a compiled function workload."""
    from pysymex.execution.executors import ExecutionConfig, SymbolicExecutor

    source = """
def target(x, y):
    z = x + y
    if z > 10:
        return z // (y - x)
    if x < 0:
        return x * 2
    return z + 1
"""
    code = compile(source, "<bench_executor_core_function>", "exec")
    config = ExecutionConfig(
        max_paths=64,
        max_depth=64,
        max_iterations=4000,
        timeout_seconds=10.0,
        enable_chtd=False,
        enable_h_acceleration=False,
        deterministic_mode=True,
    )
    result = SymbolicExecutor(config).execute_code(
        code,
        symbolic_vars={"x": "int", "y": "int"},
    )
    return {
        "instructions": _coverage_count(result.coverage),
        "paths": result.paths_explored,
        "solver_calls": _solver_queries_from_stats(result.solver_stats),
    }


def bench_executor_core_branching() -> dict[str, int]:
    """Benchmark: SymbolicExecutor core on a branch-heavy compiled workload."""
    from pysymex.execution.executors import ExecutionConfig, SymbolicExecutor

    source = """
def target(a, b, c):
    score = a + b - c
    if a > 0:
        score += 3
    else:
        score -= 2
    if b % 2 == 0:
        score *= 2
    else:
        score -= 5
    if c == 0:
        return score + 7
    if score > 20:
        return score // c
    return score + c
"""
    code = compile(source, "<bench_executor_core_branching>", "exec")
    config = ExecutionConfig(
        max_paths=128,
        max_depth=64,
        max_iterations=8000,
        timeout_seconds=10.0,
        enable_chtd=False,
        enable_h_acceleration=False,
        deterministic_mode=True,
    )
    result = SymbolicExecutor(config).execute_code(
        code,
        symbolic_vars={"a": "int", "b": "int", "c": "int"},
    )
    return {
        "instructions": _coverage_count(result.coverage),
        "paths": result.paths_explored,
        "solver_calls": _solver_queries_from_stats(result.solver_stats),
    }


def bench_branching() -> dict[str, int]:
    """Benchmark: 20-way branch explosion with IncrementalSolver."""
    import z3

    from pysymex.core.solver.engine import IncrementalSolver

    vars_ = [z3.Int(f"b{i}") for i in range(20)]
    solver = IncrementalSolver(timeout_ms=5000)
    paths = 0
    solver_calls = 0
    constraint_adds = 0
    for v in vars_:
        solver.push()
        solver.add(v > 0)
        constraint_adds += 1
        solver_calls += 1
        if solver.check().is_sat:
            paths += 1
        solver.pop()
        solver.push()
        solver.add(v <= 0)
        constraint_adds += 1
        solver_calls += 1
        if solver.check().is_sat:
            paths += 1
        solver.pop()

    return {"instructions": constraint_adds, "paths": paths, "solver_calls": solver_calls}


def bench_loop_unrolling() -> dict[str, int]:
    """Benchmark: loop with accumulating constraints."""
    from pysymex.core.solver.engine import IncrementalSolver

    solver = IncrementalSolver(timeout_ms=5000)
    base_constraints, suffix_constraints = _loop_unrolling_workload()
    solver.add(*base_constraints)
    paths = 0
    solver_calls = 0
    constraint_adds = len(base_constraints)
    for constraint in suffix_constraints:
        solver.push()
        solver.add(constraint)
        constraint_adds += 1
        solver_calls += 1
        if solver.check().is_sat:
            paths += 1
        solver.pop()

    return {"instructions": constraint_adds, "paths": paths, "solver_calls": solver_calls}


def bench_linear_constraints() -> dict[str, int]:
    """Benchmark: 100 linear integer constraints."""
    from pysymex.core.solver.engine import IncrementalSolver

    solver = IncrementalSolver(timeout_ms=10000, use_cache=False)
    constraints = _linear_constraints_workload()
    constraint_adds = len(constraints)
    solver.add(*constraints)
    solver.check()

    return {"instructions": constraint_adds, "paths": 1, "solver_calls": 1}


def bench_incremental_solver() -> dict[str, int]:
    """Benchmark: IncrementalSolver push/pop performance."""
    try:
        from pysymex.core.solver.engine import IncrementalSolver
    except ImportError:
        return {"instructions": 0, "paths": 0, "solver_calls": 0}

    solver = IncrementalSolver(timeout_ms=5000, use_cache=False)
    calls = 0

    constraint_evals = 0
    for constraints in _incremental_solver_workload():
        solver.push()
        try:
            solver.add(*constraints)
            solver.check()
            constraint_evals += len(constraints)
            calls += 1
        finally:
            solver.pop()

    return {"instructions": constraint_evals, "paths": 100, "solver_calls": calls}


def bench_state_forking() -> dict[str, int]:
    """Benchmark: VMState CoW fork performance."""
    try:
        from pysymex.core.state import VMState
    except ImportError:
        return {"instructions": 0, "paths": 0, "solver_calls": 0}

    import z3

    state = VMState()
    for i in range(50):
        v = z3.Int(f"var_{i}")
        state.local_vars[f"var_{i}"] = v
        state.add_constraint(v >= 0)

    retained_states: list[object] = []
    current = state
    forks = 0
    for i in range(1000):
        current = current.fork()
        current.local_vars[f"var_depth_{i}"] = i
        retained_states.append(current)
        forks += 1
    return {"instructions": forks, "paths": forks, "solver_calls": 0}


def bench_constraint_hashing() -> dict[str, int]:
    """Benchmark: structural constraint hashing vs string-based."""
    try:
        from pysymex.core.solver.constraints import ConstraintHasher, structural_hash
    except ImportError:
        return {"instructions": 0, "paths": 0, "solver_calls": 0}

    import z3

    x, y, z_var = z3.Ints("x y z")
    constraints = [
        x + y > 10,
        y - z_var < 5,
        x * 2 == z_var,
        x >= 0,
        y >= 0,
        z_var >= 0,
        x + y + z_var < 100,
    ]

    hasher = ConstraintHasher()

    hashes = 0
    for _ in range(10000):
        hasher.clear()
        structural_hash(constraints, hasher)
        hashes += 1

    return {"instructions": hashes * len(constraints), "paths": 0, "solver_calls": 0}


def bench_race_detection() -> dict[str, int]:
    """Benchmark: race detection with concurrent operations."""
    try:
        from pysymex.analysis.concurrency import ConcurrencyAnalyzer
    except ImportError:
        return {"instructions": 0, "paths": 0, "solver_calls": 0}

    analyzer = ConcurrencyAnalyzer(timeout_ms=5000)
    ops = 0

    for var_idx in range(5):
        addr = f"shared_var_{var_idx}"

        analyzer.record_write("thread_0", addr, f"val_{ops}")
        ops += 1

        analyzer.record_read("thread_1", addr)
        ops += 1

    analyzer.get_all_issues()
    return {"instructions": ops, "paths": 0, "solver_calls": 0}


def bench_contract_verification() -> dict[str, int]:
    """Benchmark: ContractVerifier proving preconditions, postconditions and loop invariants."""
    try:
        from pysymex.contracts.types import Contract, ContractKind
        from pysymex.contracts.verifier import ContractVerifier
    except ImportError:
        return {"instructions": 0, "paths": 0, "solver_calls": 0}

    import z3

    def _pre(x: z3.ArithRef) -> z3.BoolRef:
        return x > 0

    def _post(y: z3.ArithRef) -> z3.BoolRef:
        return y > 0

    def _inv(i: z3.ArithRef) -> z3.BoolRef:
        return i >= 0

    verifier = ContractVerifier(timeout_ms=5000)
    pre = Contract(kind=ContractKind.REQUIRES, predicate=_pre)
    post = Contract(kind=ContractKind.ENSURES, predicate=_post)
    inv = Contract(kind=ContractKind.LOOP_INVARIANT, predicate=_inv)

    x = z3.Int("x")
    y = z3.Int("y")
    i = z3.Int("i")
    i_after = z3.Int("i_after")

    total_evals = 0

    for _ in range(50):
        # 1. Verify precondition
        verifier.verify_precondition(pre, [x > 5], {"x": x})
        total_evals += 1

        # 2. Verify postcondition
        verifier.verify_postcondition(post, [pre], [y == x * 2], {"x": x, "y": y})
        total_evals += 1

        # 3. Verify loop invariant
        verifier.verify_loop_invariant(
            inv, z3.BoolVal(True), [i_after == i + 1], [i == 0], {"i": i}, {"i": i_after}
        )
        total_evals += 1

    return {"instructions": total_evals, "paths": 50, "solver_calls": total_evals * 4}
