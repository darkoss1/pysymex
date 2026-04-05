# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""
PySyMex GPU Acceleration Example.

Demonstrates GPU-accelerated constraint evaluation for
symbolic execution bag evaluation.

This example:
1. Creates a constraint representing path conditions
2. Compiles it to GPU bytecode
3. Evaluates all satisfying assignments
4. Shows timing and backend information
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from typing import Protocol, cast


class _BackendTypeLike(Protocol):
    name: str


class _BackendInfoLike(Protocol):
    name: str
    backend_type: _BackendTypeLike
    max_treewidth: int
    device_memory_mb: int | None
    compute_units: int | None


class _CompiledLike(Protocol):
    instruction_count: int
    register_count: int


class _BackendUsedLike(Protocol):
    name: str


class _EvalResultLike(Protocol):
    backend_used: _BackendUsedLike
    total_time_ms: float
    bitmap: object

    def count_satisfying(self) -> int: ...


def main() -> int:
    """Main example function."""

    print("PySyMex GPU Acceleration Example")
    print("=" * 60)

    try:
        import z3
    except ImportError:
        print("Error: z3-solver not installed")
        print("Install with: pip install z3-solver")
        return 1

    try:
        from pysymex.h_acceleration import (
            compile_constraint as _compile_constraint,
        )
        from pysymex.h_acceleration import (
            evaluate_bag as _evaluate_bag,
        )
        from pysymex.h_acceleration import (
            get_backend_info as _get_backend_info,
        )
        from pysymex.h_acceleration.dispatcher import iter_satisfying as _iter_satisfying
        from pysymex.h_acceleration.dispatcher import warmup as _warmup
    except ImportError as e:
        print(f"Error: GPU module not available: {e}")
        return 1

    compile_constraint = cast("Callable[..., _CompiledLike]", _compile_constraint)
    evaluate_bag = cast("Callable[[_CompiledLike], _EvalResultLike]", _evaluate_bag)
    get_backend_info = cast("Callable[[], _BackendInfoLike]", _get_backend_info)
    iter_satisfying = cast(
        "Callable[[object, int, list[str]], Iterable[dict[str, bool]]]",
        _iter_satisfying,
    )
    warmup = _warmup

    print("\nBackend Information:")
    print("-" * 40)

    info = get_backend_info()
    print(f"  Selected: {info.name}")
    print(f"  Type: {info.backend_type.name}")
    print(f"  Max Treewidth: {info.max_treewidth}")
    if info.device_memory_mb:
        print(f"  Device Memory: {info.device_memory_mb} MB")
    if info.compute_units:
        print(f"  Compute Units: {info.compute_units}")

    print("\nWarming up JIT compilation...")
    t0 = time.perf_counter()
    warmup()
    warmup_time = (time.perf_counter() - t0) * 1000
    print(f"  Warmup completed in {warmup_time:.0f} ms")

    print("\n" + "=" * 60)
    print("Example 1: Simple Constraint")
    print("=" * 60)

    a, b, c = z3.Bools("a b c")
    constraint = z3.And(
        z3.Or(a, b),
        z3.Or(z3.Not(b), c),
        z3.Implies(a, c),
    )

    print(f"\nConstraint: {constraint}")
    print("Variables: a, b, c (treewidth = 3)")
    print(f"Total assignments: {2**3} = 8")

    t0 = time.perf_counter()
    compiled = compile_constraint(constraint, ["a", "b", "c"])
    compile_time = (time.perf_counter() - t0) * 1000

    print("\nCompilation:")
    print(f"  Instructions: {compiled.instruction_count}")
    print(f"  Registers: {compiled.register_count}")
    print(f"  Time: {compile_time:.3f} ms")

    t0 = time.perf_counter()
    result = evaluate_bag(compiled)

    print("\nEvaluation:")
    print(f"  Backend: {result.backend_used.name}")
    print(f"  Time: {result.total_time_ms:.3f} ms")
    print(f"  Satisfying: {result.count_satisfying()}/8")

    print("\nSatisfying Assignments:")
    for assignment in iter_satisfying(result.bitmap, 3, ["a", "b", "c"]):
        print(f"  {assignment}")

    print("\n" + "=" * 60)
    print("Example 2: Larger Constraint (3-SAT with 12 variables)")
    print("=" * 60)

    import random

    random.seed(42)

    num_vars = 12
    num_clauses = int(num_vars * 4.3)

    vars_list = [z3.Bool(f"x{i}") for i in range(num_vars)]
    var_names = [f"x{i}" for i in range(num_vars)]

    clauses = []
    for _ in range(num_clauses):
        indices = random.sample(range(num_vars), 3)
        literals = [
            vars_list[i] if random.random() > 0.5 else z3.Not(vars_list[i]) for i in indices
        ]
        clauses.append(z3.Or(*literals))

    large_constraint = z3.And(*clauses)

    print("\nConstraint: Random 3-SAT")
    print(f"  Variables: {num_vars}")
    print(f"  Clauses: {num_clauses}")
    print(f"  Total assignments: {2**num_vars:,}")

    t0 = time.perf_counter()
    compiled = compile_constraint(large_constraint, var_names)
    compile_time = (time.perf_counter() - t0) * 1000

    print("\nCompilation:")
    print(f"  Instructions: {compiled.instruction_count}")
    print(f"  Time: {compile_time:.3f} ms")

    t0 = time.perf_counter()
    result = evaluate_bag(compiled)

    sat_count = result.count_satisfying()
    sat_ratio = sat_count / (2**num_vars) * 100

    print("\nEvaluation:")
    print(f"  Backend: {result.backend_used.name}")
    print(f"  Time: {result.total_time_ms:.3f} ms")
    print(f"  Satisfying: {sat_count:,}/{2**num_vars:,} ({sat_ratio:.2f}%)")

    ops = (2**num_vars) * compiled.instruction_count
    throughput = ops / (result.total_time_ms / 1000) / 1e6
    print(f"  Throughput: {throughput:.1f} Mop/s")

    print("\n" + "=" * 60)
    print("Example 3: Scaling with Treewidth")
    print("=" * 60)

    print(
        "\n{:>5} {:>12} {:>10} {:>12} {:>12}".format(
            "Width", "States", "Instrs", "Time (ms)", "Mop/s"
        )
    )
    print("-" * 55)

    for w in [8, 10, 12, 14, 16]:
        if w > info.max_treewidth:
            print(f"{w:>5} (exceeds backend limit)")
            continue

        vars_list = [z3.Bool(f"v{i}") for i in range(w)]
        var_names = [f"v{i}" for i in range(w)]

        clauses = []
        for i in range(w - 1):
            clauses.append(z3.Or(vars_list[i], vars_list[i + 1]))
        constraint = z3.And(*clauses) if clauses else z3.BoolVal(True)

        compiled = compile_constraint(constraint, var_names)

        times = []
        for _ in range(5):
            t0 = time.perf_counter()
            result = evaluate_bag(compiled)
            times.append((time.perf_counter() - t0) * 1000)

        import numpy as np

        median_time = np.median(times)

        ops = (2**w) * compiled.instruction_count
        throughput = ops / (median_time / 1000) / 1e6

        print(
            f"{w:>5} {2**w:>12,} {compiled.instruction_count:>10} "
            f"{median_time:>12.3f} {throughput:>12.1f}"
        )

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
