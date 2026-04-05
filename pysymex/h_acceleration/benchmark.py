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
GPU Acceleration Benchmark CLI.

Comprehensive benchmarking tool for PySyMex GPU acceleration.
Measures and compares performance across all available backends.

Usage:
    python -m pysymex.h_acceleration.benchmark
    python -m pysymex.h_acceleration.benchmark --treewidth 15 --iterations 100
    python -m pysymex.h_acceleration.benchmark --compare-all --output results.json
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Protocol, cast

import numpy as np
import numpy.typing as npt
import z3


def _unpackbits_little(bitmap: npt.NDArray[np.uint8]) -> npt.NDArray[np.uint8]:
    """Return unpacked bits in little-endian bit order for each byte."""
    bits = np.unpackbits(bitmap)
    return bits.reshape(-1, 8)[:, ::-1].reshape(-1)


if TYPE_CHECKING:
    from pysymex.h_acceleration.backends import BackendInfo
    from pysymex.h_acceleration.bytecode import CompiledConstraint


class BackendModule(Protocol):
    """Protocol for backend modules."""

    def is_available(self) -> bool: ...
    def get_info(self) -> BackendInfo: ...
    def evaluate_bag(self, constraint: CompiledConstraint) -> npt.NDArray[np.uint8]: ...


class Z3ModuleLike(Protocol):
    def Bool(self, name: str) -> z3.BoolRef: ...

    def Not(self, *args: object, **kwargs: object) -> z3.BoolRef: ...

    def Or(self, *args: object, **kwargs: object) -> z3.BoolRef: ...

    def And(self, *args: object, **kwargs: object) -> z3.BoolRef: ...


@dataclass
class BenchmarkConfig:
    """Benchmark configuration."""

    treewidths: list[int]
    iterations: int
    warmup_iterations: int
    clause_ratio: float
    random_seed: int


@dataclass
class BenchmarkResult:
    """Result from a single benchmark."""

    backend: str
    treewidth: int
    num_states: int
    num_instructions: int
    num_satisfying: int
    compile_time_ms: float
    kernel_time_ms: float
    kernel_time_std_ms: float
    total_time_ms: float
    throughput_mops: float


@dataclass
class SystemInfo:
    """System information for benchmark context."""

    python_version: str
    platform: str
    processor: str
    numba_version: str | None
    cuda_device: str | None
    backends_available: list[str]


def get_system_info() -> SystemInfo:
    """Gather system information."""
    numba_version = None
    try:
        import numba

        numba_version = numba.__version__
    except ImportError:
        pass

    cuda_device = None
    try:
        from numba import cuda

        if cuda.is_available():
            device = cuda.get_current_device()
            name = device.name
            cuda_device = name.decode() if isinstance(name, bytes) else str(name)
    except Exception:
        pass

    backends = []
    try:
        from pysymex.h_acceleration.dispatcher import get_dispatcher

        dispatcher = get_dispatcher()
        for info in dispatcher.list_backends():
            if info.available:
                backends.append(info.name)
    except Exception:
        pass

    return SystemInfo(
        python_version=platform.python_version(),
        platform=platform.platform(),
        processor=platform.processor() or "Unknown",
        numba_version=numba_version,
        cuda_device=cuda_device,
        backends_available=backends,
    )


def create_random_3sat(
    z3_module: Z3ModuleLike,
    num_vars: int,
    clause_ratio: float,
    seed: int,
) -> tuple[z3.BoolRef, list[str]]:
    """Create random 3-SAT instance."""
    import random

    random.seed(seed)

    num_clauses = max(1, int(num_vars * clause_ratio))
    vars_list = [z3_module.Bool(f"x{i}") for i in range(num_vars)]
    var_names = [f"x{i}" for i in range(num_vars)]

    clauses = []
    for _ in range(num_clauses):
        k = min(3, num_vars)
        indices = random.sample(range(num_vars), k)
        literals = [
            vars_list[i] if random.random() > 0.5 else z3_module.Not(vars_list[i]) for i in indices
        ]
        clauses.append(z3_module.Or(*literals))

    return z3_module.And(*clauses), var_names


def run_single_benchmark(
    backend_module: BackendModule,
    backend_name: str,
    treewidth: int,
    config: BenchmarkConfig,
    z3_module: Z3ModuleLike,
) -> BenchmarkResult | None:
    """Run benchmark for a single backend/treewidth combination."""
    from pysymex.h_acceleration.bytecode import compile_constraint

    try:
        info = backend_module.get_info()
        if treewidth > info.max_treewidth:
            return None

        expr, var_names = create_random_3sat(
            z3_module, treewidth, config.clause_ratio, config.random_seed
        )

        t0 = time.perf_counter()
        compiled = compile_constraint(expr, var_names)
        compile_time = (time.perf_counter() - t0) * 1000

        for _ in range(config.warmup_iterations):
            backend_module.evaluate_bag(compiled)

        times = []
        result_bitmap = None
        for _ in range(config.iterations):
            t0 = time.perf_counter()
            result_bitmap = backend_module.evaluate_bag(compiled)
            times.append((time.perf_counter() - t0) * 1000)

        if result_bitmap is None:
            return None

        kernel_time = np.median(times)
        kernel_std = np.std(times)
        num_states = 1 << treewidth
        num_satisfying = int(_unpackbits_little(result_bitmap).sum())

        ops = num_states * compiled.instruction_count
        throughput = ops / (kernel_time / 1000) / 1e6

        return BenchmarkResult(
            backend=backend_name,
            treewidth=treewidth,
            num_states=num_states,
            num_instructions=compiled.instruction_count,
            num_satisfying=num_satisfying,
            compile_time_ms=compile_time,
            kernel_time_ms=kernel_time,
            kernel_time_std_ms=kernel_std,
            total_time_ms=compile_time + kernel_time,
            throughput_mops=throughput,
        )

    except Exception as e:
        print(f"  Error benchmarking {backend_name} at w={treewidth}: {e}", file=sys.stderr)
        return None


def run_benchmarks(config: BenchmarkConfig) -> dict[str, object]:
    """Run all benchmarks and return results."""
    try:
        import z3
    except ImportError:
        print("Error: z3-solver not installed", file=sys.stderr)
        sys.exit(1)

    results: list[BenchmarkResult] = []
    system_info = get_system_info()

    backends: dict[str, BackendModule] = {}

    try:
        from pysymex.h_acceleration.backends import gpu as cuda

        if cuda.is_available():
            backends["CUDA"] = cuda
    except ImportError:
        pass

    try:
        from pysymex.h_acceleration.backends import cpu

        if cpu.is_available():
            backends["CPU"] = cpu
    except ImportError:
        pass

    try:
        from pysymex.h_acceleration.backends import reference

        backends["Reference"] = reference
    except ImportError:
        pass

    if not backends:
        print("Error: No backends available", file=sys.stderr)
        sys.exit(1)

    print("\nPySyMex GPU Benchmark")
    print("=" * 60)
    print(f"Python {system_info.python_version} on {system_info.platform}")
    if system_info.cuda_device:
        print(f"CUDA Device: {system_info.cuda_device}")
    print(f"Available backends: {', '.join(system_info.backends_available)}")
    print(f"Treewidths: {config.treewidths}")
    print(f"Iterations: {config.iterations}")
    print("=" * 60)

    for w in config.treewidths:
        print(f"\nTreewidth {w} ({1 << w:,} states):")

        for backend_name, backend_module in backends.items():
            result = run_single_benchmark(
                backend_module, backend_name, w, config, cast("Z3ModuleLike", z3)
            )
            if result:
                results.append(result)
                print(
                    f"  {backend_name:12s}: {result.kernel_time_ms:8.3f} ms "
                    f"± {result.kernel_time_std_ms:.3f} ms, "
                    f"{result.throughput_mops:8.1f} Mop/s, "
                    f"{result.num_satisfying:,} SAT"
                )
            else:
                print(f"  {backend_name:12s}: (skipped or failed)")

    print(f"\n{'=' * 60}")
    print("Speedup Summary (vs Reference):")
    print(f"{'=' * 60}")

    for w in config.treewidths:
        w_results = [r for r in results if r.treewidth == w]
        ref_results = [r for r in w_results if r.backend == "Reference"]
        if not ref_results:
            continue
        ref_time = ref_results[0].kernel_time_ms

        print(f"\nTreewidth {w}:")
        for r in sorted(w_results, key=lambda x: x.kernel_time_ms):
            speedup = ref_time / r.kernel_time_ms
            print(f"  {r.backend:12s}: {speedup:6.1f}x")

    return {
        "system_info": asdict(system_info),
        "config": asdict(config),
        "results": [asdict(r) for r in results],
    }


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="PySyMex GPU Acceleration Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--treewidth",
        "-w",
        type=int,
        nargs="+",
        default=[8, 10, 12, 14, 16],
        help="Treewidth(s) to benchmark (default: 8 10 12 14 16)",
    )

    parser.add_argument(
        "--iterations",
        "-n",
        type=int,
        default=10,
        help="Number of timed iterations (default: 10)",
    )

    parser.add_argument(
        "--warmup",
        type=int,
        default=3,
        help="Number of warmup iterations (default: 3)",
    )

    parser.add_argument(
        "--clause-ratio",
        type=float,
        default=4.3,
        help="Clause-to-variable ratio for 3-SAT (default: 4.3)",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Output JSON file for results",
    )

    parser.add_argument(
        "--large",
        action="store_true",
        help="Include large treewidths (16, 18, 20)",
    )

    args = parser.parse_args()

    treewidths = args.treewidth
    if args.large:
        treewidths = list({*treewidths, 16, 18, 20})
        treewidths.sort()

    config = BenchmarkConfig(
        treewidths=treewidths,
        iterations=args.iterations,
        warmup_iterations=args.warmup,
        clause_ratio=args.clause_ratio,
        random_seed=args.seed,
    )

    results = run_benchmarks(config)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
