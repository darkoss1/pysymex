"""
Performance Benchmark Tests.

Measures and reports performance metrics for GPU backends.
These tests are marked with @pytest.mark.benchmark and are
typically run separately from unit tests.
"""

from __future__ import annotations

import time
import pytest
import numpy as np
from dataclasses import dataclass

@dataclass
class BenchmarkResult:
    """Result from a single benchmark run."""
    backend: str
    treewidth: int
    num_instructions: int
    num_satisfying: int
    compile_time_ms: float
    kernel_time_ms: float
    total_time_ms: float
    throughput_mops: float                                 

    def __repr__(self) -> str:
        return (f"w={self.treewidth}: {self.kernel_time_ms:.3f}ms, "
                f"{self.throughput_mops:.1f} Mop/s, "
                f"{self.num_satisfying} SAT")

@pytest.fixture
def z3_module():
    """Import Z3."""
    return pytest.importorskip("z3")

@pytest.fixture
def dispatcher():
    """Get GPU dispatcher."""
    from pysymex.h_acceleration.dispatcher import get_dispatcher
    return get_dispatcher()

def create_random_3sat(z3_module, num_vars: int, clause_ratio: float = 4.3, seed: int = 42):
    """Create random 3-SAT instance."""
    import random
    random.seed(seed)

    num_clauses = int(num_vars * clause_ratio)
    vars = [z3_module.Bool(f'x{i}') for i in range(num_vars)]
    var_names = [f'x{i}' for i in range(num_vars)]

    clauses = []
    for _ in range(num_clauses):
        indices = random.sample(range(num_vars), min(3, num_vars))
        literals = [
            vars[i] if random.random() > 0.5 else z3_module.Not(vars[i])
            for i in indices
        ]
        clauses.append(z3_module.Or(*literals))

    return z3_module.And(*clauses), var_names

def benchmark_single(
    dispatcher,
    z3_module,
    treewidth: int,
    warmup_runs: int = 3,
    timed_runs: int = 10,
    seed: int = 42,
) -> BenchmarkResult:
    """Run benchmark for specific treewidth."""
    from pysymex.h_acceleration.bytecode import compile_constraint

    expr, var_names = create_random_3sat(z3_module, treewidth, seed=seed)

    t0 = time.perf_counter()
    compiled = compile_constraint(expr, var_names)
    compile_time = (time.perf_counter() - t0) * 1000

    for _ in range(warmup_runs):
        dispatcher.evaluate_bag(compiled)

    times = []
    for _ in range(timed_runs):
        t0 = time.perf_counter()
        result = dispatcher.evaluate_bag(compiled)
        times.append((time.perf_counter() - t0) * 1000)

    kernel_time = np.median(times)
    num_states = 1 << treewidth
    num_satisfying = result.count_satisfying()

    ops = num_states * compiled.instruction_count
    throughput = ops / (kernel_time / 1000) / 1e6

    return BenchmarkResult(
        backend=result.backend_used.name,
        treewidth=treewidth,
        num_instructions=compiled.instruction_count,
        num_satisfying=num_satisfying,
        compile_time_ms=compile_time,
        kernel_time_ms=kernel_time,
        total_time_ms=compile_time + kernel_time,
        throughput_mops=throughput,
    )

@pytest.mark.benchmark
class TestScaling:
    """Test performance scaling with treewidth."""

    @pytest.mark.slow
    @pytest.mark.parametrize("w", [8, 10, 12, 14, 16, 18])
    def test_treewidth_scaling(self, z3_module, dispatcher, w):
        """Benchmark scaling with treewidth."""
                                                 
        info = dispatcher.get_backend_info()
        if w > info.max_treewidth:
            pytest.skip(f"Treewidth {w} exceeds backend max {info.max_treewidth}")

        result = benchmark_single(dispatcher, z3_module, w)

        print(f"\n{result}")
        print(f"  Backend: {result.backend}")
        print(f"  Instructions: {result.num_instructions}")
        print(f"  Compile: {result.compile_time_ms:.2f}ms")

        assert result.kernel_time_ms < 10000                        
        assert result.throughput_mops > 0

    @pytest.mark.slow
    def test_instruction_scaling(self, z3_module, dispatcher):
        """Test scaling with instruction count."""
        from pysymex.h_acceleration.bytecode import compile_constraint

        w = 12                   

        results = []
        for num_clauses in [10, 20, 50, 100]:
            vars = [z3_module.Bool(f'x{i}') for i in range(w)]
            var_names = [f'x{i}' for i in range(w)]

            import random
            random.seed(42)
            clauses = []
            for _ in range(num_clauses):
                indices = random.sample(range(w), 3)
                clause = z3_module.Or(*[
                    vars[i] if random.random() > 0.5 else z3_module.Not(vars[i])
                    for i in indices
                ])
                clauses.append(clause)

            expr = z3_module.And(*clauses)
            compiled = compile_constraint(expr, var_names)

            times = []
            for _ in range(5):
                t0 = time.perf_counter()
                dispatcher.evaluate_bag(compiled)
                times.append((time.perf_counter() - t0) * 1000)

            results.append({
                'clauses': num_clauses,
                'instructions': compiled.instruction_count,
                'time_ms': np.median(times),
            })

        print("\nInstruction scaling:")
        for r in results:
            print(f"  {r['clauses']} clauses -> {r['instructions']} instrs: {r['time_ms']:.3f}ms")

@pytest.mark.benchmark
class TestBackendComparison:
    """Compare performance across backends."""

    @pytest.mark.slow
    def test_all_backends(self, z3_module):
        """Compare all available backends at fixed treewidth."""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.dispatcher import GPUDispatcher, BackendType

        w = 14

        expr, var_names = create_random_3sat(z3_module, w, seed=99)
        compiled = compile_constraint(expr, var_names)

        results = []

        for backend_type in [BackendType.GPU,
                            BackendType.CPU, BackendType.REFERENCE]:
            try:
                disp = GPUDispatcher(force_backend=backend_type)

                if w > disp.get_backend_info().max_treewidth:
                    continue

                for _ in range(3):
                    disp.evaluate_bag(compiled)

                times = []
                for _ in range(10):
                    t0 = time.perf_counter()
                    result = disp.evaluate_bag(compiled)
                    times.append((time.perf_counter() - t0) * 1000)

                results.append({
                    'backend': backend_type.name,
                    'time_ms': np.median(times),
                    'satisfying': result.count_satisfying(),
                })

            except Exception as e:
                print(f"  {backend_type.name}: {e}")
                continue

        print(f"\nBackend comparison at w={w}:")
        for r in results:
            print(f"  {r['backend']:12s}: {r['time_ms']:.3f}ms ({r['satisfying']} SAT)")

        if len(results) >= 2:
                          
            results.sort(key=lambda x: x['time_ms'])
            fastest = results[0]['time_ms']

            print("\nSpeedups vs fastest:")
            for r in results:
                speedup = r['time_ms'] / fastest
                print(f"  {r['backend']:12s}: {speedup:.1f}x")

@pytest.mark.benchmark
@pytest.mark.slow
class TestLargeScale:
    """Large-scale benchmarks (may take several minutes)."""

    @pytest.mark.parametrize("w", [18, 20, 22])
    def test_large_treewidth(self, z3_module, dispatcher, w):
        """Test large treewidths."""
        info = dispatcher.get_backend_info()
        if w > info.max_treewidth:
            pytest.skip(f"Treewidth {w} exceeds backend max {info.max_treewidth}")

        result = benchmark_single(
            dispatcher, z3_module, w,
            warmup_runs=1, timed_runs=3                              
        )

        print(f"\nLarge-scale w={w}:")
        print(f"  Backend: {result.backend}")
        print(f"  Time: {result.kernel_time_ms:.1f}ms")
        print(f"  States: {1 << w:,}")
        print(f"  Throughput: {result.throughput_mops:.1f} Mop/s")

@pytest.mark.benchmark
class TestMemory:
    """Memory usage benchmarks."""

    def test_memory_budget(self, z3_module):
        """Test memory budget calculations."""
        from pysymex.h_acceleration.memory import calculate_memory_budget

        for w in [10, 15, 20, 25]:
            budget = calculate_memory_budget(w, 100)
            print(f"\nw={w} memory budget:")
            print(f"  Output: {budget.output_mb:.2f} MB")
            print(f"  Total: {budget.total_mb:.2f} MB")
            print(f"  Threads: {budget.total_threads:,}")

    def test_max_treewidth_estimate(self):
        """Test maximum treewidth estimation."""
        from pysymex.h_acceleration.memory import estimate_max_treewidth

        for mem_mb in [1024, 4096, 8192, 16384]:
            max_w = estimate_max_treewidth(mem_mb)
            print(f"\n{mem_mb} MB -> max treewidth: {max_w}")
            assert max_w > 0
            assert max_w <= 30
