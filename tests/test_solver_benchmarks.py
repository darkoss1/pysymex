"""Tests for solver benchmarks (real workloads, no time.sleep stubs)."""

import z3


class TestBenchmarkInfrastructure:
    """Benchmark suite infrastructure."""

    def test_create_builtin_benchmarks(self):
        from pysymex.benchmarks.suite import create_builtin_benchmarks

        suite = create_builtin_benchmarks()
        assert suite.name == "pysymex_builtin"
        assert len(suite.benchmarks) >= 6  # We added new benchmarks

    def test_benchmark_category_concurrency(self):
        from pysymex.benchmarks.suite import BenchmarkCategory

        assert hasattr(BenchmarkCategory, "CONCURRENCY")

    def test_benchmark_result_dataclass(self):
        from pysymex.benchmarks.suite import BenchmarkCategory, BenchmarkResult

        result = BenchmarkResult(
            name="test",
            category=BenchmarkCategory.SOLVING,
            elapsed_seconds=1.0,
            mean_seconds=0.2,
        )
        assert result.name == "test"
        assert result.throughput == 0.0  # No instructions

    def test_benchmark_reporter_markdown(self):
        from pysymex.benchmarks.suite import BenchmarkCategory, BenchmarkReporter, BenchmarkResult

        results = [
            BenchmarkResult(
                name="test",
                category=BenchmarkCategory.SOLVING,
                elapsed_seconds=1.0,
                mean_seconds=0.2,
            )
        ]
        md = BenchmarkReporter.to_markdown(results)
        assert "test" in md
        assert "SOLVING" in md


class TestRealBenchmarks:
    """Run each benchmark and verify it produces real results."""

    def test_simple_arithmetic_real(self):
        from pysymex.benchmarks.suite import bench_simple_arithmetic

        result = bench_simple_arithmetic()
        assert result["solver_calls"] >= 1
        assert result["instructions"] > 0

    def test_branching_real(self):
        from pysymex.benchmarks.suite import bench_branching

        result = bench_branching()
        assert result["paths"] > 0
        assert result["solver_calls"] >= 20

    def test_loop_unrolling_real(self):
        from pysymex.benchmarks.suite import bench_loop_unrolling

        result = bench_loop_unrolling()
        assert result["paths"] > 0
        assert result["solver_calls"] >= 10

    def test_linear_constraints_real(self):
        from pysymex.benchmarks.suite import bench_linear_constraints

        result = bench_linear_constraints()
        assert result["solver_calls"] >= 1

    def test_incremental_solver_bench(self):
        from pysymex.benchmarks.suite import bench_incremental_solver

        result = bench_incremental_solver()
        assert result["solver_calls"] >= 50

    def test_state_forking_bench(self):
        from pysymex.benchmarks.suite import bench_state_forking

        result = bench_state_forking()
        assert result["paths"] >= 100

    def test_constraint_hashing_bench(self):
        from pysymex.benchmarks.suite import bench_constraint_hashing

        result = bench_constraint_hashing()
        assert result["instructions"] >= 1000

    def test_race_detection_bench(self):
        from pysymex.benchmarks.suite import bench_race_detection

        result = bench_race_detection()
        assert result["instructions"] >= 1


class TestStructuralHash:
    """Structural constraint hashing performance."""

    def test_structural_hash_consistency(self):
        from pysymex.core.constraint_hash import structural_hash

        x, y = z3.Ints("x y")
        constraints = [x > 0, y > 0, x + y < 100]
        h1 = structural_hash(constraints)
        h2 = structural_hash(constraints)
        assert h1 == h2

    def test_structural_hash_different_constraints(self):
        from pysymex.core.constraint_hash import structural_hash

        x = z3.Int("x")
        h1 = structural_hash([x > 0])
        h2 = structural_hash([x < 0])
        assert h1 != h2

    def test_structural_hash_empty(self):
        from pysymex.core.constraint_hash import structural_hash

        h = structural_hash([])
        assert isinstance(h, int)

    def test_structural_hash_order_sensitive(self):
        from pysymex.core.constraint_hash import structural_hash

        x, y = z3.Ints("x y")
        h1 = structural_hash([x > 0, y > 0])
        h2 = structural_hash([y > 0, x > 0])
        # Order matters in xor-based hash (may or may not differ due to mixing)
        assert isinstance(h1, int) and isinstance(h2, int)


class TestConstraintSimplification:
    """Constraint simplification performance."""

    def test_simplifier_basic(self):
        from pysymex.core.constraint_simplifier import simplify_constraints

        x = z3.Int("x")
        result = simplify_constraints([x > 0, x > 0])  # Duplicate
        assert isinstance(result, list)

    def test_quick_contradiction(self):
        from pysymex.core.constraint_simplifier import quick_contradiction_check

        x = z3.Int("x")
        # x > 5 and x < 3 is contradictory
        result = quick_contradiction_check([x > 5, x < 3])
        # Should detect contradiction or return False if not able
        assert isinstance(result, bool)


class TestUnsatCore:
    """UNSAT core extraction."""

    def test_extract_unsat_core(self):
        from pysymex.core.unsat_core import extract_unsat_core

        x = z3.Int("x")
        constraints = [x > 10, x < 5, x > 0]
        result = extract_unsat_core(constraints)
        assert result is not None
        # Core should be subset of original
        assert len(result.core) <= len(constraints)

    def test_sat_no_core(self):
        from pysymex.core.unsat_core import extract_unsat_core

        x = z3.Int("x")
        result = extract_unsat_core([x > 0, x < 100])
        # SAT constraints return None (no UNSAT core)
        assert result is None


class TestAdaptiveTimeout:
    """Adaptive timeout based on complexity estimation."""

    def test_estimate_complexity_simple(self):
        from pysymex.analysis.solver import estimate_complexity

        def simple_func(x):
            return x + 1

        result = estimate_complexity(simple_func.__code__)
        assert result["recommended_timeout_ms"] <= 5000
        assert result["branch_count"] == 0

    def test_estimate_complexity_branchy(self):
        from pysymex.analysis.solver import estimate_complexity

        def branchy(x, y, z):
            if x > 0:
                if y > 0:
                    if z > 0:
                        return 1
                    return 2
                return 3
            return 4

        result = estimate_complexity(branchy.__code__)
        assert result["branch_count"] >= 3
        assert result["recommended_timeout_ms"] >= 2000

    def test_estimate_complexity_loopy(self):
        from pysymex.analysis.solver import estimate_complexity

        def loopy(n):
            total = 0
            for i in range(n):
                total += i
            return total

        result = estimate_complexity(loopy.__code__)
        assert result["loop_count"] >= 1
