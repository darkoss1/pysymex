"""
Cross-Backend Correctness Tests.

Validates that all backends produce bit-exact identical results
by comparing against the reference pure-Python implementation.

Critical for ensuring GPU acceleration doesn't introduce errors.
"""

from __future__ import annotations

import pytest
import numpy as np

@pytest.fixture
def z3_module():
    """Import Z3 or skip test."""
    return pytest.importorskip("z3")

@pytest.fixture
def reference_backend():
    """Import reference backend."""
    from pysymex.h_acceleration.backends import reference
    return reference

@pytest.fixture
def cpu_backend():
    """Import CPU backend if available."""
    try:
        from pysymex.h_acceleration.backends import cpu
        if cpu.is_available():
            return cpu
    except ImportError:
        pass
    pytest.skip("CPU backend not available")

@pytest.fixture
def gpu_backend():
    """Import CUDA backend if available."""
    try:
        from pysymex.h_acceleration.backends import gpu as cuda
        if cuda.is_available():
            return cuda
    except ImportError:
        pass
    pytest.skip("CUDA backend not available")

def create_random_3sat(z3_module, num_vars: int, clause_ratio: float = 4.3, seed: int = 42):
    """
    Create random 3-SAT instance.

    Args:
        z3_module: Z3 module
        num_vars: Number of variables
        clause_ratio: Clauses per variable (4.3 is phase transition)
        seed: Random seed for reproducibility

    Returns:
        (expression, variable_names)
    """
    import random
    random.seed(seed)

    num_clauses = int(num_vars * clause_ratio)
    vars = [z3_module.Bool(f'x{i}') for i in range(num_vars)]
    var_names = [f'x{i}' for i in range(num_vars)]

    clauses = []
    for _ in range(num_clauses):
        indices = random.sample(range(num_vars), 3)
        literals = [
            vars[i] if random.random() > 0.5 else z3_module.Not(vars[i])
            for i in indices
        ]
        clauses.append(z3_module.Or(*literals))

    return z3_module.And(*clauses), var_names

class TestReferenceCPU:
    """Test CPU backend against reference implementation."""

    @pytest.mark.parametrize("expr_type", ["and", "or", "implies", "complex"])
    def test_basic_expressions(self, z3_module, reference_backend, cpu_backend, expr_type):
        """Test basic expression types."""
        from pysymex.h_acceleration.bytecode import compile_constraint

        a, b, c = z3_module.Bools('a b c')

        if expr_type == "and":
            expr = z3_module.And(a, b, c)
        elif expr_type == "or":
            expr = z3_module.Or(a, z3_module.And(b, c))
        elif expr_type == "implies":
            expr = z3_module.Implies(a, z3_module.Or(b, c))
        else:
            expr = z3_module.And(
                z3_module.Or(a, b),
                z3_module.Implies(b, c),
                z3_module.Or(z3_module.Not(a), c)
            )

        compiled = compile_constraint(expr, ['a', 'b', 'c'])

        ref_result = reference_backend.evaluate_bag(compiled)
        cpu_result = cpu_backend.evaluate_bag(compiled)

        assert np.array_equal(ref_result, cpu_result),            f"CPU differs from reference for {expr_type}"

    @pytest.mark.parametrize("w", [4, 6, 8, 10, 12])
    def test_random_3sat(self, z3_module, reference_backend, cpu_backend, w):
        """Test random 3-SAT instances at various widths."""
        from pysymex.h_acceleration.bytecode import compile_constraint

        expr, var_names = create_random_3sat(z3_module, w, seed=w * 17)
        compiled = compile_constraint(expr, var_names)

        ref_result = reference_backend.evaluate_bag(compiled)
        cpu_result = cpu_backend.evaluate_bag(compiled)

        assert np.array_equal(ref_result, cpu_result),            f"CPU differs from reference at w={w}"

        ref_count = reference_backend.count_satisfying(ref_result)
        cpu_count = int(np.unpackbits(cpu_result).sum())
        assert ref_count == cpu_count

class TestReferenceCUDA:
    """Test CUDA backend against reference implementation."""

    @pytest.mark.parametrize("w", [4, 6, 8, 10, 12, 14])
    def test_random_3sat(self, z3_module, reference_backend, gpu_backend, w):
        """Test random 3-SAT instances."""
        from pysymex.h_acceleration.bytecode import compile_constraint

        expr, var_names = create_random_3sat(z3_module, w, seed=w * 31)
        compiled = compile_constraint(expr, var_names)

        ref_result = reference_backend.evaluate_bag(compiled)
        cuda_result = gpu_backend.evaluate_bag(compiled)

        assert np.array_equal(ref_result, cuda_result),            f"CUDA differs from reference at w={w}"

    def test_all_satisfiable(self, z3_module, reference_backend, gpu_backend):
        """Test tautology (all assignments satisfy)."""
        from pysymex.h_acceleration.bytecode import compile_constraint

        a, b = z3_module.Bools('a b')
        expr = z3_module.Or(a, z3_module.Not(a))             

        compiled = compile_constraint(expr, ['a', 'b'])

        ref_result = reference_backend.evaluate_bag(compiled)
        cuda_result = gpu_backend.evaluate_bag(compiled)

        assert np.array_equal(ref_result, cuda_result)

        assert reference_backend.count_satisfying(ref_result) == 4

    def test_none_satisfiable(self, z3_module, reference_backend, gpu_backend):
        """Test contradiction (no assignments satisfy)."""
        from pysymex.h_acceleration.bytecode import compile_constraint

        a = z3_module.Bool('a')
        expr = z3_module.And(a, z3_module.Not(a))                 

        compiled = compile_constraint(expr, ['a'])

        ref_result = reference_backend.evaluate_bag(compiled)
        cuda_result = gpu_backend.evaluate_bag(compiled)

        assert np.array_equal(ref_result, cuda_result)
        assert reference_backend.count_satisfying(ref_result) == 0

class TestAllBackends:
    """Test all available backends produce identical results."""

    def test_comprehensive(self, z3_module, reference_backend):
        """Compare all backends that are available."""
        from pysymex.h_acceleration.bytecode import compile_constraint

        backends = {"reference": reference_backend}

        try:
            from pysymex.h_acceleration.backends import cpu
            if cpu.is_available():
                backends["cpu"] = cpu
        except ImportError:
            pass

        try:
            from pysymex.h_acceleration.backends import gpu as cuda
            if cuda.is_available():
                backends["cuda"] = cuda
        except ImportError:
            pass

        if len(backends) < 2:
            pytest.skip("Need at least 2 backends for comparison")

        a, b, c, d = z3_module.Bools('a b c d')
        expr = z3_module.And(
            z3_module.Or(a, b),
            z3_module.Or(z3_module.Not(b), c),
            z3_module.Implies(c, d),
            z3_module.Or(z3_module.Not(a), z3_module.Not(d))
        )

        compiled = compile_constraint(expr, ['a', 'b', 'c', 'd'])

        results = {}
        for name, backend in backends.items():
            results[name] = backend.evaluate_bag(compiled)

        names = list(results.keys())
        for i, name1 in enumerate(names):
            for name2 in names[i+1:]:
                assert np.array_equal(results[name1], results[name2]),                    f"{name1} differs from {name2}"

class TestStress:
    """Stress tests for backend correctness under load."""

    def test_many_constraints(self, z3_module, reference_backend, cpu_backend):
        """Test with many constraints."""
        from pysymex.h_acceleration.bytecode import compile_constraint

        vars = [z3_module.Bool(f'x{i}') for i in range(8)]
        var_names = [f'x{i}' for i in range(8)]

        clauses = []
        for i in range(50):
                                     
            indices = [(i + j) % 8 for j in range(3)]
            clause = z3_module.Or(*[
                vars[idx] if (i + idx) % 2 == 0 else z3_module.Not(vars[idx])
                for idx in indices
            ])
            clauses.append(clause)

        expr = z3_module.And(*clauses)
        compiled = compile_constraint(expr, var_names)

        ref_result = reference_backend.evaluate_bag(compiled)
        cpu_result = cpu_backend.evaluate_bag(compiled)

        assert np.array_equal(ref_result, cpu_result)

    def test_deep_nesting(self, z3_module, reference_backend, cpu_backend):
        """Test deeply nested expressions."""
        from pysymex.h_acceleration.bytecode import compile_constraint

        a, b, c = z3_module.Bools('a b c')

        expr = a
        for i in range(10):
            if i % 3 == 0:
                expr = z3_module.And(expr, b)
            elif i % 3 == 1:
                expr = z3_module.Or(expr, c)
            else:
                expr = z3_module.Implies(expr, z3_module.And(a, b))

        compiled = compile_constraint(expr, ['a', 'b', 'c'])

        ref_result = reference_backend.evaluate_bag(compiled)
        cpu_result = cpu_backend.evaluate_bag(compiled)

        assert np.array_equal(ref_result, cpu_result)
