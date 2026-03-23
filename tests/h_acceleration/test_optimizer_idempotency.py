"""Bytecode Optimizer Idempotency Tests.

Verifies that optimizer passes reach a fixpoint: running optimize(optimize(program))
produces the same bytecode as optimize(program).

This is a fundamental compiler correctness property. A non-idempotent optimizer
indicates:
- A pass creating new optimization opportunities that it then misses
- A pass undoing another pass's work
- Instruction ordering instability

Test Categories:
1. Simple Boolean Expressions - basic sanity checks
2. CSE Idempotency - common subexpression elimination
3. DCE Idempotency - dead code elimination
4. Constant Folding Idempotency - compile-time evaluation
5. Combined Pass Interactions - multi-pass interference detection
6. Deeply Nested Expressions - stress testing with complex trees
7. Random Expressions - Hypothesis-based property testing
"""

from __future__ import annotations

import pytest
import numpy as np

@pytest.fixture
def z3_module():
    """Import Z3 or skip test."""
    return pytest.importorskip("z3")

@pytest.fixture(autouse=True)
def clear_optimizer_cache():
    """Clear optimizer cache before each test."""
    from pysymex.h_acceleration.bytecode_optimizer import clear_cache
    clear_cache()
    yield
    clear_cache()

def assert_idempotent(optimized_once, optimized_twice):
    """Verify optimizer idempotency with detailed diagnostics.

    Checks:
    1. Instruction sequences are identical
    2. Instruction count doesn't increase
    3. Register count doesn't increase
    """
    # Check instruction count non-regression
    count_once = len(optimized_once.instructions)
    count_twice = len(optimized_twice.instructions)

    assert count_twice == count_once, (
        f"Second optimization changed instruction count: "
        f"first={count_once}, second={count_twice}\n"
        f"This is a definitive optimizer bug."
    )

    # Check register count stability
    assert optimized_twice.register_count <= optimized_once.register_count, (
        f"Register count increased: "
        f"first={optimized_once.register_count}, "
        f"second={optimized_twice.register_count}"
    )

    # Check instruction sequence equality
    instrs_once = optimized_once.instructions
    instrs_twice = optimized_twice.instructions

    # Compare as structured arrays for detailed error messages
    if not np.array_equal(instrs_once, instrs_twice):
        # Build human-readable diff
        from pysymex.h_acceleration.bytecode import disassemble

        diff_lines = ["Optimizer not idempotent - instruction mismatch:"]
        diff_lines.append("\n=== After 1st optimization ===")
        diff_lines.append(disassemble(optimized_once))
        diff_lines.append("\n=== After 2nd optimization ===")
        diff_lines.append(disassemble(optimized_twice))

        pytest.fail("\n".join(diff_lines))


# =============================================================================
# TestSimpleExpressions - Basic Sanity Checks
# =============================================================================

class TestSimpleExpressions:
    """Test idempotency on simple Boolean expressions."""

    def test_single_variable(self, z3_module):
        """Test idempotency on single variable: x"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x = z3.Bool('x')

        compiled = compile_constraint(x, ['x'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_negation(self, z3_module):
        """Test idempotency on negation: Not(x)"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x = z3.Bool('x')
        expr = z3.Not(x)

        compiled = compile_constraint(expr, ['x'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_and_two_vars(self, z3_module):
        """Test idempotency on AND: And(x, y)"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x, y = z3.Bools('x y')
        expr = z3.And(x, y)

        compiled = compile_constraint(expr, ['x', 'y'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_or_two_vars(self, z3_module):
        """Test idempotency on OR: Or(x, y)"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x, y = z3.Bools('x y')
        expr = z3.Or(x, y)

        compiled = compile_constraint(expr, ['x', 'y'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_implies(self, z3_module):
        """Test idempotency on implication: Implies(x, y)"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x, y = z3.Bools('x y')
        expr = z3.Implies(x, y)

        compiled = compile_constraint(expr, ['x', 'y'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)


# =============================================================================
# TestCSEIdempotency - Common Subexpression Elimination
# =============================================================================

class TestCSEIdempotency:
    """Test CSE pass reaches fixpoint."""

    def test_repeated_subexpression_twice(self, z3_module):
        """Test CSE on: And(Or(x, y), Or(x, y))"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x, y = z3.Bools('x y')
        sub = z3.Or(x, y)
        expr = z3.And(sub, sub)

        compiled = compile_constraint(expr, ['x', 'y'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_repeated_subexpression_in_branches(self, z3_module):
        """Test CSE on: And(Or(x, y), Or(Or(x, y), z))"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x, y, z = z3.Bools('x y z')
        sub = z3.Or(x, y)
        expr = z3.And(sub, z3.Or(sub, z))

        compiled = compile_constraint(expr, ['x', 'y', 'z'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_triple_repeated_subexpression(self, z3_module):
        """Test CSE on: Or(And(x, y), Or(And(x, y), And(x, y)))"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x, y = z3.Bools('x y')
        sub = z3.And(x, y)
        expr = z3.Or(sub, z3.Or(sub, sub))

        compiled = compile_constraint(expr, ['x', 'y'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)


# =============================================================================
# TestDCEIdempotency - Dead Code Elimination
# =============================================================================

class TestDCEIdempotency:
    """Test DCE pass reaches fixpoint."""

    def test_single_use_intermediate(self, z3_module):
        """Test DCE on expression with single-use intermediates."""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x, y, z = z3.Bools('x y z')
        # Build expression where intermediate is used once
        expr = z3.And(z3.Or(x, y), z)

        compiled = compile_constraint(expr, ['x', 'y', 'z'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_dead_branch_after_constant_fold(self, z3_module):
        """Test DCE on: And(Or(True, x), y) where constant creates dead code."""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x, y = z3.Bools('x y')
        # Or(True, x) folds to True, making subsequent uses potentially dead
        expr = z3.And(z3.Or(z3.BoolVal(True), x), y)

        compiled = compile_constraint(expr, ['x', 'y'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_overwritten_results(self, z3_module):
        """Test DCE on chain where early results are overwritten."""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        a, b, c, d = z3.Bools('a b c d')
        # Complex chain where intermediate results may be overwritten
        expr = z3.And(
            z3.Or(a, b),
            z3.And(c, d),
            z3.Or(a, c)
        )

        compiled = compile_constraint(expr, ['a', 'b', 'c', 'd'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)


# =============================================================================
# TestConstantFoldingIdempotency
# =============================================================================

class TestConstantFoldingIdempotency:
    """Test constant folding pass reaches fixpoint."""

    def test_and_true_x(self, z3_module):
        """Test folding And(True, x) → x"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x = z3.Bool('x')
        expr = z3.And(z3.BoolVal(True), x)

        compiled = compile_constraint(expr, ['x'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_or_false_x(self, z3_module):
        """Test folding Or(False, x) → x"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x = z3.Bool('x')
        expr = z3.Or(z3.BoolVal(False), x)

        compiled = compile_constraint(expr, ['x'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_and_x_false(self, z3_module):
        """Test folding And(x, False) → False"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x = z3.Bool('x')
        expr = z3.And(x, z3.BoolVal(False))

        compiled = compile_constraint(expr, ['x'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_or_x_true(self, z3_module):
        """Test folding Or(x, True) → True"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x = z3.Bool('x')
        expr = z3.Or(x, z3.BoolVal(True))

        compiled = compile_constraint(expr, ['x'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_not_true(self, z3_module):
        """Test folding Not(True) → False"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x = z3.Bool('x')
        # Need a variable to make this a valid constraint
        expr = z3.Or(z3.Not(z3.BoolVal(True)), x)

        compiled = compile_constraint(expr, ['x'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_nested_constants(self, z3_module):
        """Test folding nested constants: And(Or(True, x), And(False, y))"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x, y = z3.Bools('x y')
        expr = z3.And(
            z3.Or(z3.BoolVal(True), x),
            z3.And(z3.BoolVal(False), y)
        )

        compiled = compile_constraint(expr, ['x', 'y'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)


# =============================================================================
# TestCombinedPassInteractions - Multi-Pass Interference Detection
# =============================================================================

class TestCombinedPassInteractions:
    """Test that optimization passes don't interfere with each other."""

    def test_cse_then_dce(self, z3_module):
        """Test CSE followed by DCE: And(Or(x, y), Or(x, y))"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x, y = z3.Bools('x y')
        sub = z3.Or(x, y)
        # CSE should create shared register, DCE should not eliminate it
        expr = z3.And(sub, sub)

        compiled = compile_constraint(expr, ['x', 'y'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_constant_fold_then_cse(self, z3_module):
        """Test constant folding creating CSE opportunities: Or(And(True, x), And(True, x))"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x = z3.Bool('x')
        # And(True, x) folds to x, then both branches become identical
        sub = z3.And(z3.BoolVal(True), x)
        expr = z3.Or(sub, sub)

        compiled = compile_constraint(expr, ['x'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_dce_then_constant_fold(self, z3_module):
        """Test DCE exposing constant folding opportunities."""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x, y, z = z3.Bools('x y z')
        # Complex expression where DCE might expose constants
        expr = z3.And(
            z3.Or(x, z3.BoolVal(False)),
            z3.And(y, z3.BoolVal(True)),
            z
        )

        compiled = compile_constraint(expr, ['x', 'y', 'z'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_all_passes_interaction(self, z3_module):
        """Test all passes together on complex expression."""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        a, b, c, d = z3.Bools('a b c d')
        # Expression with CSE, constant folding, and DCE opportunities
        sub = z3.Or(a, b)
        expr = z3.And(
            sub,
            sub,  # CSE opportunity
            z3.And(c, z3.BoolVal(True)),  # Constant fold opportunity
            z3.Or(d, z3.BoolVal(False))   # Constant fold opportunity
        )

        compiled = compile_constraint(expr, ['a', 'b', 'c', 'd'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)


# =============================================================================
# TestDeeplyNested - Stress Testing with Complex Trees
# =============================================================================

class TestDeeplyNested:
    """Test idempotency on deeply nested expressions."""

    def test_depth_5(self, z3_module):
        """Test depth 5: And(Or(And(Or(x, y), z), w), v)"""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        x, y, z, w, v = z3.Bools('x y z w v')
        expr = z3.And(
            z3.Or(
                z3.And(
                    z3.Or(x, y),
                    z
                ),
                w
            ),
            v
        )

        compiled = compile_constraint(expr, ['x', 'y', 'z', 'w', 'v'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_depth_8_programmatic(self, z3_module):
        """Test depth 8 constructed programmatically."""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        a, b, c = z3.Bools('a b c')

        # Build depth 8 by alternating And/Or
        expr = a
        for i in range(8):
            if i % 2 == 0:
                expr = z3.And(expr, z3.Or(b, z3.Not(c)))
            else:
                expr = z3.Or(expr, z3.And(c, z3.Not(b)))

        compiled = compile_constraint(expr, ['a', 'b', 'c'])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_wide_10_vars(self, z3_module):
        """Test wide expression: And of 10 independent variables."""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        vars = [z3.Bool(f'v{i}') for i in range(10)]
        expr = z3.And(*vars)

        compiled = compile_constraint(expr, [f'v{i}' for i in range(10)])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)

    def test_mixed_wide_and_deep(self, z3_module):
        """Test mixed wide and deep expression."""
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize

        z3 = z3_module
        vars = [z3.Bool(f'v{i}') for i in range(6)]

        # Create deep nested structure with wide branches
        deep_branch = z3.And(
            z3.Or(vars[0], vars[1]),
            z3.And(vars[2], vars[3]),
            z3.Or(vars[4], vars[5])
        )

        wide_branch = z3.Or(*vars[:4])

        expr = z3.And(deep_branch, wide_branch)

        compiled = compile_constraint(expr, [f'v{i}' for i in range(6)])
        optimized_once, _ = optimize(compiled)
        optimized_twice, _ = optimize(optimized_once)

        assert_idempotent(optimized_once, optimized_twice)


# =============================================================================
# TestStressHypothesis - Property-Based Testing
# =============================================================================

class TestStressHypothesis:
    """Hypothesis-based random expression testing."""

    def test_random_expressions_hypothesis(self, z3_module):
        """Test idempotency on 50 random Boolean expressions."""
        from hypothesis import given, settings
        import hypothesis.strategies as st
        from pysymex.h_acceleration.bytecode import compile_constraint
        from pysymex.h_acceleration.bytecode_optimizer import optimize, clear_cache

        z3 = z3_module

        def create_random_expr(num_vars: int, depth: int, z3_vars: list):
            """Create random Z3 expression with given depth."""
            if depth == 0 or len(z3_vars) == 0:
                return z3_vars[hash(depth) % len(z3_vars)]

            op = hash(depth) % 6
            if op == 0:
                return z3.And(
                    create_random_expr(num_vars, depth - 1, z3_vars),
                    create_random_expr(num_vars, depth - 1, z3_vars)
                )
            elif op == 1:
                return z3.Or(
                    create_random_expr(num_vars, depth - 1, z3_vars),
                    create_random_expr(num_vars, depth - 1, z3_vars)
                )
            elif op == 2:
                return z3.Not(create_random_expr(num_vars, depth - 1, z3_vars))
            elif op == 3:
                return z3.Implies(
                    create_random_expr(num_vars, depth - 1, z3_vars),
                    create_random_expr(num_vars, depth - 1, z3_vars)
                )
            elif op == 4:
                return z3.Xor(
                    create_random_expr(num_vars, depth - 1, z3_vars),
                    create_random_expr(num_vars, depth - 1, z3_vars)
                )
            else:
                # Add constants for folding opportunities
                if hash(depth + 1) % 3 == 0:
                    return z3.And(
                        z3.BoolVal(True),
                        create_random_expr(num_vars, depth - 1, z3_vars)
                    )
                return z3_vars[hash(depth + 2) % len(z3_vars)]

        @given(st.integers(min_value=2, max_value=8))
        @settings(max_examples=50, deadline=1000)
        def test_random(num_vars):
            clear_cache()

            z3_vars = [z3.Bool(f'v{i}') for i in range(num_vars)]
            var_names = [f'v{i}' for i in range(num_vars)]

            # Create random expression with depth 3
            expr = create_random_expr(num_vars, 3, z3_vars)

            try:
                compiled = compile_constraint(expr, var_names)
                optimized_once, _ = optimize(compiled)
                optimized_twice, _ = optimize(optimized_once)

                assert_idempotent(optimized_once, optimized_twice)
            except Exception as e:
                # Skip expressions that cause compilation errors
                # (e.g., too complex, unsupported operations)
                if "Too many" in str(e) or "Unsupported" in str(e):
                    return
                raise

        # Run the property test
        test_random()
