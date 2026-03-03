"""Tests for property-based verification."""

import pytest

import z3


from pysymex.analysis.properties import (
    PropertyKind,
    ProofStatus,
    PropertySpec,
    PropertyProof,
    PropertyProver,
    ArithmeticVerifier,
    EquivalenceChecker,
)


class TestPropertyKind:
    """Tests for PropertyKind enum."""

    def test_commutativity_kind(self):
        assert PropertyKind.COMMUTATIVITY.name == "COMMUTATIVITY"

    def test_associativity_kind(self):
        assert PropertyKind.ASSOCIATIVITY.name == "ASSOCIATIVITY"

    def test_monotonic_kinds(self):
        assert PropertyKind.MONOTONIC_INC.name == "MONOTONIC_INC"

        assert PropertyKind.MONOTONIC_DEC.name == "MONOTONIC_DEC"

    def test_bound_kinds(self):
        assert PropertyKind.LOWER_BOUND.name == "LOWER_BOUND"

        assert PropertyKind.UPPER_BOUND.name == "UPPER_BOUND"

        assert PropertyKind.BOUNDED.name == "BOUNDED"


class TestProofStatus:
    """Tests for ProofStatus enum."""

    def test_proven_status(self):
        assert ProofStatus.PROVEN.name == "PROVEN"

    def test_disproven_status(self):
        assert ProofStatus.DISPROVEN.name == "DISPROVEN"

    def test_unknown_status(self):
        assert ProofStatus.UNKNOWN.name == "UNKNOWN"


class TestPropertySpec:
    """Tests for PropertySpec dataclass."""

    def test_create_spec(self):
        spec = PropertySpec(
            kind=PropertyKind.COMMUTATIVITY,
            name="Addition Commutativity",
            description="a + b == b + a",
        )

        assert spec.kind == PropertyKind.COMMUTATIVITY

        assert spec.name == "Addition Commutativity"

    def test_spec_with_bounds(self):
        spec = PropertySpec(
            kind=PropertyKind.BOUNDED,
            name="Bounded Result",
            lower_bound=z3.IntVal(0),
            upper_bound=z3.IntVal(100),
        )

        assert spec.lower_bound is not None

        assert spec.upper_bound is not None


class TestPropertyProof:
    """Tests for PropertyProof dataclass."""

    def test_proven_proof(self):
        spec = PropertySpec(kind=PropertyKind.COMMUTATIVITY, name="Test")

        proof = PropertyProof(property=spec, status=ProofStatus.PROVEN)

        assert proof.is_proven

        assert not proof.is_disproven

    def test_disproven_proof_with_counterexample(self):
        spec = PropertySpec(kind=PropertyKind.COMMUTATIVITY, name="Test")

        proof = PropertyProof(
            property=spec,
            status=ProofStatus.DISPROVEN,
            counterexample={"a": 1, "b": 2},
        )

        assert proof.is_disproven

        assert proof.counterexample == {"a": 1, "b": 2}

    def test_format_proof(self):
        spec = PropertySpec(kind=PropertyKind.COMMUTATIVITY, name="Test Property")

        proof = PropertyProof(property=spec, status=ProofStatus.PROVEN)

        formatted = proof.format()

        assert "Test Property" in formatted

        assert "PROVEN" in formatted


class TestPropertyProver:
    """Tests for PropertyProver."""

    def test_prove_addition_commutative(self):
        prover = PropertyProver()

        a = z3.Int("a")

        b = z3.Int("b")

        proof = prover.prove_commutativity(lambda x, y: x + y, a, b)

        assert proof.is_proven

    def test_prove_subtraction_not_commutative(self):
        prover = PropertyProver()

        a = z3.Int("a")

        b = z3.Int("b")

        proof = prover.prove_commutativity(lambda x, y: x - y, a, b)

        assert proof.is_disproven

        assert proof.counterexample is not None

    def test_prove_multiplication_commutative(self):
        prover = PropertyProver()

        a = z3.Int("a")

        b = z3.Int("b")

        proof = prover.prove_commutativity(lambda x, y: x * y, a, b)

        assert proof.is_proven

    def test_prove_addition_associative(self):
        prover = PropertyProver()

        a = z3.Int("a")

        b = z3.Int("b")

        c = z3.Int("c")

        proof = prover.prove_associativity(lambda x, y: x + y, a, b, c)

        assert proof.is_proven

    def test_prove_multiplication_associative(self):
        prover = PropertyProver()

        a = z3.Int("a")

        b = z3.Int("b")

        c = z3.Int("c")

        proof = prover.prove_associativity(lambda x, y: x * y, a, b, c)

        assert proof.is_proven

    def test_prove_subtraction_not_associative(self):
        prover = PropertyProver()

        a = z3.Int("a")

        b = z3.Int("b")

        c = z3.Int("c")

        proof = prover.prove_associativity(lambda x, y: x - y, a, b, c)

        assert proof.is_disproven

    def test_prove_zero_identity_for_addition(self):
        prover = PropertyProver()

        a = z3.Int("a")

        zero = z3.IntVal(0)

        proof = prover.prove_identity(lambda x, y: x + y, a, zero)

        assert proof.is_proven

    def test_prove_one_identity_for_multiplication(self):
        prover = PropertyProver()

        a = z3.Int("a")

        one = z3.IntVal(1)

        proof = prover.prove_identity(lambda x, y: x * y, a, one)

        assert proof.is_proven

    def test_prove_max_idempotent(self):
        prover = PropertyProver()

        a = z3.Int("a")

        proof = prover.prove_idempotence(lambda x, y: z3.If(x >= y, x, y), a)

        assert proof.is_proven

    def test_prove_monotonic_increasing(self):
        prover = PropertyProver()

        x = z3.Int("x")

        y = z3.Int("y")

        proof = prover.prove_monotonic_increasing(lambda v: v + 1, x, y)

        assert proof.is_proven

    def test_prove_monotonic_decreasing(self):
        prover = PropertyProver()

        x = z3.Int("x")

        y = z3.Int("y")

        proof = prover.prove_monotonic_decreasing(lambda v: -v, x, y)

        assert proof.is_proven

    def test_prove_lower_bound(self):
        prover = PropertyProver()

        x = z3.Int("x")

        expr = x * x

        proof = prover.prove_lower_bound(expr, z3.IntVal(0), {"x": x})

        assert proof.is_proven

    def test_prove_upper_bound_fails(self):
        prover = PropertyProver()

        x = z3.Int("x")

        proof = prover.prove_upper_bound(x, z3.IntVal(100), {"x": x})

        assert proof.is_disproven

    def test_prove_bounded_with_constraints(self):
        prover = PropertyProver()

        x = z3.Int("x")

        constraints = [x >= 0, x <= 10]

        proof = prover.prove_bounded(x, z3.IntVal(0), z3.IntVal(10), {"x": x}, constraints)

        assert proof.is_proven

    def test_prove_non_negative(self):
        prover = PropertyProver()

        x = z3.Int("x")

        expr = x * x

        proof = prover.prove_non_negative(expr, {"x": x})

        assert proof.is_proven

    def test_prove_positive_fails_at_zero(self):
        prover = PropertyProver()

        x = z3.Int("x")

        expr = x * x

        proof = prover.prove_positive(expr, {"x": x})

        assert proof.is_disproven

        assert proof.counterexample.get("x") == 0

    def test_prove_equivalence(self):
        prover = PropertyProver()

        x = z3.Int("x")

        expr1 = x + x

        expr2 = 2 * x

        proof = prover.prove_equivalence(expr1, expr2, {"x": x})

        assert proof.is_proven

    def test_prove_even_function(self):
        prover = PropertyProver()

        x = z3.Int("x")

        proof = prover.prove_even_function(lambda v: v * v, x)

        assert proof.is_proven

    def test_prove_odd_function(self):
        prover = PropertyProver()

        x = z3.Int("x")

        proof = prover.prove_odd_function(lambda v: v * v * v, x)

        assert proof.is_proven

    def test_prove_not_odd_function(self):
        prover = PropertyProver()

        x = z3.Int("x")

        proof = prover.prove_odd_function(lambda v: v * v, x)

        assert proof.is_disproven

    def test_prove_injective_identity(self):
        prover = PropertyProver()

        x = z3.Int("x")

        y = z3.Int("y")

        proof = prover.prove_injective(lambda v: v, x, y)

        assert proof.is_proven

    def test_prove_not_injective_square(self):
        prover = PropertyProver()

        x = z3.Int("x")

        y = z3.Int("y")

        proof = prover.prove_injective(lambda v: v * v, x, y)

        assert proof.is_disproven

    def test_prove_custom_property(self):
        prover = PropertyProver()

        x = z3.Int("x")

        y = z3.Int("y")

        property_expr = z3.Implies(x > y, x - y > 0)

        proof = prover.prove_custom("Subtraction Positive", property_expr, {"x": x, "y": y})

        assert proof.is_proven


class TestArithmeticVerifier:
    """Tests for ArithmeticVerifier."""

    def test_check_overflow_unbounded(self):
        verifier = ArithmeticVerifier(int_bits=8)

        x = z3.Int("x")

        y = z3.Int("y")

        proof = verifier.check_overflow(x + y, {"x": x, "y": y})

        assert proof.is_disproven

    def test_check_overflow_bounded_input(self):
        verifier = ArithmeticVerifier(int_bits=8)

        x = z3.Int("x")

        y = z3.Int("y")

        constraints = [
            x >= 0,
            x <= 50,
            y >= 0,
            y <= 50,
        ]

        proof = verifier.check_overflow(x + y, {"x": x, "y": y}, constraints)

        assert proof.is_proven

    def test_check_division_safe(self):
        verifier = ArithmeticVerifier()

        x = z3.Int("x")

        y = z3.Int("y")

        proof = verifier.check_division_safe(x, y, {"x": x, "y": y})

        assert proof.is_disproven

        assert proof.counterexample.get("y") == 0

    def test_check_division_safe_with_constraint(self):
        verifier = ArithmeticVerifier()

        x = z3.Int("x")

        y = z3.Int("y")

        constraints = [y != 0]

        proof = verifier.check_division_safe(x, y, {"x": x, "y": y}, constraints)

        assert proof.is_proven

    def test_check_array_bounds_unsafe(self):
        verifier = ArithmeticVerifier()

        index = z3.Int("index")

        length = z3.IntVal(10)

        proof = verifier.check_array_bounds(index, length, {"index": index})

        assert proof.is_disproven

    def test_check_array_bounds_safe(self):
        verifier = ArithmeticVerifier()

        index = z3.Int("index")

        length = z3.IntVal(10)

        constraints = [index >= 0, index < length]

        proof = verifier.check_array_bounds(index, length, {"index": index}, constraints)

        assert proof.is_proven


class TestEquivalenceChecker:
    """Tests for EquivalenceChecker."""

    def test_equivalent_implementations(self):
        checker = EquivalenceChecker()

        x = z3.Int("x")

        impl1 = lambda v: v + v

        impl2 = lambda v: 2 * v

        proof = checker.check_equivalent(impl1, impl2, [x])

        assert proof.is_proven

    def test_non_equivalent_implementations(self):
        checker = EquivalenceChecker()

        x = z3.Int("x")

        impl1 = lambda v: v + 1

        impl2 = lambda v: v + 2

        proof = checker.check_equivalent(impl1, impl2, [x])

        assert proof.is_disproven

    def test_equivalent_with_two_args(self):
        checker = EquivalenceChecker()

        x = z3.Int("x")

        y = z3.Int("y")

        impl1 = lambda a, b: (a + b) * (a + b)

        impl2 = lambda a, b: a * a + 2 * a * b + b * b

        proof = checker.check_equivalent(impl1, impl2, [x, y])

        assert proof.is_proven

    def test_check_refinement(self):
        checker = EquivalenceChecker()

        x = z3.Int("x")

        spec_impl = lambda v: v > 0

        actual_impl = lambda v: v > 5

        proof = checker.check_refinement(spec_impl, actual_impl, [x])

        assert proof.is_proven

    def test_check_refinement_fails(self):
        checker = EquivalenceChecker()

        x = z3.Int("x")

        spec_impl = lambda v: v > 5

        actual_impl = lambda v: v > 0

        proof = checker.check_refinement(spec_impl, actual_impl, [x])

        assert proof.is_disproven


class TestComplexProperties:
    """Tests for more complex mathematical properties."""

    def test_distributivity(self):
        """Test a * (b + c) == a*b + a*c"""

        prover = PropertyProver()

        a = z3.Int("a")

        b = z3.Int("b")

        c = z3.Int("c")

        lhs = a * (b + c)

        rhs = a * b + a * c

        proof = prover.prove_equivalence(lhs, rhs, {"a": a, "b": b, "c": c})

        assert proof.is_proven

    def test_absolute_value_properties(self):
        """Test properties of absolute value."""

        prover = PropertyProver()

        x = z3.Int("x")

        abs_x = z3.If(x >= 0, x, -x)

        proof = prover.prove_lower_bound(abs_x, z3.IntVal(0), {"x": x})

        assert proof.is_proven

    def test_triangle_inequality(self):
        """Test |a| + |b| >= |a + b|."""

        prover = PropertyProver()

        a = z3.Int("a")

        b = z3.Int("b")

        abs_a = z3.If(a >= 0, a, -a)

        abs_b = z3.If(b >= 0, b, -b)

        abs_sum = z3.If(a + b >= 0, a + b, -(a + b))

        property_expr = abs_a + abs_b >= abs_sum

        proof = prover.prove_custom("Triangle Inequality", property_expr, {"a": a, "b": b})

        assert proof.is_proven

    def test_modular_arithmetic(self):
        """Test (a + b) mod n == ((a mod n) + (b mod n)) mod n."""

        prover = PropertyProver(timeout_ms=2000)

        a = z3.Int("a")

        b = z3.Int("b")

        n = z3.Int("n")

        lhs = (a + b) % n

        rhs = ((a % n) + (b % n)) % n

        constraints = [n == 7, a >= 0, a < 100, b >= 0, b < 100]

        proof = prover.prove_equivalence(lhs, rhs, {"a": a, "b": b, "n": n}, constraints)

        assert proof.status in (ProofStatus.PROVEN, ProofStatus.UNKNOWN, ProofStatus.TIMEOUT)

    def test_floor_division_property(self):
        """Test a == (a // b) * b + (a % b) when b != 0."""

        prover = PropertyProver()

        a = z3.Int("a")

        b = z3.Int("b")

        lhs = a

        rhs = (a / b) * b + (a % b)

        constraints = [b != 0]

        proof = prover.prove_equivalence(lhs, rhs, {"a": a, "b": b}, constraints)

        assert proof.is_proven
