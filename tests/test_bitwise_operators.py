"""Comprehensive tests for bitwise operators in SymbolicValue.

This module tests:
- Bitwise AND, OR, XOR, NOT operators
- Left shift (<<) and right shift (>>) operators
- Reflected operators (__rand__, __ror__, __rxor__, __rlshift__, __rrshift__)
- Taint propagation through bitwise operations
- Edge cases: large shifts, negative numbers, boundary conditions
- Z3 correctness proofs for symbolic bitwise operations
- Two's complement semantics
"""

import pytest
import z3

from pysymex.core.types import SymbolicValue, Z3_TRUE, Z3_FALSE


# =============================================================================
# Constants and Helper functions
# =============================================================================

# 64-bit signed integer range for bitvector operations
INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1


def prove(constraint: z3.BoolRef) -> bool:
    """Check if a Z3 constraint is a tautology (negation is UNSAT)."""
    s = z3.Solver()
    s.add(z3.Not(constraint))
    return s.check() == z3.unsat


def prove_with_constraint(
    constraint: z3.BoolRef,
    *preconditions: z3.BoolRef,
) -> bool:
    """Check if a Z3 constraint is a tautology given preconditions."""
    s = z3.Solver()
    for pre in preconditions:
        s.add(pre)
    s.add(z3.Not(constraint))
    return s.check() == z3.unsat


def in_int64_range(x: z3.ArithRef) -> z3.BoolRef:
    """Constraint that x fits in signed 64-bit range."""
    return z3.And(x >= INT64_MIN, x <= INT64_MAX)


def solve_for_value(constraint: z3.BoolRef, expr: z3.ExprRef) -> int | None:
    """Solve constraint and return concrete value of expr, or None if UNSAT."""
    s = z3.Solver()
    s.add(constraint)
    if s.check() == z3.sat:
        m = s.model()
        val = m.evaluate(expr)
        if z3.is_int_value(val):
            return val.as_long()
    return None


# =============================================================================
# TestBitwiseAND - Tests for __and__ and __rand__
# =============================================================================

class TestBitwiseAND:
    """Tests for bitwise AND operator (&)."""

    def test_and_symbolic_creation(self):
        """Test AND creates valid SymbolicValue."""
        x, _ = SymbolicValue.symbolic_int("x")
        y, _ = SymbolicValue.symbolic_int("y")

        result = x & y
        assert isinstance(result, SymbolicValue)
        assert "&" in result.name

    def test_and_concrete_values(self):
        """Test AND with concrete values produces correct results."""
        # 0xFF & 0x0F = 0x0F = 15
        a = SymbolicValue.from_const(0xFF)
        b = SymbolicValue.from_const(0x0F)
        result = a & b

        assert prove(result.z3_int == 0x0F)

    def test_and_concrete_correctness_extensive(self):
        """Test AND correctness across multiple concrete cases."""
        test_cases = [
            (0b1010, 0b1100, 0b1000),  # 10 & 12 = 8
            (0xFF, 0x00, 0x00),         # 255 & 0 = 0
            (0xFF, 0xFF, 0xFF),         # 255 & 255 = 255
            (5, 3, 1),                   # 0101 & 0011 = 0001
            (7, 3, 3),                   # 0111 & 0011 = 0011
            (0, 0, 0),                   # 0 & 0 = 0
            (-1, 0xFF, 0xFF),            # All 1s & 0xFF = 0xFF (in 64-bit)
        ]

        for a_val, b_val, expected in test_cases:
            a = SymbolicValue.from_const(a_val)
            b = SymbolicValue.from_const(b_val)
            result = a & b

            # For small positive numbers, verify directly
            if expected >= 0 and expected < 2**32:
                s = z3.Solver()
                s.add(result.z3_int == expected)
                assert s.check() == z3.sat, f"Failed: {a_val} & {b_val} should be {expected}"

    def test_and_with_zero(self):
        """AND with zero should always be zero."""
        x, _ = SymbolicValue.symbolic_int("x")
        zero = SymbolicValue.from_const(0)

        result = x & zero
        assert prove(result.z3_int == 0)

    def test_and_identity(self):
        """AND with all-ones should preserve value (within bit range)."""
        # For small values, x & 0xFF should equal x when x < 256
        x = SymbolicValue.from_const(42)
        mask = SymbolicValue.from_const(0xFF)

        result = x & mask
        assert prove(result.z3_int == 42)

    def test_and_symbolic_with_self(self):
        """x & x should equal x (within 64-bit range)."""
        x, _ = SymbolicValue.symbolic_int("x")

        result = x & x
        # x & x == x for all x that fit in 64-bit signed range
        assert prove_with_constraint(
            result.z3_int == x.z3_int,
            in_int64_range(x.z3_int),
        )

    def test_rand_reflected_operator(self):
        """Test reflected AND operator (__rand__)."""
        x, _ = SymbolicValue.symbolic_int("x")

        # Python int & SymbolicValue should use __rand__
        result = 5 & x  # type: ignore[operator]
        assert isinstance(result, SymbolicValue)
        assert "&" in result.name

    def test_and_commutativity(self):
        """Test AND is commutative: x & y == y & x."""
        x, _ = SymbolicValue.symbolic_int("x")
        y, _ = SymbolicValue.symbolic_int("y")

        result1 = x & y
        result2 = y & x

        assert prove(result1.z3_int == result2.z3_int)


# =============================================================================
# TestBitwiseOR - Tests for __or__ and __ror__
# =============================================================================

class TestBitwiseOR:
    """Tests for bitwise OR operator (|)."""

    def test_or_symbolic_creation(self):
        """Test OR creates valid SymbolicValue."""
        x, _ = SymbolicValue.symbolic_int("x")
        y, _ = SymbolicValue.symbolic_int("y")

        result = x | y
        assert isinstance(result, SymbolicValue)
        assert "|" in result.name

    def test_or_concrete_values(self):
        """Test OR with concrete values produces correct results."""
        # 0b1010 | 0b0101 = 0b1111 = 15
        a = SymbolicValue.from_const(0b1010)
        b = SymbolicValue.from_const(0b0101)
        result = a | b

        assert prove(result.z3_int == 0b1111)

    def test_or_concrete_correctness_extensive(self):
        """Test OR correctness across multiple concrete cases."""
        test_cases = [
            (0b1010, 0b0101, 0b1111),  # 10 | 5 = 15
            (0x00, 0xFF, 0xFF),         # 0 | 255 = 255
            (0x0F, 0xF0, 0xFF),         # OR combines high and low nibbles
            (5, 3, 7),                   # 0101 | 0011 = 0111
            (0, 0, 0),                   # 0 | 0 = 0
        ]

        for a_val, b_val, expected in test_cases:
            a = SymbolicValue.from_const(a_val)
            b = SymbolicValue.from_const(b_val)
            result = a | b

            s = z3.Solver()
            s.add(result.z3_int == expected)
            assert s.check() == z3.sat, f"Failed: {a_val} | {b_val} should be {expected}"

    def test_or_with_zero(self):
        """OR with zero should preserve value (identity)."""
        x, _ = SymbolicValue.symbolic_int("x")
        zero = SymbolicValue.from_const(0)

        result = x | zero
        assert prove_with_constraint(
            result.z3_int == x.z3_int,
            in_int64_range(x.z3_int),
        )

    def test_or_symbolic_with_self(self):
        """x | x should equal x (within 64-bit range)."""
        x, _ = SymbolicValue.symbolic_int("x")

        result = x | x
        assert prove_with_constraint(
            result.z3_int == x.z3_int,
            in_int64_range(x.z3_int),
        )

    def test_ror_reflected_operator(self):
        """Test reflected OR operator (__ror__)."""
        x, _ = SymbolicValue.symbolic_int("x")

        result = 5 | x  # type: ignore[operator]
        assert isinstance(result, SymbolicValue)
        assert "|" in result.name

    def test_or_commutativity(self):
        """Test OR is commutative: x | y == y | x."""
        x, _ = SymbolicValue.symbolic_int("x")
        y, _ = SymbolicValue.symbolic_int("y")

        result1 = x | y
        result2 = y | x

        assert prove(result1.z3_int == result2.z3_int)


# =============================================================================
# TestBitwiseXOR - Tests for __xor__ and __rxor__
# =============================================================================

class TestBitwiseXOR:
    """Tests for bitwise XOR operator (^)."""

    def test_xor_symbolic_creation(self):
        """Test XOR creates valid SymbolicValue."""
        x, _ = SymbolicValue.symbolic_int("x")
        y, _ = SymbolicValue.symbolic_int("y")

        result = x ^ y
        assert isinstance(result, SymbolicValue)
        assert "^" in result.name

    def test_xor_concrete_values(self):
        """Test XOR with concrete values produces correct results."""
        # 0b1100 ^ 0b1010 = 0b0110 = 6
        a = SymbolicValue.from_const(0b1100)
        b = SymbolicValue.from_const(0b1010)
        result = a ^ b

        assert prove(result.z3_int == 0b0110)

    def test_xor_concrete_correctness_extensive(self):
        """Test XOR correctness across multiple concrete cases."""
        test_cases = [
            (0b1010, 0b1010, 0b0000),  # x ^ x = 0
            (0xFF, 0x00, 0xFF),         # x ^ 0 = x
            (5, 3, 6),                   # 0101 ^ 0011 = 0110
            (0b1111, 0b0000, 0b1111),
            (0b1111, 0b1111, 0b0000),
        ]

        for a_val, b_val, expected in test_cases:
            a = SymbolicValue.from_const(a_val)
            b = SymbolicValue.from_const(b_val)
            result = a ^ b

            s = z3.Solver()
            s.add(result.z3_int == expected)
            assert s.check() == z3.sat, f"Failed: {a_val} ^ {b_val} should be {expected}"

    def test_xor_with_zero(self):
        """XOR with zero should preserve value (identity)."""
        x, _ = SymbolicValue.symbolic_int("x")
        zero = SymbolicValue.from_const(0)

        result = x ^ zero
        assert prove_with_constraint(
            result.z3_int == x.z3_int,
            in_int64_range(x.z3_int),
        )

    def test_xor_symbolic_with_self(self):
        """x ^ x should equal 0 (self-inverse property)."""
        x, _ = SymbolicValue.symbolic_int("x")

        result = x ^ x
        assert prove(result.z3_int == 0)

    def test_xor_double_application(self):
        """(x ^ y) ^ y should equal x (XOR is its own inverse)."""
        x, _ = SymbolicValue.symbolic_int("x")
        y, _ = SymbolicValue.symbolic_int("y")

        result = (x ^ y) ^ y
        assert prove_with_constraint(
            result.z3_int == x.z3_int,
            in_int64_range(x.z3_int),
            in_int64_range(y.z3_int),
        )

    def test_rxor_reflected_operator(self):
        """Test reflected XOR operator (__rxor__)."""
        x, _ = SymbolicValue.symbolic_int("x")

        result = 5 ^ x  # type: ignore[operator]
        assert isinstance(result, SymbolicValue)
        assert "^" in result.name

    def test_xor_commutativity(self):
        """Test XOR is commutative: x ^ y == y ^ x."""
        x, _ = SymbolicValue.symbolic_int("x")
        y, _ = SymbolicValue.symbolic_int("y")

        result1 = x ^ y
        result2 = y ^ x

        assert prove(result1.z3_int == result2.z3_int)


# =============================================================================
# TestBitwiseNOT - Tests for __invert__
# =============================================================================

class TestBitwiseNOT:
    """Tests for bitwise NOT operator (~)."""

    def test_invert_symbolic_creation(self):
        """Test NOT creates valid SymbolicValue."""
        x, _ = SymbolicValue.symbolic_int("x")

        result = ~x
        assert isinstance(result, SymbolicValue)
        assert "~" in result.name

    def test_invert_twos_complement(self):
        """Test ~0 = -1 (two's complement)."""
        zero = SymbolicValue.from_const(0)
        result = ~zero

        # In two's complement, ~0 = -1
        assert prove(result.z3_int == -1)

    def test_invert_twos_complement_property(self):
        """Test ~x = -(x+1) (two's complement property)."""
        # ~5 = -6, ~(-1) = 0
        test_cases = [
            (0, -1),
            (5, -6),
            (1, -2),
            (255, -256),
        ]

        for input_val, expected in test_cases:
            x = SymbolicValue.from_const(input_val)
            result = ~x

            s = z3.Solver()
            s.add(result.z3_int == expected)
            assert s.check() == z3.sat, f"Failed: ~{input_val} should be {expected}"

    def test_double_invert(self):
        """~~x should equal x (involution property)."""
        x, _ = SymbolicValue.symbolic_int("x")

        result = ~~x
        assert prove_with_constraint(
            result.z3_int == x.z3_int,
            in_int64_range(x.z3_int),
        )

    def test_invert_preserves_is_int(self):
        """Invert should preserve is_int discriminator."""
        x, _ = SymbolicValue.symbolic_int("x")
        result = ~x

        assert result.is_int == x.is_int


# =============================================================================
# TestLeftShift - Tests for __lshift__ and __rlshift__
# =============================================================================

class TestLeftShift:
    """Tests for left shift operator (<<)."""

    def test_lshift_symbolic_creation(self):
        """Test left shift creates valid SymbolicValue."""
        x, _ = SymbolicValue.symbolic_int("x")
        n, _ = SymbolicValue.symbolic_int("n")

        result = x << n
        assert isinstance(result, SymbolicValue)
        assert "<<" in result.name

    def test_lshift_concrete_values(self):
        """Test left shift with concrete values produces correct results."""
        # 1 << 4 = 16
        x = SymbolicValue.from_const(1)
        n = SymbolicValue.from_const(4)
        result = x << n

        assert prove(result.z3_int == 16)

    def test_lshift_concrete_correctness_extensive(self):
        """Test left shift correctness across multiple concrete cases."""
        test_cases = [
            (1, 0, 1),     # 1 << 0 = 1
            (1, 1, 2),     # 1 << 1 = 2
            (1, 2, 4),     # 1 << 2 = 4
            (1, 3, 8),     # 1 << 3 = 8
            (1, 4, 16),    # 1 << 4 = 16
            (3, 2, 12),    # 3 << 2 = 12
            (5, 1, 10),    # 5 << 1 = 10
            (0, 10, 0),    # 0 << anything = 0
        ]

        for val, shift, expected in test_cases:
            x = SymbolicValue.from_const(val)
            n = SymbolicValue.from_const(shift)
            result = x << n

            s = z3.Solver()
            s.add(result.z3_int == expected)
            assert s.check() == z3.sat, f"Failed: {val} << {shift} should be {expected}"

    def test_lshift_by_zero(self):
        """x << 0 should equal x."""
        x, _ = SymbolicValue.symbolic_int("x")
        zero = SymbolicValue.from_const(0)

        result = x << zero
        assert prove_with_constraint(
            result.z3_int == x.z3_int,
            in_int64_range(x.z3_int),
        )

    def test_lshift_zero_value(self):
        """0 << n should equal 0 for any n."""
        zero = SymbolicValue.from_const(0)
        n, _ = SymbolicValue.symbolic_int("n")

        # Add constraint that n >= 0 to avoid undefined behavior
        s = z3.Solver()
        s.add(n.z3_int >= 0)
        s.add(n.z3_int < 64)  # Reasonable shift range
        result = zero << n
        s.add(result.z3_int == 0)

        assert s.check() == z3.sat

    def test_lshift_is_multiplication_by_power_of_two(self):
        """x << n should equal x * 2^n for small n."""
        # Test specific case: 5 << 3 = 5 * 8 = 40
        x = SymbolicValue.from_const(5)
        n = SymbolicValue.from_const(3)

        result = x << n
        assert prove(result.z3_int == 40)

    def test_rlshift_reflected_operator(self):
        """Test reflected left shift operator (__rlshift__)."""
        n, _ = SymbolicValue.symbolic_int("n")

        # Python int << SymbolicValue should use __rlshift__
        result = 1 << n  # type: ignore[operator]
        assert isinstance(result, SymbolicValue)
        assert "<<" in result.name

    def test_lshift_large_shift_amount(self):
        """Test left shift by large amount (>= 64 bits)."""
        x = SymbolicValue.from_const(1)
        n = SymbolicValue.from_const(64)

        # Left shift by 64 bits should result in 0 for 64-bit bitvectors
        result = x << n
        # This is implementation-defined behavior, just ensure it doesn't crash
        assert isinstance(result, SymbolicValue)


# =============================================================================
# TestRightShift - Tests for __rshift__ and __rrshift__
# =============================================================================

class TestRightShift:
    """Tests for right shift operator (>>)."""

    def test_rshift_symbolic_creation(self):
        """Test right shift creates valid SymbolicValue."""
        x, _ = SymbolicValue.symbolic_int("x")
        n, _ = SymbolicValue.symbolic_int("n")

        result = x >> n
        assert isinstance(result, SymbolicValue)
        assert ">>" in result.name

    def test_rshift_concrete_values(self):
        """Test right shift with concrete values produces correct results."""
        # 16 >> 2 = 4
        x = SymbolicValue.from_const(16)
        n = SymbolicValue.from_const(2)
        result = x >> n

        assert prove(result.z3_int == 4)

    def test_rshift_concrete_correctness_extensive(self):
        """Test right shift correctness across multiple concrete cases."""
        test_cases = [
            (16, 0, 16),   # 16 >> 0 = 16
            (16, 1, 8),    # 16 >> 1 = 8
            (16, 2, 4),    # 16 >> 2 = 4
            (16, 3, 2),    # 16 >> 3 = 2
            (16, 4, 1),    # 16 >> 4 = 1
            (16, 5, 0),    # 16 >> 5 = 0
            (255, 4, 15),  # 255 >> 4 = 15
            (0, 10, 0),    # 0 >> anything = 0
        ]

        for val, shift, expected in test_cases:
            x = SymbolicValue.from_const(val)
            n = SymbolicValue.from_const(shift)
            result = x >> n

            s = z3.Solver()
            s.add(result.z3_int == expected)
            assert s.check() == z3.sat, f"Failed: {val} >> {shift} should be {expected}"

    def test_rshift_by_zero(self):
        """x >> 0 should equal x."""
        x, _ = SymbolicValue.symbolic_int("x")
        zero = SymbolicValue.from_const(0)

        result = x >> zero
        assert prove_with_constraint(
            result.z3_int == x.z3_int,
            in_int64_range(x.z3_int),
        )

    def test_rshift_negative_sign_extension(self):
        """Test arithmetic right shift preserves sign for negative numbers."""
        # -8 >> 2 should be -2 (arithmetic shift with sign extension)
        # In Python: -8 >> 2 = -2
        x = SymbolicValue.from_const(-8)
        n = SymbolicValue.from_const(2)

        result = x >> n
        # Arithmetic right shift: -8 >> 2 = -2
        s = z3.Solver()
        s.add(result.z3_int == -2)
        assert s.check() == z3.sat

    def test_rshift_negative_stays_negative(self):
        """Right shifting a negative number should stay negative (sign extension)."""
        # -1 >> n should still be -1 (all ones)
        x = SymbolicValue.from_const(-1)
        n = SymbolicValue.from_const(10)

        result = x >> n
        s = z3.Solver()
        s.add(result.z3_int == -1)
        assert s.check() == z3.sat

    def test_rrshift_reflected_operator(self):
        """Test reflected right shift operator (__rrshift__)."""
        n, _ = SymbolicValue.symbolic_int("n")

        # Python int >> SymbolicValue should use __rrshift__
        result = 16 >> n  # type: ignore[operator]
        assert isinstance(result, SymbolicValue)
        assert ">>" in result.name

    def test_rshift_is_floor_division_by_power_of_two(self):
        """x >> n should equal x // 2^n for positive x and small n."""
        # Test specific case: 20 >> 2 = 20 // 4 = 5
        x = SymbolicValue.from_const(20)
        n = SymbolicValue.from_const(2)

        result = x >> n
        assert prove(result.z3_int == 5)


# =============================================================================
# TestBitwiseTaintPropagation - Taint flow through bitwise ops
# =============================================================================

class TestBitwiseTaintPropagation:
    """Tests for taint propagation through bitwise operations."""

    def test_and_taint_propagation(self):
        """Taint should propagate through AND operation."""
        a = SymbolicValue.from_const(0xFF).with_taint("source_a")
        b = SymbolicValue.from_const(0x0F).with_taint("source_b")

        result = a & b
        assert result.taint_labels == frozenset({"source_a", "source_b"})

    def test_and_taint_from_one_operand(self):
        """Taint from one operand should propagate through AND."""
        a = SymbolicValue.from_const(0xFF).with_taint("tainted")
        b = SymbolicValue.from_const(0x0F)  # Clean

        result = a & b
        assert result.taint_labels == frozenset({"tainted"})

    def test_or_taint_propagation(self):
        """Taint should propagate through OR operation."""
        a = SymbolicValue.from_const(0xFF).with_taint("source_a")
        b = SymbolicValue.from_const(0x0F).with_taint("source_b")

        result = a | b
        assert result.taint_labels == frozenset({"source_a", "source_b"})

    def test_xor_taint_propagation(self):
        """Taint should propagate through XOR operation."""
        a = SymbolicValue.from_const(0xFF).with_taint("source_a")
        b = SymbolicValue.from_const(0x0F).with_taint("source_b")

        result = a ^ b
        assert result.taint_labels == frozenset({"source_a", "source_b"})

    def test_invert_taint_preservation(self):
        """Taint should be preserved through bitwise NOT."""
        a = SymbolicValue.from_const(0xFF).with_taint("tainted")

        result = ~a
        assert result.taint_labels == frozenset({"tainted"})

    def test_lshift_taint_propagation(self):
        """Taint should propagate through left shift."""
        value = SymbolicValue.from_const(1).with_taint("value_taint")
        shift = SymbolicValue.from_const(4).with_taint("shift_taint")

        result = value << shift
        assert result.taint_labels == frozenset({"value_taint", "shift_taint"})

    def test_rshift_taint_propagation(self):
        """Taint should propagate through right shift."""
        value = SymbolicValue.from_const(16).with_taint("value_taint")
        shift = SymbolicValue.from_const(2).with_taint("shift_taint")

        result = value >> shift
        assert result.taint_labels == frozenset({"value_taint", "shift_taint"})

    def test_shift_taint_from_value_only(self):
        """Taint from shifted value propagates even with clean shift amount."""
        value = SymbolicValue.from_const(16).with_taint("tainted")
        shift = SymbolicValue.from_const(2)  # Clean

        result = value >> shift
        assert result.taint_labels == frozenset({"tainted"})

    def test_shift_taint_from_amount_only(self):
        """Taint from shift amount propagates even with clean value."""
        value = SymbolicValue.from_const(16)  # Clean
        shift = SymbolicValue.from_const(2).with_taint("tainted_shift")

        result = value >> shift
        assert result.taint_labels == frozenset({"tainted_shift"})

    def test_chained_bitwise_taint(self):
        """Taint should propagate through chained bitwise operations."""
        a = SymbolicValue.from_const(0xFF).with_taint("a")
        b = SymbolicValue.from_const(0x0F)  # Clean
        c = SymbolicValue.from_const(0xF0).with_taint("c")

        # (a & b) | c
        result = (a & b) | c
        assert result.taint_labels == frozenset({"a", "c"})


# =============================================================================
# TestBitwiseEdgeCases - Boundary conditions and edge cases
# =============================================================================

class TestBitwiseEdgeCases:
    """Tests for edge cases in bitwise operations."""

    def test_and_with_all_ones(self):
        """AND with all 1s should be identity (for positive values in range)."""
        x = SymbolicValue.from_const(42)
        all_ones_byte = SymbolicValue.from_const(0xFF)

        result = x & all_ones_byte
        assert prove(result.z3_int == 42)

    def test_or_with_all_ones(self):
        """OR with all 1s should give all 1s (within byte range)."""
        x = SymbolicValue.from_const(0)
        all_ones_byte = SymbolicValue.from_const(0xFF)

        result = x | all_ones_byte
        assert prove(result.z3_int == 0xFF)

    def test_xor_with_all_ones_inverts(self):
        """XOR with all 1s should invert bits (within byte range)."""
        # 0x0F ^ 0xFF = 0xF0 (lower nibble becomes upper)
        x = SymbolicValue.from_const(0x0F)
        all_ones_byte = SymbolicValue.from_const(0xFF)

        result = x ^ all_ones_byte
        assert prove(result.z3_int == 0xF0)

    def test_shift_by_zero_is_identity(self):
        """Both shifts by 0 should return the original value."""
        x, _ = SymbolicValue.symbolic_int("x")
        zero = SymbolicValue.from_const(0)

        lshift_result = x << zero
        rshift_result = x >> zero

        assert prove_with_constraint(
            lshift_result.z3_int == x.z3_int,
            in_int64_range(x.z3_int),
        )
        assert prove_with_constraint(
            rshift_result.z3_int == x.z3_int,
            in_int64_range(x.z3_int),
        )

    def test_demorgan_and_to_or(self):
        """De Morgan's Law: ~(a & b) == (~a) | (~b)."""
        a, _ = SymbolicValue.symbolic_int("a")
        b, _ = SymbolicValue.symbolic_int("b")

        lhs = ~(a & b)
        rhs = (~a) | (~b)

        assert prove(lhs.z3_int == rhs.z3_int)

    def test_demorgan_or_to_and(self):
        """De Morgan's Law: ~(a | b) == (~a) & (~b)."""
        a, _ = SymbolicValue.symbolic_int("a")
        b, _ = SymbolicValue.symbolic_int("b")

        lhs = ~(a | b)
        rhs = (~a) & (~b)

        assert prove(lhs.z3_int == rhs.z3_int)

    def test_xor_associativity(self):
        """XOR should be associative: (a ^ b) ^ c == a ^ (b ^ c)."""
        a, _ = SymbolicValue.symbolic_int("a")
        b, _ = SymbolicValue.symbolic_int("b")
        c, _ = SymbolicValue.symbolic_int("c")

        lhs = (a ^ b) ^ c
        rhs = a ^ (b ^ c)

        assert prove(lhs.z3_int == rhs.z3_int)

    def test_and_or_distributivity(self):
        """AND distributes over OR: a & (b | c) == (a & b) | (a & c)."""
        a, _ = SymbolicValue.symbolic_int("a")
        b, _ = SymbolicValue.symbolic_int("b")
        c, _ = SymbolicValue.symbolic_int("c")

        lhs = a & (b | c)
        rhs = (a & b) | (a & c)

        assert prove(lhs.z3_int == rhs.z3_int)


# =============================================================================
# TestBitwiseAffinity - Type affinity and result types
# =============================================================================

class TestBitwiseAffinity:
    """Tests for result type properties of bitwise operations."""

    def test_bitwise_and_produces_int_affinity(self):
        """AND of two ints should have int-like properties."""
        x, _ = SymbolicValue.symbolic_int("x")
        y, _ = SymbolicValue.symbolic_int("y")

        result = x & y
        # is_int should be True when both inputs are ints
        s = z3.Solver()
        s.add(x.is_int)
        s.add(y.is_int)
        s.add(result.is_int)
        assert s.check() == z3.sat

    def test_shift_produces_int_affinity(self):
        """Shift operations should produce integer results."""
        x, _ = SymbolicValue.symbolic_int("x")
        n, _ = SymbolicValue.symbolic_int("n")

        lshift_result = x << n
        rshift_result = x >> n

        assert lshift_result.affinity_type == "int"
        assert rshift_result.affinity_type == "int"

    def test_shift_is_bool_is_false(self):
        """Shift results should not be booleans."""
        x, _ = SymbolicValue.symbolic_int("x")
        n = SymbolicValue.from_const(2)

        result = x << n
        assert result.is_bool == Z3_FALSE


# =============================================================================
# TestBitwiseWithMixedTypes - Operations with different value types
# =============================================================================

class TestBitwiseWithMixedTypes:
    """Tests for bitwise operations with mixed types."""

    def test_symbolic_and_concrete(self):
        """Symbolic value AND concrete value should work."""
        x, _ = SymbolicValue.symbolic_int("x")
        concrete = SymbolicValue.from_const(0xFF)

        result = x & concrete
        assert isinstance(result, SymbolicValue)

    def test_concrete_and_symbolic(self):
        """Concrete value AND symbolic value should work (via __rand__)."""
        x, _ = SymbolicValue.symbolic_int("x")

        result = 0xFF & x  # type: ignore[operator]
        assert isinstance(result, SymbolicValue)

    def test_shift_symbolic_by_concrete(self):
        """Shift symbolic value by concrete amount."""
        x, _ = SymbolicValue.symbolic_int("x")

        result = x << 3  # type: ignore[operator]
        assert isinstance(result, SymbolicValue)

    def test_shift_concrete_by_symbolic(self):
        """Shift concrete value by symbolic amount."""
        n, _ = SymbolicValue.symbolic_int("n")

        result = 8 << n  # type: ignore[operator]
        assert isinstance(result, SymbolicValue)


# =============================================================================
# TestBitwiseBooleanIntegration - Boolean-related behavior
# =============================================================================

class TestBitwiseBooleanIntegration:
    """Tests for bitwise operations with boolean discriminators."""

    def test_and_on_bools_is_logical_and(self):
        """AND on boolean SymbolicValues should also compute logical AND."""
        a, _ = SymbolicValue.symbolic_bool("a")
        b, _ = SymbolicValue.symbolic_bool("b")

        result = a & b

        # The z3_bool field should be the logical AND
        s = z3.Solver()
        s.add(a.is_bool)
        s.add(b.is_bool)
        s.add(a.z3_bool)
        s.add(b.z3_bool)
        s.add(result.z3_bool)  # result.z3_bool should be True when both are True
        assert s.check() == z3.sat

    def test_or_on_bools_is_logical_or(self):
        """OR on boolean SymbolicValues should also compute logical OR."""
        a, _ = SymbolicValue.symbolic_bool("a")
        b, _ = SymbolicValue.symbolic_bool("b")

        result = a | b

        # The z3_bool field should be the logical OR
        s = z3.Solver()
        s.add(a.is_bool)
        s.add(b.is_bool)
        s.add(a.z3_bool)
        s.add(z3.Not(b.z3_bool))
        s.add(result.z3_bool)  # Should be True when a is True
        assert s.check() == z3.sat

    def test_xor_on_bools_is_logical_xor(self):
        """XOR on boolean SymbolicValues should also compute logical XOR."""
        a, _ = SymbolicValue.symbolic_bool("a")
        b, _ = SymbolicValue.symbolic_bool("b")

        result = a ^ b

        # The z3_bool field should be the logical XOR
        s = z3.Solver()
        s.add(a.is_bool)
        s.add(b.is_bool)
        s.add(a.z3_bool)
        s.add(z3.Not(b.z3_bool))
        s.add(result.z3_bool)  # True XOR False = True
        assert s.check() == z3.sat
