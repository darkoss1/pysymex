"""Tests for pysymex/analysis/detectors/specialized/integer_overflow.py."""

from __future__ import annotations

import dis
import z3

from pysymex.analysis.detectors.specialized.integer_overflow import (
    IntegerOverflowDetector,
    pure_check_bounded_overflow,
)
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicValue


def _always_sat(constraints: list[z3.BoolRef]) -> bool:
    """Always return True for satisfiability checks."""
    _ = constraints
    return True


def _never_sat(constraints: list[z3.BoolRef]) -> bool:
    """Always return False for satisfiability checks."""
    _ = constraints
    return False


def _make_instruction(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    """Create deterministic bytecode instructions for detector tests."""

    def _dummy() -> None:
        """Provide a stable instruction template."""
        return None

    template = next(dis.get_instructions(_dummy))
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


def test_pure_check_rejects_non_numeric_left_operand() -> None:
    """Return None when left operand is not int-like or symbolic."""
    issue = pure_check_bounded_overflow("x", 5, "+", [], 1, 64, 0, 10, _always_sat)
    assert issue is None


def test_pure_check_rejects_non_numeric_right_operand() -> None:
    """Return None when right operand is not int-like or symbolic."""
    issue = pure_check_bounded_overflow(5, "y", "+", [], 1, 64, 0, 10, _always_sat)
    assert issue is None


def test_pure_check_rejects_unrelated_op() -> None:
    """Return None for binary operators not known to cause bounded integer overflow."""
    issue = pure_check_bounded_overflow(5, 5, "/", [], 1, 64, 0, 10, _always_sat)
    assert issue is None


def test_pure_check_reports_lshift_overflow() -> None:
    """Report overflow when left shift distance exceeds 63 bits."""
    # Symbolic right side to bypass constant checks, using is_satisfiable_fn to trigger
    issue = pure_check_bounded_overflow(
        1, SymbolicValue.from_const(70), "<<", [], 1, 64, 0, 10, _always_sat
    )
    assert issue is not None


def test_pure_check_ignores_safe_lshift() -> None:
    """Return None when left shift distance is mathematically bounded <= 63."""
    issue = pure_check_bounded_overflow(
        1, SymbolicValue.from_const(50), "<<", [], 1, 64, 0, 10, _never_sat
    )
    assert issue is None


def test_pure_check_reports_pow_overflow() -> None:
    """Report overflow when exponentiation base > 2 and exponent > 62."""
    issue = pure_check_bounded_overflow(
        SymbolicValue.from_const(5),
        SymbolicValue.from_const(70),
        "**",
        [],
        1,
        64,
        0,
        10,
        _always_sat,
    )
    assert issue is not None


def test_pure_check_ignores_safe_pow() -> None:
    """Return None when exponentiation inputs are mathematically constrained within safe bounds."""
    issue = pure_check_bounded_overflow(
        SymbolicValue.from_const(2),
        SymbolicValue.from_const(10),
        "**",
        [],
        1,
        64,
        0,
        10,
        _never_sat,
    )
    assert issue is None


def test_pure_check_reports_add_overflow() -> None:
    """Report overflow when addition exceeds max bounds."""
    issue = pure_check_bounded_overflow(
        SymbolicValue.from_const(100),
        SymbolicValue.from_const(100),
        "+",
        [],
        1,
        64,
        0,
        150,
        _always_sat,
    )
    assert issue is not None


def test_pure_check_ignores_safe_add() -> None:
    """Return None when addition results cannot exceed bounds."""
    issue = pure_check_bounded_overflow(
        SymbolicValue.from_const(10),
        SymbolicValue.from_const(10),
        "+",
        [],
        1,
        64,
        0,
        150,
        _never_sat,
    )
    assert issue is None


def test_pure_check_reports_sub_overflow() -> None:
    """Report overflow when subtraction drops below min bounds."""
    issue = pure_check_bounded_overflow(
        SymbolicValue.from_const(10),
        SymbolicValue.from_const(100),
        "-",
        [],
        1,
        64,
        0,
        150,
        _always_sat,
    )
    assert issue is not None


def test_pure_check_reports_mul_overflow() -> None:
    """Report overflow when multiplication exceeds max bounds."""
    issue = pure_check_bounded_overflow(
        SymbolicValue.from_const(10),
        SymbolicValue.from_const(20),
        "*",
        [],
        1,
        64,
        0,
        150,
        _always_sat,
    )
    assert issue is not None


class TestIntegerOverflowDetector:
    """Test suite for specialized bounded overflow detector behavior."""

    def test_initialization_sets_32bit_bounds(self) -> None:
        """Initialize min/max tracking correctly for 32 bits."""
        detector = IntegerOverflowDetector(bits=32)
        assert detector.min_val == -(2**31)
        assert detector.max_val == 2**31 - 1

    def test_initialization_sets_64bit_bounds(self) -> None:
        """Initialize min/max tracking correctly for 64 bits."""
        detector = IntegerOverflowDetector(bits=64)
        assert detector.min_val == -(2**63)
        assert detector.max_val == 2**63 - 1

    def test_check_delegates_to_runtime_overflow(self) -> None:
        """Delegate generic BINARY_OP bounded checks to the inherited runtime implementation."""
        detector = IntegerOverflowDetector(bits=32)
        instruction = _make_instruction("BINARY_OP", argrepr="+")
        state = VMState(stack=[2**31 - 1, 1], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _always_sat)
        assert issue is not None
        assert issue.kind.name == "OVERFLOW"
