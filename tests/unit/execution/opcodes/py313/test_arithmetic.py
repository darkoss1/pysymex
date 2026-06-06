from __future__ import annotations

import dis

import z3

from pysymex.analysis.detectors.detector.types import IssueKind
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.fallback import FallbackKind, RiskLevel, SoundnessTag
from pysymex.execution.opcodes.common.lowering import CollectionLowerer
from pysymex.execution.opcodes.common.numeric.helpers import (
    check_division_by_zero,
    check_negative_shift,
)
from pysymex.execution.opcodes.common.numeric.labels import (
    SYMBOLIC_POWER_ABSTRACTION,
    SYMBOLIC_SHIFT_ABSTRACTION,
    UNARY_POSITIVE_TYPE_UNCERTAIN,
    UNSUPPORTED_NUMERIC_ABSTRACTION,
)
from pysymex.execution.opcodes.py313 import arithmetic


def _instr(
    opname: str,
    argval: object = None,
    argrepr: str = "",
    offset: int = 0,
) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, argrepr=argrepr, offset=offset)


def test_check_division_by_zero() -> None:
    """Test check_division_by_zero behavior."""
    state = VMState(pc=7)
    left = SymbolicValue.from_const(10)
    right = SymbolicValue.from_const(0)
    has_zero = check_division_by_zero(right, state, "/", left)
    assert has_zero is True


def test_check_negative_shift() -> None:
    """Test check_negative_shift behavior."""
    state = VMState(pc=3)
    left = SymbolicValue.from_const(1)
    right = SymbolicValue.from_const(-1)
    has_negative_shift = check_negative_shift(right, state, "<<", left)
    assert has_negative_shift is True


def test_handle_unary_positive() -> None:
    """Test handle_unary_positive behavior."""
    state = VMState(stack=[5], pc=0)
    result = arithmetic.handle_unary_positive(_instr("UNARY_POSITIVE"), state, OpcodeDispatcher())
    assert result.terminal is False
    assert result.new_states[0].peek() == 5


def test_handle_unary_positive_reports_concrete_string_type_error() -> None:
    """Unary plus on str follows CPython's definite TypeError path."""
    state = VMState(stack=["text"], pc=0)
    result = arithmetic.handle_unary_positive(_instr("UNARY_POSITIVE"), state, OpcodeDispatcher())
    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]


def test_handle_unary_positive_uncertain_symbolic_affinity_records_fallback_event() -> None:
    value, _ = SymbolicValue.symbolic_int("operand")
    value.affinity_type = "unknown"
    state = VMState(stack=[value], pc=3)

    result = arithmetic.handle_unary_positive(_instr("UNARY_POSITIVE"), state, OpcodeDispatcher())

    assert result.terminal is False
    assert result.degraded_passes == [UNARY_POSITIVE_TYPE_UNCERTAIN]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.PRECISION_LOSS
    assert event.label == UNARY_POSITIVE_TYPE_UNCERTAIN
    assert event.owner == "execution.opcodes.numeric"
    assert event.reason == "symbolic unary + affinity is not provably numeric"
    assert event.pc == 3
    assert event.soundness is SoundnessTag.PRECISION_LOSS
    assert event.false_positive_risk is RiskLevel.LOW
    assert event.false_negative_risk is RiskLevel.MEDIUM


def test_handle_unary_negative() -> None:
    """Test handle_unary_negative behavior."""
    state = VMState(stack=[5], pc=0)
    result = arithmetic.handle_unary_negative(_instr("UNARY_NEGATIVE"), state, OpcodeDispatcher())
    assert result.new_states[0].peek() == -5


def test_handle_unary_not() -> None:
    """Test handle_unary_not behavior."""
    state = VMState(stack=[0], pc=0)
    result = arithmetic.handle_unary_not(_instr("UNARY_NOT"), state, OpcodeDispatcher())
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_unary_invert() -> None:
    """Test handle_unary_invert behavior."""
    state = VMState(stack=[3], pc=0)
    result = arithmetic.handle_unary_invert(_instr("UNARY_INVERT"), state, OpcodeDispatcher())
    assert result.new_states[0].peek() == ~3


def test_handle_binary_op() -> None:
    """Test handle_binary_op behavior."""
    state = VMState(stack=[5, 6], pc=0)
    result = arithmetic.handle_binary_op(
        _instr("BINARY_OP", argrepr="+"), state, OpcodeDispatcher()
    )
    assert result.terminal is False
    assert isinstance(result.new_states[0].peek(), SymbolicValue)


def test_handle_binary_op_list_add_preserves_heap_backed_items() -> None:
    """Heap-backed list concatenation should preserve retained symbolic items."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    lowerer = CollectionLowerer(pc=0)
    left = lowerer.build_list([value])
    right = lowerer.build_list([])
    state = VMState(stack=[left.handle, right.handle], pc=4)
    state = state.store_heap(left.handle.address, left.storage)
    state = state.store_heap(right.handle.address, right.storage)

    result = arithmetic.handle_binary_op(
        _instr("BINARY_OP", argrepr="+"), state, OpcodeDispatcher()
    )

    assert result.terminal is False
    combined = result.new_states[0].peek()
    assert isinstance(combined, SymbolicList)
    assert combined.concrete_items == [value]

    solver = z3.Solver()
    solver.add(value_constraint, combined[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_handle_binary_op_list_mul_one_preserves_heap_backed_items() -> None:
    """Heap-backed list repetition by one should preserve retained symbolic items."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    lowerer = CollectionLowerer(pc=0)
    source = lowerer.build_list([value])
    state = VMState(stack=[source.handle, 1], pc=4)
    state = state.store_heap(source.handle.address, source.storage)

    result = arithmetic.handle_binary_op(
        _instr("BINARY_OP", argrepr="*"), state, OpcodeDispatcher()
    )

    assert result.terminal is False
    repeated = result.new_states[0].peek()
    assert isinstance(repeated, SymbolicList)
    assert repeated.concrete_items == [value]

    solver = z3.Solver()
    solver.add(value_constraint, repeated[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_handle_binary_op_reflected_list_mul_one_preserves_heap_backed_items() -> None:
    """int * heap-backed list follows the reflected list repetition semantics."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    lowerer = CollectionLowerer(pc=0)
    source = lowerer.build_list([value])
    state = VMState(stack=[1, source.handle], pc=4)
    state = state.store_heap(source.handle.address, source.storage)

    result = arithmetic.handle_binary_op(
        _instr("BINARY_OP", argrepr="*"), state, OpcodeDispatcher()
    )

    assert result.terminal is False
    repeated = result.new_states[0].peek()
    assert isinstance(repeated, SymbolicList)
    assert repeated.concrete_items == [value]

    solver = z3.Solver()
    solver.add(value_constraint, repeated[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_symbolic_int_string_add_reports_type_error_without_degradation() -> None:
    value, constraint = SymbolicValue.symbolic_int("value")
    state = VMState(stack=[value, SymbolicString.from_const("bad")], pc=7).add_constraint(
        constraint
    )

    result = arithmetic.handle_binary_op(
        _instr("BINARY_OP", argrepr="+"), state, OpcodeDispatcher()
    )

    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert result.degraded_passes == []
    assert result.fallback_events == []


def test_unsupported_binary_op_consumes_operands_and_reports_abstraction() -> None:
    state = VMState(stack=[5, 6], pc=0)

    result = arithmetic.handle_binary_op(
        _instr("BINARY_OP", argrepr="@"), state, OpcodeDispatcher()
    )

    assert result.degraded_passes == [UNSUPPORTED_NUMERIC_ABSTRACTION]
    assert len(result.new_states[0].stack) == 1
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.PRECISION_LOSS
    assert event.label == UNSUPPORTED_NUMERIC_ABSTRACTION
    assert event.owner == "execution.opcodes.numeric"
    assert event.reason == "unsupported numeric operation 'binop_havoc_0' produced a havoc value"
    assert event.pc == 0
    assert event.soundness is SoundnessTag.PRECISION_LOSS
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_symbolic_power_abstraction_records_fallback_event() -> None:
    exponent, constraint = SymbolicValue.symbolic_int("exp")
    state = VMState(stack=[SymbolicValue.from_const(2), exponent], pc=5).add_constraint(constraint)

    result = arithmetic.handle_binary_op(
        _instr("BINARY_OP", argrepr="**"), state, OpcodeDispatcher()
    )

    assert result.degraded_passes == [SYMBOLIC_POWER_ABSTRACTION]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.PRECISION_LOSS
    assert event.label == SYMBOLIC_POWER_ABSTRACTION
    assert event.owner == "execution.opcodes.numeric"
    assert event.reason == "symbolic exponent range is too broad for exact power modeling"
    assert event.pc == 5


def test_symbolic_shift_abstraction_records_fallback_event() -> None:
    shift_count, constraint = SymbolicValue.symbolic_int("shift_count")
    state = VMState(stack=[SymbolicValue.from_const(2), shift_count], pc=6).add_constraint(
        constraint
    )

    result = arithmetic.handle_binary_op(
        _instr("BINARY_OP", argrepr="<<"), state, OpcodeDispatcher()
    )

    assert result.degraded_passes == [SYMBOLIC_SHIFT_ABSTRACTION]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.PRECISION_LOSS
    assert event.label == SYMBOLIC_SHIFT_ABSTRACTION
    assert event.owner == "execution.opcodes.numeric"
    assert event.reason == "symbolic shift count for '<<' is too broad for exact modeling"
    assert event.pc == 6


def test_handle_load_attr_reports_none_receiver() -> None:
    """LOAD_ATTR on None reports a feasible null dereference."""
    state = VMState(stack=[SymbolicNone()], pc=0)
    result = arithmetic.handle_load_attr(_instr("LOAD_ATTR", "x"), state, OpcodeDispatcher())
    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.NULL_DEREFERENCE]
