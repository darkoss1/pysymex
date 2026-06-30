from __future__ import annotations

import dis

import pytest
import z3

import pysymex._internal.execution.opcodes.common.compare.ops as common_compare
from pysymex._internal.core.classes.classes import SymbolicClass
from pysymex._internal.core.classes.registry import class_registry
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.state.types import VMStateError
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.dict_views import SymbolicDictView
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.fallback.types import FallbackKind, RiskLevel, SoundnessTag
from pysymex._internal.execution.opcodes.common.compare.identity import handle_common_is_op
from pysymex._internal.execution.opcodes.common.compare.membership import handle_common_contains_op
from pysymex._internal.execution.opcodes.common.compare.ops import handle_common_compare_op
from pysymex._internal.execution.opcodes.common.control.protocol.fallbacks import (
    COMPARISON_CALL_UNAVAILABLE_REASON,
    MEMBERSHIP_CALL_UNAVAILABLE_REASON,
    UNSUPPORTED_COMPARISON_PROTOCOL,
    UNSUPPORTED_MEMBERSHIP_PROTOCOL,
)
from pysymex._internal.execution.opcodes.common.lowering.comparison import ComparisonLowerer


def _instr(opname: str, argval: object = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)


def _symbolic_instance_value(name: str, modeled_cls: SymbolicClass) -> SymbolicValue:
    instance = class_registry.instantiate(modeled_cls)
    instance_value = SymbolicValue(
        _name=f"{name}instance",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
        is_path=z3.BoolVal(False),
        affinity_type=name,
    )
    instance_value.attach_modeled_object(instance)
    return instance_value


def test_handle_common_compare_op_rejects_missing_operands() -> None:
    state = VMState(stack=[1], pc=30)

    with pytest.raises(VMStateError, match="COMPARE_OP operands"):
        handle_common_compare_op(_instr("COMPARE_OP", "<"), state, OpcodeDispatcher())


def test_handle_common_compare_op_lowers_symbolic_types_without_state_fork_explosion() -> None:
    left, left_constraint = SymbolicValue.symbolic("left")
    right, right_constraint = SymbolicValue.symbolic("right")
    state = VMState(stack=[left, right], pc=31)
    state = state.add_constraint(left_constraint)
    state = state.add_constraint(right_constraint)

    # Constrain types to be numeric to avoid TypeError fork
    state = state.add_constraint(left.is_int)
    state = state.add_constraint(right.is_int)

    result = handle_common_compare_op(_instr("COMPARE_OP", "<"), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    assert result.terminal is False
    assert len(result.new_states) == 1
    assert len(next_state.stack) == 1
    assert isinstance(next_state.stack[0], SymbolicValue)
    assert next_state.stack[0].affinity_type == "bool"


def test_handle_common_compare_op_fast_path_symbolic_int_matches_python_ordering() -> None:
    left, left_constraint = SymbolicValue.symbolic_int("left_fast_compare")
    right, right_constraint = SymbolicValue.symbolic_int("right_fast_compare")
    state = VMState(stack=[left, right], pc=35)
    state = state.add_constraint(left_constraint)
    state = state.add_constraint(right_constraint)
    state = state.add_constraint(left.z3_int == 1)
    state = state.add_constraint(right.z3_int == 2)

    result = handle_common_compare_op(_instr("COMPARE_OP", "<"), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    compared = next_state.stack[0]
    assert isinstance(compared, SymbolicValue)
    assert compared.affinity_type == "bool"
    solver = z3.Solver()
    solver.add(next_state.path_constraints.to_list())
    solver.add(z3.Not(compared.z3_bool))
    assert solver.check() == z3.unsat


def test_compare_lowerer_preserves_symbolic_bytes_equality() -> None:
    """Bytes comparisons must keep Z3 sequence structure instead of opaque objects."""
    left = SymbolicBytes.symbolic("payload")
    right = SymbolicBytes.concrete(b"abc")

    compared, type_error = ComparisonLowerer(42).lower(left, b"abc", "==")

    assert z3.is_false(simplify_expr(type_error))
    solver = z3.Solver()
    solver.add(compared.z3_bool != (left.z3_bytes == right.z3_bytes))
    assert solver.check() == z3.unsat


def test_compare_lowerer_fast_paths_definite_int_without_affinity() -> None:
    length_like = SymbolicValue(
        _name="len_subject",
        z3_int=z3.IntVal(3),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
    )

    compared, type_error = ComparisonLowerer(41).lower(
        length_like,
        SymbolicValue.from_const(1),
        ">=",
    )

    assert z3.is_false(simplify_expr(type_error))
    assert z3.is_true(simplify_expr(compared.z3_bool))
    formula = str(compared.z3_bool)
    assert "fpToFP" not in formula
    assert "str.<=" not in formula


def test_handle_common_compare_op_skips_feasibility_for_literal_non_type_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    left = SymbolicValue.from_const(1)
    right = SymbolicValue.from_const(2)
    state = VMState(stack=[left, right], pc=39)

    def fail_path_check_result(*args: object, **kwargs: object) -> object:
        _ = args
        _ = kwargs
        pytest.fail("literal false TypeError conditions must not call feasibility checks")

    monkeypatch.setattr(common_compare, "_path_satisfiability_result", fail_path_check_result)

    result = handle_common_compare_op(_instr("COMPARE_OP", "<"), state, OpcodeDispatcher())

    compared = result.new_states[0].stack[0]
    assert isinstance(compared, SymbolicValue)
    solver = z3.Solver()
    solver.add(z3.Not(compared.z3_bool))
    assert solver.check() == z3.unsat


def test_handle_common_compare_op_decodes_numeric_compare_arg() -> None:
    left = SymbolicValue.from_const(4)
    right = SymbolicValue.from_const(2)
    state = VMState(stack=[left, right], pc=36)

    result = handle_common_compare_op(_instr("COMPARE_OP", 4), state, OpcodeDispatcher())

    compared = result.new_states[0].stack[0]
    assert isinstance(compared, SymbolicValue)
    solver = z3.Solver()
    solver.add(z3.Not(compared.z3_bool))
    assert solver.check() == z3.unsat


def test_handle_common_compare_op_drops_uncaught_type_error_branch() -> None:
    left, left_constraint = SymbolicValue.symbolic("left")
    right, right_constraint = SymbolicValue.symbolic("right")
    state = VMState(stack=[left, right], pc=31)
    state = state.add_constraint(left_constraint)
    state = state.add_constraint(right_constraint)

    result = handle_common_compare_op(_instr("COMPARE_OP", "<"), state, OpcodeDispatcher())

    assert result.terminal is False
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 32
    assert len(result.new_states[0].stack) == 1


def test_handle_common_compare_op_normalizes_non_arithmetic_numeric_payloads() -> None:
    left = SymbolicValue.from_const(1)
    object.__setattr__(left, "z3_int", z3.FPVal(1.0, z3.Float64()))
    right = SymbolicValue.from_const(2.0)
    state = VMState(stack=[left, right], pc=34)

    result = handle_common_compare_op(_instr("COMPARE_OP", "<"), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    assert result.terminal is False
    assert isinstance(next_state.stack[0], SymbolicValue)


def test_handle_common_compare_op_symbolic_float_equality_does_not_cast_z3_bool() -> None:
    left, constraint = SymbolicValue.symbolic_float("left_float_compare")
    right = SymbolicValue.from_const(0.0)
    state = VMState(stack=[left, right], pc=38).add_constraint(constraint)

    result = handle_common_compare_op(_instr("COMPARE_OP", "=="), state, OpcodeDispatcher())

    assert result.terminal is False
    compared = result.new_states[0].stack[0]
    assert isinstance(compared, SymbolicValue)
    assert compared.affinity_type == "bool"


def test_handle_common_compare_op_records_unexecutable_modeled_protocol_event() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_UnsupportedCompare"))
    modeled_cls.add_method("__lt__")
    left = _symbolic_instance_value("_UnsupportedCompare", modeled_cls)
    right = SymbolicValue.from_const(2)
    state = VMState(stack=[left, right], pc=37)

    result = handle_common_compare_op(_instr("COMPARE_OP", "<"), state, OpcodeDispatcher())

    assert result.terminal is True
    assert result.new_states == []
    assert result.degraded_passes == [UNSUPPORTED_COMPARISON_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_COMPARISON_PROTOCOL
    assert event.owner == "execution.opcodes.compare"
    assert event.reason == COMPARISON_CALL_UNAVAILABLE_REASON
    assert event.pc == 37
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_is_op_rejects_missing_operands() -> None:
    state = VMState(stack=[SymbolicValue.from_const(1)], pc=32)

    with pytest.raises(VMStateError, match="IS_OP operands"):
        handle_common_is_op(_instr("IS_OP", 0), state, OpcodeDispatcher())


def test_handle_common_is_op_result_is_bool_affinity_for_branch_truth() -> None:
    state = VMState(
        stack=[SymbolicValue.from_const(True), SymbolicValue.from_const(True)],
        pc=32,
    )

    result = handle_common_is_op(_instr("IS_OP", 0), state, OpcodeDispatcher())

    compared = result.new_states[0].stack[0]
    assert isinstance(compared, SymbolicValue)
    assert compared.affinity_type == "bool"
    assert z3.is_true(simplify_expr(compared.z3_bool))


def test_handle_common_is_op_distinguishes_int_one_from_true_singleton() -> None:
    state = VMState(
        stack=[SymbolicValue.from_const(1), SymbolicValue.from_const(True)],
        pc=32,
    )

    result = handle_common_is_op(_instr("IS_OP", 0), state, OpcodeDispatcher())

    compared = result.new_states[0].stack[0]
    assert isinstance(compared, SymbolicValue)
    assert compared.affinity_type == "bool"
    assert z3.is_false(simplify_expr(compared.z3_bool))


def test_handle_common_contains_op_rejects_missing_operands() -> None:
    state = VMState(stack=[SymbolicString.from_const("needle")], pc=33)

    with pytest.raises(VMStateError, match="CONTAINS_OP operands"):
        handle_common_contains_op(_instr("CONTAINS_OP", 0), state, OpcodeDispatcher())


def test_handle_common_contains_op_resolves_symbolic_object_dict_membership() -> None:
    mapping, mapping_constraint = SymbolicDict.symbolic("mapping")
    key, key_constraint = SymbolicString.symbolic("key")
    obj = SymbolicObject("mapping", 201, z3.IntVal(201), {201})
    state = VMState(stack=[key, obj], memory={201: mapping}, pc=34)
    state = state.add_constraint(mapping_constraint)
    state = state.add_constraint(key_constraint)

    result = handle_common_contains_op(_instr("CONTAINS_OP", 0), state, OpcodeDispatcher())

    membership = result.new_states[0].stack[0]
    assert isinstance(membership, SymbolicValue)
    solver = z3.Solver()
    solver.add(result.new_states[0].path_constraints.to_list())
    solver.add(membership.z3_bool != mapping.contains_key(key).z3_bool)
    assert solver.check() == z3.unsat


def test_handle_common_contains_op_constrains_concrete_symbolic_list_membership() -> None:
    item, item_constraint = SymbolicValue.symbolic_int("item")
    values = SymbolicList.from_const([1, 2, 3])
    state = VMState(stack=[item, values], pc=35).add_constraint(item_constraint)

    result = handle_common_contains_op(_instr("CONTAINS_OP", 0), state, OpcodeDispatcher())

    membership = result.new_states[0].stack[0]
    assert isinstance(membership, SymbolicValue)
    solver = z3.Solver()
    solver.add(result.new_states[0].path_constraints.to_list())
    solver.add(membership.z3_bool)
    solver.add(z3.And(item.z3_int != 1, item.z3_int != 2, item.z3_int != 3))
    assert solver.check() == z3.unsat


def test_handle_common_contains_op_constrains_concrete_symbolic_set_membership() -> None:
    item, item_constraint = SymbolicValue.symbolic_int("item")
    values = SymbolicValue.from_const({1, 2, 3})
    state = VMState(stack=[item, values], pc=36).add_constraint(item_constraint)

    result = handle_common_contains_op(_instr("CONTAINS_OP", 0), state, OpcodeDispatcher())

    membership = result.new_states[0].stack[0]
    assert isinstance(membership, SymbolicValue)
    solver = z3.Solver()
    solver.add(result.new_states[0].path_constraints.to_list())
    solver.add(membership.z3_bool)
    solver.add(z3.And(item.z3_int != 1, item.z3_int != 2, item.z3_int != 3))
    assert solver.check() == z3.unsat


def test_handle_common_contains_op_constrains_symbolic_dict_values_view_membership() -> None:
    item, item_constraint = SymbolicValue.symbolic_int("dict_value")
    source = SymbolicDict.from_const({"den": item, "sentinel": 5})
    values = SymbolicDictView("dict_values", source, "values")
    state = VMState(stack=[SymbolicValue.from_const(0), values], pc=39).add_constraint(
        item_constraint
    )

    result = handle_common_contains_op(_instr("CONTAINS_OP", 0), state, OpcodeDispatcher())

    membership = result.new_states[0].stack[0]
    assert isinstance(membership, SymbolicValue)
    solver = z3.Solver()
    solver.add(result.new_states[0].path_constraints.to_list())
    solver.add(membership.z3_bool)
    solver.add(item.z3_int != 0)
    assert solver.check() == z3.unsat


@pytest.mark.parametrize("values", [(1, 2, 3), frozenset({1, 2, 3}), range(1, 4)])
def test_handle_common_contains_op_constrains_retained_exact_iterable_membership(
    values: tuple[int, ...] | frozenset[int] | range,
) -> None:
    item, item_constraint = SymbolicValue.symbolic_int("retained_item")
    retained = SymbolicValue.from_const(values)
    state = VMState(stack=[item, retained], pc=37).add_constraint(item_constraint)

    result = handle_common_contains_op(_instr("CONTAINS_OP", 0), state, OpcodeDispatcher())

    membership = result.new_states[0].stack[0]
    assert isinstance(membership, SymbolicValue)
    solver = z3.Solver()
    solver.add(result.new_states[0].path_constraints.to_list())
    solver.add(membership.z3_bool)
    solver.add(z3.And(item.z3_int != 1, item.z3_int != 2, item.z3_int != 3))
    assert solver.check() == z3.unsat


def test_handle_common_contains_op_keeps_bool_and_int_projection_consistent() -> None:
    true_state = VMState(
        stack=[SymbolicValue.from_const(b"a"), SymbolicValue.from_const(b"abc")],
        pc=37,
    )
    false_state = VMState(
        stack=[SymbolicValue.from_const(b"z"), SymbolicValue.from_const(b"abc")],
        pc=38,
    )

    true_result = handle_common_contains_op(
        _instr("CONTAINS_OP", 0), true_state, OpcodeDispatcher()
    )
    false_result = handle_common_contains_op(
        _instr("CONTAINS_OP", 0), false_state, OpcodeDispatcher()
    )

    true_membership = true_result.new_states[0].stack[0]
    false_membership = false_result.new_states[0].stack[0]
    assert isinstance(true_membership, SymbolicValue)
    assert isinstance(false_membership, SymbolicValue)
    assert z3.is_true(simplify_expr(true_membership.z3_bool))
    assert z3.is_true(simplify_expr(true_membership.z3_int == 1))
    assert z3.is_false(simplify_expr(false_membership.z3_bool))
    assert z3.is_true(simplify_expr(false_membership.z3_int == 0))


def test_handle_common_contains_op_records_unexecutable_modeled_protocol_event() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_UnsupportedContains"))
    modeled_cls.add_method("__contains__")
    haystack = _symbolic_instance_value("_UnsupportedContains", modeled_cls)
    needle = SymbolicValue.from_const(1)
    state = VMState(stack=[needle, haystack], pc=38)

    result = handle_common_contains_op(_instr("CONTAINS_OP", 0), state, OpcodeDispatcher())

    assert result.terminal is True
    assert result.new_states == []
    assert result.degraded_passes == [UNSUPPORTED_MEMBERSHIP_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_MEMBERSHIP_PROTOCOL
    assert event.owner == "execution.opcodes.compare.membership"
    assert event.reason == MEMBERSHIP_CALL_UNAVAILABLE_REASON
    assert event.pc == 38
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH
