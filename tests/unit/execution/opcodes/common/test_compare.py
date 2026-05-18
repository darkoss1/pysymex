from __future__ import annotations

import dis

import pytest
import z3

from pysymex.core.state import VMState, VMStateError
from pysymex.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicObject,
    SymbolicString,
    SymbolicValue,
)
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.common.compare import (
    handle_common_compare_op,
    handle_common_contains_op,
    handle_common_is_op,
)


def _instr(opname: str, argval: object = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)


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


def test_handle_common_is_op_rejects_missing_operands() -> None:
    state = VMState(stack=[SymbolicValue.from_const(1)], pc=32)

    with pytest.raises(VMStateError, match="IS_OP operands"):
        handle_common_is_op(_instr("IS_OP", 0), state, OpcodeDispatcher())


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
