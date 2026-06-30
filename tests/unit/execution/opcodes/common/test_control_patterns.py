from __future__ import annotations

import dis
from typing import cast

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.truthiness import get_truthy_expr
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.opcodes.common.control.match.handlers import (
    handle_common_match_keys,
    handle_common_match_mapping,
    handle_common_match_sequence,
)


def _instr(opname: str, argval: object = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)


def test_handle_common_match_keys_retains_concrete_symbolic_dict_values() -> None:
    subject = SymbolicDict.from_const({"rate": SymbolicValue.from_const(0)})
    state = VMState(stack=[subject, ("rate",)], pc=4)

    result = handle_common_match_keys(_instr("MATCH_KEYS"), state, OpcodeDispatcher())

    values = result.new_states[0].stack[-1]
    assert isinstance(values, tuple)
    captured = cast("tuple[object, ...]", values)[0]
    assert isinstance(captured, SymbolicValue)
    assert captured.value == 0


def test_handle_common_match_predicates_are_truthy_bool_carriers() -> None:
    mapping_state = VMState(stack=[{"rate": 0}], pc=5)
    sequence_state = VMState(stack=[("fallback", 0)], pc=6)

    mapping_result = handle_common_match_mapping(
        _instr("MATCH_MAPPING"), mapping_state, OpcodeDispatcher()
    )
    sequence_result = handle_common_match_sequence(
        _instr("MATCH_SEQUENCE"), sequence_state, OpcodeDispatcher()
    )

    mapping_predicate = mapping_result.new_states[0].peek()
    sequence_predicate = sequence_result.new_states[0].peek()
    assert isinstance(mapping_predicate, SymbolicValue)
    assert isinstance(sequence_predicate, SymbolicValue)
    assert mapping_predicate.affinity_type == "bool"
    assert sequence_predicate.affinity_type == "bool"
    assert z3.is_true(simplify_expr(get_truthy_expr(mapping_predicate)))
    assert z3.is_true(simplify_expr(get_truthy_expr(sequence_predicate)))


def test_handle_common_match_sequence_accepts_symbolic_tuple_payload() -> None:
    """Concrete tuple payloads retained in scalar carriers still match sequence patterns."""
    state = VMState(stack=[SymbolicValue.from_const((1, 2))], pc=6)

    result = handle_common_match_sequence(_instr("MATCH_SEQUENCE"), state, OpcodeDispatcher())

    predicate = result.new_states[0].peek()
    assert isinstance(predicate, SymbolicValue)
    assert z3.is_true(simplify_expr(get_truthy_expr(predicate)))
