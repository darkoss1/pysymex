from __future__ import annotations

import dis
from typing import cast

import z3

from pysymex.core.state.record import VMState
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.truthiness import get_truthy_expr
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.common.control.match import (
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
    assert z3.is_true(z3.simplify(get_truthy_expr(mapping_predicate)))
    assert z3.is_true(z3.simplify(get_truthy_expr(sequence_predicate)))
