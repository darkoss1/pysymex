from __future__ import annotations

import z3

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.common.collections.subscript import handle_common_binary_subscr
from tests.unit.execution.opcodes.common.collections_helpers import instr


def test_binary_subscr_simplifies_symbolic_concrete_list_index() -> None:
    """A constant arithmetic index expression should behave like the literal index."""
    index = SymbolicValue(
        _name="one_plus_one",
        z3_int=z3.IntVal(1) + z3.IntVal(1),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        affinity_type="int",
    )
    state = VMState(stack=[[11, 22, 33], index], pc=17)

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert not result.terminal
    assert len(result.new_states) == 1
    assert result.new_states[0].stack[-1] == 33
