from __future__ import annotations

import z3

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.models.builtins import ReprModel


def _state() -> VMState:
    return VMState(pc=0)


def test_repr_decodes_literal_symbolic_string_instead_of_carrier_repr() -> None:
    result = ReprModel().apply([SymbolicString.from_const("value")], {}, _state())

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == repr("value")


def test_repr_leaves_unknown_symbolic_string_unconstrained() -> None:
    unknown, _constraint = SymbolicString.symbolic("unknown")
    result = ReprModel().apply([unknown], {}, _state())

    assert isinstance(result.value, SymbolicString)
    assert not z3.is_string_value(result.value.z3_str)
