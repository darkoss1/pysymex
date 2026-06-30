from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.reflection.identity import HashModel, IdModel, ReprModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


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


def test_id_reuses_symbolic_address_for_same_object() -> None:
    """Repeated id() calls on one carrier are constrained to the same identity."""
    value, value_constraint = SymbolicValue.symbolic("identity_value")
    first = IdModel().apply([value], {}, _state())
    second = IdModel().apply([value], {}, _state())

    assert isinstance(first.value, SymbolicValue)
    assert isinstance(second.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(value_constraint, *first.constraints, *second.constraints)
    solver.add(first.value.z3_int != second.value.z3_int)
    assert solver.check() == z3.unsat


def test_hash_nested_unhashable_tuple_is_modeled_type_error() -> None:
    """hash(([],)) must not escape through a host TypeError."""
    nested: list[object] = []
    nested_tuple = cast("StackValue", (nested,))
    result = HashModel().apply([nested_tuple], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
