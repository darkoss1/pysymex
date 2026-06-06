from __future__ import annotations

import z3

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FormatModel, OrdModel
from pysymex.models.builtins.base import is_raised_exception_effect


def _state() -> VMState:
    return VMState(pc=0)


def test_ord_decodes_literal_symbolic_string_and_reports_invalid_length() -> None:
    valid = OrdModel().apply([SymbolicString.from_const("A")], {}, _state())
    invalid = OrdModel().apply([SymbolicString.from_const("AB")], {}, _state())
    effect = invalid.side_effects.get("raised_exception")

    assert isinstance(valid.value, SymbolicValue)
    assert valid.value.value == ord("A")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_ord_preserves_symbolic_single_character_codepoint_relation() -> None:
    source, source_constraint = SymbolicString.symbolic("source")
    character = source.substring(0, 1)

    result = OrdModel().apply([character], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert z3.is_true(z3.simplify(result.value.is_int))
    assert z3.is_false(z3.simplify(result.value.is_bool))
    solver = z3.Solver()
    solver.add(*result.constraints, source_constraint)
    solver.add(result.value.z3_int != z3.StrToCode(character.z3_str))
    assert solver.check() == z3.unsat


def test_ord_uses_fresh_symbols_for_repeated_symbolic_characters() -> None:
    """Repeated symbolic ord() calls must not alias unrelated characters."""
    source, _source_constraint = SymbolicString.symbolic("source")
    first = source.substring(0, 1)
    second = source.substring(1, 1)

    first_result = OrdModel().apply([first], {}, _state())
    second_result = OrdModel().apply([second], {}, _state())

    assert isinstance(first_result.value, SymbolicValue)
    assert isinstance(second_result.value, SymbolicValue)
    assert not z3.eq(first_result.value.z3_int, second_result.value.z3_int)


def test_format_decodes_literal_symbolic_string_without_formatting_carrier() -> None:
    valid = FormatModel().apply([SymbolicString.from_const("a"), ">3"], {}, _state())
    unknown, _constraint = SymbolicString.symbolic("unknown")
    unresolved = FormatModel().apply([unknown, ">3"], {}, _state())

    assert isinstance(valid.value, SymbolicString)
    assert valid.value.z3_str.as_string() == format("a", ">3")
    assert "raised_exception" not in unresolved.side_effects
    assert isinstance(unresolved.value, SymbolicString)
    assert not z3.is_string_value(unresolved.value.z3_str)
