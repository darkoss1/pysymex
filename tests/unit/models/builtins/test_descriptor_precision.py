from __future__ import annotations

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.models.builtins import AsciiModel, VarsModel
from pysymex.models.builtins.base import is_raised_exception_effect


def _state() -> VMState:
    return VMState(pc=0)


def test_vars_rejects_literal_symbolic_string_without_dict() -> None:
    result = VarsModel().apply([SymbolicString.from_const("value")], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_ascii_decodes_literal_symbolic_string_value() -> None:
    result = AsciiModel().apply(
        [SymbolicString.from_const("\N{LATIN SMALL LETTER E WITH ACUTE}")], {}, _state()
    )

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == ascii("\N{LATIN SMALL LETTER E WITH ACUTE}")
