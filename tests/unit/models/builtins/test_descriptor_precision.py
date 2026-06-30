from __future__ import annotations

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.builtins.attributes.descriptors import AsciiModel, VarsModel
from pysymex._internal.models.contracts.results import SideEffects


def _state() -> VMState:
    return VMState(pc=0)


def test_vars_rejects_literal_symbolic_string_without_dict() -> None:
    result = VarsModel().apply([SymbolicString.from_const("value")], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_ascii_decodes_literal_symbolic_string_value() -> None:
    result = AsciiModel().apply(
        [SymbolicString.from_const("\N{LATIN SMALL LETTER E WITH ACUTE}")], {}, _state()
    )

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == ascii("\N{LATIN SMALL LETTER E WITH ACUTE}")
