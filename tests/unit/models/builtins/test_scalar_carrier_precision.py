from __future__ import annotations

from collections.abc import Callable

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.conversions.scalar import IntModel, StrModel
from pysymex._internal.models.builtins.numeric.format import (
    BinModel,
    DivmodModel,
    HexModel,
    OctModel,
)
from pysymex._internal.models.builtins.text.codepoints import ChrModel, RoundModel
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects


def _state() -> VMState:
    return VMState(pc=0)


def test_chr_decodes_integer_symbolic_value_literal() -> None:
    result = ChrModel().apply([SymbolicValue.from_const(65)], {}, _state())
    invalid = ChrModel().apply([SymbolicValue.from_const(1.5)], {}, _state())
    effect = invalid.side_effects.get("raised_exception")

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == chr(65)
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize(
    ("model", "formatter"),
    [
        (BinModel(), bin),
        (OctModel(), oct),
        (HexModel(), hex),
    ],
)
def test_integer_formatters_decode_integer_symbolic_value_literal(
    model: FunctionModel, formatter: Callable[[int], str]
) -> None:
    result = model.apply([SymbolicValue.from_const(65)], {}, _state())
    invalid = model.apply([SymbolicValue.from_const(1.5)], {}, _state())
    effect = invalid.side_effects.get("raised_exception")

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == formatter(65)
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_divmod_decodes_numeric_symbolic_values_and_reports_zero_divisor() -> None:
    valid = DivmodModel().apply(
        [SymbolicValue.from_const(17), SymbolicValue.from_const(5)], {}, _state()
    )
    invalid = DivmodModel().apply(
        [SymbolicValue.from_const(5), SymbolicValue.from_const(0)], {}, _state()
    )
    effect = invalid.side_effects.get("raised_exception")

    assert "raised_exception" not in valid.side_effects
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "ZeroDivisionError"


def test_round_decodes_numeric_symbolic_values_and_rejects_invalid_payloads() -> None:
    valid = RoundModel().apply(
        [SymbolicValue.from_const(1.25), SymbolicValue.from_const(1)], {}, _state()
    )
    invalid_number = RoundModel().apply([SymbolicValue.from_const("value")], {}, _state())
    invalid_digits = RoundModel().apply(
        [SymbolicValue.from_const(1.25), SymbolicValue.from_const(1.0)], {}, _state()
    )

    assert valid.value == round(1.25, 1)
    for result in (invalid_number, invalid_digits):
        effect = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"


def test_str_decodes_literal_symbolic_codec_names_without_false_type_error() -> None:
    result = StrModel().apply(
        [b"value", SymbolicString.from_const("utf-8"), SymbolicString.from_const("strict")],
        {},
        _state(),
    )

    assert result.value == "value"
    assert "raised_exception" not in result.side_effects


def test_int_decodes_literal_base_carrier_and_rejects_explicit_none_base() -> None:
    valid = IntModel().apply(
        [SymbolicString.from_const("10"), SymbolicValue.from_const(10)], {}, _state()
    )
    invalid = IntModel().apply([SymbolicString.from_const("10")], {"base": None}, _state())

    assert valid.value == int("10", 10)
    effect = invalid.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
