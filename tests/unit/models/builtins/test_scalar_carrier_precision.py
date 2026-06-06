from __future__ import annotations

from collections.abc import Callable

import pytest

import pysymex.models.builtins as builtins_models
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, is_raised_exception_effect


def _state() -> VMState:
    return VMState(pc=0)


def test_chr_decodes_integer_symbolic_value_literal() -> None:
    result = builtins_models.ChrModel().apply([SymbolicValue.from_const(65)], {}, _state())
    invalid = builtins_models.ChrModel().apply([SymbolicValue.from_const(1.5)], {}, _state())
    effect = invalid.side_effects.get("raised_exception")

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == chr(65)
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize(
    ("model", "formatter"),
    [
        (builtins_models.BinModel(), bin),
        (builtins_models.OctModel(), oct),
        (builtins_models.HexModel(), hex),
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
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_divmod_decodes_numeric_symbolic_values_and_reports_zero_divisor() -> None:
    valid = builtins_models.DivmodModel().apply(
        [SymbolicValue.from_const(17), SymbolicValue.from_const(5)], {}, _state()
    )
    invalid = builtins_models.DivmodModel().apply(
        [SymbolicValue.from_const(5), SymbolicValue.from_const(0)], {}, _state()
    )
    effect = invalid.side_effects.get("raised_exception")

    assert "raised_exception" not in valid.side_effects
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "ZeroDivisionError"


def test_round_decodes_numeric_symbolic_values_and_rejects_invalid_payloads() -> None:
    valid = builtins_models.RoundModel().apply(
        [SymbolicValue.from_const(1.25), SymbolicValue.from_const(1)], {}, _state()
    )
    invalid_number = builtins_models.RoundModel().apply(
        [SymbolicValue.from_const("value")], {}, _state()
    )
    invalid_digits = builtins_models.RoundModel().apply(
        [SymbolicValue.from_const(1.25), SymbolicValue.from_const(1.0)], {}, _state()
    )

    assert valid.value == round(1.25, 1)
    for result in (invalid_number, invalid_digits):
        effect = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


def test_str_decodes_literal_symbolic_codec_names_without_false_type_error() -> None:
    result = builtins_models.StrModel().apply(
        [b"value", SymbolicString.from_const("utf-8"), SymbolicString.from_const("strict")],
        {},
        _state(),
    )

    assert result.value == "value"
    assert "raised_exception" not in result.side_effects


def test_int_decodes_literal_base_carrier_and_rejects_explicit_none_base() -> None:
    valid = builtins_models.IntModel().apply(
        [SymbolicString.from_const("10"), SymbolicValue.from_const(10)], {}, _state()
    )
    invalid = builtins_models.IntModel().apply(
        [SymbolicString.from_const("10")], {"base": None}, _state()
    )

    assert valid.value == int("10", 10)
    effect = invalid.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"
