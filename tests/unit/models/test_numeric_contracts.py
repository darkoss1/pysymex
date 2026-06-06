from __future__ import annotations

import pytest

import pysymex.models.numeric as numeric

from pysymex.typing import StackValue
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, is_raised_exception_effect


def _state() -> VMState:
    return VMState(pc=0)


RECEIVER_ONLY_MODELS: list[tuple[FunctionModel, StackValue]] = [
    (numeric.IntBitLengthModel(), 1),
    (numeric.IntBitCountModel(), 1),
    (numeric.IntAsIntegerRatioModel(), 1),
    (numeric.IntConjugateModel(), 1),
    (numeric.FloatIsIntegerModel(), 1.0),
    (numeric.FloatAsIntegerRatioModel(), 1.0),
    (numeric.FloatHexModel(), 1.0),
    (numeric.FloatConjugateModel(), 1.0),
    (numeric.ComplexConjugateModel(), SymbolicValue.symbolic("complex_receiver")[0]),
]


@pytest.mark.parametrize(("model", "receiver"), RECEIVER_ONLY_MODELS)
def test_receiver_only_numeric_methods_enforce_contract(
    model: FunctionModel, receiver: StackValue
) -> None:
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([receiver, 1], {}),
        ([receiver], {"unexpected": 1}),
    ]
    for args, kwargs in invalid_calls:
        result = model.apply(args, kwargs, _state())
        effect = result.side_effects.get("raised_exception")

        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"

    assert "raised_exception" not in model.apply([receiver], {}, _state()).side_effects


def test_int_to_bytes_accepts_named_options_and_rejects_duplicates() -> None:
    model = numeric.IntToBytesModel()
    valid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([1], {}),
        ([1, 2, "big"], {}),
        ([1], {"length": 2, "byteorder": "big", "signed": True}),
    ]
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([], {}),
        ([1, 2, "big", True], {}),
        ([1, 2], {"length": 2}),
        ([1], {"unexpected": 1}),
    ]

    for args, kwargs in valid_calls:
        assert "raised_exception" not in model.apply(args, kwargs, _state()).side_effects
    for args, kwargs in invalid_calls:
        effect = model.apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


def test_int_from_bytes_accepts_classmethod_options_and_rejects_duplicates() -> None:
    model = numeric.IntFromBytesModel()
    valid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([b"a"], {}),
        ([b"a", "big"], {"signed": True}),
        ([], {"bytes": b"a", "byteorder": "big", "signed": False}),
    ]
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([], {}),
        ([b"a"], {"bytes": b"a"}),
        ([b"a", "big"], {"byteorder": "little"}),
        ([b"a"], {"unexpected": 1}),
    ]

    for args, kwargs in valid_calls:
        assert "raised_exception" not in model.apply(args, kwargs, _state()).side_effects
    for args, kwargs in invalid_calls:
        effect = model.apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


def test_float_fromhex_requires_one_positional_string() -> None:
    model = numeric.FloatFromhexModel()

    assert "raised_exception" not in model.apply(["0x1p0"], {}, _state()).side_effects
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([], {}),
        (["0x1p0", "extra"], {}),
        (["0x1p0"], {"string": "0x1p0"}),
    ]
    for args, kwargs in invalid_calls:
        effect = model.apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"
