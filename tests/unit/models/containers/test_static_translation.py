from __future__ import annotations

from pysymex.core.state.record import VMState
from pysymex.models.builtins.base import is_raised_exception_effect
from pysymex.models.containers.bytes.translation import BytesMaketransModel
from pysymex.models.containers.strings.encoding import StrMaketransModel
from pysymex.typing import StackValue


def _assert_type_error(model_result: object) -> None:
    side_effects = getattr(model_result, "side_effects")
    effect = side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_str_maketrans_accepts_supported_positional_forms() -> None:
    model = StrMaketransModel()
    state = VMState()
    valid_calls: list[list[StackValue]] = [["a"], ["a", "b"], ["a", "b", "c"]]

    for args in valid_calls:
        result = model.apply(args, {}, state)
        assert "raised_exception" not in result.side_effects


def test_str_maketrans_rejects_invalid_call_forms() -> None:
    model = StrMaketransModel()
    state = VMState()
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([], {}),
        (["a", "b", "c", "d"], {}),
        (["a"], {"y": "b"}),
    ]

    for args, kwargs in invalid_calls:
        _assert_type_error(model.apply(args, kwargs, state))


def test_bytes_maketrans_accepts_two_positional_arguments() -> None:
    result = BytesMaketransModel().apply([b"a", b"b"], {}, VMState())

    assert "raised_exception" not in result.side_effects


def test_bytes_maketrans_rejects_invalid_call_forms() -> None:
    model = BytesMaketransModel()
    state = VMState()
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([], {}),
        ([b"a"], {}),
        ([b"a", b"b", b"c"], {}),
        ([b"a", b"b"], {"frm": b"a"}),
    ]

    for args, kwargs in invalid_calls:
        _assert_type_error(model.apply(args, kwargs, state))
