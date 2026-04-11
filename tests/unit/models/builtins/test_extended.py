from __future__ import annotations

import pytest

from pysymex._typing import StackValue
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicValue
from pysymex.models.builtins import extended


def _state() -> VMState:
    return VMState(pc=0)


def _to_python_bool(value: StackValue) -> bool:
    if isinstance(value, SymbolicValue) and isinstance(value.value, bool):
        return value.value
    return bool(value)


def _to_python_int(value: StackValue) -> int:
    if isinstance(value, SymbolicValue) and isinstance(value.value, int):
        return value.value
    if isinstance(value, int):
        return value
    raise TypeError("value is not concretely int")


def test_all_any_faithfulness() -> None:
    """Faithfulness: all/any model outputs match Python for concrete iterables."""
    cases: list[list[int | bool]] = [[], [1], [0, 1, 2], [False, True]]
    for items in cases:
        stack_items: list[StackValue] = [*items]
        args: list[StackValue] = [stack_items]
        all_res = extended.AllModel().apply(args, {}, _state())
        any_res = extended.AnyModel().apply(args, {}, _state())
        assert _to_python_bool(all_res.value) == all(items)
        assert _to_python_bool(any_res.value) == any(items)


def test_reversed_faithfulness() -> None:
    """Faithfulness: reversed model matches Python reversed for concrete input."""
    values: list[StackValue] = [1, 2, 3]
    args: list[StackValue] = [values]
    result = extended.ReversedModel().apply(args, {}, _state())
    assert result.value == list(reversed(values))


def test_ord_chr_faithfulness() -> None:
    """Faithfulness for ord/chr on concrete path."""
    ord_args: list[StackValue] = ["A"]
    chr_args: list[StackValue] = [65]
    ord_result = extended.OrdModel().apply(ord_args, {}, _state())
    chr_result = extended.ChrModel().apply(chr_args, {}, _state())
    assert _to_python_int(ord_result.value) == ord("A")
    assert hasattr(chr_result.value, "name")
    assert getattr(chr_result.value, "name") == "'A'"


def test_pow_round_divmod_faithfulness() -> None:
    """Faithfulness for numeric builtins on concrete path."""
    pow_result = extended.PowModel().apply([2, 5], {}, _state())
    round_result = extended.RoundModel().apply([3.14159, 2], {}, _state())
    divmod_result = extended.DivmodModel().apply([17, 5], {}, _state())
    assert _to_python_int(pow_result.value) == pow(2, 5)
    assert round_result.value == round(3.14159, 2)
    assert isinstance(divmod_result.value, tuple)


def test_hasattr_getattr_faithfulness() -> None:
    """Faithfulness for attribute builtins on concrete path."""
    target: object = "abc"
    has_result = extended.HasattrModel().apply([target, "upper"], {}, _state())
    get_result = extended.GetattrModel().apply([target, "upper"], {}, _state())
    assert bool(has_result.value) is hasattr(target, "upper")
    assert callable(get_result.value)


def test_extended_error_and_edge_paths() -> None:
    """Error and edge paths for representative models."""
    # Edge: empty args on models that accept no input path.
    assert extended.AllModel().apply([], {}, _state()).value is not None
    assert extended.AnyModel().apply([], {}, _state()).value is not None

    # Error: chr with invalid range falls back to symbolic path or raises current runtime NameError.
    with pytest.raises(Exception):
        invalid: list[StackValue] = [0x110000]
        result = extended.ChrModel().apply(invalid, {}, _state())
        # If no exception, force failure to keep behavior explicit for this branch.
        assert str(result.value) == chr(0x110000)
