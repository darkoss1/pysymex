"""Tests for symbolic class parameter type seeding."""

from __future__ import annotations

from pysymex._internal.core.classes.types import InitParameter
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.sets import SymbolicSet
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.strings import SymbolicString


def test_init_parameter_uses_shared_hint_alias_normalization() -> None:
    assert isinstance(InitParameter("name", "STRING").to_symbolic(1), SymbolicString)
    assert isinstance(InitParameter("data", "bytes").to_symbolic(1), SymbolicBytes)
    assert isinstance(InitParameter("members", "set[int]").to_symbolic(1), SymbolicSet)
    pair = InitParameter("pair", "tuple[int, string]").to_symbolic(1)
    assert isinstance(pair, SymbolicTuple)
    assert len(pair) == 2


def test_init_parameter_marks_unknown_tuple_hint_as_tuple_carrier() -> None:
    value = InitParameter("items", "tuple").to_symbolic(1)

    assert isinstance(value, SymbolicList)
    assert getattr(value, "_type", None) == "tuple"
