"""Regression tests for shared symbolic type capabilities and affinities."""

from __future__ import annotations

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.affinity import AffinityKind, normalize_affinity
from pysymex._internal.core.types.capabilities import (
    has_retained_concrete_value,
    length_expr,
    symbolic_affinity,
)
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.sets import SymbolicSet
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue


def test_affinity_aliases_have_one_canonical_storage_spelling() -> None:
    assert normalize_affinity("NoneType") == AffinityKind.NONE
    assert normalize_affinity("object") == AffinityKind.OBJECT
    assert SymbolicValue.from_const(None).affinity_type == AffinityKind.NONE


def test_unclassified_symbolic_value_is_unknown_instead_of_none() -> None:
    value = SymbolicValue(
        z3_int=z3.Int("unknown_int"),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
    )

    assert value.affinity_type == AffinityKind.UNKNOWN


def test_specialized_container_affinities_and_channels_are_preserved() -> None:
    byte_value = SymbolicValue.from_specialized(SymbolicBytes.symbolic("data"))
    tuple_value = SymbolicValue.from_specialized(SymbolicTuple.from_elements(1, 2))
    set_value = SymbolicValue.from_specialized(SymbolicSet.from_const({1, 2}))

    assert byte_value.affinity_type == AffinityKind.BYTES
    assert z3.is_true(byte_value.is_bytes)
    assert tuple_value.affinity_type == AffinityKind.TUPLE
    assert z3.is_true(tuple_value.is_tuple)
    assert set_value.affinity_type == AffinityKind.SET
    assert z3.is_true(set_value.is_set)


def test_symbolic_affinity_covers_specialized_and_concrete_families() -> None:
    empty_frozenset: frozenset[int] = frozenset()
    assert symbolic_affinity(SymbolicBytes.symbolic("data")) == AffinityKind.BYTES
    assert symbolic_affinity(SymbolicTuple.from_elements()) == AffinityKind.TUPLE
    assert symbolic_affinity(SymbolicSet.from_const(set())) == AffinityKind.SET
    assert symbolic_affinity(empty_frozenset) == AffinityKind.FROZENSET


def test_length_capability_covers_every_length_bearing_symbolic_carrier() -> None:
    symbolic_list, _ = SymbolicList.symbolic("items")
    symbolic_dict, _ = SymbolicDict.symbolic("mapping")
    symbolic_set, _ = SymbolicSet.symbolic("members")
    carriers = (
        (SymbolicBytes.symbolic("data"), SymbolicBytes.symbolic("data").z3_len),
        (SymbolicString.from_const("abc"), z3.IntVal(3)),
        (symbolic_list, symbolic_list.z3_len),
        (symbolic_dict, symbolic_dict.z3_len),
        (SymbolicTuple.from_elements(1, 2), z3.IntVal(2)),
        (symbolic_set, symbolic_set.length.z3_int),
    )

    for value, expected in carriers:
        actual = length_expr(value)
        assert actual is not None
        assert z3.is_true(simplify_expr(actual == expected))


def test_concrete_capability_never_mistakes_unresolved_symbolic_carriers_for_constants() -> None:
    assert not has_retained_concrete_value(SymbolicBytes.symbolic("data"))
    assert has_retained_concrete_value(SymbolicBytes.concrete(b"abc"))
    assert not has_retained_concrete_value(SymbolicString.symbolic("text")[0])
    assert has_retained_concrete_value(SymbolicString.from_const("text"))


def test_symbolic_value_type_tag_uses_all_central_affinity_channels() -> None:
    carriers = (
        (SymbolicValue.from_specialized(SymbolicBytes.symbolic("data")), "bytes"),
        (SymbolicValue.from_specialized(SymbolicTuple.from_elements(1)), "tuple"),
        (SymbolicValue.from_specialized(SymbolicSet.from_const({1})), "set"),
        (SymbolicValue.from_const(frozenset({1})), "frozenset"),
    )

    for value, expected in carriers:
        assert value.type_tag == expected

    raw_bytes_channel = SymbolicValue(
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_bytes=z3.BoolVal(True),
    )
    assert raw_bytes_channel.type_tag == "bytes"
