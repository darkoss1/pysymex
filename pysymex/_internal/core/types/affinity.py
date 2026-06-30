# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Canonical runtime affinity labels and semantic affinity families."""

from __future__ import annotations

from enum import StrEnum


class AffinityKind(StrEnum):
    """Stable coarse type labels carried by unified symbolic values."""

    BOOL = "bool"
    BYTEARRAY = "bytearray"
    BYTES = "bytes"
    CALLABLE = "callable"
    DICT = "dict"
    FLOAT = "float"
    FROZENSET = "frozenset"
    INT = "int"
    LIST = "list"
    NONE = "none"
    OBJECT = "obj"
    PATH = "path"
    SET = "set"
    STR = "str"
    TUPLE = "tuple"
    TYPE = "type"
    UNKNOWN = "unknown"


_AFFINITY_ALIASES = {
    "NoneType": AffinityKind.NONE,
    "object": AffinityKind.OBJECT,
}

NUMERIC_AFFINITIES = frozenset((AffinityKind.BOOL, AffinityKind.FLOAT, AffinityKind.INT))
INTEGER_LIKE_AFFINITIES = frozenset((AffinityKind.BOOL, AffinityKind.INT))
SEQUENCE_AFFINITIES = frozenset(
    (
        AffinityKind.BYTEARRAY,
        AffinityKind.BYTES,
        AffinityKind.STR,
        AffinityKind.TUPLE,
    ),
)
CONTAINER_AFFINITIES = frozenset(
    (
        AffinityKind.BYTEARRAY,
        AffinityKind.BYTES,
        AffinityKind.DICT,
        AffinityKind.FROZENSET,
        AffinityKind.LIST,
        AffinityKind.SET,
        AffinityKind.STR,
        AffinityKind.TUPLE,
    ),
)
LENGTH_AFFINITIES = CONTAINER_AFFINITIES
LENGTH_CHANNEL_AFFINITIES = frozenset(
    (
        AffinityKind.BYTEARRAY,
        AffinityKind.DICT,
        AffinityKind.FROZENSET,
        AffinityKind.LIST,
        AffinityKind.SET,
        AffinityKind.TUPLE,
    ),
)
ALWAYS_TRUTHY_AFFINITIES = frozenset((AffinityKind.OBJECT, AffinityKind.PATH))
ALWAYS_FALSY_AFFINITIES = frozenset((AffinityKind.NONE,))
DEFINITELY_NON_CALLABLE_AFFINITIES = frozenset(
    (
        AffinityKind.BOOL,
        AffinityKind.BYTEARRAY,
        AffinityKind.BYTES,
        AffinityKind.DICT,
        AffinityKind.FLOAT,
        AffinityKind.FROZENSET,
        AffinityKind.INT,
        AffinityKind.LIST,
        AffinityKind.NONE,
        AffinityKind.SET,
        AffinityKind.STR,
        AffinityKind.TUPLE,
    ),
)
IMMUTABLE_SUBSCRIPT_AFFINITIES = frozenset(
    (AffinityKind.BYTES, AffinityKind.STR, AffinityKind.TUPLE),
)
SUBSCRIPT_MUTATION_UNSUPPORTED_AFFINITIES = frozenset(
    (
        AffinityKind.BOOL,
        AffinityKind.BYTES,
        AffinityKind.FLOAT,
        AffinityKind.FROZENSET,
        AffinityKind.INT,
        AffinityKind.NONE,
        AffinityKind.SET,
        AffinityKind.STR,
        AffinityKind.TUPLE,
    ),
)


def normalize_affinity(value: str | AffinityKind | None) -> str:
    """Return the canonical stored spelling for an affinity label."""
    if value is None or value == "":
        return AffinityKind.UNKNOWN
    return str(_AFFINITY_ALIASES.get(str(value), value))


def python_type_name_for_affinity(value: str | AffinityKind) -> str:
    """Return the CPython-facing type name for a canonical affinity."""
    normalized = normalize_affinity(value)
    if normalized == AffinityKind.NONE:
        return "NoneType"
    if normalized == AffinityKind.OBJECT:
        return "object"
    return normalized
