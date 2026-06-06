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

"""Helper functions for constructing PyType instances from values and literals."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Self, cast

from pysymex.analysis.static.types.kinds import TypeKind


class PyTypeConstructorMixin:
    kind: TypeKind

    def __init__(
        self,
        *,
        kind: TypeKind,
        name: str = "",
        params: tuple[Self, ...] = (),
        literal_values: frozenset[object] = frozenset(),
        class_name: str | None = None,
        union_members: frozenset[Self] = frozenset(),
        attributes: Mapping[str, Self] | None = None,
        nullable: bool = False,
        confidence: float = 1.0,
        source: str = "inferred",
        length: int | None = None,
        value_constraints: frozenset[str] = frozenset(),
        known_keys: frozenset[object] = frozenset(),
    ) -> None: ...

    @classmethod
    def none(cls: type[Self]) -> Self:
        """Create None type."""
        return cls(kind=TypeKind.NONE, name="None")

    @classmethod
    def none_type(cls: type[Self]) -> Self:
        """Create None type (alias for none())."""
        return cls.none()

    @classmethod
    def bool_(cls: type[Self]) -> Self:
        """Create bool type."""
        return cls(kind=TypeKind.BOOL, name="bool")

    @classmethod
    def int_(cls: type[Self]) -> Self:
        """Create int type."""
        return cls(kind=TypeKind.INT, name="int")

    @classmethod
    def float_(cls: type[Self]) -> Self:
        """Create float type."""
        return cls(kind=TypeKind.FLOAT, name="float")

    @classmethod
    def str_(cls: type[Self]) -> Self:
        """Create str type."""
        return cls(kind=TypeKind.STR, name="str")

    @classmethod
    def bytes_(cls: type[Self]) -> Self:
        """Create bytes type."""
        return cls(kind=TypeKind.BYTES, name="bytes")

    @classmethod
    def list_(cls: type[Self], element_type: Self | None = None) -> Self:
        """Create list type with optional element type."""
        params = (element_type,) if element_type else ()
        return cls(kind=TypeKind.LIST, name="list", params=params)

    @classmethod
    def dict_(
        cls,
        key_type: Self | None = None,
        value_type: Self | None = None,
    ) -> Self:
        """Create dict type with optional key/value types."""
        params = ()
        if key_type and value_type:
            params = (key_type, value_type)
        return cls(kind=TypeKind.DICT, name="dict", params=params)

    @classmethod
    def defaultdict_(
        cls,
        key_type: Self | None = None,
        value_type: Self | None = None,
    ) -> Self:
        """Create defaultdict type."""
        params = ()
        if key_type and value_type:
            params = (key_type, value_type)
        return cls(kind=TypeKind.DEFAULTDICT, name="defaultdict", params=params)

    @classmethod
    def set_(cls: type[Self], element_type: Self | None = None) -> Self:
        """Create set type with optional element type."""
        params = (element_type,) if element_type else ()
        return cls(kind=TypeKind.SET, name="set", params=params)

    @classmethod
    def tuple_(cls: type[Self], *element_types: Self) -> Self:
        """Create tuple type with element types."""
        return cls(kind=TypeKind.TUPLE, name="tuple", params=element_types)

    @classmethod
    def deque_(cls: type[Self], element_type: Self | None = None) -> Self:
        """Create deque type with optional element type."""
        params = (element_type,) if element_type else ()
        return cls(kind=TypeKind.DEQUE, name="deque", params=params)

    @classmethod
    def union_(cls: type[Self], *types: Self) -> Self:
        """Create union type."""
        members: set[Self] = set()
        for typ in types:
            if typ.kind == TypeKind.UNION:
                members.update(cast("frozenset[Self]", getattr(typ, "union_members")))
            else:
                members.add(typ)
        if len(members) == 1:
            return members.pop()
        return cls(kind=TypeKind.UNION, name="Union", union_members=frozenset(members))

    @classmethod
    def optional_(cls: type[Self], inner_type: Self) -> Self:
        """Create Optional type (Union with None)."""
        return cls.union_(inner_type, cls.none())

    @classmethod
    def literal_(cls: type[Self], *values: object) -> Self:
        """Create Literal type with specific values."""
        return cls(kind=TypeKind.LITERAL, name="Literal", literal_values=frozenset(values))

    @classmethod
    def any_(cls: type[Self]) -> Self:
        """Create Any type."""
        return cls(kind=TypeKind.ANY, name="Any")

    @classmethod
    def unknown(cls: type[Self]) -> Self:
        """Create unknown type."""
        return cls(kind=TypeKind.UNKNOWN, name="?")

    @classmethod
    def bottom(cls: type[Self]) -> Self:
        """Create bottom type (empty/unreachable)."""
        return cls(kind=TypeKind.BOTTOM, name="\u22a5")

    @classmethod
    def instance(cls: type[Self], class_name: str, **attributes: Self) -> Self:
        """Create instance type for a class."""
        return cls(
            kind=TypeKind.INSTANCE,
            name=class_name,
            class_name=class_name,
            attributes=attributes,
        )

    @classmethod
    def callable_(
        cls,
        params: Sequence[Self] = (),
        return_type: Self | None = None,
    ) -> Self:
        """Create Callable type."""
        ret = return_type or cls.any_()
        return cls(kind=TypeKind.CALLABLE, name="Callable", params=(*tuple(params), ret))

    int_type = int_
    str_type = str_
    bool_type = bool_
    float_type = float_
    list_type = list_
    dict_type = dict_
    tuple_type = tuple_
    set_type = set_
