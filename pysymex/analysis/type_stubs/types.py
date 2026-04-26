# pysymex: Python Symbolic Execution & Formal Verification
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

"""Type stub types — StubType, FunctionStub, ClassStub, ModuleStub."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from pysymex.analysis.type_inference.kinds import TypeKind, PyType

__all__ = ["ClassStub", "FunctionStub", "ModuleStub", "StubType"]


@dataclass(frozen=True)
class StubType:
    """
    Representation of a type from stub files.
    This is a more detailed representation than PyType,
    supporting full generic types, unions, etc.
    """

    name: str
    module: str = ""
    type_args: tuple[StubType, ...] = ()
    is_optional: bool = False
    is_union: bool = False
    is_callable: bool = False
    is_protocol: bool = False
    is_typevar: bool = False
    is_literal: bool = False
    param_types: tuple[StubType, ...] = ()
    return_type: StubType | None = None
    literal_values: tuple[object, ...] = ()
    union_members: tuple[StubType, ...] = ()

    @classmethod
    def any_type(cls) -> StubType:
        return cls("Any", "typing")

    @classmethod
    def none_type(cls) -> StubType:
        return cls("None", "builtins")

    @classmethod
    def int_type(cls) -> StubType:
        return cls("int", "builtins")

    @classmethod
    def str_type(cls) -> StubType:
        return cls("str", "builtins")

    @classmethod
    def bool_type(cls) -> StubType:
        return cls("bool", "builtins")

    @classmethod
    def float_type(cls) -> StubType:
        return cls("float", "builtins")

    @classmethod
    def bytes_type(cls) -> StubType:
        return cls("bytes", "builtins")

    @classmethod
    def object_type(cls) -> StubType:
        return cls("object", "builtins")

    @classmethod
    def list_of(cls, element_type: StubType) -> StubType:
        return cls("list", "builtins", (element_type,))

    @classmethod
    def dict_of(cls, key_type: StubType, value_type: StubType) -> StubType:
        return cls("dict", "builtins", (key_type, value_type))

    @classmethod
    def set_of(cls, element_type: StubType) -> StubType:
        return cls("set", "builtins", (element_type,))

    @classmethod
    def tuple_of(cls, *element_types: StubType) -> StubType:
        return cls("tuple", "builtins", element_types)

    @classmethod
    def optional(cls, inner: StubType) -> StubType:
        return cls("Optional", "typing", (inner,), is_optional=True)

    @classmethod
    def union(cls, *members: StubType) -> StubType:
        return cls("Union", "typing", members, is_union=True, union_members=members)

    @classmethod
    def callable(
        cls,
        param_types: Sequence[StubType],
        return_type: StubType,
    ) -> StubType:
        return cls(
            "Callable",
            "typing",
            is_callable=True,
            param_types=tuple(param_types),
            return_type=return_type,
        )

    @classmethod
    def literal(cls, *values: object) -> StubType:
        return cls("Literal", "typing", is_literal=True, literal_values=values)

    @classmethod
    def typevar(cls, name: str) -> StubType:
        return cls(name, "typing", is_typevar=True)

    def __str__(self) -> str:
        """Return a human-readable string representation."""
        if self.is_callable:
            params = ", ".join(str(p) for p in self.param_types)
            ret = str(self.return_type) if self.return_type else "None"
            return f"Callable[[{params}], {ret}]"
        if self.is_union:
            return " | ".join(str(m) for m in self.union_members)
        if self.is_literal:
            return f"Literal[{', '.join(repr(v) for v in self.literal_values)}]"
        if self.type_args:
            args = ", ".join(str(a) for a in self.type_args)
            return f"{self.name}[{args}]"
        return self.name

    def to_pytype(self) -> PyType:
        """Convert StubType to PyType for type inference."""
        name_to_kind = {
            "Any": TypeKind.ANY,
            "None": TypeKind.NONE,
            "int": TypeKind.INT,
            "str": TypeKind.STR,
            "bool": TypeKind.BOOL,
            "float": TypeKind.FLOAT,
            "bytes": TypeKind.BYTES,
            "object": TypeKind.OBJECT,
            "list": TypeKind.LIST,
            "dict": TypeKind.DICT,
            "set": TypeKind.SET,
            "tuple": TypeKind.TUPLE,
            "Optional": TypeKind.OPTIONAL,
            "Union": TypeKind.UNION,
        }

        kind = name_to_kind.get(self.name, TypeKind.OBJECT)

        if self.is_optional:
            return PyType(kind, name=self.name, nullable=True)

        if self.is_union:
            member_types = frozenset(m.to_pytype() for m in self.union_members)
            return PyType(kind, name=self.name, union_members=member_types)

        if self.type_args:
            arg_types = tuple(arg.to_pytype() for arg in self.type_args)
            return PyType(kind, name=self.name, params=arg_types)

        return PyType(kind, name=self.name)


def _empty_overloads() -> list[FunctionStub]:
    """Create a typed empty function-overload list."""
    return []


def _empty_submodules() -> dict[str, ModuleStub]:
    """Create a typed empty submodule map."""
    return {}


@dataclass
class FunctionStub:
    """Stub information for a function."""

    name: str
    params: dict[str, StubType] = field(default_factory=dict[str, StubType])
    return_type: StubType | None = None
    overloads: list[FunctionStub] = field(default_factory=_empty_overloads)
    is_staticmethod: bool = False
    is_classmethod: bool = False
    is_property: bool = False
    is_abstractmethod: bool = False
    is_overload: bool = False
    type_params: dict[str, StubType] = field(default_factory=dict[str, StubType])


@dataclass
class ClassStub:
    """Stub information for a class."""

    name: str
    bases: list[StubType] = field(default_factory=list[StubType])
    methods: dict[str, FunctionStub] = field(default_factory=dict[str, FunctionStub])
    attributes: dict[str, StubType] = field(default_factory=dict[str, StubType])
    class_vars: dict[str, StubType] = field(default_factory=dict[str, StubType])
    type_params: dict[str, StubType] = field(default_factory=dict[str, StubType])
    is_protocol: bool = False
    is_abstract: bool = False
    is_final: bool = False
    is_dataclass: bool = False
    is_namedtuple: bool = False


@dataclass
class ModuleStub:
    """Stub information for a module."""

    name: str
    functions: dict[str, FunctionStub] = field(default_factory=dict[str, FunctionStub])
    classes: dict[str, ClassStub] = field(default_factory=dict[str, ClassStub])
    variables: dict[str, StubType] = field(default_factory=dict[str, StubType])
    type_aliases: dict[str, StubType] = field(default_factory=dict[str, StubType])
    imports: dict[str, str] = field(default_factory=dict[str, str])
    submodules: dict[str, ModuleStub] = field(default_factory=_empty_submodules)
