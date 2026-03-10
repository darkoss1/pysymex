"""Type stub types — StubType, FunctionStub, ClassStub, ModuleStub."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from pysymex.analysis.type_inference import PyType, TypeKind

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

    def to_pytype(self) -> PyType:
        """Convert to the simpler PyType representation."""
        kind_map = {
            "int": TypeKind.INT,
            "float": TypeKind.FLOAT,
            "str": TypeKind.STR,
            "bytes": TypeKind.BYTES,
            "bool": TypeKind.BOOL,
            "None": TypeKind.NONE,
            "list": TypeKind.LIST,
            "dict": TypeKind.DICT,
            "set": TypeKind.SET,
            "frozenset": TypeKind.FROZENSET,
            "tuple": TypeKind.TUPLE,
            "object": TypeKind.OBJECT,
            "type": TypeKind.TYPE,
            "Callable": TypeKind.CALLABLE,
            "Iterator": TypeKind.ITERATOR,
            "Generator": TypeKind.GENERATOR,
            "Coroutine": TypeKind.COROUTINE,
            "Any": TypeKind.ANY,
        }
        if self.is_union:
            return PyType(kind=TypeKind.UNION)
        if self.is_optional:
            return PyType(kind=TypeKind.OPTIONAL)
        kind = kind_map.get(self.name, TypeKind.OBJECT)
        return PyType(kind=kind, name=self.name)

    def __str__(self) -> str:
        if self.is_callable:
            params = ", ".join(str(p) for p in self.param_types)
            ret = str(self.return_type) if self.return_type else "None"
            return f"Callable[[{params }], {ret }]"
        if self.is_union:
            return " | ".join(str(m) for m in self.union_members)
        if self.is_literal:
            return f"Literal[{', '.join (repr (v )for v in self .literal_values )}]"
        if self.type_args:
            args = ", ".join(str(a) for a in self.type_args)
            return f"{self .name }[{args }]"
        return self.name


@dataclass
class FunctionStub:
    """Stub information for a function."""

    name: str
    params: dict[str, StubType] = field(default_factory=dict[str, StubType])
    return_type: StubType | None = None
    overloads: list[FunctionStub] = field(default_factory=list)
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
    submodules: dict[str, ModuleStub] = field(default_factory=dict)
