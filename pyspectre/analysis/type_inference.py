"""
Advanced Type Inference Engine for PySpectre.
This module provides sophisticated type inference to reduce false positives
by understanding Python's dynamic type system more accurately.
Features:
- Flow-sensitive type narrowing (isinstance checks, type guards)
- Collection type tracking (dict keys, list element types)
- Type annotation parsing and utilization
- Type state tracking across control flow
- Pattern-based type inference for common idioms
"""

from __future__ import annotations
import inspect
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Union,
    get_type_hints,
)


class TypeKind(Enum):
    """Enumeration of Python type categories."""

    NONE = auto()
    BOOL = auto()
    INT = auto()
    FLOAT = auto()
    COMPLEX = auto()
    STR = auto()
    BYTES = auto()
    LIST = auto()
    TUPLE = auto()
    SET = auto()
    FROZENSET = auto()
    DICT = auto()
    DEFAULTDICT = auto()
    COUNTER = auto()
    ORDERED_DICT = auto()
    CHAIN_MAP = auto()
    SEQUENCE = auto()
    MAPPING = auto()
    ITERABLE = auto()
    DEQUE = auto()

    @classmethod
    def int_type(cls) -> PyType:
        return cls.int_()

    @classmethod
    def str_type(cls) -> PyType:
        return cls.str_()

    @classmethod
    def bool_type(cls) -> PyType:
        return cls.bool_()

    @classmethod
    def float_type(cls) -> PyType:
        return cls.float_()

    @classmethod
    def list_type(cls, element_type: PyType | None = None) -> PyType:
        return cls.list_(element_type)

    @classmethod
    def dict_type(cls, key_type: PyType | None = None, value_type: PyType | None = None) -> PyType:
        return cls.dict_(key_type, value_type)

    @classmethod
    def tuple_type(cls, *element_types: PyType) -> PyType:
        return cls.tuple_(*element_types)

    @classmethod
    def set_type(cls, element_type: PyType | None = None) -> PyType:
        return cls.set_(element_type)

    @classmethod
    def none_type(cls) -> PyType:
        return cls.none()

    FUNCTION = auto()
    METHOD = auto()
    LAMBDA = auto()
    COROUTINE = auto()
    GENERATOR = auto()
    ASYNC_GENERATOR = auto()
    CLASS = auto()
    INSTANCE = auto()
    MODULE = auto()
    ANY = auto()
    UNION = auto()
    OPTIONAL = auto()
    LITERAL = auto()
    TYPE_VAR = auto()
    PROTOCOL = auto()
    CALLABLE = auto()
    UNKNOWN = auto()
    BOTTOM = auto()


@dataclass(frozen=True)
class PyType:
    """
    Represents a Python type in the analysis.
    This is a rich representation that captures:
    - The kind of type (int, str, list, etc.)
    - Generic parameters (List[int], Dict[str, Any], etc.)
    - Known attributes and methods
    - Value constraints (Literal types, enum values)
    - Nullability
    """

    kind: TypeKind
    name: str = ""
    params: tuple[PyType, ...] = ()
    literal_values: frozenset[Any] = frozenset()
    class_name: str | None = None
    union_members: frozenset[PyType] = frozenset()
    attributes: Mapping[str, PyType] = field(default_factory=dict)
    nullable: bool = False
    confidence: float = 1.0
    source: str = "inferred"
    length: int | None = None
    value_constraints: frozenset[str] = frozenset()
    known_keys: frozenset[Any] = frozenset()

    def __hash__(self) -> int:
        return hash(
            (
                self.kind,
                self.name,
                self.params,
                self.literal_values,
                self.class_name,
                self.nullable,
                self.length,
                self.value_constraints,
                self.known_keys,
            )
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PyType):
            return False
        return (
            self.kind == other.kind
            and self.name == other.name
            and self.params == other.params
            and self.literal_values == other.literal_values
            and self.class_name == other.class_name
            and self.length == other.length
            and self.value_constraints == other.value_constraints
            and self.known_keys == other.known_keys
        )

    @classmethod
    def none(cls) -> PyType:
        """Create None type."""
        return cls(kind=TypeKind.NONE, name="None")

    @classmethod
    def bool_(cls) -> PyType:
        """Create bool type."""
        return cls(kind=TypeKind.BOOL, name="bool")

    @classmethod
    def int_(cls) -> PyType:
        """Create int type."""
        return cls(kind=TypeKind.INT, name="int")

    @classmethod
    def float_(cls) -> PyType:
        """Create float type."""
        return cls(kind=TypeKind.FLOAT, name="float")

    @classmethod
    def str_(cls) -> PyType:
        """Create str type."""
        return cls(kind=TypeKind.STR, name="str")

    @classmethod
    def bytes_(cls) -> PyType:
        """Create bytes type."""
        return cls(kind=TypeKind.BYTES, name="bytes")

    @classmethod
    def list_(cls, element_type: PyType | None = None) -> PyType:
        """Create list type with optional element type."""
        params = (element_type,) if element_type else ()
        return cls(kind=TypeKind.LIST, name="list", params=params)

    @classmethod
    def dict_(
        cls,
        key_type: PyType | None = None,
        value_type: PyType | None = None,
    ) -> PyType:
        """Create dict type with optional key/value types."""
        params = ()
        if key_type and value_type:
            params = (key_type, value_type)
        return cls(kind=TypeKind.DICT, name="dict", params=params)

    @classmethod
    def defaultdict_(
        cls,
        key_type: PyType | None = None,
        value_type: PyType | None = None,
    ) -> PyType:
        """Create defaultdict type."""
        params = ()
        if key_type and value_type:
            params = (key_type, value_type)
        return cls(kind=TypeKind.DEFAULTDICT, name="defaultdict", params=params)

    @classmethod
    def set_(cls, element_type: PyType | None = None) -> PyType:
        """Create set type with optional element type."""
        params = (element_type,) if element_type else ()
        return cls(kind=TypeKind.SET, name="set", params=params)

    @classmethod
    def tuple_(cls, *element_types: PyType) -> PyType:
        """Create tuple type with element types."""
        return cls(kind=TypeKind.TUPLE, name="tuple", params=element_types)

    @classmethod
    def deque_(cls, element_type: PyType | None = None) -> PyType:
        """Create deque type with optional element type."""
        params = (element_type,) if element_type else ()
        return cls(kind=TypeKind.DEQUE, name="deque", params=params)

    @classmethod
    def union_(cls, *types: PyType) -> PyType:
        """Create union type."""
        members: set[PyType] = set()
        for t in types:
            if t.kind == TypeKind.UNION:
                members.update(t.union_members)
            else:
                members.add(t)
        if len(members) == 1:
            return members.pop()
        return cls(
            kind=TypeKind.UNION,
            name="Union",
            union_members=frozenset(members),
        )

    @classmethod
    def optional_(cls, inner_type: PyType) -> PyType:
        """Create Optional type (Union with None)."""
        return cls.union_(inner_type, cls.none())

    @classmethod
    def literal_(cls, *values: Any) -> PyType:
        """Create Literal type with specific values."""
        return cls(
            kind=TypeKind.LITERAL,
            name="Literal",
            literal_values=frozenset(values),
        )

    @classmethod
    def any_(cls) -> PyType:
        """Create Any type."""
        return cls(kind=TypeKind.ANY, name="Any")

    @classmethod
    def unknown(cls) -> PyType:
        """Create unknown type."""
        return cls(kind=TypeKind.UNKNOWN, name="?")

    @classmethod
    def bottom(cls) -> PyType:
        """Create bottom type (empty/unreachable)."""
        return cls(kind=TypeKind.BOTTOM, name="⊥")

    @classmethod
    def instance(cls, class_name: str, **attributes: PyType) -> PyType:
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
        params: Sequence[PyType] = (),
        return_type: PyType | None = None,
    ) -> PyType:
        """Create Callable type."""
        ret = return_type or cls.any_()
        return cls(
            kind=TypeKind.CALLABLE,
            name="Callable",
            params=tuple(params) + (ret,),
        )

    int_type = int_
    str_type = str_
    bool_type = bool_
    float_type = float_
    list_type = list_
    dict_type = dict_
    tuple_type = tuple_
    set_type = set_

    def is_numeric(self) -> bool:
        """Check if this is a numeric type."""
        return self.kind in {TypeKind.INT, TypeKind.FLOAT, TypeKind.COMPLEX}

    def is_collection(self) -> bool:
        """Check if this is a collection type."""
        return self.kind in {
            TypeKind.LIST,
            TypeKind.TUPLE,
            TypeKind.SET,
            TypeKind.FROZENSET,
            TypeKind.DICT,
            TypeKind.DEFAULTDICT,
            TypeKind.DEQUE,
        }

    def is_mapping(self) -> bool:
        """Check if this is a mapping type."""
        return self.kind in {TypeKind.DICT, TypeKind.DEFAULTDICT}

    def is_sequence(self) -> bool:
        """Check if this is a sequence type."""
        return self.kind in {TypeKind.LIST, TypeKind.TUPLE, TypeKind.DEQUE, TypeKind.STR}

    def is_subscriptable(self) -> bool:
        """Check if this type supports subscript operations."""
        return self.kind in {
            TypeKind.LIST,
            TypeKind.TUPLE,
            TypeKind.DICT,
            TypeKind.DEFAULTDICT,
            TypeKind.STR,
            TypeKind.BYTES,
            TypeKind.DEQUE,
        }

    def is_nullable(self) -> bool:
        """Check if this type can be None."""
        if self.kind == TypeKind.NONE:
            return True
        if self.nullable:
            return True
        if self.kind == TypeKind.UNION:
            return any(m.kind == TypeKind.NONE for m in self.union_members)
        return False

    def is_definitely_not_none(self) -> bool:
        """Check if this type definitely cannot be None."""
        if self.kind == TypeKind.NONE:
            return False
        if self.nullable:
            return False
        if self.kind == TypeKind.UNION:
            return not any(m.kind == TypeKind.NONE for m in self.union_members)
        return True

    def get_element_type(self) -> PyType:
        """Get element type for collections."""
        if self.params and len(self.params) >= 1:
            return self.params[0]
        return PyType.any_()

    def get_key_type(self) -> PyType:
        """Get key type for mappings."""
        if self.params and len(self.params) >= 1:
            return self.params[0]
        return PyType.any_()

    def get_value_type(self) -> PyType:
        """Get value type for mappings."""
        if self.params and len(self.params) >= 2:
            return self.params[1]
        return PyType.any_()

    def get_return_type(self) -> PyType:
        """Get return type for callables."""
        if self.kind == TypeKind.CALLABLE and self.params:
            return self.params[-1]
        return PyType.any_()

    def without_none(self) -> PyType:
        """Return this type with None removed from union."""
        if self.kind == TypeKind.NONE:
            return PyType.bottom()
        if self.kind == TypeKind.UNION:
            non_none = [m for m in self.union_members if m.kind != TypeKind.NONE]
            if not non_none:
                return PyType.bottom()
            if len(non_none) == 1:
                return non_none[0]
            return PyType.union_(*non_none)
        return self

    def join(self, other: PyType) -> PyType:
        """Compute least upper bound (join) of two types."""
        if self == other:
            return self
        if self.kind == TypeKind.BOTTOM:
            return other
        if other.kind == TypeKind.BOTTOM:
            return self
        if self.kind == TypeKind.ANY or other.kind == TypeKind.ANY:
            return PyType.any_()
        if self.kind == TypeKind.UNKNOWN or other.kind == TypeKind.UNKNOWN:
            return PyType.unknown()
        if self.kind == TypeKind.UNION or other.kind == TypeKind.UNION:
            members: set[PyType] = set()
            if self.kind == TypeKind.UNION:
                members.update(self.union_members)
            else:
                members.add(self)
            if other.kind == TypeKind.UNION:
                members.update(other.union_members)
            else:
                members.add(other)
            return PyType.union_(*members)
        if self.is_numeric() and other.is_numeric():
            if self.kind == TypeKind.COMPLEX or other.kind == TypeKind.COMPLEX:
                return PyType(kind=TypeKind.COMPLEX, name="complex")
            if self.kind == TypeKind.FLOAT or other.kind == TypeKind.FLOAT:
                return PyType.float_()
            return PyType.int_()
        if self.kind == other.kind and self.is_collection():
            if self.params and other.params:
                joined_params = tuple(p1.join(p2) for p1, p2 in zip(self.params, other.params))
                return PyType(
                    kind=self.kind,
                    name=self.name,
                    params=joined_params,
                )
            return PyType(kind=self.kind, name=self.name)
        return PyType.union_(self, other)

    def meet(self, other: PyType) -> PyType:
        """Compute greatest lower bound (meet) of two types."""
        if self == other:
            return self
        if self.kind == TypeKind.ANY:
            return other
        if other.kind == TypeKind.ANY:
            return self
        if self.kind == TypeKind.BOTTOM or other.kind == TypeKind.BOTTOM:
            return PyType.bottom()
        if self.kind == TypeKind.UNION and other.kind == TypeKind.UNION:
            common = self.union_members & other.union_members
            if not common:
                return PyType.bottom()
            return PyType.union_(*common)
        if self.kind == TypeKind.UNION:
            if other in self.union_members:
                return other
            return PyType.bottom()
        if other.kind == TypeKind.UNION:
            if self in other.union_members:
                return self
            return PyType.bottom()
        return PyType.bottom()

    def is_subtype_of(self, other: PyType) -> bool:
        """Check if self is a subtype of other."""
        if self == other:
            return True
        if self.kind == TypeKind.BOTTOM:
            return True
        if other.kind == TypeKind.ANY:
            return True
        if self.kind == TypeKind.NONE and other.is_nullable():
            return True
        if self.kind == TypeKind.UNION:
            return all(m.is_subtype_of(other) for m in self.union_members)
        if other.kind == TypeKind.UNION:
            return any(self.is_subtype_of(m) for m in other.union_members)
        if self.is_numeric() and other.is_numeric():
            order = {TypeKind.INT: 0, TypeKind.FLOAT: 1, TypeKind.COMPLEX: 2}
            return order.get(self.kind, 99) <= order.get(other.kind, 99)
        if self.kind == other.kind and self.params and other.params:
            if len(self.params) != len(other.params):
                return False
            return all(p1.is_subtype_of(p2) for p1, p2 in zip(self.params, other.params))
        return False

    def __repr__(self) -> str:
        if self.kind == TypeKind.UNION:
            members = " | ".join(repr(m) for m in sorted(self.union_members, key=str))
            return f"({members})"
        if self.kind == TypeKind.LITERAL:
            values = ", ".join(repr(v) for v in self.literal_values)
            return f"Literal[{values}]"
        if self.params:
            params = ", ".join(repr(p) for p in self.params)
            return f"{self.name}[{params}]"
        return self.name


@dataclass
class TypeEnvironment:
    """
    Tracks type information for variables in a scope.
    Supports:
    - Variable type assignments
    - Type narrowing from control flow
    - Scope hierarchies (local, enclosing, global, builtin)
    """

    types: dict[str, PyType] = field(default_factory=dict)
    parent: TypeEnvironment | None = None
    globals: dict[str, PyType] = field(default_factory=dict)
    refinements: dict[str, PyType] = field(default_factory=dict)
    definitely_assigned: set[str] = field(default_factory=set)
    maybe_assigned: set[str] = field(default_factory=set)

    def get_type(self, name: str) -> PyType:
        """Look up type for a variable."""
        if name in self.refinements:
            return self.refinements[name]
        if name in self.types:
            return self.types[name]
        if self.parent:
            return self.parent.get_type(name)
        if name in self.globals:
            return self.globals[name]
        builtin_type = self._get_builtin_type(name)
        if builtin_type:
            return builtin_type
        return PyType.unknown()

    def set_type(self, name: str, typ: PyType) -> None:
        """Set type for a variable."""
        self.types[name] = typ
        self.definitely_assigned.add(name)
        self.maybe_assigned.add(name)

    def refine_type(self, name: str, typ: PyType) -> None:
        """Refine type based on control flow (isinstance, etc.)."""
        current = self.get_type(name)
        refined = current.meet(typ)
        if refined.kind != TypeKind.BOTTOM:
            self.refinements[name] = refined

    def clear_refinement(self, name: str) -> None:
        """Clear type refinement for a variable."""
        self.refinements.pop(name, None)

    def copy(self) -> TypeEnvironment:
        """Create a copy of this environment."""
        return TypeEnvironment(
            types=dict(self.types),
            parent=self.parent,
            globals=self.globals,
            refinements=dict(self.refinements),
            definitely_assigned=set(self.definitely_assigned),
            maybe_assigned=set(self.maybe_assigned),
        )

    def join(self, other: TypeEnvironment) -> TypeEnvironment:
        """Join two environments (for control flow merge points)."""
        result = TypeEnvironment(
            parent=self.parent,
            globals=self.globals,
        )
        all_vars = set(self.types.keys()) | set(other.types.keys())
        for var in all_vars:
            t1 = self.get_type(var)
            t2 = other.get_type(var)
            result.types[var] = t1.join(t2)
        result.definitely_assigned = self.definitely_assigned & other.definitely_assigned
        result.maybe_assigned = self.maybe_assigned | other.maybe_assigned
        return result

    def enter_scope(self) -> TypeEnvironment:
        """Create a new child scope."""
        return TypeEnvironment(parent=self, globals=self.globals)

    def _get_builtin_type(self, name: str) -> PyType | None:
        """Get type for a builtin name."""
        builtin_types = {
            "int": PyType(kind=TypeKind.CLASS, name="int", class_name="int"),
            "str": PyType(kind=TypeKind.CLASS, name="str", class_name="str"),
            "float": PyType(kind=TypeKind.CLASS, name="float", class_name="float"),
            "bool": PyType(kind=TypeKind.CLASS, name="bool", class_name="bool"),
            "list": PyType(kind=TypeKind.CLASS, name="list", class_name="list"),
            "dict": PyType(kind=TypeKind.CLASS, name="dict", class_name="dict"),
            "set": PyType(kind=TypeKind.CLASS, name="set", class_name="set"),
            "tuple": PyType(kind=TypeKind.CLASS, name="tuple", class_name="tuple"),
            "bytes": PyType(kind=TypeKind.CLASS, name="bytes", class_name="bytes"),
            "type": PyType(kind=TypeKind.CLASS, name="type", class_name="type"),
            "object": PyType(kind=TypeKind.CLASS, name="object", class_name="object"),
            "None": PyType.none(),
            "True": PyType.literal_(True),
            "False": PyType.literal_(False),
            "Ellipsis": PyType(kind=TypeKind.INSTANCE, name="ellipsis"),
            "NotImplemented": PyType(kind=TypeKind.INSTANCE, name="NotImplementedType"),
            "len": PyType.callable_([PyType.any_()], PyType.int_()),
            "range": PyType.callable_([PyType.int_()], PyType.instance("range")),
            "enumerate": PyType.callable_([PyType.any_()], PyType.instance("enumerate")),
            "zip": PyType.callable_([PyType.any_()], PyType.instance("zip")),
            "map": PyType.callable_([PyType.any_(), PyType.any_()], PyType.instance("map")),
            "filter": PyType.callable_([PyType.any_(), PyType.any_()], PyType.instance("filter")),
            "sorted": PyType.callable_([PyType.any_()], PyType.list_()),
            "reversed": PyType.callable_([PyType.any_()], PyType.instance("reversed")),
            "min": PyType.callable_([PyType.any_()], PyType.any_()),
            "max": PyType.callable_([PyType.any_()], PyType.any_()),
            "sum": PyType.callable_([PyType.any_()], PyType.union_(PyType.int_(), PyType.float_())),
            "abs": PyType.callable_([PyType.any_()], PyType.union_(PyType.int_(), PyType.float_())),
            "round": PyType.callable_([PyType.float_()], PyType.int_()),
            "pow": PyType.callable_([PyType.any_(), PyType.any_()], PyType.any_()),
            "divmod": PyType.callable_(
                [PyType.any_(), PyType.any_()], PyType.tuple_(PyType.any_(), PyType.any_())
            ),
            "hash": PyType.callable_([PyType.any_()], PyType.int_()),
            "id": PyType.callable_([PyType.any_()], PyType.int_()),
            "isinstance": PyType.callable_([PyType.any_(), PyType.any_()], PyType.bool_()),
            "issubclass": PyType.callable_([PyType.any_(), PyType.any_()], PyType.bool_()),
            "callable": PyType.callable_([PyType.any_()], PyType.bool_()),
            "hasattr": PyType.callable_([PyType.any_(), PyType.str_()], PyType.bool_()),
            "getattr": PyType.callable_([PyType.any_(), PyType.str_()], PyType.any_()),
            "setattr": PyType.callable_(
                [PyType.any_(), PyType.str_(), PyType.any_()], PyType.none()
            ),
            "delattr": PyType.callable_([PyType.any_(), PyType.str_()], PyType.none()),
            "repr": PyType.callable_([PyType.any_()], PyType.str_()),
            "str": PyType.callable_([PyType.any_()], PyType.str_()),
            "int": PyType.callable_([PyType.any_()], PyType.int_()),
            "float": PyType.callable_([PyType.any_()], PyType.float_()),
            "bool": PyType.callable_([PyType.any_()], PyType.bool_()),
            "print": PyType.callable_([], PyType.none()),
            "input": PyType.callable_([], PyType.str_()),
            "open": PyType.callable_([PyType.str_()], PyType.instance("TextIOWrapper")),
            "iter": PyType.callable_([PyType.any_()], PyType.instance("iterator")),
            "next": PyType.callable_([PyType.any_()], PyType.any_()),
            "all": PyType.callable_([PyType.any_()], PyType.bool_()),
            "any": PyType.callable_([PyType.any_()], PyType.bool_()),
            "ord": PyType.callable_([PyType.str_()], PyType.int_()),
            "chr": PyType.callable_([PyType.int_()], PyType.str_()),
            "hex": PyType.callable_([PyType.int_()], PyType.str_()),
            "oct": PyType.callable_([PyType.int_()], PyType.str_()),
            "bin": PyType.callable_([PyType.int_()], PyType.str_()),
            "format": PyType.callable_([PyType.any_()], PyType.str_()),
            "vars": PyType.callable_([], PyType.dict_(PyType.str_(), PyType.any_())),
            "dir": PyType.callable_([], PyType.list_(PyType.str_())),
            "globals": PyType.callable_([], PyType.dict_(PyType.str_(), PyType.any_())),
            "locals": PyType.callable_([], PyType.dict_(PyType.str_(), PyType.any_())),
            "exec": PyType.callable_([PyType.str_()], PyType.none()),
            "eval": PyType.callable_([PyType.str_()], PyType.any_()),
            "compile": PyType.callable_([PyType.str_()], PyType.instance("code")),
            "type": PyType.callable_([PyType.any_()], PyType(kind=TypeKind.CLASS, name="type")),
            "super": PyType.callable_([], PyType.instance("super")),
            "property": PyType.callable_([], PyType.instance("property")),
            "staticmethod": PyType.callable_([PyType.any_()], PyType.instance("staticmethod")),
            "classmethod": PyType.callable_([PyType.any_()], PyType.instance("classmethod")),
            "slice": PyType.callable_([], PyType.instance("slice")),
            "memoryview": PyType.callable_([PyType.bytes_()], PyType.instance("memoryview")),
            "bytearray": PyType.callable_([], PyType.instance("bytearray")),
            "frozenset": PyType.callable_([], PyType(kind=TypeKind.FROZENSET, name="frozenset")),
            "complex": PyType.callable_([], PyType(kind=TypeKind.COMPLEX, name="complex")),
            "Exception": PyType(kind=TypeKind.CLASS, name="Exception", class_name="Exception"),
            "BaseException": PyType(
                kind=TypeKind.CLASS, name="BaseException", class_name="BaseException"
            ),
            "ValueError": PyType(kind=TypeKind.CLASS, name="ValueError", class_name="ValueError"),
            "TypeError": PyType(kind=TypeKind.CLASS, name="TypeError", class_name="TypeError"),
            "KeyError": PyType(kind=TypeKind.CLASS, name="KeyError", class_name="KeyError"),
            "IndexError": PyType(kind=TypeKind.CLASS, name="IndexError", class_name="IndexError"),
            "AttributeError": PyType(
                kind=TypeKind.CLASS, name="AttributeError", class_name="AttributeError"
            ),
            "RuntimeError": PyType(
                kind=TypeKind.CLASS, name="RuntimeError", class_name="RuntimeError"
            ),
            "StopIteration": PyType(
                kind=TypeKind.CLASS, name="StopIteration", class_name="StopIteration"
            ),
        }
        return builtin_types.get(name)


class TypeInferenceEngine:
    """
    Main type inference engine.
    Performs:
    - Forward type propagation
    - Flow-sensitive type narrowing
    - Pattern-based inference
    - Type annotation integration
    """

    def __init__(self) -> None:
        self.environments: dict[int, TypeEnvironment] = {}
        self.function_signatures: dict[str, tuple[list[PyType], PyType]] = {}
        self.class_attributes: dict[str, dict[str, PyType]] = {}
        self._inference_cache: dict[tuple[str, int], PyType] = {}

    def infer_from_annotation(self, annotation: Any) -> PyType:
        """Convert a type annotation to PyType."""
        if annotation is None:
            return PyType.any_()
        if annotation is type(None):
            return PyType.none()
        if annotation is int:
            return PyType.int_()
        if annotation is str:
            return PyType.str_()
        if annotation is float:
            return PyType.float_()
        if annotation is bool:
            return PyType.bool_()
        if annotation is bytes:
            return PyType.bytes_()
        origin = getattr(annotation, "__origin__", None)
        args = getattr(annotation, "__args__", ())
        if origin is list:
            elem_type = self.infer_from_annotation(args[0]) if args else PyType.any_()
            return PyType.list_(elem_type)
        if origin is dict:
            key_type = self.infer_from_annotation(args[0]) if args else PyType.any_()
            val_type = self.infer_from_annotation(args[1]) if len(args) > 1 else PyType.any_()
            return PyType.dict_(key_type, val_type)
        if origin is set:
            elem_type = self.infer_from_annotation(args[0]) if args else PyType.any_()
            return PyType.set_(elem_type)
        if origin is tuple:
            if args:
                elem_types = tuple(self.infer_from_annotation(a) for a in args)
                return PyType.tuple_(*elem_types)
            return PyType.tuple_()
        if origin is Union:
            member_types = [self.infer_from_annotation(a) for a in args]
            return PyType.union_(*member_types)
        if origin is Union and len(args) == 2 and type(None) in args:
            inner = args[0] if args[1] is type(None) else args[1]
            return PyType.optional_(self.infer_from_annotation(inner))
        if isinstance(annotation, str):
            return self._parse_string_annotation(annotation)
        if isinstance(annotation, type):
            return PyType.instance(annotation.__name__)
        return PyType.any_()

    def _parse_string_annotation(self, annotation: str) -> PyType:
        """Parse a string type annotation."""
        annotation = annotation.strip()
        if annotation == "None":
            return PyType.none()
        basic_types = {
            "int": PyType.int_(),
            "str": PyType.str_(),
            "float": PyType.float_(),
            "bool": PyType.bool_(),
            "bytes": PyType.bytes_(),
            "Any": PyType.any_(),
        }
        if annotation in basic_types:
            return basic_types[annotation]
        if annotation.startswith("Optional[") and annotation.endswith("]"):
            inner = annotation[9:-1]
            return PyType.optional_(self._parse_string_annotation(inner))
        if annotation.startswith("list[") and annotation.endswith("]"):
            inner = annotation[5:-1]
            return PyType.list_(self._parse_string_annotation(inner))
        if annotation.startswith("List[") and annotation.endswith("]"):
            inner = annotation[5:-1]
            return PyType.list_(self._parse_string_annotation(inner))
        if annotation.startswith("dict[") or annotation.startswith("Dict["):
            inner = annotation[5:-1] if annotation.startswith("dict[") else annotation[5:-1]
            parts = inner.split(",", 1)
            if len(parts) == 2:
                key_type = self._parse_string_annotation(parts[0].strip())
                val_type = self._parse_string_annotation(parts[1].strip())
                return PyType.dict_(key_type, val_type)
        if annotation.startswith("set[") or annotation.startswith("Set["):
            inner = annotation[4:-1]
            return PyType.set_(self._parse_string_annotation(inner))
        if annotation.startswith("tuple[") or annotation.startswith("Tuple["):
            inner = annotation[6:-1]
            parts = [p.strip() for p in inner.split(",")]
            elem_types = [self._parse_string_annotation(p) for p in parts]
            return PyType.tuple_(*elem_types)
        if annotation.startswith("Union[") and annotation.endswith("]"):
            inner = annotation[6:-1]
            parts = [p.strip() for p in inner.split(",")]
            member_types = [self._parse_string_annotation(p) for p in parts]
            return PyType.union_(*member_types)
        return PyType.instance(annotation)

    def infer_function_signature(self, func: Callable) -> tuple[list[PyType], PyType]:
        """Infer parameter and return types for a function."""
        func_name = getattr(func, "__qualname__", str(func))
        if func_name in self.function_signatures:
            return self.function_signatures[func_name]
        try:
            hints = get_type_hints(func)
        except Exception:
            hints = {}
        sig = inspect.signature(func)
        param_types: list[PyType] = []
        for param_name, param in sig.parameters.items():
            if param_name in hints:
                param_types.append(self.infer_from_annotation(hints[param_name]))
            elif param.default is not inspect.Parameter.empty:
                param_types.append(self.infer_from_value(param.default))
            else:
                param_types.append(PyType.any_())
        return_type = self.infer_from_annotation(hints.get("return", None))
        self.function_signatures[func_name] = (param_types, return_type)
        return param_types, return_type

    def infer_from_value(self, value: Any) -> PyType:
        """Infer type from a concrete Python value."""
        if value is None:
            return PyType.none()
        if isinstance(value, bool):
            return PyType.literal_(value)
        if isinstance(value, int):
            return PyType.int_()
        if isinstance(value, float):
            return PyType.float_()
        if isinstance(value, str):
            if len(value) <= 50:
                return PyType.literal_(value)
            return PyType.str_()
        if isinstance(value, bytes):
            return PyType.bytes_()
        if isinstance(value, list):
            if not value:
                return PyType.list_()
            elem_types = [self.infer_from_value(e) for e in value[:5]]
            combined = elem_types[0]
            for t in elem_types[1:]:
                combined = combined.join(t)
            return PyType.list_(combined)
        if isinstance(value, dict):
            if not value:
                return PyType.dict_()
            keys = list(value.keys())[:5]
            vals = list(value.values())[:5]
            key_types = [self.infer_from_value(k) for k in keys]
            val_types = [self.infer_from_value(v) for v in vals]
            key_type = key_types[0]
            val_type = val_types[0]
            for t in key_types[1:]:
                key_type = key_type.join(t)
            for t in val_types[1:]:
                val_type = val_type.join(t)
            return PyType.dict_(key_type, val_type)
        if isinstance(value, set):
            if not value:
                return PyType.set_()
            elem_types = [self.infer_from_value(e) for e in list(value)[:5]]
            combined = elem_types[0]
            for t in elem_types[1:]:
                combined = combined.join(t)
            return PyType.set_(combined)
        if isinstance(value, tuple):
            elem_types = tuple(self.infer_from_value(e) for e in value)
            return PyType.tuple_(*elem_types)
        if isinstance(value, frozenset):
            if not value:
                return PyType(kind=TypeKind.FROZENSET, name="frozenset")
            elem_types = [self.infer_from_value(e) for e in list(value)[:5]]
            combined = elem_types[0]
            for t in elem_types[1:]:
                combined = combined.join(t)
            return PyType(
                kind=TypeKind.FROZENSET,
                name="frozenset",
                params=(combined,),
            )
        if callable(value):
            try:
                param_types, return_type = self.infer_function_signature(value)
                return PyType.callable_(param_types, return_type)
            except Exception:
                return PyType(kind=TypeKind.CALLABLE, name="Callable")
        return PyType.instance(type(value).__name__)

    def infer_binary_op_result(
        self,
        op: str,
        left: PyType,
        right: PyType,
    ) -> PyType:
        """Infer result type of a binary operation."""
        if op in {"+", "-", "*", "/", "//", "%", "**"}:
            if left.is_numeric() and right.is_numeric():
                if op == "/":
                    return PyType.float_()
                if left.kind == TypeKind.COMPLEX or right.kind == TypeKind.COMPLEX:
                    return PyType(kind=TypeKind.COMPLEX, name="complex")
                if left.kind == TypeKind.FLOAT or right.kind == TypeKind.FLOAT:
                    return PyType.float_()
                return PyType.int_()
            if op == "+" and left.kind == TypeKind.STR and right.kind == TypeKind.STR:
                return PyType.str_()
            if op == "*":
                if left.kind == TypeKind.STR and right.kind == TypeKind.INT:
                    return PyType.str_()
                if left.kind == TypeKind.INT and right.kind == TypeKind.STR:
                    return PyType.str_()
                if left.kind == TypeKind.LIST and right.kind == TypeKind.INT:
                    return left
                if left.kind == TypeKind.INT and right.kind == TypeKind.LIST:
                    return right
            if op == "+" and left.kind == TypeKind.LIST and right.kind == TypeKind.LIST:
                elem_type = left.get_element_type().join(right.get_element_type())
                return PyType.list_(elem_type)
        if op in {"==", "!=", "<", ">", "<=", ">=", "is", "is not", "in", "not in"}:
            return PyType.bool_()
        if op in {"&", "|", "^", "<<", ">>", "~"}:
            if left.kind == TypeKind.INT and right.kind == TypeKind.INT:
                return PyType.int_()
            if left.kind == TypeKind.BOOL and right.kind == TypeKind.BOOL:
                return PyType.bool_()
            if left.kind == TypeKind.SET and right.kind == TypeKind.SET:
                return left
        if op in {"and", "or"}:
            return left.join(right)
        return PyType.any_()

    def infer_unary_op_result(self, op: str, operand: PyType) -> PyType:
        """Infer result type of a unary operation."""
        if op == "-":
            if operand.is_numeric():
                return operand
        if op == "+":
            if operand.is_numeric():
                return operand
        if op == "~":
            if operand.kind == TypeKind.INT:
                return PyType.int_()
        if op == "not":
            return PyType.bool_()
        return PyType.any_()

    def infer_subscript_result(
        self,
        container: PyType,
        index: PyType,
    ) -> PyType:
        """Infer result type of a subscript operation."""
        if container.kind in {TypeKind.LIST, TypeKind.DEQUE}:
            return container.get_element_type()
        if container.kind == TypeKind.TUPLE:
            if index.kind == TypeKind.LITERAL and index.literal_values:
                for val in index.literal_values:
                    if isinstance(val, int) and 0 <= val < len(container.params):
                        return container.params[val]
            if container.params:
                return PyType.union_(*container.params)
            return PyType.any_()
        if container.kind in {TypeKind.DICT, TypeKind.DEFAULTDICT}:
            return container.get_value_type()
        if container.kind == TypeKind.STR:
            return PyType.str_()
        if container.kind == TypeKind.BYTES:
            return PyType.int_()
        return PyType.any_()

    def infer_attribute_result(
        self,
        obj: PyType,
        attr_name: str,
    ) -> PyType:
        """Infer result type of an attribute access."""
        if attr_name in obj.attributes:
            return obj.attributes[attr_name]
        if obj.kind == TypeKind.STR:
            str_methods = {
                "lower": PyType.callable_([], PyType.str_()),
                "upper": PyType.callable_([], PyType.str_()),
                "strip": PyType.callable_([], PyType.str_()),
                "lstrip": PyType.callable_([], PyType.str_()),
                "rstrip": PyType.callable_([], PyType.str_()),
                "split": PyType.callable_([], PyType.list_(PyType.str_())),
                "rsplit": PyType.callable_([], PyType.list_(PyType.str_())),
                "join": PyType.callable_([PyType.any_()], PyType.str_()),
                "replace": PyType.callable_([PyType.str_(), PyType.str_()], PyType.str_()),
                "find": PyType.callable_([PyType.str_()], PyType.int_()),
                "rfind": PyType.callable_([PyType.str_()], PyType.int_()),
                "index": PyType.callable_([PyType.str_()], PyType.int_()),
                "rindex": PyType.callable_([PyType.str_()], PyType.int_()),
                "count": PyType.callable_([PyType.str_()], PyType.int_()),
                "startswith": PyType.callable_([PyType.str_()], PyType.bool_()),
                "endswith": PyType.callable_([PyType.str_()], PyType.bool_()),
                "isdigit": PyType.callable_([], PyType.bool_()),
                "isalpha": PyType.callable_([], PyType.bool_()),
                "isalnum": PyType.callable_([], PyType.bool_()),
                "isspace": PyType.callable_([], PyType.bool_()),
                "isupper": PyType.callable_([], PyType.bool_()),
                "islower": PyType.callable_([], PyType.bool_()),
                "title": PyType.callable_([], PyType.str_()),
                "capitalize": PyType.callable_([], PyType.str_()),
                "swapcase": PyType.callable_([], PyType.str_()),
                "encode": PyType.callable_([], PyType.bytes_()),
                "format": PyType.callable_([], PyType.str_()),
                "format_map": PyType.callable_([PyType.any_()], PyType.str_()),
                "center": PyType.callable_([PyType.int_()], PyType.str_()),
                "ljust": PyType.callable_([PyType.int_()], PyType.str_()),
                "rjust": PyType.callable_([PyType.int_()], PyType.str_()),
                "zfill": PyType.callable_([PyType.int_()], PyType.str_()),
                "partition": PyType.callable_(
                    [PyType.str_()], PyType.tuple_(PyType.str_(), PyType.str_(), PyType.str_())
                ),
                "rpartition": PyType.callable_(
                    [PyType.str_()], PyType.tuple_(PyType.str_(), PyType.str_(), PyType.str_())
                ),
                "expandtabs": PyType.callable_([], PyType.str_()),
                "splitlines": PyType.callable_([], PyType.list_(PyType.str_())),
                "translate": PyType.callable_([PyType.any_()], PyType.str_()),
                "maketrans": PyType.callable_([], PyType.dict_(PyType.int_(), PyType.any_())),
                "removeprefix": PyType.callable_([PyType.str_()], PyType.str_()),
                "removesuffix": PyType.callable_([PyType.str_()], PyType.str_()),
            }
            if attr_name in str_methods:
                return str_methods[attr_name]
        if obj.kind == TypeKind.LIST:
            elem_type = obj.get_element_type()
            list_methods = {
                "append": PyType.callable_([elem_type], PyType.none()),
                "extend": PyType.callable_([PyType.any_()], PyType.none()),
                "insert": PyType.callable_([PyType.int_(), elem_type], PyType.none()),
                "remove": PyType.callable_([elem_type], PyType.none()),
                "pop": PyType.callable_([], elem_type),
                "clear": PyType.callable_([], PyType.none()),
                "index": PyType.callable_([elem_type], PyType.int_()),
                "count": PyType.callable_([elem_type], PyType.int_()),
                "sort": PyType.callable_([], PyType.none()),
                "reverse": PyType.callable_([], PyType.none()),
                "copy": PyType.callable_([], obj),
            }
            if attr_name in list_methods:
                return list_methods[attr_name]
        if obj.kind in {TypeKind.DICT, TypeKind.DEFAULTDICT}:
            key_type = obj.get_key_type()
            val_type = obj.get_value_type()
            dict_methods = {
                "keys": PyType.callable_([], PyType.instance("dict_keys")),
                "values": PyType.callable_([], PyType.instance("dict_values")),
                "items": PyType.callable_([], PyType.instance("dict_items")),
                "get": PyType.callable_([key_type], PyType.optional_(val_type)),
                "pop": PyType.callable_([key_type], val_type),
                "popitem": PyType.callable_([], PyType.tuple_(key_type, val_type)),
                "setdefault": PyType.callable_([key_type, val_type], val_type),
                "update": PyType.callable_([PyType.any_()], PyType.none()),
                "clear": PyType.callable_([], PyType.none()),
                "copy": PyType.callable_([], obj),
                "fromkeys": PyType.callable_([PyType.any_()], obj),
            }
            if attr_name in dict_methods:
                return dict_methods[attr_name]
        if obj.kind == TypeKind.SET:
            elem_type = obj.get_element_type()
            set_methods = {
                "add": PyType.callable_([elem_type], PyType.none()),
                "remove": PyType.callable_([elem_type], PyType.none()),
                "discard": PyType.callable_([elem_type], PyType.none()),
                "pop": PyType.callable_([], elem_type),
                "clear": PyType.callable_([], PyType.none()),
                "copy": PyType.callable_([], obj),
                "update": PyType.callable_([PyType.any_()], PyType.none()),
                "union": PyType.callable_([PyType.any_()], obj),
                "intersection": PyType.callable_([PyType.any_()], obj),
                "difference": PyType.callable_([PyType.any_()], obj),
                "symmetric_difference": PyType.callable_([PyType.any_()], obj),
                "issubset": PyType.callable_([PyType.any_()], PyType.bool_()),
                "issuperset": PyType.callable_([PyType.any_()], PyType.bool_()),
                "isdisjoint": PyType.callable_([PyType.any_()], PyType.bool_()),
            }
            if attr_name in set_methods:
                return set_methods[attr_name]
        if obj.kind == TypeKind.DEQUE:
            elem_type = obj.get_element_type()
            deque_methods = {
                "append": PyType.callable_([elem_type], PyType.none()),
                "appendleft": PyType.callable_([elem_type], PyType.none()),
                "pop": PyType.callable_([], elem_type),
                "popleft": PyType.callable_([], elem_type),
                "extend": PyType.callable_([PyType.any_()], PyType.none()),
                "extendleft": PyType.callable_([PyType.any_()], PyType.none()),
                "clear": PyType.callable_([], PyType.none()),
                "copy": PyType.callable_([], obj),
                "rotate": PyType.callable_([PyType.int_()], PyType.none()),
                "count": PyType.callable_([elem_type], PyType.int_()),
                "index": PyType.callable_([elem_type], PyType.int_()),
                "insert": PyType.callable_([PyType.int_(), elem_type], PyType.none()),
                "remove": PyType.callable_([elem_type], PyType.none()),
                "reverse": PyType.callable_([], PyType.none()),
                "maxlen": PyType.optional_(PyType.int_()),
            }
            if attr_name in deque_methods:
                return deque_methods[attr_name]
        return PyType.any_()

    def infer_call_result(
        self,
        callee: PyType,
        args: list[PyType],
        kwargs: dict[str, PyType],
    ) -> PyType:
        """Infer result type of a function call."""
        if callee.kind == TypeKind.CALLABLE:
            return callee.get_return_type()
        if callee.kind == TypeKind.CLASS:
            class_name = callee.class_name or callee.name
            if class_name == "int":
                return PyType.int_()
            if class_name == "str":
                return PyType.str_()
            if class_name == "float":
                return PyType.float_()
            if class_name == "bool":
                return PyType.bool_()
            if class_name == "list":
                return PyType.list_()
            if class_name == "dict":
                return PyType.dict_()
            if class_name == "set":
                return PyType.set_()
            if class_name == "tuple":
                return PyType.tuple_()
            if class_name == "bytes":
                return PyType.bytes_()
            return PyType.instance(class_name)
        return PyType.any_()

    def narrow_type_for_isinstance(
        self,
        var_type: PyType,
        check_type: PyType,
        positive: bool = True,
    ) -> PyType:
        """
        Narrow a type based on isinstance() check.
        Args:
            var_type: Current type of the variable
            check_type: Type being checked against
            positive: True if check passed, False if failed
        Returns:
            Narrowed type
        """
        if positive:
            return var_type.meet(check_type)
        else:
            if var_type.kind == TypeKind.UNION:
                remaining = [m for m in var_type.union_members if not m.is_subtype_of(check_type)]
                if not remaining:
                    return PyType.bottom()
                if len(remaining) == 1:
                    return remaining[0]
                return PyType.union_(*remaining)
            if var_type.is_subtype_of(check_type):
                return PyType.bottom()
            return var_type

    def narrow_type_for_none_check(
        self,
        var_type: PyType,
        is_none: bool,
    ) -> PyType:
        """
        Narrow type based on None check.
        Args:
            var_type: Current type
            is_none: True if "x is None" passed, False if "x is not None" passed
        Returns:
            Narrowed type
        """
        if is_none:
            return PyType.none()
        else:
            return var_type.without_none()

    def narrow_type_for_truthiness(
        self,
        var_type: PyType,
        is_truthy: bool,
    ) -> PyType:
        """
        Narrow type based on truthiness check (if x:).
        Args:
            var_type: Current type
            is_truthy: True if truthy branch, False if falsy branch
        Returns:
            Narrowed type
        """
        if is_truthy:
            narrowed = var_type.without_none()
            return narrowed
        else:
            return var_type


class PatternRecognizer:
    """
    Recognizes common Python patterns that affect type inference.
    Patterns recognized:
    - defaultdict usage
    - dict.get() with default
    - isinstance() checks
    - None checks (is None, is not None)
    - Type guards
    - Container membership tests
    - Exception handling
    """

    def __init__(self, type_engine: TypeInferenceEngine) -> None:
        self.type_engine = type_engine

    def is_dict_get_pattern(
        self,
        callee_type: PyType,
        method_name: str,
        args: list[PyType],
    ) -> PyType | None:
        """
        Recognize dict.get() pattern.
        dict.get(key) returns Optional[V]
        dict.get(key, default) returns V | type(default)
        """
        if callee_type.kind not in {TypeKind.DICT, TypeKind.DEFAULTDICT}:
            return None
        if method_name != "get":
            return None
        val_type = callee_type.get_value_type()
        if len(args) == 1:
            return PyType.optional_(val_type)
        if len(args) >= 2:
            default_type = args[1]
            return val_type.join(default_type)
        return None

    def is_defaultdict_pattern(
        self,
        container_type: PyType,
    ) -> bool:
        """Check if this is a defaultdict (no KeyError on missing keys)."""
        return container_type.kind == TypeKind.DEFAULTDICT

    def is_safe_dict_access(
        self,
        container_type: PyType,
        access_method: str,
    ) -> bool:
        """
        Check if dictionary access is safe (won't raise KeyError).
        Safe patterns:
        - defaultdict[key]
        - dict.get(key)
        - dict.get(key, default)
        - dict.setdefault(key, default)
        - key in dict before dict[key]
        """
        if container_type.kind == TypeKind.DEFAULTDICT:
            return True
        if access_method in {"get", "setdefault", "pop"}:
            return True
        return False

    def is_membership_guard(
        self,
        guard_var: str,
        guarded_var: str,
        container_var: str,
    ) -> bool:
        """
        Check if a variable access is guarded by a membership test.
        Pattern: if key in dict: dict[key]
        """
        return guard_var == guarded_var

    def recognize_iteration_pattern(
        self,
        container_type: PyType,
    ) -> PyType | None:
        """
        Recognize type of iteration variable.
        for x in list[T]: x is T
        for k in dict[K, V]: k is K
        for k, v in dict.items(): k is K, v is V
        """
        if container_type.kind == TypeKind.LIST:
            return container_type.get_element_type()
        if container_type.kind == TypeKind.SET:
            return container_type.get_element_type()
        if container_type.kind == TypeKind.TUPLE:
            if container_type.params:
                return PyType.union_(*container_type.params)
            return PyType.any_()
        if container_type.kind in {TypeKind.DICT, TypeKind.DEFAULTDICT}:
            return container_type.get_key_type()
        if container_type.kind == TypeKind.STR:
            return PyType.str_()
        if container_type.kind == TypeKind.DEQUE:
            return container_type.get_element_type()
        return None

    def recognize_dict_items_pattern(
        self,
        container_type: PyType,
        method_name: str,
    ) -> tuple[PyType, PyType] | None:
        """
        Recognize dict.items() iteration pattern.
        for k, v in dict.items(): returns (K, V)
        """
        if container_type.kind not in {TypeKind.DICT, TypeKind.DEFAULTDICT}:
            return None
        if method_name != "items":
            return None
        return (container_type.get_key_type(), container_type.get_value_type())

    def is_string_operation_safe(
        self,
        left_type: PyType,
        right_type: PyType,
        op: str,
    ) -> bool:
        """
        Check if a string operation is type-safe.
        Safe: str + str, str * int, int * str
        Unsafe: str + int, str - str
        """
        if op == "+":
            return left_type.kind == TypeKind.STR and right_type.kind == TypeKind.STR
        if op == "*":
            return (left_type.kind == TypeKind.STR and right_type.kind == TypeKind.INT) or (
                left_type.kind == TypeKind.INT and right_type.kind == TypeKind.STR
            )
        return False


@dataclass
class TypeState:
    """
    Represents type state at a program point.
    Tracks:
    - Variable types
    - Refinements from control flow
    - Definitely/maybe assigned
    """

    env: TypeEnvironment
    pc: int = 0
    in_try_block: bool = False
    in_except_block: bool = False
    in_finally_block: bool = False
    loop_depth: int = 0
    in_loop_body: bool = False
    branch_condition: str | None = None
    positive_branch: bool = True

    def copy(self) -> TypeState:
        """Create a copy of this state."""
        return TypeState(
            env=self.env.copy(),
            pc=self.pc,
            in_try_block=self.in_try_block,
            in_except_block=self.in_except_block,
            in_finally_block=self.in_finally_block,
            loop_depth=self.loop_depth,
            in_loop_body=self.in_loop_body,
            branch_condition=self.branch_condition,
            positive_branch=self.positive_branch,
        )

    def join(self, other: TypeState) -> TypeState:
        """Join two states at a merge point."""
        return TypeState(
            env=self.env.join(other.env),
            pc=max(self.pc, other.pc),
            in_try_block=self.in_try_block or other.in_try_block,
            in_except_block=self.in_except_block or other.in_except_block,
            in_finally_block=self.in_finally_block or other.in_finally_block,
            loop_depth=max(self.loop_depth, other.loop_depth),
            in_loop_body=self.in_loop_body or other.in_loop_body,
        )


class TypeStateMachine:
    """
    Tracks type state through control flow.
    Handles:
    - If/else branches with type narrowing
    - Loop iterations with widening
    - Try/except/finally blocks
    - Function calls and returns
    """

    def __init__(
        self,
        type_engine: TypeInferenceEngine,
        pattern_recognizer: PatternRecognizer,
    ) -> None:
        self.type_engine = type_engine
        self.pattern_recognizer = pattern_recognizer
        self.states: dict[int, TypeState] = {}
        self.pending: list[TypeState] = []
        self.branch_narrowings: dict[int, dict[str, PyType]] = defaultdict(dict)

    def get_state(self, pc: int) -> TypeState | None:
        """Get type state at a program point."""
        return self.states.get(pc)

    def set_state(self, pc: int, state: TypeState) -> None:
        """Set type state at a program point."""
        self.states[pc] = state

    def enter_branch(
        self,
        state: TypeState,
        condition_var: str,
        condition_type: PyType,
        positive: bool,
    ) -> TypeState:
        """
        Enter a branch with type narrowing.
        Args:
            state: Current state
            condition_var: Variable in condition
            condition_type: Type from condition (e.g., the class in isinstance)
            positive: True for if branch, False for else branch
        Returns:
            New state with narrowed types
        """
        new_state = state.copy()
        new_state.branch_condition = condition_var
        new_state.positive_branch = positive
        current_type = new_state.env.get_type(condition_var)
        narrowed = self.type_engine.narrow_type_for_isinstance(
            current_type, condition_type, positive
        )
        new_state.env.refine_type(condition_var, narrowed)
        return new_state

    def enter_none_branch(
        self,
        state: TypeState,
        var_name: str,
        is_none: bool,
    ) -> TypeState:
        """Enter a branch after None check."""
        new_state = state.copy()
        current_type = new_state.env.get_type(var_name)
        narrowed = self.type_engine.narrow_type_for_none_check(current_type, is_none)
        new_state.env.refine_type(var_name, narrowed)
        return new_state

    def enter_truthiness_branch(
        self,
        state: TypeState,
        var_name: str,
        is_truthy: bool,
    ) -> TypeState:
        """Enter a branch after truthiness check."""
        new_state = state.copy()
        current_type = new_state.env.get_type(var_name)
        narrowed = self.type_engine.narrow_type_for_truthiness(current_type, is_truthy)
        new_state.env.refine_type(var_name, narrowed)
        return new_state

    def merge_branches(
        self,
        states: list[TypeState],
    ) -> TypeState:
        """Merge states from multiple branches."""
        if not states:
            raise ValueError("Cannot merge empty state list")
        if len(states) == 1:
            result = states[0].copy()
            result.env.refinements.clear()
            return result
        result = states[0]
        for state in states[1:]:
            result = result.join(state)
        result.env.refinements.clear()
        return result

    def enter_loop(self, state: TypeState) -> TypeState:
        """Enter a loop body."""
        new_state = state.copy()
        new_state.loop_depth += 1
        new_state.in_loop_body = True
        return new_state

    def exit_loop(self, state: TypeState) -> TypeState:
        """Exit a loop body."""
        new_state = state.copy()
        new_state.loop_depth = max(0, new_state.loop_depth - 1)
        new_state.in_loop_body = new_state.loop_depth > 0
        return new_state

    def widen_loop_state(
        self,
        before: TypeState,
        after: TypeState,
    ) -> TypeState:
        """Apply widening for loop convergence."""
        result = after.copy()
        for var in set(before.env.types.keys()) | set(after.env.types.keys()):
            before_type = before.env.get_type(var)
            after_type = after.env.get_type(var)
            if before_type != after_type:
                result.env.types[var] = before_type.join(after_type)
        return result

    def enter_try_block(self, state: TypeState) -> TypeState:
        """Enter a try block."""
        new_state = state.copy()
        new_state.in_try_block = True
        return new_state

    def enter_except_block(
        self,
        state: TypeState,
        exception_var: str | None = None,
        exception_type: PyType | None = None,
    ) -> TypeState:
        """Enter an except block."""
        new_state = state.copy()
        new_state.in_try_block = False
        new_state.in_except_block = True
        if exception_var and exception_type:
            new_state.env.set_type(exception_var, exception_type)
        return new_state

    def enter_finally_block(self, state: TypeState) -> TypeState:
        """Enter a finally block."""
        new_state = state.copy()
        new_state.in_try_block = False
        new_state.in_except_block = False
        new_state.in_finally_block = True
        return new_state

    def exit_exception_handling(self, state: TypeState) -> TypeState:
        """Exit exception handling blocks."""
        new_state = state.copy()
        new_state.in_try_block = False
        new_state.in_except_block = False
        new_state.in_finally_block = False
        return new_state


@dataclass
class ConfidenceScore:
    """
    Confidence score for type inference.
    Factors:
    - Source reliability (annotation > inference > unknown)
    - Path length (shorter paths = higher confidence)
    - Corroboration (multiple sources agreeing)
    - Narrowing (type guards increase confidence)
    """

    score: float
    source: str
    factors: dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_annotation(cls) -> ConfidenceScore:
        """High confidence from explicit annotation."""
        return cls(
            score=0.95,
            source="annotation",
            factors={"explicit": 0.95},
        )

    @classmethod
    def from_literal(cls) -> ConfidenceScore:
        """Very high confidence from literal value."""
        return cls(
            score=0.99,
            source="literal",
            factors={"literal": 0.99},
        )

    @classmethod
    def from_inference(cls, reliability: float = 0.7) -> ConfidenceScore:
        """Medium confidence from inference."""
        return cls(
            score=reliability,
            source="inferred",
            factors={"inference": reliability},
        )

    @classmethod
    def from_isinstance_guard(cls) -> ConfidenceScore:
        """High confidence from isinstance check."""
        return cls(
            score=0.9,
            source="isinstance_guard",
            factors={"type_guard": 0.9},
        )

    @classmethod
    def from_none_check(cls) -> ConfidenceScore:
        """High confidence from None check."""
        return cls(
            score=0.9,
            source="none_check",
            factors={"none_guard": 0.9},
        )

    @classmethod
    def unknown(cls) -> ConfidenceScore:
        """Low confidence for unknown."""
        return cls(
            score=0.3,
            source="unknown",
            factors={"unknown": 0.3},
        )

    def combine(self, other: ConfidenceScore) -> ConfidenceScore:
        """Combine confidence scores."""
        combined_score = min(self.score, other.score)
        combined_factors = {**self.factors, **other.factors}
        return ConfidenceScore(
            score=combined_score,
            source=f"{self.source}+{other.source}",
            factors=combined_factors,
        )

    def boost_from_guard(self, boost: float = 0.1) -> ConfidenceScore:
        """Boost confidence from a type guard."""
        new_score = min(1.0, self.score + boost)
        return ConfidenceScore(
            score=new_score,
            source=self.source,
            factors={**self.factors, "guard_boost": boost},
        )


class TypeAnalyzer:
    """
    Main type analysis integration for PySpectre.
    Combines:
    - Type inference engine
    - Pattern recognition
    - Type state tracking
    - Confidence scoring
    """

    def __init__(self) -> None:
        self.type_engine = TypeInferenceEngine()
        self.pattern_recognizer = PatternRecognizer(self.type_engine)
        self.state_machine = TypeStateMachine(self.type_engine, self.pattern_recognizer)
        self.confidence_scores: dict[tuple[int, str], ConfidenceScore] = {}

    def analyze_function(
        self,
        func: Callable | Any,
        initial_types: dict[str, PyType] | None = None,
    ) -> dict[int, TypeEnvironment]:
        """
        Perform type analysis on a function.
        Args:
            func: Function or code object to analyze
            initial_types: Optional initial type assignments
        Returns:
            Mapping from PC to type environment
        """
        initial_env = TypeEnvironment()

        if hasattr(func, "co_code"):
            code = func
            for var in code.co_varnames[: code.co_argcount]:
                initial_env.set_type(var, PyType.unknown())
        else:
            try:
                param_types, return_type = self.type_engine.infer_function_signature(func)
                sig = inspect.signature(func)
                for (param_name, _), param_type in zip(sig.parameters.items(), param_types):
                    initial_env.set_type(param_name, param_type)
            except (ValueError, TypeError):
                pass

        if initial_types:
            for name, typ in initial_types.items():
                initial_env.set_type(name, typ)

        initial_state = TypeState(env=initial_env, pc=0)
        self.state_machine.set_state(0, initial_state)

        return {pc: state.env for pc, state in self.state_machine.states.items()}

    def get_type_at(self, pc: int, var_name: str) -> PyType:
        """Get type of a variable at a program point."""
        state = self.state_machine.get_state(pc)
        if state:
            return state.env.get_type(var_name)
        return PyType.unknown()

    def get_confidence_at(self, pc: int, var_name: str) -> ConfidenceScore:
        """Get confidence score for a variable at a program point."""
        key = (pc, var_name)
        return self.confidence_scores.get(key, ConfidenceScore.unknown())

    def is_safe_subscript(
        self,
        pc: int,
        container_var: str,
        index_var: str,
    ) -> tuple[bool, str]:
        """
        Check if a subscript operation is safe.
        Returns:
            (is_safe, reason)
        """
        container_type = self.get_type_at(pc, container_var)
        index_type = self.get_type_at(pc, index_var)
        if container_type.kind == TypeKind.DEFAULTDICT:
            return True, "defaultdict never raises KeyError"
        if not container_type.is_subscriptable():
            return False, f"Type {container_type.name} is not subscriptable"
        if container_type.kind == TypeKind.DICT:
            key_type = container_type.get_key_type()
            if not index_type.is_subtype_of(key_type) and key_type.kind != TypeKind.ANY:
                return (
                    False,
                    f"Key type {index_type.name} doesn't match dict key type {key_type.name}",
                )
        if container_type.kind in {TypeKind.LIST, TypeKind.TUPLE, TypeKind.DEQUE}:
            if index_type.kind != TypeKind.INT and index_type.kind != TypeKind.LITERAL:
                pass
        return True, "No obvious type issue"

    def is_safe_binary_op(
        self,
        pc: int,
        left_var: str,
        right_var: str,
        op: str,
    ) -> tuple[bool, str]:
        """
        Check if a binary operation is type-safe.
        Returns:
            (is_safe, reason)
        """
        left_type = self.get_type_at(pc, left_var)
        right_type = self.get_type_at(pc, right_var)
        if op in {"+", "-", "*", "/", "//", "%", "**"}:
            if left_type.is_numeric() and right_type.is_numeric():
                return True, "Numeric operation"
            if op == "+":
                if left_type.kind == TypeKind.STR and right_type.kind == TypeKind.STR:
                    return True, "String concatenation"
                if left_type.kind == TypeKind.LIST and right_type.kind == TypeKind.LIST:
                    return True, "List concatenation"
                if left_type.kind == TypeKind.STR and right_type.kind != TypeKind.STR:
                    return False, f"Cannot concatenate str with {right_type.name}"
                if left_type.kind != TypeKind.STR and right_type.kind == TypeKind.STR:
                    return False, f"Cannot concatenate {left_type.name} with str"
            if op == "*":
                if left_type.kind == TypeKind.STR and right_type.kind == TypeKind.INT:
                    return True, "String repetition"
                if left_type.kind == TypeKind.INT and right_type.kind == TypeKind.STR:
                    return True, "String repetition"
                if left_type.kind == TypeKind.LIST and right_type.kind == TypeKind.INT:
                    return True, "List repetition"
                if left_type.kind == TypeKind.INT and right_type.kind == TypeKind.LIST:
                    return True, "List repetition"
                if left_type.kind == TypeKind.STR and right_type.kind != TypeKind.INT:
                    return False, f"Cannot multiply str with {right_type.name}"
        if op in {"/", "//", "%"}:
            if right_type.kind == TypeKind.LITERAL:
                for val in right_type.literal_values:
                    if val == 0:
                        return False, "Division by zero literal"
        return True, "No obvious type issue"

    def check_none_dereference(
        self,
        pc: int,
        var_name: str,
    ) -> tuple[bool, str]:
        """
        Check if a variable could be None when dereferenced.
        Returns:
            (could_be_none, reason)
        """
        var_type = self.get_type_at(pc, var_name)
        if var_type.kind == TypeKind.NONE:
            return True, "Variable is always None"
        if var_type.is_nullable():
            return True, "Variable could be None"
        return False, "Variable is not nullable"


_default_type_analyzer: TypeAnalyzer | None = None


def get_type_analyzer() -> TypeAnalyzer:
    """Get the default type analyzer instance."""
    global _default_type_analyzer
    if _default_type_analyzer is None:
        _default_type_analyzer = TypeAnalyzer()
    return _default_type_analyzer
