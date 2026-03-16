"""Type constraint types and data structures.

Contains the fundamental enums, dataclasses and type representations
used throughout the type constraint analysis system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


class TypeKind(Enum):
    """Kinds of types in the type system."""

    INT = auto()
    FLOAT = auto()
    BOOL = auto()
    STR = auto()
    BYTES = auto()
    NONE = auto()
    LIST = auto()
    TUPLE = auto()
    DICT = auto()
    SET = auto()
    FROZENSET = auto()
    ANY = auto()
    UNKNOWN = auto()
    NEVER = auto()
    OBJECT = auto()
    CALLABLE = auto()
    CLASS = auto()
    INSTANCE = auto()
    UNION = auto()
    INTERSECTION = auto()
    TYPE_VAR = auto()
    PARAM_SPEC = auto()
    TYPE_VAR_TUPLE = auto()
    LITERAL = auto()
    PROTOCOL = auto()


class Variance(Enum):
    """Variance of type parameters."""

    INVARIANT = auto()
    COVARIANT = auto()
    CONTRAVARIANT = auto()


@dataclass(frozen=True)
class SymbolicType:
    """
    Symbolic representation of a type for Z3 analysis.
    Immutable to allow use as dict keys and in sets.
    """

    kind: TypeKind
    name: str = ""
    args: tuple[SymbolicType, ...] = ()
    bounds: tuple[SymbolicType, ...] | None = None
    literal_values: frozenset[object] | None = None
    variance: Variance = Variance.INVARIANT

    @classmethod
    def int_type(cls) -> SymbolicType:
        return cls(TypeKind.INT, "int")

    @classmethod
    def float_type(cls) -> SymbolicType:
        return cls(TypeKind.FLOAT, "float")

    @classmethod
    def bool_type(cls) -> SymbolicType:
        return cls(TypeKind.BOOL, "bool")

    @classmethod
    def str_type(cls) -> SymbolicType:
        return cls(TypeKind.STR, "str")

    @classmethod
    def none_type(cls) -> SymbolicType:
        return cls(TypeKind.NONE, "None")

    @classmethod
    def any_type(cls) -> SymbolicType:
        return cls(TypeKind.ANY, "Any")

    @classmethod
    def never_type(cls) -> SymbolicType:
        return cls(TypeKind.NEVER, "Never")

    @classmethod
    def list_of(cls, element_type: SymbolicType) -> SymbolicType:
        return cls(TypeKind.LIST, "list", (element_type,))

    @classmethod
    def dict_of(cls, key_type: SymbolicType, value_type: SymbolicType) -> SymbolicType:
        return cls(TypeKind.DICT, "dict", (key_type, value_type))

    @classmethod
    def tuple_of(cls, *element_types: SymbolicType) -> SymbolicType:
        return cls(TypeKind.TUPLE, "tuple", element_types)

    @classmethod
    def union_of(cls, *types: SymbolicType) -> SymbolicType:
        """Union of."""
        flat_types: set[SymbolicType] = set()
        for t in types:
            if t.kind == TypeKind.UNION:
                flat_types.update(t.args)
            elif t.kind != TypeKind.NEVER:
                flat_types.add(t)
        if len(flat_types) == 0:
            return cls.never_type()
        if len(flat_types) == 1:
            return flat_types.pop()
        return cls(TypeKind.UNION, "Union", tuple(sorted(flat_types, key=str)))

    @classmethod
    def optional_of(cls, inner_type: SymbolicType) -> SymbolicType:
        """Shorthand for Union[T, None]."""
        return cls.union_of(inner_type, cls.none_type())

    @classmethod
    def callable_type(cls, params: list[SymbolicType], return_type: SymbolicType) -> SymbolicType:
        return cls(TypeKind.CALLABLE, "Callable", tuple(params) + (return_type,))

    @classmethod
    def type_var(
        cls, name: str, *bounds: SymbolicType, variance: Variance = Variance.INVARIANT
    ) -> SymbolicType:
        return cls(TypeKind.TYPE_VAR, name, bounds=bounds if bounds else None, variance=variance)

    @classmethod
    def literal(cls, *values: object) -> SymbolicType:
        return cls(TypeKind.LITERAL, "Literal", literal_values=frozenset(values))

    @classmethod
    def class_type(cls, name: str, bases: tuple[SymbolicType, ...] = ()) -> SymbolicType:
        return cls(TypeKind.CLASS, name, bases)

    def __str__(self) -> str:
        """Return a human-readable string representation."""
        if self.kind == TypeKind.UNION:
            return " | ".join(str(t) for t in self.args)
        elif self.kind == TypeKind.LIST:
            return f"list[{self .args [0 ]}]"
        elif self.kind == TypeKind.DICT:
            return f"dict[{self .args [0 ]}, {self .args [1 ]}]"
        elif self.kind == TypeKind.TUPLE:
            return f"tuple[{', '.join (str (t )for t in self .args )}]"
        elif self.kind == TypeKind.CALLABLE:
            params = ", ".join(str(t) for t in self.args[:-1])
            return f"Callable[[{params }], {self .args [-1 ]}]"
        elif self.kind == TypeKind.LITERAL:
            return (
                f"Literal[{', '.join (repr (v )for v in (self .literal_values or frozenset ()))}]"
            )
        else:
            return self.name


class TypeIssueKind(Enum):
    """Types of type safety issues."""

    INCOMPATIBLE_TYPES = auto()
    INCOMPATIBLE_RETURN = auto()
    INCOMPATIBLE_ARGUMENT = auto()
    MISSING_ATTRIBUTE = auto()
    ATTRIBUTE_TYPE_MISMATCH = auto()
    TOO_FEW_ARGUMENTS = auto()
    TOO_MANY_ARGUMENTS = auto()
    UNEXPECTED_KEYWORD = auto()
    MISSING_KEYWORD = auto()
    UNSAFE_UNION_ACCESS = auto()
    INCOMPLETE_EXHAUSTIVE = auto()
    POSSIBLE_NONE = auto()
    NONE_NOT_ALLOWED = auto()
    GENERIC_CONSTRAINT_VIOLATED = auto()
    VARIANCE_MISMATCH = auto()
    PROTOCOL_NOT_SATISFIED = auto()
    UNREACHABLE_CODE = auto()
    REDUNDANT_CHECK = auto()


@dataclass
class TypeIssue:
    """Represents a detected type safety issue."""

    kind: TypeIssueKind
    message: str
    expected_type: SymbolicType | None = None
    actual_type: SymbolicType | None = None
    location: str | None = None
    line_number: int | None = None
    constraints: list[object] = field(default_factory=list[object])
    counterexample: dict[str, object] = field(default_factory=dict[str, object])
    severity: str = "error"

    def format(self) -> str:
        """Format issue for display."""
        loc = f" at line {self .line_number }" if self.line_number else ""
        types = ""
        if self.expected_type and self.actual_type:
            types = f" (expected {self .expected_type }, got {self .actual_type })"
        return f"[{self .kind .name }]{loc }: {self .message }{types }"


__all__ = [
    "SymbolicType",
    "TypeIssue",
    "TypeIssueKind",
    "TypeKind",
    "Variance",
]
