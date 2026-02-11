"""Advanced Type Constraint Analysis with Z3.
This module provides comprehensive type safety checking using Z3 SMT solver
for mathematical proofs of type correctness. Covers:
- Type inference with constraints
- Union type checking
- Generic type bounds
- Protocol/structural typing verification
- Type narrowing proofs
- Variance checking
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
import z3


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
    literal_values: frozenset[Any] | None = None
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
    def literal(cls, *values: Any) -> SymbolicType:
        return cls(TypeKind.LITERAL, "Literal", literal_values=frozenset(values))

    @classmethod
    def class_type(cls, name: str, bases: tuple[SymbolicType, ...] = ()) -> SymbolicType:
        return cls(TypeKind.CLASS, name, bases)

    def __str__(self) -> str:
        if self.kind == TypeKind.UNION:
            return " | ".join(str(t) for t in self.args)
        elif self.kind == TypeKind.LIST:
            return f"list[{self.args[0]}]"
        elif self.kind == TypeKind.DICT:
            return f"dict[{self.args[0]}, {self.args[1]}]"
        elif self.kind == TypeKind.TUPLE:
            return f"tuple[{', '.join(str(t) for t in self.args)}]"
        elif self.kind == TypeKind.CALLABLE:
            params = ", ".join(str(t) for t in self.args[:-1])
            return f"Callable[[{params}], {self.args[-1]}]"
        elif self.kind == TypeKind.LITERAL:
            return f"Literal[{', '.join(repr(v) for v in self.literal_values)}]"
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
    constraints: list[Any] = field(default_factory=list)
    counterexample: dict[str, Any] = field(default_factory=dict)
    severity: str = "error"

    def format(self) -> str:
        """Format issue for display."""
        loc = f" at line {self.line_number}" if self.line_number else ""
        types = ""
        if self.expected_type and self.actual_type:
            types = f" (expected {self.expected_type}, got {self.actual_type})"
        return f"[{self.kind.name}]{loc}: {self.message}{types}"


class TypeEncoder:
    """
    Encodes types as Z3 expressions for constraint solving.
    Uses an uninterpreted sort for types with axioms for subtyping.
    """

    def __init__(self):
        self.TypeSort = z3.DeclareSort("Type")
        self.int_t = z3.Const("int_t", self.TypeSort)
        self.float_t = z3.Const("float_t", self.TypeSort)
        self.bool_t = z3.Const("bool_t", self.TypeSort)
        self.str_t = z3.Const("str_t", self.TypeSort)
        self.none_t = z3.Const("none_t", self.TypeSort)
        self.any_t = z3.Const("any_t", self.TypeSort)
        self.never_t = z3.Const("never_t", self.TypeSort)
        self.object_t = z3.Const("object_t", self.TypeSort)
        self.subtype = z3.Function("subtype", self.TypeSort, self.TypeSort, z3.BoolSort())
        self.compatible = z3.Function("compatible", self.TypeSort, self.TypeSort, z3.BoolSort())
        self._type_cache: dict[SymbolicType, z3.ExprRef] = {}
        self._type_counter = 0
        self._base_axioms = self._generate_axioms()

    def _generate_axioms(self) -> list[z3.BoolRef]:
        """Generate base axioms for the type system."""
        T = z3.Const("T", self.TypeSort)
        T1 = z3.Const("T1", self.TypeSort)
        T2 = z3.Const("T2", self.TypeSort)
        T3 = z3.Const("T3", self.TypeSort)
        axioms = [
            z3.ForAll([T], self.subtype(T, T)),
            z3.ForAll(
                [T1, T2, T3],
                z3.Implies(
                    z3.And(self.subtype(T1, T2), self.subtype(T2, T3)), self.subtype(T1, T3)
                ),
            ),
            z3.ForAll([T], self.subtype(T, self.any_t)),
            z3.ForAll([T], self.subtype(self.never_t, T)),
            z3.ForAll([T], z3.Implies(T != self.any_t, self.subtype(T, self.object_t))),
            self.subtype(self.bool_t, self.int_t),
            self.subtype(self.int_t, self.float_t),
            z3.ForAll([T1, T2], z3.Implies(self.subtype(T1, T2), self.compatible(T1, T2))),
        ]
        return axioms

    def encode(self, typ: SymbolicType) -> z3.ExprRef:
        """Encode a SymbolicType as a Z3 expression."""
        if typ in self._type_cache:
            return self._type_cache[typ]
        if typ.kind == TypeKind.INT:
            result = self.int_t
        elif typ.kind == TypeKind.FLOAT:
            result = self.float_t
        elif typ.kind == TypeKind.BOOL:
            result = self.bool_t
        elif typ.kind == TypeKind.STR:
            result = self.str_t
        elif typ.kind == TypeKind.NONE:
            result = self.none_t
        elif typ.kind == TypeKind.ANY:
            result = self.any_t
        elif typ.kind == TypeKind.NEVER:
            result = self.never_t
        elif typ.kind == TypeKind.OBJECT:
            result = self.object_t
        else:
            self._type_counter += 1
            result = z3.Const(f"type_{self._type_counter}", self.TypeSort)
        self._type_cache[typ] = result
        return result

    def get_axioms(self) -> list[z3.BoolRef]:
        """Get all axioms including those for cached types."""
        return list(self._base_axioms)


class TypeConstraintChecker:
    """
    Comprehensive type constraint checker using Z3.
    Provides mathematically proven type safety verification.
    """

    def __init__(self, timeout_ms: int = 5000):
        self.timeout_ms = timeout_ms
        self.encoder = TypeEncoder()
        self._solver = z3.Solver()
        self._solver.set("timeout", timeout_ms)
        for axiom in self.encoder.get_axioms():
            self._solver.add(axiom)
        self._issues: list[TypeIssue] = []

    def reset(self) -> None:
        """Reset checker state."""
        self._solver.reset()
        for axiom in self.encoder.get_axioms():
            self._solver.add(axiom)
        self._issues.clear()

    def is_subtype(
        self,
        sub: SymbolicType,
        sup: SymbolicType,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[bool, str | None]:
        """
        Check if sub is a subtype of sup.
        Returns (is_subtype, reason_if_not).
        """
        if sup.kind == TypeKind.ANY:
            return (True, None)
        if sub.kind == TypeKind.NEVER:
            return (True, None)
        if sub.kind == TypeKind.ANY:
            return (sup.kind == TypeKind.ANY, "Any is not subtype of non-Any")
        if sup.kind == TypeKind.UNION:
            for t in sup.args:
                is_sub, _ = self.is_subtype(sub, t, path_constraints)
                if is_sub:
                    return (True, None)
            return (False, f"{sub} is not subtype of any member of {sup}")
        if sub.kind == TypeKind.UNION:
            for t in sub.args:
                is_sub, reason = self.is_subtype(t, sup, path_constraints)
                if not is_sub:
                    return (False, f"Union member {t} is not subtype of {sup}")
            return (True, None)
        if sub.kind == TypeKind.LITERAL:
            for val in sub.literal_values:
                if isinstance(val, bool):
                    base = SymbolicType.bool_type()
                elif isinstance(val, int):
                    base = SymbolicType.int_type()
                elif isinstance(val, str):
                    base = SymbolicType.str_type()
                else:
                    continue
                is_sub, reason = self.is_subtype(base, sup, path_constraints)
                if is_sub:
                    return (True, None)
            return (False, f"Literal values not compatible with {sup}")
        if sub.kind == sup.kind and sub.args and sup.args:
            return self._check_parameterized_subtype(sub, sup, path_constraints)
        sub_z3 = self.encoder.encode(sub)
        sup_z3 = self.encoder.encode(sup)
        constraints = list(path_constraints or [])
        is_subtype_expr = self.encoder.subtype(sub_z3, sup_z3)
        self._solver.push()
        for c in constraints:
            self._solver.add(c)
        self._solver.add(z3.Not(is_subtype_expr))
        result = self._solver.check()
        self._solver.pop()
        if result == z3.unsat:
            return (True, None)
        else:
            return (False, f"{sub} is not a subtype of {sup}")

    def _check_parameterized_subtype(
        self,
        sub: SymbolicType,
        sup: SymbolicType,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[bool, str | None]:
        """Check subtyping for parameterized types (List, Dict, etc.)."""
        if len(sub.args) != len(sup.args):
            return (False, "Different number of type parameters")
        if sub.variance == Variance.INVARIANT:
            for s_arg, p_arg in zip(sub.args, sup.args):
                if s_arg != p_arg:
                    return (False, f"Type parameter mismatch: {s_arg} vs {p_arg}")
            return (True, None)
        elif sub.variance == Variance.COVARIANT:
            for s_arg, p_arg in zip(sub.args, sup.args):
                is_sub, reason = self.is_subtype(s_arg, p_arg, path_constraints)
                if not is_sub:
                    return (False, reason)
            return (True, None)
        else:
            for s_arg, p_arg in zip(sub.args, sup.args):
                is_sub, reason = self.is_subtype(p_arg, s_arg, path_constraints)
                if not is_sub:
                    return (False, reason)
            return (True, None)

    def check_assignment(
        self,
        target_type: SymbolicType,
        value_type: SymbolicType,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> TypeIssue | None:
        """Check if value_type can be assigned to target_type."""
        is_sub, reason = self.is_subtype(value_type, target_type, path_constraints)
        if not is_sub:
            return TypeIssue(
                kind=TypeIssueKind.INCOMPATIBLE_TYPES,
                message=f"Cannot assign {value_type} to {target_type}: {reason}",
                expected_type=target_type,
                actual_type=value_type,
            )
        return None

    def check_return(
        self,
        declared_return: SymbolicType,
        actual_return: SymbolicType,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> TypeIssue | None:
        """Check if actual return type matches declared."""
        is_sub, reason = self.is_subtype(actual_return, declared_return, path_constraints)
        if not is_sub:
            return TypeIssue(
                kind=TypeIssueKind.INCOMPATIBLE_RETURN,
                message=f"Return type {actual_return} incompatible with declared {declared_return}",
                expected_type=declared_return,
                actual_type=actual_return,
            )
        return None

    def check_argument(
        self,
        param_type: SymbolicType,
        arg_type: SymbolicType,
        param_name: str = "arg",
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> TypeIssue | None:
        """Check if argument type matches parameter type."""
        is_sub, reason = self.is_subtype(arg_type, param_type, path_constraints)
        if not is_sub:
            return TypeIssue(
                kind=TypeIssueKind.INCOMPATIBLE_ARGUMENT,
                message=f"Argument '{param_name}' has type {arg_type}, expected {param_type}",
                expected_type=param_type,
                actual_type=arg_type,
            )
        return None

    def check_union_access(
        self,
        union_type: SymbolicType,
        attribute: str,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> TypeIssue | None:
        """
        Check if attribute access is safe on all union members.
        E.g., for Union[str, int], can we safely call .upper()?
        """
        if union_type.kind != TypeKind.UNION:
            return None
        members_without_attr = []
        for member in union_type.args:
            if not self._type_has_attribute(member, attribute):
                members_without_attr.append(member)
        if members_without_attr:
            return TypeIssue(
                kind=TypeIssueKind.UNSAFE_UNION_ACCESS,
                message=f"Attribute '{attribute}' not available on all union members: {members_without_attr}",
                actual_type=union_type,
            )
        return None

    def _type_has_attribute(self, typ: SymbolicType, attr: str) -> bool:
        """Check if type has a given attribute (simplified)."""
        str_attrs = {
            "upper",
            "lower",
            "strip",
            "split",
            "join",
            "replace",
            "find",
            "startswith",
            "endswith",
        }
        int_attrs = {"bit_length", "to_bytes"}
        list_attrs = {"append", "extend", "pop", "insert", "remove", "sort", "reverse"}
        dict_attrs = {"keys", "values", "items", "get", "pop", "update"}
        if typ.kind == TypeKind.STR:
            return attr in str_attrs
        elif typ.kind == TypeKind.INT:
            return attr in int_attrs
        elif typ.kind == TypeKind.LIST:
            return attr in list_attrs
        elif typ.kind == TypeKind.DICT:
            return attr in dict_attrs
        elif typ.kind == TypeKind.ANY:
            return True
        return False

    def check_none_safety(
        self,
        value_type: SymbolicType,
        operation: str = "access",
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> TypeIssue | None:
        """
        Check if None is possible and would cause an error.
        E.g., Optional[str].upper() is unsafe without None check.
        """
        if value_type.kind == TypeKind.NONE:
            return TypeIssue(
                kind=TypeIssueKind.POSSIBLE_NONE,
                message=f"Value is always None, cannot {operation}",
                actual_type=value_type,
            )
        if value_type.kind == TypeKind.UNION:
            none_in_union = any(t.kind == TypeKind.NONE for t in value_type.args)
            if none_in_union:
                return TypeIssue(
                    kind=TypeIssueKind.POSSIBLE_NONE,
                    message=f"Value may be None, need to check before {operation}",
                    actual_type=value_type,
                )
        return None

    def narrow_type(
        self,
        original_type: SymbolicType,
        condition: str,
        is_true_branch: bool = True,
    ) -> SymbolicType:
        """
        Narrow type based on a type guard condition.
        E.g., after `if isinstance(x, str)`, x is narrowed from Union[str, int] to str.
        """
        if original_type.kind != TypeKind.UNION:
            return original_type
        if condition.startswith("isinstance(") and "str" in condition:
            if is_true_branch:
                return SymbolicType.str_type()
            else:
                remaining = [t for t in original_type.args if t.kind != TypeKind.STR]
                return SymbolicType.union_of(*remaining)
        elif condition.startswith("isinstance(") and "int" in condition:
            if is_true_branch:
                return SymbolicType.int_type()
            else:
                remaining = [t for t in original_type.args if t.kind != TypeKind.INT]
                return SymbolicType.union_of(*remaining)
        elif "is None" in condition or "is not None" in condition:
            is_none_check = "is not None" not in condition
            if is_true_branch == is_none_check:
                return SymbolicType.none_type()
            else:
                remaining = [t for t in original_type.args if t.kind != TypeKind.NONE]
                return SymbolicType.union_of(*remaining)
        return original_type

    def check_exhaustive(
        self,
        union_type: SymbolicType,
        handled_types: list[SymbolicType],
    ) -> TypeIssue | None:
        """
        Check if all union members are handled.
        For match statements or exhaustive type checks.
        """
        if union_type.kind != TypeKind.UNION:
            return None
        unhandled = []
        for member in union_type.args:
            handled = False
            for handled_type in handled_types:
                is_sub, _ = self.is_subtype(member, handled_type)
                if is_sub:
                    handled = True
                    break
            if not handled:
                unhandled.append(member)
        if unhandled:
            return TypeIssue(
                kind=TypeIssueKind.INCOMPLETE_EXHAUSTIVE,
                message=f"Unhandled union members: {unhandled}",
                actual_type=union_type,
            )
        return None

    def check_generic_constraints(
        self,
        type_var: SymbolicType,
        concrete_type: SymbolicType,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> TypeIssue | None:
        """
        Check if concrete type satisfies TypeVar bounds.
        E.g., for T(bound=Comparable), check that int satisfies Comparable.
        """
        if type_var.kind != TypeKind.TYPE_VAR:
            return None
        if type_var.bounds:
            for bound in type_var.bounds:
                is_sub, reason = self.is_subtype(concrete_type, bound, path_constraints)
                if not is_sub:
                    return TypeIssue(
                        kind=TypeIssueKind.GENERIC_CONSTRAINT_VIOLATED,
                        message=f"Type {concrete_type} does not satisfy bound {bound}",
                        expected_type=bound,
                        actual_type=concrete_type,
                    )
        return None

    def check_variance(
        self,
        declared_variance: Variance,
        actual_usage: str,
    ) -> TypeIssue | None:
        """Check if variance usage is correct."""
        usage_variance = {
            "covariant": Variance.COVARIANT,
            "contravariant": Variance.CONTRAVARIANT,
            "invariant": Variance.INVARIANT,
        }.get(actual_usage, Variance.INVARIANT)
        if declared_variance == Variance.INVARIANT:
            if usage_variance != Variance.INVARIANT:
                return TypeIssue(
                    kind=TypeIssueKind.VARIANCE_MISMATCH,
                    message=f"Invariant type parameter used {actual_usage}ly",
                )
        elif declared_variance == Variance.COVARIANT:
            if usage_variance == Variance.CONTRAVARIANT:
                return TypeIssue(
                    kind=TypeIssueKind.VARIANCE_MISMATCH,
                    message="Covariant type parameter used contravariantly",
                )
        elif declared_variance == Variance.CONTRAVARIANT:
            if usage_variance == Variance.COVARIANT:
                return TypeIssue(
                    kind=TypeIssueKind.VARIANCE_MISMATCH,
                    message="Contravariant type parameter used covariantly",
                )
        return None

    def check_callable_application(
        self,
        callable_type: SymbolicType,
        arg_types: list[SymbolicType],
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[SymbolicType, list[TypeIssue]]:
        """
        Check if callable can be applied with given arguments.
        Returns (return_type, issues).
        """
        issues = []
        if callable_type.kind != TypeKind.CALLABLE:
            issues.append(
                TypeIssue(
                    kind=TypeIssueKind.INCOMPATIBLE_TYPES,
                    message=f"Cannot call non-callable type {callable_type}",
                    actual_type=callable_type,
                )
            )
            return (SymbolicType.any_type(), issues)
        param_types = list(callable_type.args[:-1])
        return_type = callable_type.args[-1]
        if len(arg_types) < len(param_types):
            issues.append(
                TypeIssue(
                    kind=TypeIssueKind.TOO_FEW_ARGUMENTS,
                    message=f"Expected {len(param_types)} arguments, got {len(arg_types)}",
                )
            )
        elif len(arg_types) > len(param_types):
            issues.append(
                TypeIssue(
                    kind=TypeIssueKind.TOO_MANY_ARGUMENTS,
                    message=f"Expected {len(param_types)} arguments, got {len(arg_types)}",
                )
            )
        for i, (param, arg) in enumerate(zip(param_types, arg_types)):
            issue = self.check_argument(param, arg, f"arg{i}", path_constraints)
            if issue:
                issues.append(issue)
        return (return_type, issues)

    def infer_binary_op_type(
        self,
        left_type: SymbolicType,
        right_type: SymbolicType,
        operator: str,
    ) -> tuple[SymbolicType, list[TypeIssue]]:
        """
        Infer result type of binary operation.
        E.g., int + int -> int, str + str -> str
        """
        issues = []
        if operator in {"+", "-", "*", "/", "//", "%", "**"}:
            if left_type.kind == TypeKind.INT and right_type.kind == TypeKind.INT:
                if operator == "/":
                    return (SymbolicType.float_type(), issues)
                return (SymbolicType.int_type(), issues)
            if left_type.kind in {TypeKind.INT, TypeKind.FLOAT} and right_type.kind in {
                TypeKind.INT,
                TypeKind.FLOAT,
            }:
                return (SymbolicType.float_type(), issues)
            if (
                operator == "+"
                and left_type.kind == TypeKind.STR
                and right_type.kind == TypeKind.STR
            ):
                return (SymbolicType.str_type(), issues)
            if operator == "*":
                if left_type.kind == TypeKind.STR and right_type.kind == TypeKind.INT:
                    return (SymbolicType.str_type(), issues)
                if left_type.kind == TypeKind.INT and right_type.kind == TypeKind.STR:
                    return (SymbolicType.str_type(), issues)
            issues.append(
                TypeIssue(
                    kind=TypeIssueKind.INCOMPATIBLE_TYPES,
                    message=f"Cannot apply '{operator}' to {left_type} and {right_type}",
                )
            )
            return (SymbolicType.any_type(), issues)
        if operator in {"<", ">", "<=", ">=", "==", "!="}:
            return (SymbolicType.bool_type(), issues)
        if operator in {"and", "or"}:
            return (SymbolicType.bool_type(), issues)
        return (SymbolicType.any_type(), issues)


@dataclass
class Protocol:
    """Represents a structural protocol (like typing.Protocol)."""

    name: str
    required_methods: dict[str, SymbolicType] = field(default_factory=dict)
    required_attributes: dict[str, SymbolicType] = field(default_factory=dict)


class ProtocolChecker:
    """Checks if types satisfy protocols."""

    def __init__(self, type_checker: TypeConstraintChecker):
        self.type_checker = type_checker

    def check_protocol_satisfaction(
        self,
        concrete_type: SymbolicType,
        protocol: Protocol,
        available_methods: dict[str, SymbolicType],
        available_attributes: dict[str, SymbolicType],
    ) -> list[TypeIssue]:
        """Check if concrete type satisfies protocol requirements."""
        issues = []
        for method_name, expected_type in protocol.required_methods.items():
            if method_name not in available_methods:
                issues.append(
                    TypeIssue(
                        kind=TypeIssueKind.PROTOCOL_NOT_SATISFIED,
                        message=f"Missing method '{method_name}' required by protocol '{protocol.name}'",
                        expected_type=expected_type,
                    )
                )
            else:
                actual_type = available_methods[method_name]
                is_sub, reason = self.type_checker.is_subtype(actual_type, expected_type)
                if not is_sub:
                    issues.append(
                        TypeIssue(
                            kind=TypeIssueKind.PROTOCOL_NOT_SATISFIED,
                            message=f"Method '{method_name}' has incompatible type for protocol '{protocol.name}'",
                            expected_type=expected_type,
                            actual_type=actual_type,
                        )
                    )
        for attr_name, expected_type in protocol.required_attributes.items():
            if attr_name not in available_attributes:
                issues.append(
                    TypeIssue(
                        kind=TypeIssueKind.PROTOCOL_NOT_SATISFIED,
                        message=f"Missing attribute '{attr_name}' required by protocol '{protocol.name}'",
                        expected_type=expected_type,
                    )
                )
            else:
                actual_type = available_attributes[attr_name]
                is_sub, reason = self.type_checker.is_subtype(actual_type, expected_type)
                if not is_sub:
                    issues.append(
                        TypeIssue(
                            kind=TypeIssueKind.PROTOCOL_NOT_SATISFIED,
                            message=f"Attribute '{attr_name}' has incompatible type for protocol '{protocol.name}'",
                            expected_type=expected_type,
                            actual_type=actual_type,
                        )
                    )
        return issues


__all__ = [
    "TypeKind",
    "Variance",
    "TypeIssueKind",
    "SymbolicType",
    "TypeIssue",
    "Protocol",
    "TypeEncoder",
    "TypeConstraintChecker",
    "ProtocolChecker",
]
