"""Advanced Type Constraint Analysis with Z3.

This module provides comprehensive type safety checking using Z3 SMT solver.

Implementation split for maintainability:
- type_constraints_types: TypeKind, Variance, SymbolicType, TypeIssueKind, TypeIssue
- type_constraints_encoder: TypeEncoder
- protocol_checker: Protocol, ProtocolChecker
- This file (hub): TypeConstraintChecker + re-exports
"""

from __future__ import annotations

import z3

from pysymex.analysis.protocol_checker import (
    Protocol,
    ProtocolChecker,
)
from pysymex.analysis.type_constraints.encoder import TypeEncoder
from pysymex.analysis.type_constraints.types import (
    SymbolicType,
    TypeIssue,
    TypeIssueKind,
    TypeKind,
    Variance,
)


class TypeConstraintChecker:
    """
    Comprehensive type constraint checker using Z3.
    Provides mathematically proven type safety verification.
    """

    def __init__(self, timeout_ms: int = 5000):
        """Init."""
        """Initialize the class instance."""
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
            return (False, "Any is not subtype of non-Any")
        if sup.kind == TypeKind.UNION:
            for t in sup.args:
                is_sub, _ = self.is_subtype(sub, t, path_constraints)
                if is_sub:
                    return (True, None)
            return (False, f"{sub } is not subtype of any member of {sup }")
        if sub.kind == TypeKind.UNION:
            for t in sub.args:
                is_sub, _reason = self.is_subtype(t, sup, path_constraints)
                if not is_sub:
                    return (False, f"Union member {t } is not subtype of {sup }")
            return (True, None)
        if sub.kind == TypeKind.LITERAL:
            for val in sub.literal_values or frozenset():
                if isinstance(val, bool):
                    base = SymbolicType.bool_type()
                elif isinstance(val, int):
                    base = SymbolicType.int_type()
                elif isinstance(val, str):
                    base = SymbolicType.str_type()
                else:
                    continue
                is_sub, _reason = self.is_subtype(base, sup, path_constraints)
                if is_sub:
                    return (True, None)
            return (False, f"Literal values not compatible with {sup }")
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
            return (False, f"{sub } is not a subtype of {sup }")

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
            for s_arg, p_arg in zip(sub.args, sup.args, strict=False):
                if s_arg != p_arg:
                    return (False, f"Type parameter mismatch: {s_arg } vs {p_arg }")
            return (True, None)
        elif sub.variance == Variance.COVARIANT:
            for s_arg, p_arg in zip(sub.args, sup.args, strict=False):
                is_sub, reason = self.is_subtype(s_arg, p_arg, path_constraints)
                if not is_sub:
                    return (False, reason)
            return (True, None)
        else:
            for s_arg, p_arg in zip(sub.args, sup.args, strict=False):
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
                message=f"Cannot assign {value_type } to {target_type }: {reason }",
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
        is_sub, _reason = self.is_subtype(actual_return, declared_return, path_constraints)
        if not is_sub:
            return TypeIssue(
                kind=TypeIssueKind.INCOMPATIBLE_RETURN,
                message=f"Return type {actual_return } incompatible with declared {declared_return }",
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
        is_sub, _reason = self.is_subtype(arg_type, param_type, path_constraints)
        if not is_sub:
            return TypeIssue(
                kind=TypeIssueKind.INCOMPATIBLE_ARGUMENT,
                message=f"Argument '{param_name }' has type {arg_type }, expected {param_type }",
                expected_type=param_type,
                actual_type=arg_type,
            )
        return None

    def check_union_access(
        self,
        union_type: SymbolicType,
        attribute: str,
        path_constraints: list[z3.BoolRef] | None = None,
        runtime_type: z3.ExprRef | None = None,
    ) -> TypeIssue | None:
        """
        Check if attribute access is safe on all union members.
        E.g., for Union[str, int], can we safely call .upper()?
        """
        if union_type.kind != TypeKind.UNION:
            return None
        if path_constraints and not self._constraints_are_feasible(path_constraints):
            return None
        members_without_attr: list[SymbolicType] = []
        for member in self._possible_union_members(union_type, path_constraints, runtime_type):
            if not self._type_has_attribute(member, attribute):
                members_without_attr.append(member)
        if members_without_attr:
            return TypeIssue(
                kind=TypeIssueKind.UNSAFE_UNION_ACCESS,
                message=f"Attribute '{attribute }' not available on all union members: {members_without_attr }",
                actual_type=union_type,
                constraints=list(path_constraints or []),
            )
        return None

    def _constraints_are_feasible(self, path_constraints: list[z3.BoolRef] | None) -> bool:
        """Constraints are feasible."""
        if not path_constraints:
            return True
        self._solver.push()
        for constraint in path_constraints:
            self._solver.add(constraint)
        result = self._solver.check()
        self._solver.pop()
        return result != z3.unsat

    def _possible_union_members(
        self,
        union_type: SymbolicType,
        path_constraints: list[z3.BoolRef] | None,
        runtime_type: z3.ExprRef | None,
    ) -> tuple[SymbolicType, ...]:
        """Possible union members."""
        if union_type.kind != TypeKind.UNION:
            return (union_type,)
        if runtime_type is None:
            return union_type.args

        possible_members: list[SymbolicType] = []
        for member in union_type.args:
            self._solver.push()
            for constraint in path_constraints or []:
                self._solver.add(constraint)
            self._solver.add(runtime_type == self.encoder.encode(member))
            if self._solver.check() == z3.sat:
                possible_members.append(member)
            self._solver.pop()
        return tuple(possible_members)

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
        runtime_type: z3.ExprRef | None = None,
    ) -> TypeIssue | None:
        """
        Check if None is possible and would cause an error.
        E.g., Optional[str].upper() is unsafe without None check.
        """
        if path_constraints and not self._constraints_are_feasible(path_constraints):
            return None
        if value_type.kind == TypeKind.NONE:
            if runtime_type is not None:
                self._solver.push()
                for constraint in path_constraints or []:
                    self._solver.add(constraint)
                self._solver.add(runtime_type == self.encoder.encode(SymbolicType.none_type()))
                possible = self._solver.check() == z3.sat
                self._solver.pop()
                if not possible:
                    return None
            return TypeIssue(
                kind=TypeIssueKind.POSSIBLE_NONE,
                message=f"Value is always None, cannot {operation }",
                actual_type=value_type,
                constraints=list(path_constraints or []),
            )
        if value_type.kind == TypeKind.UNION:
            possible_members = self._possible_union_members(
                value_type, path_constraints, runtime_type
            )
            none_in_union = any(t.kind == TypeKind.NONE for t in possible_members)
            if none_in_union:
                return TypeIssue(
                    kind=TypeIssueKind.POSSIBLE_NONE,
                    message=f"Value may be None, need to check before {operation }",
                    actual_type=value_type,
                    constraints=list(path_constraints or []),
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
        unhandled: list[SymbolicType] = []
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
                message=f"Unhandled union members: {unhandled }",
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
                is_sub, _reason = self.is_subtype(concrete_type, bound, path_constraints)
                if not is_sub:
                    return TypeIssue(
                        kind=TypeIssueKind.GENERIC_CONSTRAINT_VIOLATED,
                        message=f"Type {concrete_type } does not satisfy bound {bound }",
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
                    message=f"Invariant type parameter used {actual_usage }ly",
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
        issues: list[TypeIssue] = []
        if callable_type.kind != TypeKind.CALLABLE:
            issues.append(
                TypeIssue(
                    kind=TypeIssueKind.INCOMPATIBLE_TYPES,
                    message=f"Cannot call non-callable type {callable_type }",
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
                    message=f"Expected {len (param_types )} arguments, got {len (arg_types )}",
                )
            )
        elif len(arg_types) > len(param_types):
            issues.append(
                TypeIssue(
                    kind=TypeIssueKind.TOO_MANY_ARGUMENTS,
                    message=f"Expected {len (param_types )} arguments, got {len (arg_types )}",
                )
            )
        for i, (param, arg) in enumerate(zip(param_types, arg_types, strict=False)):
            issue = self.check_argument(param, arg, f"arg{i }", path_constraints)
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
        issues: list[TypeIssue] = []
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
                    message=f"Cannot apply '{operator }' to {left_type } and {right_type }",
                )
            )
            return (SymbolicType.any_type(), issues)
        if operator in {"<", ">", "<=", ">=", "==", "!="}:
            return (SymbolicType.bool_type(), issues)
        if operator in {"and", "or"}:
            return (SymbolicType.bool_type(), issues)
        return (SymbolicType.any_type(), issues)


__all__ = [
    "Protocol",
    "ProtocolChecker",
    "SymbolicType",
    "TypeConstraintChecker",
    "TypeEncoder",
    "TypeIssue",
    "TypeIssueKind",
    "TypeKind",
    "Variance",
]
