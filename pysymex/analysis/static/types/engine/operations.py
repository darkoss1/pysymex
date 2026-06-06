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

"""TypeOperationInferenceMixin implementation for type inference."""

from __future__ import annotations

from pysymex.analysis.static.types.kinds import PyType, TypeKind


def _is_int_like(typ: PyType) -> bool:
    return typ.kind in {TypeKind.BOOL, TypeKind.INT}


class TypeOperationInferenceMixin:
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
                if left.kind == TypeKind.STR and _is_int_like(right):
                    return PyType.str_()
                if _is_int_like(left) and right.kind == TypeKind.STR:
                    return PyType.str_()
                if left.kind == TypeKind.LIST and _is_int_like(right):
                    return left
                if _is_int_like(left) and right.kind == TypeKind.LIST:
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
                if operand.kind == TypeKind.BOOL:
                    return PyType.int_()
                return operand
        if op == "+":
            if operand.is_numeric():
                if operand.kind == TypeKind.BOOL:
                    return PyType.int_()
                return operand
        if op == "~":
            if _is_int_like(operand):
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


__all__ = ["TypeOperationInferenceMixin"]
