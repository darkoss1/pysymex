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

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from pysymex.analysis.type_inference import PyType, TypeKind

from pysymex.analysis.detectors.types import DetectionContext, Issue, IssueKind, StaticDetector


class StaticTypeErrorDetector(StaticDetector):
    """
    Enhanced detector for TypeError.
    Considers:
    - Type inference for operation compatibility
    - String multiplication (str * int is valid)
    - isinstance checks that narrow type
    - Union types and overloads
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.TYPE_ERROR

    def should_check(self, ctx: DetectionContext) -> bool:
        """Should check."""
        instr = ctx.instruction
        if instr.opname == "BINARY_OP":
            return True
        if instr.opname in {"CALL", "CALL_FUNCTION"}:
            return True
        if instr.opname == "LOAD_ATTR":
            return True
        return False

    def check(self, ctx: DetectionContext) -> Issue | None:
        """Check."""
        instr = ctx.instruction
        if instr.opname == "BINARY_OP":
            return self._check_binary_op(ctx)
        elif instr.opname in {"CALL", "CALL_FUNCTION"}:
            return self._check_call(ctx)
        elif instr.opname == "LOAD_ATTR":
            return self._check_attribute(ctx)
        return None

    def _check_binary_op(self, ctx: DetectionContext) -> Issue | None:
        """Check binary operation for type errors."""
        instr = ctx.instruction
        op = instr.argrepr
        operands = self._get_binary_operands(ctx)
        if operands is None:
            return None
        left_type, right_type, _left_var, _right_var = operands
        if ctx.can_pattern_suppress("TypeError"):
            return None
        if self._is_valid_binary_op(op, left_type, right_type):
            return None
        message = f"TypeError: unsupported operand types for '{op}': `{left_type.kind.name}` and `{right_type.kind.name}`"
        return self.create_issue(
            ctx,
            message=message,
            confidence=0.8,
        )

    def _check_call(self, ctx: DetectionContext) -> Issue | None:
        """Check function call for type errors."""
        func_info = self._get_function_info(ctx)
        if func_info is None:
            return None
        func_name, func_type = func_info
        if func_type.kind in (TypeKind.CALLABLE, TypeKind.UNKNOWN, TypeKind.CLASS):
            return None
        return self.create_issue(
            ctx,
            message=f"TypeError: `{func_name}` of type `{func_type.kind.name}` is not callable",
            confidence=0.7,
        )

    def _check_attribute(self, ctx: DetectionContext) -> Issue | None:
        """Check attribute access for type errors."""
        instr = ctx.instruction
        attr_name = instr.argval
        obj_info = self._get_object_info(ctx)
        if obj_info is None:
            return None
        obj_var, obj_type = obj_info
        if obj_type.kind == TypeKind.NONE:
            return self.create_issue(
                ctx,
                message=f"AttributeError: 'NoneType' object has no attribute '{attr_name}'",
                confidence=0.95,
            )
        if ctx.can_pattern_suppress("AttributeError"):
            return None
        if obj_type.kind != TypeKind.UNKNOWN:
            if not self._type_has_attribute(obj_type, attr_name):
                return self.create_issue(
                    ctx,
                    message=f"AttributeError: `{obj_var}` of type `{obj_type.kind.name}` may not have attribute '{attr_name}'",
                    confidence=0.6,
                )
        return None

    def _get_binary_operands(
        self,
        ctx: DetectionContext,
    ) -> tuple[PyType, PyType, str | None, str | None] | None:
        """Get types of binary operation operands."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None or idx < 2:
            return None
        left_type = PyType.unknown()
        right_type = PyType.unknown()
        left_var = None
        right_var = None
        prev = instructions[idx - 1]
        if prev.opname == "LOAD_CONST":
            right_type = self._type_from_value(prev.argval)
        elif prev.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            right_var = prev.argval
            right_type = ctx.get_type(right_var)
        for i in range(idx - 2, max(0, idx - 5), -1):
            instr = instructions[i]
            if instr.opname == "LOAD_CONST":
                left_type = self._type_from_value(instr.argval)
                break
            elif instr.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
                left_var = instr.argval
                left_type = ctx.get_type(left_var)
                break
        return (left_type, right_type, left_var, right_var)

    def _type_from_value(self, value: object) -> PyType:
        """Infer type from a constant value."""
        match value:
            case None:
                return PyType.none_type()
            case bool():
                return PyType.bool_type()
            case int():
                return PyType.int_type()
            case float():
                return PyType.float_type()
            case str():
                return PyType.str_type()
            case list():
                return PyType.list_type()
            case tuple():
                return PyType.tuple_type()
            case dict():
                return PyType.dict_type()
            case set():
                return PyType.set_type()
            case _:
                return PyType.unknown()

    def _is_valid_binary_op(
        self,
        op: str,
        left: PyType,
        right: PyType,
    ) -> bool:
        """Check if binary operation is valid for the types."""
        if left.kind == TypeKind.UNKNOWN or right.kind == TypeKind.UNKNOWN:
            return True
        numeric_kinds = {TypeKind.INT, TypeKind.FLOAT, TypeKind.BOOL}
        if left.kind in numeric_kinds and right.kind in numeric_kinds:
            return True
        if op == "+":
            if left.kind == TypeKind.STR and right.kind == TypeKind.STR:
                return True
        if op == "*":
            if (left.kind == TypeKind.STR and right.kind == TypeKind.INT) or (
                left.kind == TypeKind.INT and right.kind == TypeKind.STR
            ):
                return True
            if (left.kind == TypeKind.LIST and right.kind == TypeKind.INT) or (
                left.kind == TypeKind.INT and right.kind == TypeKind.LIST
            ):
                return True
        if op == "+":
            if left.kind == TypeKind.LIST and right.kind == TypeKind.LIST:
                return True
            if left.kind == TypeKind.TUPLE and right.kind == TypeKind.TUPLE:
                return True
        if op in {"<", ">", "<=", ">=", "==", "!="}:
            return True
        return False

    def _get_function_info(
        self,
        ctx: DetectionContext,
    ) -> tuple[str, PyType] | None:
        """Get information about function being called."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None:
            return None
        for i in range(idx - 1, max(0, idx - 10), -1):
            instr = instructions[i]
            if instr.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
                func_name = instr.argval
                func_type = ctx.get_type(func_name)
                return (func_name, func_type)
        return None

    def _get_object_info(
        self,
        ctx: DetectionContext,
    ) -> tuple[str, PyType] | None:
        """Get information about object for attribute access."""
        pc = ctx.pc
        instructions = ctx.instructions
        idx = None
        for i, instr in enumerate(instructions):
            if instr.offset == pc:
                idx = i
                break
        if idx is None or idx < 1:
            return None
        prev = instructions[idx - 1]
        if prev.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            obj_name = prev.argval
            obj_type = ctx.get_type(obj_name)
            return (obj_name, obj_type)
        return None

    def _type_has_attribute(self, obj_type: PyType, attr: str) -> bool:
        """Check if a type has an attribute."""
        type_attrs: dict[TypeKind, set[str]] = {
            TypeKind.STR: {
                "upper",
                "lower",
                "strip",
                "split",
                "join",
                "format",
                "replace",
                "find",
                "index",
                "startswith",
                "endswith",
                "isdigit",
                "isalpha",
                "encode",
                "decode",
            },
            TypeKind.LIST: {
                "append",
                "extend",
                "insert",
                "remove",
                "pop",
                "clear",
                "index",
                "count",
                "sort",
                "reverse",
                "copy",
            },
            TypeKind.DICT: {
                "keys",
                "values",
                "items",
                "get",
                "pop",
                "update",
                "setdefault",
                "clear",
                "copy",
                "fromkeys",
            },
            TypeKind.SET: {
                "add",
                "remove",
                "discard",
                "pop",
                "clear",
                "copy",
                "union",
                "intersection",
                "difference",
                "symmetric_difference",
                "update",
                "issubset",
                "issuperset",
            },
        }
        if obj_type.kind in type_attrs:
            return attr in type_attrs[obj_type.kind]
        return True
