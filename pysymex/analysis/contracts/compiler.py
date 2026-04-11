# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Contract expression compiler for pysymex.

Compiles Python expression strings to Z3 constraints using AST parsing.
"""

from __future__ import annotations

import ast
import logging
from typing import cast

import z3

from pysymex.core.memory.addressing import next_address

logger = logging.getLogger(__name__)


class ContractCompiler(ast.NodeVisitor):
    """Compiles Python expressions to Z3 constraints."""

    def __init__(self, symbols: dict[str, z3.ExprRef]) -> None:
        self.symbols = symbols
        self._old_prefix = "old_"

    @classmethod
    def compile_expression(cls, expr_str: str, symbols: dict[str, z3.ExprRef]) -> z3.BoolRef:
        """Compile a Python expression string to Z3."""
        try:
            tree = ast.parse(expr_str, mode="eval")
            compiler = cls(symbols)
            return compiler.visit(tree.body)
        except (SyntaxError, KeyError, TypeError, z3.Z3Exception):
            logger.debug("Failed to compile contract expression: %s", expr_str, exc_info=True)
            return z3.Bool(f"contract_{hash(expr_str)}")

    def visit_Compare(self, node: ast.Compare) -> z3.BoolRef:
        """Handle comparison operators."""
        left = self.visit(node.left)
        result = None
        current = left
        for op, comparator in zip(node.ops, node.comparators, strict=False):
            right = self.visit(comparator)
            match op:
                case ast.Lt():
                    cmp = current < right
                case ast.LtE():
                    cmp = current <= right
                case ast.Gt():
                    cmp = current > right
                case ast.GtE():
                    cmp = current >= right
                case ast.Eq():
                    cmp = current == right
                case ast.NotEq():
                    cmp = current != right
                case _:
                    cmp = z3.Bool(f"cmp_{next_address()}")
            if result is None:
                result = cmp
            else:
                result = z3.And(result, cmp)
            current = right
        return cast("z3.BoolRef", result)

    def visit_BoolOp(self, node: ast.BoolOp) -> z3.BoolRef:
        """Handle and/or operators."""
        values = [self.visit(v) for v in node.values]
        match node.op:
            case ast.And():
                return z3.And(*values)
            case ast.Or():
                return z3.Or(*values)
            case _:
                return z3.Bool(f"boolop_{next_address()}")

    def visit_UnaryOp(self, node: ast.UnaryOp) -> z3.ExprRef:
        """Handle unary operators."""
        operand = self.visit(node.operand)
        match node.op:
            case ast.Not():
                return z3.Not(operand)
            case ast.USub():
                return -operand
            case ast.UAdd():
                return operand
            case _:
                return operand

    def visit_BinOp(self, node: ast.BinOp) -> z3.ExprRef:
        """Handle binary operators."""
        left = self.visit(node.left)
        right = self.visit(node.right)
        match node.op:
            case ast.Add():
                return left + right
            case ast.Sub():
                return left - right
            case ast.Mult():
                return left * right
            case ast.Div():
                return left / right
            case ast.FloorDiv():
                trunc = left / right
                return z3.If(
                    left % right == 0,
                    trunc,
                    z3.If((left >= 0) == (right >= 0), trunc, trunc - 1),
                )
            case ast.Mod():
                return left % right
            case ast.Pow():
                if isinstance(node.right, ast.Constant) and isinstance(node.right.value, int):
                    if node.right.value == 2:
                        return left * left
                    elif node.right.value == 3:
                        return left * left * left
                return z3.Int(f"pow_{next_address()}")
            case ast.BitAnd():
                return left & right
            case ast.BitOr():
                return left | right
            case ast.BitXor():
                return left ^ right
            case _:
                return z3.Int(f"binop_{next_address()}")

    def visit_Name(self, node: ast.Name) -> z3.ExprRef:
        """Handle variable references."""
        name = node.id
        if name == "result":
            if "__result__" in self.symbols:
                return self.symbols["__result__"]
            return z3.Int("__result__")
        if name.startswith(self._old_prefix):
            actual_name = name[len(self._old_prefix) :]
            old_name = f"old_{actual_name}"
            if old_name in self.symbols:
                return self.symbols[old_name]
        if name in self.symbols:
            return self.symbols[name]
        return z3.Int(name)

    def visit_Attribute(self, node: ast.Attribute) -> z3.ExprRef:
        """Handle dotted attribute references (e.g., self.x)."""
        parts: list[str] = [node.attr]
        cur: ast.AST = node.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            name = ".".join(reversed(parts))
            if name in self.symbols:
                return self.symbols[name]
            sym = z3.Int(name)
            self.symbols[name] = sym
            return sym
        return z3.Int(f"attr_{next_address()}")

    def visit_Constant(self, node: ast.Constant) -> z3.ExprRef:
        """Handle literals."""
        match node.value:
            case bool() as v:
                return z3.BoolVal(v)
            case int() as v:
                return z3.IntVal(v)
            case float() as v:
                return z3.RealVal(v)
            case _:
                return z3.Int(f"const_{next_address()}")

    def visit_Call(self, node: ast.Call) -> z3.ExprRef:
        """Handle function calls in contracts."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name == "old" and len(node.args) == 1:
                if isinstance(node.args[0], ast.Name):
                    var_name = node.args[0].id
                    old_name = f"old_{var_name}"
                    if old_name in self.symbols:
                        return self.symbols[old_name]
                    return z3.Int(old_name)
            if func_name == "result" and len(node.args) == 0:
                if "__result__" in self.symbols:
                    return self.symbols["__result__"]
                return z3.Int("__result__")
            if func_name == "abs" and len(node.args) == 1:
                arg = self.visit(node.args[0])
                return z3.If(arg >= 0, arg, -arg)
            if func_name == "min" and len(node.args) == 2:
                a, b = self.visit(node.args[0]), self.visit(node.args[1])
                return z3.If(a <= b, a, b)
            if func_name == "max" and len(node.args) == 2:
                a, b = self.visit(node.args[0]), self.visit(node.args[1])
                return z3.If(a >= b, a, b)
            if func_name == "len" and len(node.args) == 1:
                if isinstance(node.args[0], ast.Name):
                    return z3.Int(f"len_{node.args[0].id}")
            if func_name in ("forall", "exists", "exists_unique"):
                from pysymex.contracts.quantifiers import (
                    replace_quantifiers_with_z3,
                )

                try:
                    expr_str = ast.unparse(node)
                    return replace_quantifiers_with_z3(expr_str, self.symbols)
                except (ValueError, TypeError, z3.Z3Exception):
                    logger.debug("Quantifier replacement failed", exc_info=True)
        return z3.Int(f"call_{next_address()}")

    def visit_IfExp(self, node: ast.IfExp) -> z3.ExprRef:
        """Handle ternary if expressions."""
        test = self.visit(node.test)
        body = self.visit(node.body)
        orelse = self.visit(node.orelse)
        return z3.If(test, body, orelse)

    def visit_Subscript(self, node: ast.Subscript) -> z3.ExprRef:
        """Handle array subscript."""
        if isinstance(node.value, ast.Name):
            base_name = node.value.id
            if isinstance(node.slice, ast.Constant):
                return z3.Int(f"{base_name}_{node.slice.value}")
            elif isinstance(node.slice, ast.Name):
                return z3.Int(f"{base_name}_{node.slice.id}")
        return z3.Int(f"subscript_{next_address()}")

    def generic_visit(self, node: ast.AST) -> z3.ExprRef:
        """Default handler for unknown nodes."""
        return z3.Int(f"unknown_{next_address()}")


__all__ = [
    "ContractCompiler",
]
