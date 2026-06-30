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

"""Translate parsed contract condition AST nodes to Z3 expressions.

:class:`~pysymex._internal.contracts.quantifiers.translator.ConditionTranslator` walks Python
``ast`` trees for string predicates under a name-to-``z3.ExprRef`` environment. Does not
invoke the solver or register decorators.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.contracts.binding.snapshots import old_symbol_name
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues

if TYPE_CHECKING:
    from collections.abc import Mapping


def parse_condition_to_z3(
    condition: str,
    context: Mapping[str, z3.ExprRef],
) -> z3.BoolRef:
    """Parse a Python-like condition string to Z3.

    Supports basic comparisons (``<``, ``<=``, ``>``, ``>=``, ``==``, ``!=``),
    boolean operators (``and``, ``or``, ``not``), basic arithmetic (``+``, ``-``,
    ``*``), indexing (``x[i]``), and attribute checks (``x.length``).

    Args:
        condition: The Python-style boolean expression string.
        context: Mapping of variable identifiers to active Z3 variable expressions.

    Returns:
        A compiled ``z3.BoolRef`` representing the condition constraint.

    Raises:
        ValueError: If the condition is not boolean, or contains invalid syntax.

    """
    try:
        tree = ast.parse(condition, mode="eval")
        res = ConditionTranslator(context).visit(tree.body)
        if not z3.is_bool(res):
            msg = f"Condition is not boolean: {condition!r}"
            raise ValueError(msg)
        return res
    except SyntaxError as exc:
        msg = f"Invalid condition syntax: {condition!r}"
        raise ValueError(msg) from exc


class ConditionTranslator(ast.NodeVisitor):
    """Translates a Python AST condition node to an equivalent Z3 expression.

    Attributes:
        context: Variable mapping used to resolve identifiers inside the AST.

    """

    def __init__(self, context: Mapping[str, z3.ExprRef]) -> None:
        """Initialize the AST-to-Z3 condition translator.

        Args:
            context: A mapping of variable identifier strings to their corresponding
                Z3 expression objects, used to resolve variables parsed in the AST.

        """
        self.context = context

    def _visit_expr(self, node: ast.AST) -> z3.ExprRef:
        """Visit an AST node and assert that it evaluates to a Z3 expression.

        Args:
            node: The AST node to evaluate.

        Returns:
            The evaluated ``z3.ExprRef``.

        Raises:
            ValueError: If the AST node evaluates to an unsupported type.

        """
        visited = self.visit(node)
        if isinstance(visited, z3.ExprRef):
            return visited
        msg = f"Unsupported expression node: {type(node).__name__}"
        raise ValueError(msg)

    def visit_Compare(self, node: ast.Compare) -> z3.BoolRef:
        """Handle comparisons."""
        left = self.visit(node.left)
        comparisons: list[z3.BoolRef] = []
        prev = left
        for op, comp in zip(node.ops, node.comparators, strict=False):
            right = self.visit(comp)
            match op:
                case ast.Lt():
                    comparisons.append(prev < right)
                case ast.LtE():
                    comparisons.append(prev <= right)
                case ast.Gt():
                    comparisons.append(prev > right)
                case ast.GtE():
                    comparisons.append(prev >= right)
                case ast.Eq():
                    comparisons.append(prev == right)
                case ast.NotEq():
                    comparisons.append(prev != right)
                case _:
                    msg = f"Unsupported comparison: {type(op)}"
                    raise ValueError(msg)
            prev = right
        return z3.And(*comparisons) if len(comparisons) > 1 else comparisons[0]

    def visit_BoolOp(self, node: ast.BoolOp) -> z3.BoolRef:
        """Handle and/or."""
        match node.op:
            case ast.And():
                and_values: list[z3.BoolRef] = []
                for value in node.values:
                    translated = self._visit_expr(value)
                    if not z3.is_bool(translated):
                        msg = "Boolean operator operand is not boolean"
                        raise ValueError(msg)
                    bool_value = translated
                    simplified = cast("z3.ExprRef", simplify_expr(bool_value))
                    if z3.is_false(simplified):
                        return ConstraintValues.bool(False)
                    if not z3.is_true(simplified):
                        and_values.append(bool_value)
                return z3.And(*and_values) if and_values else ConstraintValues.bool(True)
            case ast.Or():
                or_values: list[z3.BoolRef] = []
                for value in node.values:
                    translated = self._visit_expr(value)
                    if not z3.is_bool(translated):
                        msg = "Boolean operator operand is not boolean"
                        raise ValueError(msg)
                    bool_value = translated
                    simplified = cast("z3.ExprRef", simplify_expr(bool_value))
                    if z3.is_true(simplified):
                        return ConstraintValues.bool(True)
                    if not z3.is_false(simplified):
                        or_values.append(bool_value)
                return z3.Or(*or_values) if or_values else ConstraintValues.bool(False)
            case _:
                msg = f"Unsupported bool op: {type(node.op)}"
                raise ValueError(msg)

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
                msg = f"Unsupported unary op: {type(node.op)}"
                raise ValueError(msg)

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
            case ast.FloorDiv():
                msg = "Floor division is unsupported in contract conditions"
                raise ValueError(msg)
            case ast.Mod():
                msg = "Modulo is unsupported in contract conditions"
                raise ValueError(msg)
            case ast.Pow():
                msg = "Exponentiation is unsupported in contract conditions"
                raise ValueError(msg)
            case _:
                msg = f"Unsupported binary op: {type(node.op)}"
                raise ValueError(msg)

    def visit_Subscript(self, node: ast.Subscript) -> z3.ExprRef:
        """Handle indexing."""
        value = self.visit(node.value)
        index = self.visit(node.slice)
        import typing

        return typing.cast("z3.ExprRef", z3.Select(value, index))

    def visit_Attribute(self, node: ast.Attribute) -> z3.ExprRef:
        """Handle attribute access."""
        if isinstance(node.value, ast.Name):
            key = f"{node.value.id}.{node.attr}"
            if key in self.context:
                return self.context[key]
            if node.attr == "length":
                length_key = f"len_{node.value.id}"
                if length_key in self.context:
                    return self.context[length_key]
            msg = f"Unsupported attribute reference: {key}"
            raise ValueError(msg)
        msg = f"Unsupported attribute reference: {ast.unparse(node)}"
        raise ValueError(msg)

    def visit_Name(self, node: ast.Name) -> z3.ExprRef:
        """Handle variable names."""
        name = node.id
        if name in self.context:
            return self.context[name]
        msg = f"Unbound contract symbol: {name}"
        raise ValueError(msg)

    def visit_Constant(self, node: ast.Constant) -> z3.ExprRef:
        """Handle constants."""
        match node.value:
            case bool() as v:
                return ConstraintValues.bool(v)
            case int() as v:
                return ConstraintValues.int(v)
            case float():
                msg = "Floating-point constants are unsupported in contract conditions"
                raise ValueError(msg)
            case None:
                msg = "None constants are unsupported in contract conditions"
                raise ValueError(msg)
            case _:
                msg = f"Unsupported constant type: {type(node.value)}"
                raise ValueError(msg)

    def visit_Call(self, node: ast.Call) -> z3.ExprRef:
        """Handle function calls."""
        if node.keywords:
            msg = "Keyword arguments are unsupported in contract calls"
            raise ValueError(msg)
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name == "result" and not node.args:
                for key in ("__result__", "result", "__return__", "return"):
                    if key in self.context:
                        return self.context[key]
                msg = "result() requires a bound return-value symbol"
                raise ValueError(msg)
            if func_name == "old":
                if len(node.args) != 1:
                    msg = "old() expects exactly one argument"
                    raise ValueError(msg)
                source_name = _old_source_name(node.args[0])
                if source_name is None:
                    msg = (
                        "old() currently supports scalar locals, shallow attributes, and len(name)"
                    )
                    raise ValueError(
                        msg,
                    )
                snapshot_key = old_symbol_name(source_name)
                if snapshot_key in self.context:
                    return self.context[snapshot_key]
                msg = f"old({source_name}) requires a supported entry snapshot"
                raise ValueError(msg)
            if func_name == "len" and len(node.args) == 1:
                arg = node.args[0]
                if isinstance(arg, ast.Name):
                    length_key = f"len_{arg.id}"
                    if length_key in self.context:
                        return self.context[length_key]
                    msg = f"len({arg.id}) requires a modeled length symbol"
                    raise ValueError(msg)
                if _is_result_call(arg):
                    for key in ("__result__", "result", "__return__", "return"):
                        length_key = f"len_{key}"
                        if length_key in self.context:
                            return self.context[length_key]
                    msg = "len(result()) requires a modeled return length symbol"
                    raise ValueError(msg)
            if func_name == "abs" and len(node.args) == 1:
                arg = self._visit_expr(node.args[0])
                if isinstance(arg, z3.ArithRef):
                    return z3.If(arg >= 0, arg, -arg)
            if func_name == "min" and len(node.args) == 2:
                a = self._visit_expr(node.args[0])
                b = self._visit_expr(node.args[1])
                if isinstance(a, z3.ArithRef) and isinstance(b, z3.ArithRef):
                    return z3.If(a <= b, a, b)
            if func_name == "max" and len(node.args) == 2:
                a = self._visit_expr(node.args[0])
                b = self._visit_expr(node.args[1])
                if isinstance(a, z3.ArithRef) and isinstance(b, z3.ArithRef):
                    return z3.If(a >= b, a, b)
            msg = f"Unsupported contract call: {func_name}"
            raise ValueError(msg)
        msg = f"Unsupported contract call: {ast.unparse(node.func)}"
        raise ValueError(msg)

    def generic_visit(self, node: ast.AST) -> z3.ExprRef:
        """Reject unsupported AST nodes explicitly."""
        msg = f"Unsupported condition node: {type(node).__name__}"
        raise ValueError(msg)


def _is_result_call(node: ast.AST) -> bool:
    """Return whether ``node`` is the supported zero-argument ``result()`` call."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "result"
        and not node.args
        and not node.keywords
    )


def _old_source_name(node: ast.AST) -> str | None:
    """Return the source key supported by ``old()`` for a limited AST shape."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "len"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
    ):
        return f"len({node.args[0].id})"
    return None
