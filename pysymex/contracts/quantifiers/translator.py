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

:class:`~pysymex.contracts.quantifiers.translator.ConditionTranslator` walks Python
``ast`` trees for string predicates under a name-to-``z3.ExprRef`` environment. Does not
invoke the solver or register decorators.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping

import z3

from pysymex.contracts.binding import old_symbol_name
from pysymex.core.solver.constraints.hashing import get_bool_val, get_int_val


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
            raise ValueError(f"Condition is not boolean: {condition!r}")
        return res
    except SyntaxError as exc:
        raise ValueError(f"Invalid condition syntax: {condition!r}") from exc


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
        raise ValueError(f"Unsupported expression node: {type(node).__name__}")

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
                    raise ValueError(f"Unsupported comparison: {type(op)}")
            prev = right
        return z3.And(*comparisons) if len(comparisons) > 1 else comparisons[0]

    def visit_BoolOp(self, node: ast.BoolOp) -> z3.BoolRef:
        """Handle and/or."""
        values = [self.visit(v) for v in node.values]
        match node.op:
            case ast.And():
                return z3.And(*values)
            case ast.Or():
                return z3.Or(*values)
            case _:
                raise ValueError(f"Unsupported bool op: {type(node.op)}")

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
                raise ValueError(f"Unsupported unary op: {type(node.op)}")

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
                raise ValueError("Floor division is unsupported in contract conditions")
            case ast.Mod():
                raise ValueError("Modulo is unsupported in contract conditions")
            case ast.Pow():
                raise ValueError("Exponentiation is unsupported in contract conditions")
            case _:
                raise ValueError(f"Unsupported binary op: {type(node.op)}")

    def visit_Subscript(self, node: ast.Subscript) -> z3.ExprRef:
        """Handle indexing."""
        value = self.visit(node.value)
        index = self.visit(node.slice)
        import typing

        return typing.cast(z3.ExprRef, z3.Select(value, index))

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
            raise ValueError(f"Unsupported attribute reference: {key}")
        raise ValueError(f"Unsupported attribute reference: {ast.unparse(node)}")

    def visit_Name(self, node: ast.Name) -> z3.ExprRef:
        """Handle variable names."""
        name = node.id
        if name in self.context:
            return self.context[name]
        raise ValueError(f"Unbound contract symbol: {name}")

    def visit_Constant(self, node: ast.Constant) -> z3.ExprRef:
        """Handle constants."""
        match node.value:
            case bool() as v:
                return get_bool_val(v)
            case int() as v:
                return get_int_val(v)
            case float():
                raise ValueError("Floating-point constants are unsupported in contract conditions")
            case None:
                raise ValueError("None constants are unsupported in contract conditions")
            case _:
                raise ValueError(f"Unsupported constant type: {type(node.value)}")

    def visit_Call(self, node: ast.Call) -> z3.ExprRef:
        """Handle function calls."""
        if node.keywords:
            raise ValueError("Keyword arguments are unsupported in contract calls")
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name == "result" and not node.args:
                for key in ("__result__", "result", "__return__", "return"):
                    if key in self.context:
                        return self.context[key]
                raise ValueError("result() requires a bound return-value symbol")
            if func_name == "old":
                if len(node.args) != 1:
                    raise ValueError("old() expects exactly one argument")
                source_name = _old_source_name(node.args[0])
                if source_name is None:
                    raise ValueError(
                        "old() currently supports scalar locals, shallow attributes, and len(name)"
                    )
                snapshot_key = old_symbol_name(source_name)
                if snapshot_key in self.context:
                    return self.context[snapshot_key]
                raise ValueError(f"old({source_name}) requires a supported entry snapshot")
            if func_name == "len" and len(node.args) == 1:
                arg = node.args[0]
                if isinstance(arg, ast.Name):
                    length_key = f"len_{arg.id}"
                    if length_key in self.context:
                        return self.context[length_key]
                    raise ValueError(f"len({arg.id}) requires a modeled length symbol")
                if _is_result_call(arg):
                    for key in ("__result__", "result", "__return__", "return"):
                        length_key = f"len_{key}"
                        if length_key in self.context:
                            return self.context[length_key]
                    raise ValueError("len(result()) requires a modeled return length symbol")
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
            raise ValueError(f"Unsupported contract call: {func_name}")
        raise ValueError(f"Unsupported contract call: {ast.unparse(node.func)}")

    def generic_visit(self, node: ast.AST) -> z3.ExprRef:
        """Reject unsupported AST nodes explicitly."""
        raise ValueError(f"Unsupported condition node: {type(node).__name__}")


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


__all__ = ["ConditionTranslator", "parse_condition_to_z3"]
