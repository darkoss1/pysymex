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

"""Equality-guarded zero-division static diagnostics.

Part of the source preflight layer. Detects divisions where the divisor is a
subtraction of expressions proven equal by an active ``if`` guard, such as
``if x == y: return 1 // (x - y)``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from pysymex.analysis.scan.preflight.exception_handlers import try_suppresses_exception
from pysymex.analysis.scan.records import IssueRecord


def _empty_equalities() -> set[frozenset[str]]:
    return set()


def _empty_names_by_key() -> dict[str, frozenset[str]]:
    return {}


@dataclass(slots=True)
class _GuardFacts:
    """Equality facts active in the current syntactic path."""

    equalities: set[frozenset[str]] = field(default_factory=_empty_equalities)
    names_by_key: dict[str, frozenset[str]] = field(default_factory=_empty_names_by_key)

    def fork(self) -> "_GuardFacts":
        """Return an isolated copy for branch-local scanning."""
        return _GuardFacts(equalities=set(self.equalities), names_by_key=dict(self.names_by_key))

    def add_equality(self, left: ast.expr, right: ast.expr) -> None:
        """Add a stable equality relation when both sides are side-effect-free."""
        left_key = _stable_expr_key(left)
        right_key = _stable_expr_key(right)
        if left_key is None or right_key is None or left_key == right_key:
            return
        self.equalities.add(frozenset((left_key, right_key)))
        self.names_by_key[left_key] = frozenset(_referenced_names(left))
        self.names_by_key[right_key] = frozenset(_referenced_names(right))

    def clear_name(self, name: str) -> None:
        """Remove equality facts invalidated by assigning *name*."""
        stale_keys = {key for key, names in self.names_by_key.items() if name in names}
        if not stale_keys:
            return
        self.equalities = {
            equality for equality in self.equalities if not equality.intersection(stale_keys)
        }
        for key in stale_keys:
            self.names_by_key.pop(key, None)


class EqualityGuardedZeroDivisionCollector(ast.NodeVisitor):
    """Find divisions by expressions made zero through active equality guards."""

    def __init__(self) -> None:
        self.issues: list[IssueRecord] = []
        self._class_stack: list[str] = []
        self._function_stack: list[str] = []
        self._seen: set[tuple[int, str, str]] = set()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class body while preserving report context."""
        self._class_stack.append(node.name)
        for child in node.body:
            self.visit(child)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Scan one function body with fresh equality facts."""
        self._function_stack.append(node.name)
        self._scan_statements(node.body, _GuardFacts())
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _scan_statements(self, statements: list[ast.stmt], facts: _GuardFacts) -> None:
        current = facts.fork()
        for statement in statements:
            self._scan_statement(statement, current)

    def _scan_statement(self, statement: ast.stmt, facts: _GuardFacts) -> None:
        if isinstance(statement, ast.Assign):
            self._scan_expr(statement.value, facts)
            for target in statement.targets:
                self._clear_target(target, facts)
            return
        if isinstance(statement, ast.AnnAssign):
            self._scan_expr(statement.value, facts)
            self._clear_target(statement.target, facts)
            return
        if isinstance(statement, ast.AugAssign):
            self._scan_expr(statement.value, facts)
            self._clear_target(statement.target, facts)
            return
        if isinstance(statement, ast.If):
            self._scan_expr(statement.test, facts)
            body_facts = facts.fork()
            _add_equalities_from_test(statement.test, body_facts)
            self._scan_statements(statement.body, body_facts)
            self._scan_statements(statement.orelse, facts)
            return
        if isinstance(statement, ast.Return):
            self._scan_expr(statement.value, facts)
            return
        if isinstance(statement, ast.Expr):
            self._scan_expr(statement.value, facts)
            return
        if isinstance(statement, ast.Try):
            if not try_suppresses_exception(statement, "ZeroDivisionError"):
                self._scan_statements(statement.body, facts)
            for handler in statement.handlers:
                self._scan_statements(handler.body, facts)
            self._scan_statements(statement.orelse, facts)
            self._scan_statements(statement.finalbody, facts)
            return
        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            self._scan_expr(getattr(statement, "test", None), facts)
            self._scan_statements(statement.body, facts)
            self._scan_statements(statement.orelse, facts)
            return
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.visit(statement)
            return
        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.expr):
                self._scan_expr(child, facts)

    def _scan_expr(self, expression: ast.AST | None, facts: _GuardFacts) -> None:
        if expression is None:
            return
        if isinstance(expression, ast.BinOp) and isinstance(
            expression.op, (ast.Div, ast.FloorDiv, ast.Mod)
        ):
            if _expr_is_equality_guarded_zero(expression.right, facts):
                self._report(expression, ast.unparse(expression.right))
        for child in ast.iter_child_nodes(expression):
            if isinstance(child, ast.expr):
                self._scan_expr(child, facts)

    def _clear_target(self, target: ast.expr, facts: _GuardFacts) -> None:
        if isinstance(target, ast.Name):
            facts.clear_name(target.id)

    def _report(self, node: ast.BinOp, reason: str) -> None:
        function_name = self._function_stack[-1] if self._function_stack else None
        class_name = self._class_stack[-1] if self._class_stack else None
        full_path = ".".join([*self._class_stack, *self._function_stack])
        key = (node.lineno, full_path, reason)
        if key in self._seen:
            return
        self._seen.add(key)
        self.issues.append(
            {
                "kind": "DIVISION_BY_ZERO",
                "message": f"Possible division by zero: {reason} is equality-guarded zero",
                "line": node.lineno,
                "pc": 0,
                "function_name": function_name,
                "class_name": class_name,
                "full_path": full_path or None,
                "counterexample": None,
            }
        )


def _expr_is_equality_guarded_zero(expression: ast.expr, facts: _GuardFacts) -> bool:
    if not isinstance(expression, ast.BinOp) or not isinstance(expression.op, ast.Sub):
        return False
    left_key = _stable_expr_key(expression.left)
    right_key = _stable_expr_key(expression.right)
    if left_key is None or right_key is None:
        return False
    return left_key == right_key or frozenset((left_key, right_key)) in facts.equalities


def _add_equalities_from_test(test: ast.AST, facts: _GuardFacts) -> None:
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        for value in test.values:
            _add_equalities_from_test(value, facts)
        return
    if not isinstance(test, ast.Compare):
        return
    operands = [test.left, *test.comparators]
    for left, op, right in zip(operands, test.ops, operands[1:], strict=False):
        if isinstance(op, ast.Eq):
            facts.add_equality(left, right)


def _stable_expr_key(expression: ast.expr) -> str | None:
    if isinstance(expression, ast.Name):
        return f"name:{expression.id}"
    if isinstance(expression, ast.Attribute):
        owner = _stable_expr_key(expression.value)
        if owner is None:
            return None
        return f"attr:{owner}.{expression.attr}"
    if isinstance(expression, ast.Subscript):
        owner = _stable_expr_key(expression.value)
        index = _stable_expr_key(expression.slice)
        if owner is None or index is None:
            return None
        return f"subscr:{owner}[{index}]"
    if isinstance(expression, ast.Constant):
        return f"const:{expression.value!r}"
    return None


def _referenced_names(expression: ast.AST) -> set[str]:
    return {node.id for node in ast.walk(expression) if isinstance(node, ast.Name)}


def collect_equality_guarded_zero_division_diagnostics(content: str) -> list[IssueRecord]:
    """Return divisions whose divisors are zero under active equality guards."""
    tree = ast.parse(content)
    collector = EqualityGuardedZeroDivisionCollector()
    collector.visit(tree)
    return collector.issues


__all__ = [
    "EqualityGuardedZeroDivisionCollector",
    "collect_equality_guarded_zero_division_diagnostics",
]
