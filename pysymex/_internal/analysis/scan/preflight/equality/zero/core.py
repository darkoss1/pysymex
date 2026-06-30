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
from typing import TYPE_CHECKING

from pysymex._internal.analysis.scan.preflight.equality.zero.facts import (
    EqualityGuardFacts,
    add_equalities_from_test,
    clear_equality_target,
    expr_is_equality_guarded_zero,
)
from pysymex._internal.analysis.scan.preflight.equality.zero.issues import (
    append_equality_zero_issue,
)
from pysymex._internal.analysis.scan.preflight.exception.handlers import try_suppresses_exception
from pysymex._internal.analysis.scan.preflight.exception.reachability import (
    statement_may_complete_normally,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.analysis.records import IssueRecord


def _scan_statements(
    scan_statement: Callable[[ast.stmt, EqualityGuardFacts], None],
    statements: list[ast.stmt],
    facts: EqualityGuardFacts,
) -> None:
    """Scan statements with isolated branch-local equality facts."""
    current = facts.fork()
    for statement in statements:
        scan_statement(statement, current)
        if not statement_may_complete_normally(statement):
            break


class EqualityZeroCollector(ast.NodeVisitor):
    """Find divisions by expressions made zero through active equality guards."""

    def __init__(self) -> None:
        self.issues: list[IssueRecord] = []
        self._class_stack: list[str] = []
        self._function_stack: list[str] = []
        self._seen: set[tuple[int, str, str]] = set()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        for child in node.body:
            self.visit(child)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        _scan_statements(self._scan_statement, node.body, EqualityGuardFacts())
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _scan_statement(self, statement: ast.stmt, facts: EqualityGuardFacts) -> None:
        if isinstance(statement, ast.Assign):
            self._scan_expr(statement.value, facts)
            for target in statement.targets:
                clear_equality_target(target, facts)
            return
        if isinstance(statement, ast.AnnAssign):
            self._scan_expr(statement.value, facts)
            clear_equality_target(statement.target, facts)
            return
        if isinstance(statement, ast.AugAssign):
            self._scan_expr(statement.value, facts)
            clear_equality_target(statement.target, facts)
            return
        if isinstance(statement, ast.If):
            self._scan_expr(statement.test, facts)
            body_facts = facts.fork()
            add_equalities_from_test(statement.test, body_facts)
            _scan_statements(self._scan_statement, statement.body, body_facts)
            _scan_statements(self._scan_statement, statement.orelse, facts)
            return
        if isinstance(statement, ast.Return):
            self._scan_expr(statement.value, facts)
            return
        if isinstance(statement, ast.Expr):
            self._scan_expr(statement.value, facts)
            return
        if isinstance(statement, ast.Try):
            if not try_suppresses_exception(statement, "ZeroDivisionError"):
                _scan_statements(self._scan_statement, statement.body, facts)
            for handler in statement.handlers:
                _scan_statements(self._scan_statement, handler.body, facts)
            _scan_statements(self._scan_statement, statement.orelse, facts)
            _scan_statements(self._scan_statement, statement.finalbody, facts)
            return
        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            self._scan_expr(getattr(statement, "test", None), facts)
            _scan_statements(self._scan_statement, statement.body, facts)
            _scan_statements(self._scan_statement, statement.orelse, facts)
            return
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.visit(statement)
            return
        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.expr):
                self._scan_expr(child, facts)

    def _scan_expr(self, expression: ast.AST | None, facts: EqualityGuardFacts) -> None:
        if expression is None:
            return
        if (
            isinstance(expression, ast.BinOp)
            and isinstance(
                expression.op,
                (ast.Div, ast.FloorDiv, ast.Mod),
            )
            and expr_is_equality_guarded_zero(expression.right, facts)
        ):
            append_equality_zero_issue(
                self.issues,
                self._seen,
                expression,
                ast.unparse(expression.right),
                self._class_stack,
                self._function_stack,
            )
        for child in ast.iter_child_nodes(expression):
            if isinstance(child, ast.expr):
                self._scan_expr(child, facts)


def find_equality_guarded_zero_division(content: str) -> list[IssueRecord]:
    """Return divisions whose divisors are zero under active equality guards."""
    tree = ast.parse(content)
    collector = EqualityZeroCollector()
    collector.visit(tree)
    return collector.issues
