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

"""Guarded sequence off-by-offset static diagnostics.

Part of the source preflight layer. Detects patterns where a branch bounds an
index below ``len(seq) - margin`` and a guarded subscript uses ``index + offset``
with an offset that can step outside the same sequence.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from pysymex._internal.analysis.scan.preflight.exception.reachability import (
    statement_may_complete_normally,
)
from pysymex._internal.analysis.scan.preflight.guarded.index.facts import (
    IndexFacts,
    add_upper_bounds_from_test,
    apply_assignment,
    clear_target,
)
from pysymex._internal.analysis.scan.preflight.guarded.index.issues import check_subscript

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.analysis.records import IssueRecord


def _scan_statements(
    scan_statement: Callable[[ast.stmt, IndexFacts], None],
    statements: list[ast.stmt],
    facts: IndexFacts,
) -> None:
    """Scan statements with isolated branch-local index facts."""
    current = facts.fork()
    for statement in statements:
        scan_statement(statement, current)
        if not statement_may_complete_normally(statement):
            break


class GuardedIndexCollector(ast.NodeVisitor):
    """Find sequence subscripts that exceed their own active upper guard."""

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
        """Scan one function body with fresh sequence facts."""
        self._function_stack.append(node.name)
        _scan_statements(self._scan_statement, node.body, IndexFacts())
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _scan_statement(self, statement: ast.stmt, facts: IndexFacts) -> None:
        if isinstance(statement, ast.Assign):
            self._scan_expr(statement.value, facts)
            apply_assignment(statement.targets, statement.value, facts)
            return
        if isinstance(statement, ast.AnnAssign):
            self._scan_expr(statement.value, facts)
            if statement.value is not None:
                apply_assignment([statement.target], statement.value, facts)
            return
        if isinstance(statement, ast.AugAssign):
            self._scan_expr(statement.value, facts)
            clear_target(statement.target, facts)
            return
        if isinstance(statement, ast.If):
            self._scan_expr(statement.test, facts)
            body_facts = facts.fork()
            add_upper_bounds_from_test(statement.test, body_facts)
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

    def _scan_expr(self, expression: ast.AST | None, facts: IndexFacts) -> None:
        if expression is None:
            return
        if isinstance(expression, ast.Subscript):
            check_subscript(
                self.issues,
                self._seen,
                expression,
                facts,
                self._class_stack,
                self._function_stack,
            )
        for child in ast.iter_child_nodes(expression):
            if isinstance(child, ast.expr):
                self._scan_expr(child, facts)


def find_guarded_index_offset(content: str) -> list[IssueRecord]:
    """Return guarded offset subscripts that can exceed a known sequence length."""
    tree = ast.parse(content)
    collector = GuardedIndexCollector()
    collector.visit(tree)
    return collector.issues
