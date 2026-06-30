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

"""Self-canceling zero-division static diagnostics.

Part of the symbolic scan preflight layer. Traces dataflow facts and inspects ASTs to detect
occurrences of division operations whose divisor evaluates to zero via self-canceling
subtraction expressions (e.g. ``expr - expr``).
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from pysymex._internal.analysis.scan.preflight.exception.handlers import try_suppresses_exception
from pysymex._internal.analysis.scan.preflight.exception.reachability import (
    statement_may_complete_normally,
)
from pysymex._internal.analysis.scan.preflight.self.canceling.facts import (
    FlowFacts,
    apply_assignment,
    clear_target,
    expr_is_zero,
    merge_branch_facts,
    zero_reason,
)
from pysymex._internal.analysis.scan.preflight.self.canceling.issues import (
    append_self_canceling_issue,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.analysis.records import IssueRecord


def _scan_statements(
    scan_statement: Callable[[ast.stmt, FlowFacts], FlowFacts],
    statements: list[ast.stmt],
    facts: FlowFacts,
) -> FlowFacts:
    """Scan statements sequentially with isolated flow facts."""
    current = facts.fork()
    for statement in statements:
        current = scan_statement(statement, current)
        if not statement_may_complete_normally(statement):
            break
    return current


def _scan_statement(
    statement: ast.stmt,
    facts: FlowFacts,
    scan_expr: Callable[[ast.AST | None, FlowFacts], None],
    scan_statements: Callable[[list[ast.stmt], FlowFacts], FlowFacts],
    visit_node: Callable[[ast.AST], object],
) -> FlowFacts:
    """Scan one statement and return updated self-canceling flow facts."""
    current = facts.fork()
    if isinstance(statement, ast.Assign):
        scan_expr(statement.value, current)
        apply_assignment(statement.targets, statement.value, current)
        return current
    if isinstance(statement, ast.AnnAssign):
        if statement.value is not None:
            scan_expr(statement.value, current)
            apply_assignment([statement.target], statement.value, current)
        return current
    if isinstance(statement, ast.AugAssign):
        scan_expr(statement.value, current)
        clear_target(statement.target, current)
        return current
    if isinstance(statement, ast.If):
        scan_expr(statement.test, current)
        body_facts = scan_statements(statement.body, current)
        else_facts = scan_statements(statement.orelse, current)
        return merge_branch_facts(current, body_facts, else_facts)
    if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
        scan_expr(getattr(statement, "test", None), current)
        body_facts = scan_statements(statement.body, current)
        else_facts = scan_statements(statement.orelse, current)
        return merge_branch_facts(current, body_facts, else_facts)
    if isinstance(statement, ast.Return):
        scan_expr(statement.value, current)
        return current
    if isinstance(statement, ast.Expr):
        scan_expr(statement.value, current)
        return current
    if isinstance(statement, ast.Try):
        _scan_try(statement, current, scan_statements)
        return current
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        visit_node(statement)
        return current
    for child in ast.iter_child_nodes(statement):
        if isinstance(child, ast.expr):
            scan_expr(child, current)
    return current


def _scan_try(
    statement: ast.Try,
    facts: FlowFacts,
    scan_statements: Callable[[list[ast.stmt], FlowFacts], FlowFacts],
) -> None:
    """Scan try bodies while respecting local ZeroDivisionError handlers."""
    if not try_suppresses_exception(statement, "ZeroDivisionError"):
        scan_statements(statement.body, facts)
    for handler in statement.handlers:
        scan_statements(handler.body, facts)
    scan_statements(statement.orelse, facts)
    scan_statements(statement.finalbody, facts)


def _scan_expr(
    expression: ast.AST | None,
    facts: FlowFacts,
    issues: list[IssueRecord],
    seen: set[tuple[int, str, str]],
    class_stack: list[str],
    function_stack: list[str],
) -> None:
    """Scan an expression for self-canceling zero divisors."""
    if expression is None:
        return
    if (
        isinstance(expression, ast.BinOp)
        and isinstance(
            expression.op,
            (ast.Div, ast.FloorDiv, ast.Mod),
        )
        and expr_is_zero(expression.right, facts)
    ):
        append_self_canceling_issue(
            issues,
            seen,
            expression,
            zero_reason(expression.right, facts),
            class_stack,
            function_stack,
        )
    for child in ast.iter_child_nodes(expression):
        if isinstance(child, ast.expr):
            _scan_expr(child, facts, issues, seen, class_stack, function_stack)


class SelfCancelingZeroCollector(ast.NodeVisitor):
    """Find divisions by values proven zero through ``expr - expr`` cancellation.

    Traverses functions and control flow blocks, updating and propagating flow facts
    to identify divisions or modulo operations where the divisor evaluates to zero.
    Discovered findings are appended to `issues`.

    Attributes:
        issues: List of discovered division-by-zero issue records.

    """

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
        self._scan_statements(node.body, FlowFacts())
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _scan_statements(self, statements: list[ast.stmt], facts: FlowFacts) -> FlowFacts:
        return _scan_statements(self._scan_statement, statements, facts)

    def _scan_statement(self, statement: ast.stmt, facts: FlowFacts) -> FlowFacts:
        return _scan_statement(
            statement,
            facts,
            self._scan_expr,
            self._scan_statements,
            self.visit,
        )

    def _scan_expr(self, expression: ast.AST | None, facts: FlowFacts) -> None:
        _scan_expr(
            expression,
            facts,
            self.issues,
            self._seen,
            self._class_stack,
            self._function_stack,
        )


def find_self_canceling_zero_division(content: str) -> list[IssueRecord]:
    """Parse Python source code and identify occurrences of divisions where the divisor evaluates to zero.

    Args:
        content: The Python source code string to analyze.

    Returns:
        A list of collected division by zero issue records.

    """
    tree = ast.parse(content)
    collector = SelfCancelingZeroCollector()
    collector.visit(tree)
    return collector.issues
