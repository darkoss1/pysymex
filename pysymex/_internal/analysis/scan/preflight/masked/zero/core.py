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

"""Masked zero-division static diagnostics.

Part of the symbolic scan preflight layer. Inspects target source ASTs to find
occurrences of division operations where the divisor is a bitwise-masked variable
currently guarded as zero in a conditional branch.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from pysymex._internal.analysis.scan.preflight.exception.handlers import try_suppresses_exception
from pysymex._internal.analysis.scan.preflight.exception.reachability import (
    statement_may_complete_normally,
)
from pysymex._internal.analysis.scan.preflight.masked.zero.facts import (
    apply_assignment_masks,
    guarded_divisor_name,
    zero_guard_names,
)
from pysymex._internal.analysis.scan.preflight.masked.zero.issues import append_masked_zero_issue

if TYPE_CHECKING:
    from pysymex._internal.analysis.records import IssueRecord


class MaskedZeroCollector(ast.NodeVisitor):
    """Find ``if (masked == 0): ... / masked``-style division by zero.

    Traverses AST structures, identifying variables assigned to bitwise AND operations
    and checking if their subsequent division or modulo divisors reside in blocks guarded
    by zero-equality checks. Saves results in `issues`.

    Attributes:
        issues: List of discovered division-by-zero issue records.

    """

    def __init__(self) -> None:
        self.issues: list[IssueRecord] = []
        self._class_stack: list[str] = []
        self._function_stack: list[str] = []
        self._masked_vars_stack: list[set[str]] = []
        self._zero_guard_stack: list[set[str]] = []
        self._seen: set[tuple[int, str, str]] = set()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self._visit_statement_block(node.body)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self._masked_vars_stack.append(set())
        self._zero_guard_stack.append(set())
        self._visit_statement_block(node.body)
        self._zero_guard_stack.pop()
        self._masked_vars_stack.pop()
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        apply_assignment_masks(
            node,
            self._masked_vars_stack,
            self._zero_guard_stack,
        )
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        guarded_zero = zero_guard_names(node.test, self._masked_vars_stack)
        if not guarded_zero:
            self.visit(node.test)
            self._visit_statement_block(node.body)
            self._visit_statement_block(node.orelse)
            return
        self._zero_guard_stack.append(set(self._zero_guard_stack[-1]) | guarded_zero)
        self._visit_statement_block(node.body)
        self._zero_guard_stack.pop()
        self._visit_statement_block(node.orelse)

    def visit_Try(self, node: ast.Try) -> None:
        if not try_suppresses_exception(node, "ZeroDivisionError"):
            self._visit_statement_block(node.body)
        for handler in node.handlers:
            self._visit_statement_block(handler.body)
        self._visit_statement_block(node.orelse)
        self._visit_statement_block(node.finalbody)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        name = guarded_divisor_name(node, self._zero_guard_stack)
        if name is not None:
            append_masked_zero_issue(
                self.issues,
                self._seen,
                node,
                name,
                self._class_stack,
                self._function_stack,
            )
        self.generic_visit(node)

    def _visit_statement_block(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            self.visit(statement)
            if not statement_may_complete_normally(statement):
                break


def find_masked_zero_division(content: str) -> list[IssueRecord]:
    """Parse Python source code and identify occurrences of divisions where the divisor is a masked variable guarded as zero.

    Identifies issues where a bitwise-masked variable is guarded as equal to zero,
    and then used as a divisor in the guarded block.

    Args:
        content: The Python source code string to analyze.

    Returns:
        A list of collected division by zero issue records.

    """
    tree = ast.parse(content)
    collector = MaskedZeroCollector()
    collector.visit(tree)
    return collector.issues
