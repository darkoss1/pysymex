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

"""Bytearray modulo-index static diagnostics.

Part of the symbolic scan preflight layer. Inspects target source ASTs for potential
out-of-bounds bytearray index access when using modulo operators (e.g. ``idx % Modulo``).
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from pysymex._internal.analysis.scan.preflight.bytearray.facts import (
    bytearray_literal_size,
    guarded_upper_bounds,
    index_guard_covers_size,
    merge_guarded_bounds,
    modulus_upper_bound,
    record_assignment_value,
    record_bytearray_sizes,
    resolve_container_size,
)
from pysymex._internal.analysis.scan.preflight.bytearray.issues import append_modulo_index_issue
from pysymex._internal.analysis.scan.preflight.exception.reachability import (
    statement_may_complete_normally,
)

if TYPE_CHECKING:
    from pysymex._internal.analysis.records import IssueRecord


class BytearrayIndexCollector(ast.NodeVisitor):
    """Find unguarded bytearray modulo indexes wider than concrete size."""

    def __init__(self) -> None:
        """Initialize scope stacks and tracking state."""
        self.issues: list[IssueRecord] = []
        self._bytearray_attrs: dict[str, int] = {}
        self._class_stack: list[str] = []
        self._function_stack: list[str] = []
        self._local_sizes_stack: list[dict[str, int]] = []
        self._assignments_stack: list[dict[str, ast.AST]] = []
        self._index_upper_bounds_stack: list[dict[str, int]] = []
        self._seen: set[tuple[int, str, int]] = set()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track class scope while visiting its body."""
        self._class_stack.append(node.name)
        self._visit_statement_block(node.body)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Track function-local bytearray and index facts while visiting a body."""
        self._function_stack.append(node.name)
        self._local_sizes_stack.append({})
        self._assignments_stack.append({})
        self._index_upper_bounds_stack.append({})
        self._visit_statement_block(node.body)
        self._index_upper_bounds_stack.pop()
        self._assignments_stack.pop()
        self._local_sizes_stack.pop()
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track simple assignments and concrete bytearray sizes."""
        record_assignment_value(self._assignments_stack, node)
        size = bytearray_literal_size(node.value)
        if size is not None:
            record_bytearray_sizes(
                self._bytearray_attrs,
                self._class_stack,
                self._local_sizes_stack,
                node.targets,
                size,
            )
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Apply simple upper-bound guards while visiting the guarded body."""
        guarded_bounds = guarded_upper_bounds(node.test)
        if not guarded_bounds:
            self.visit(node.test)
            self._visit_statement_block(node.body)
            self._visit_statement_block(node.orelse)
            return
        current_bounds = (
            self._index_upper_bounds_stack[-1] if self._index_upper_bounds_stack else {}
        )
        merged_bounds = merge_guarded_bounds(current_bounds, guarded_bounds)
        self._index_upper_bounds_stack.append(merged_bounds)
        self._visit_statement_block(node.body)
        self._index_upper_bounds_stack.pop()
        self._visit_statement_block(node.orelse)

    def visit_Try(self, node: ast.Try) -> None:
        """Visit try sections as statement blocks so terminal calls stop flow."""
        self._visit_statement_block(node.body)
        for handler in node.handlers:
            self._visit_statement_block(handler.body)
        self._visit_statement_block(node.orelse)
        self._visit_statement_block(node.finalbody)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Report unguarded oversized modulo indexes into tracked bytearrays."""
        size = resolve_container_size(node.value, self._local_sizes_stack, self._bytearray_attrs)
        if size is None:
            self.generic_visit(node)
            return

        assignments = self._assignments_stack[-1] if self._assignments_stack else {}
        modulus_upper = modulus_upper_bound(node.slice, assignments)
        if index_guard_covers_size(node.slice, self._index_upper_bounds_stack, size):
            self.generic_visit(node)
            return
        if modulus_upper is not None and modulus_upper > size:
            append_modulo_index_issue(
                self.issues,
                self._seen,
                node,
                size,
                modulus_upper,
                self._class_stack,
                self._function_stack,
            )
        self.generic_visit(node)

    def _visit_statement_block(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            self.visit(statement)
            if not statement_may_complete_normally(statement):
                break


def find_bytearray_modulo_index(content: str) -> list[IssueRecord]:
    """Parse Python source code and identify unguarded modulo indexing violations on bytearrays.

    Identifies issues where a modulo index range exceeds the array's statically determined size.

    Args:
        content: The Python source code string to analyze.

    Returns:
        A list of collected index-out-of-bounds issue records.

    """
    tree = ast.parse(content)
    collector = BytearrayIndexCollector()
    collector.visit(tree)
    return collector.issues
