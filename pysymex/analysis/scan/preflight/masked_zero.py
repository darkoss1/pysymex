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

from pysymex.analysis.scan.preflight.exception_handlers import try_suppresses_exception
from pysymex.analysis.scan.records import IssueRecord


def expr_mentions_name(node: ast.AST, name: str) -> bool:
    """Check if the given AST expression references the specified variable name.

    Args:
        node (ast.AST): The AST node to search.
        name (str): The variable name to search for.

    Returns:
        bool: True if the variable name is referenced in the AST node, False otherwise.
    """
    return any(isinstance(child, ast.Name) and child.id == name for child in ast.walk(node))


class MaskedZeroDivisionCollector(ast.NodeVisitor):
    """Find ``if (masked == 0): ... / masked``-style division by zero.

    Traverses AST structures, identifying variables assigned to bitwise AND operations
    and checking if their subsequent division or modulo divisors reside in blocks guarded
    by zero-equality checks. Saves results in `issues`.

    Attributes:
        issues: List of discovered division-by-zero issue records.
    """

    def __init__(self) -> None:
        """Initialize the MaskedZeroDivisionCollector instance."""
        self.issues: list[IssueRecord] = []
        self._class_stack: list[str] = []
        self._function_stack: list[str] = []
        self._masked_vars_stack: list[set[str]] = []
        self._zero_guard_stack: list[set[str]] = []
        self._seen: set[tuple[int, str, str]] = set()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class definition node, pushing and popping the class name on the class stack.

        Args:
            node (ast.ClassDef): The class definition AST node.
        """
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Visit a function definition node, pushing the function name and initializing state stacks.

        Args:
            node (ast.FunctionDef | ast.AsyncFunctionDef): The function definition AST node.
        """
        self._function_stack.append(node.name)
        self._masked_vars_stack.append(set())
        self._zero_guard_stack.append(set())
        self.generic_visit(node)
        self._zero_guard_stack.pop()
        self._masked_vars_stack.pop()
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit an assignment node, checking if the assigned value is a bitwise AND operation and tracking masked variables.

        Args:
            node (ast.Assign): The assignment AST node.
        """
        masked_assignment = (
            isinstance(node.value, ast.BinOp)
            and isinstance(node.value.op, ast.BitAnd)
            and isinstance(node.value.right, ast.Constant)
            and isinstance(node.value.right.value, int)
            and node.value.right.value >= 0
        )
        if self._masked_vars_stack:
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if masked_assignment:
                    self._masked_vars_stack[-1].add(target.id)
                else:
                    self._masked_vars_stack[-1].discard(target.id)
                    if self._zero_guard_stack:
                        self._zero_guard_stack[-1].discard(target.id)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Visit an if statement node, checking if the test condition guards a masked variable to be zero.

        Args:
            node (ast.If): The if statement AST node.
        """
        guarded_zero = self._zero_guard_names(node.test)
        if not guarded_zero:
            self.generic_visit(node)
            return
        self._zero_guard_stack.append(set(self._zero_guard_stack[-1]) | guarded_zero)
        for child in node.body:
            self.visit(child)
        self._zero_guard_stack.pop()
        for child in node.orelse:
            self.visit(child)

    def visit_Try(self, node: ast.Try) -> None:
        """Visit try blocks without reporting body failures caught by local handlers."""
        if not try_suppresses_exception(node, "ZeroDivisionError"):
            for child in node.body:
                self.visit(child)
        for handler in node.handlers:
            for child in handler.body:
                self.visit(child)
        for child in node.orelse:
            self.visit(child)
        for child in node.finalbody:
            self.visit(child)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Visit a binary operation node, checking if a division or modulo divisor references a variable currently guarded as zero.

        Args:
            node (ast.BinOp): The binary operation AST node.
        """
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            for name in self._zero_guard_stack[-1] if self._zero_guard_stack else ():
                if expr_mentions_name(node.right, name):
                    self._report(node, name)
                    break
        self.generic_visit(node)

    def _zero_guard_names(self, test: ast.AST) -> set[str]:
        """Identify variables that are guarded as zero in a comparison expression.

        Args:
            test (ast.AST): The comparison AST node to evaluate.

        Returns:
            set[str]: A set containing the variable names guarded as zero.
        """
        if not self._masked_vars_stack or not isinstance(test, ast.Compare):
            return set()
        if len(test.ops) != 1 or len(test.comparators) != 1 or not isinstance(test.ops[0], ast.Eq):
            return set()
        left = test.left
        right = test.comparators[0]
        if isinstance(left, ast.Name) and isinstance(right, ast.Constant) and right.value == 0:
            return {left.id} & self._masked_vars_stack[-1]
        if isinstance(right, ast.Name) and isinstance(left, ast.Constant) and left.value == 0:
            return {right.id} & self._masked_vars_stack[-1]
        return set()

    def _report(self, node: ast.BinOp, name: str) -> None:
        """Record a division by zero warning issue for a division operation whose divisor references a variable guarded as zero.

        Args:
            node (ast.BinOp): The binary operation node causing the issue.
            name (str): The name of the variable guarded as zero.
        """
        function_name = self._function_stack[-1] if self._function_stack else None
        class_name = self._class_stack[-1] if self._class_stack else None
        full_path = ".".join([*self._class_stack, *self._function_stack])
        key = (node.lineno, full_path, name)
        if key in self._seen:
            return
        self._seen.add(key)
        self.issues.append(
            {
                "kind": "DIVISION_BY_ZERO",
                "message": f"Possible division by zero: {name} is guarded equal to 0",
                "line": node.lineno,
                "pc": 0,
                "function_name": function_name,
                "class_name": class_name,
                "full_path": full_path or None,
                "counterexample": None,
            }
        )


def collect_masked_zero_division_diagnostics(content: str) -> list[IssueRecord]:
    """Parse Python source code and identify occurrences of divisions where the divisor is a masked variable guarded as zero.

    Identifies issues where a bitwise-masked variable is guarded as equal to zero,
    and then used as a divisor in the guarded block.

    Args:
        content: The Python source code string to analyze.

    Returns:
        A list of collected division by zero issue records.
    """
    tree = ast.parse(content)
    collector = MaskedZeroDivisionCollector()
    collector.visit(tree)
    return collector.issues
