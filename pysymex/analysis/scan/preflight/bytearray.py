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

from pysymex.analysis.scan.records import IssueRecord


def bytearray_literal_size(node: ast.AST) -> int | None:
    """Return the concrete size for simple ``bytearray([...])`` constructors."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if not isinstance(func, ast.Name) or func.id != "bytearray" or not node.args:
        return None
    first_arg = node.args[0]
    if isinstance(first_arg, (ast.List, ast.Tuple)):
        return len(first_arg.elts)
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, (bytes, bytearray)):
        return len(first_arg.value)
    return None


def attribute_chain_leaf(node: ast.AST) -> str | None:
    """Retrieve the attribute name from an attribute access node.

    Args:
        node (ast.AST): The AST node to inspect.

    Returns:
        str | None: The attribute name if the node is an Attribute, otherwise None.
    """
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def modulus_upper_bound(index_expr: ast.AST, assignments: dict[str, ast.AST]) -> int | None:
    """Return the exclusive upper bound for ``expr % constant`` indexes."""
    expr = index_expr
    if isinstance(expr, ast.Name):
        expr = assignments.get(expr.id, expr)
    if not isinstance(expr, ast.BinOp) or not isinstance(expr.op, ast.Mod):
        return None
    if isinstance(expr.right, ast.Constant) and isinstance(expr.right.value, int):
        modulus = expr.right.value
        if modulus > 0:
            return modulus
    return None


def index_name(index_expr: ast.AST) -> str | None:
    """Retrieve the variable name from a subscript index expression node.

    Args:
        index_expr (ast.AST): The subscript index AST node.

    Returns:
        str | None: The variable name if the index is a Name, otherwise None.
    """
    if isinstance(index_expr, ast.Name):
        return index_expr.id
    return None


class BytearrayModuloIndexCollector(ast.NodeVisitor):
    """Find unguarded bytearray indexes whose modulo range exceeds concrete size.

    Traverses function bodies, tracking assignment sizes and guarding if conditions to
    ensure modulo index ranges do not exceed the tracked bytearray bounds. Discovered
    issues are saved in `issues`.

    Attributes:
        issues: List of discovered index out-of-bounds issue records.
    """

    def __init__(self) -> None:
        """Initialize the BytearrayModuloIndexCollector instance with empty scope stacks and tracking states."""
        self.issues: list[IssueRecord] = []
        self._bytearray_attrs: dict[str, int] = {}
        self._class_stack: list[str] = []
        self._function_stack: list[str] = []
        self._local_sizes_stack: list[dict[str, int]] = []
        self._assignments_stack: list[dict[str, ast.AST]] = []
        self._index_upper_bounds_stack: list[dict[str, int]] = []
        self._seen: set[tuple[int, str, int]] = set()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class definition node, pushing and popping the class name on the class stack to track class scope.

        Args:
            node (ast.ClassDef): The class definition AST node.
        """
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Visit a function definition node, initializing local tracking dictionaries and pushing the function scope.

        Args:
            node (ast.FunctionDef | ast.AsyncFunctionDef): The function definition AST node.
        """
        self._function_stack.append(node.name)
        self._local_sizes_stack.append({})
        self._assignments_stack.append({})
        self._index_upper_bounds_stack.append({})
        self.generic_visit(node)
        self._index_upper_bounds_stack.pop()
        self._assignments_stack.pop()
        self._local_sizes_stack.pop()
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit an assignment node to track variable values and bytearray sizes.

        Args:
            node (ast.Assign): The assignment AST node.
        """
        if self._assignments_stack:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._assignments_stack[-1][target.id] = node.value

        size = bytearray_literal_size(node.value)
        if size is not None:
            for target in node.targets:
                if isinstance(target, ast.Name) and self._local_sizes_stack:
                    self._local_sizes_stack[-1][target.id] = size
                elif (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "self"
                    and self._class_stack
                ):
                    self._bytearray_attrs[target.attr] = size
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Visit an if statement node, extracting upper bounds guarded by the test condition.

        Args:
            node (ast.If): The if statement AST node.
        """
        guarded_bounds = self._guarded_upper_bounds(node.test)
        if not guarded_bounds:
            self.generic_visit(node)
            return
        current_bounds = (
            self._index_upper_bounds_stack[-1] if self._index_upper_bounds_stack else {}
        )
        merged_bounds = dict(current_bounds)
        for name, upper in guarded_bounds.items():
            old_upper = merged_bounds.get(name)
            merged_bounds[name] = upper if old_upper is None else min(old_upper, upper)
        self._index_upper_bounds_stack.append(merged_bounds)
        for child in node.body:
            self.visit(child)
        self._index_upper_bounds_stack.pop()
        for child in node.orelse:
            self.visit(child)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Visit a subscript node, checking if the index accesses a bytearray with an out-of-bounds modulo upper bound.

        Args:
            node (ast.Subscript): The subscript AST node.
        """
        size = self._resolve_container_size(node.value)
        if size is None:
            self.generic_visit(node)
            return

        assignments = self._assignments_stack[-1] if self._assignments_stack else {}
        modulus_upper = modulus_upper_bound(node.slice, assignments)
        index_name_value = index_name(node.slice)
        if index_name_value is not None and self._index_upper_bounds_stack:
            guarded_upper = self._index_upper_bounds_stack[-1].get(index_name_value)
            if guarded_upper is not None and guarded_upper <= size:
                self.generic_visit(node)
                return
        if modulus_upper is not None and modulus_upper > size:
            function_name = self._function_stack[-1] if self._function_stack else None
            class_name = self._class_stack[-1] if self._class_stack else None
            full_path = ".".join([*self._class_stack, *self._function_stack])
            key = (node.lineno, full_path, size)
            if key not in self._seen:
                self._seen.add(key)
                self.issues.append(
                    {
                        "kind": "INDEX_ERROR",
                        "message": (
                            "Possible bytearray index out of bounds: modulo "
                            f"{modulus_upper} can exceed size {size}"
                        ),
                        "line": node.lineno,
                        "pc": 0,
                        "function_name": function_name,
                        "class_name": class_name,
                        "full_path": full_path or None,
                        "counterexample": None,
                    }
                )
        self.generic_visit(node)

    def _resolve_container_size(self, node: ast.AST) -> int | None:
        """Resolve the tracked size of a bytearray variable or attribute if available.

        Args:
            node (ast.AST): The node representing the bytearray container.

        Returns:
            int | None: The tracked size in bytes, or None if unknown.
        """
        if isinstance(node, ast.Name) and self._local_sizes_stack:
            return self._local_sizes_stack[-1].get(node.id)
        attr_name = attribute_chain_leaf(node)
        if attr_name is None:
            return None
        return self._bytearray_attrs.get(attr_name)

    def _guarded_upper_bounds(self, test: ast.AST) -> dict[str, int]:
        """Extract variable upper bounds from comparison test expressions.

        Args:
            test (ast.AST): The test expression node.

        Returns:
            dict[str, int]: A mapping of variable names to their upper bound values.
        """
        if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
            return {}
        left = test.left
        right = test.comparators[0]
        if (
            isinstance(left, ast.Name)
            and isinstance(right, ast.Constant)
            and isinstance(right.value, int)
            and isinstance(test.ops[0], ast.Lt)
        ):
            return {left.id: right.value}
        return {}


def collect_bytearray_modulo_index_diagnostics(content: str) -> list[IssueRecord]:
    """Parse Python source code and identify unguarded modulo indexing violations on bytearrays.

    Identifies issues where a modulo index range exceeds the array's statically determined size.

    Args:
        content: The Python source code string to analyze.

    Returns:
        A list of collected index-out-of-bounds issue records.
    """
    tree = ast.parse(content)
    collector = BytearrayModuloIndexCollector()
    collector.visit(tree)
    return collector.issues
