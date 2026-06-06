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
from dataclasses import dataclass, field

from pysymex.analysis.scan.preflight.exception_handlers import try_suppresses_exception
from pysymex.analysis.scan.records import IssueRecord


@dataclass
class _FlowFacts:
    """Represents dataflow facts tracked during preflight analysis of self-canceling operations.

    Tracks which variable names resolve to zero, and caches static dictionary literal keys to
    support dictionary lookup analysis.

    Attributes:
        zero_vars: Set of variable names currently known to evaluate to zero.
        dict_values: Dictionary value mappings tracked for local key-value lookups.
    """

    zero_vars: set[str] = field(default_factory=set[str])
    dict_values: dict[str, dict[str, ast.expr]] = field(
        default_factory=dict[str, dict[str, ast.expr]]
    )

    def fork(self) -> "_FlowFacts":
        """Create a copy of the flow facts for path branching.

        Returns:
            _FlowFacts: A new _FlowFacts instance with copies of tracked variables and dict mappings.
        """
        return _FlowFacts(
            zero_vars=set(self.zero_vars),
            dict_values={name: dict(values) for name, values in self.dict_values.items()},
        )


class SelfCancelingZeroDivisionCollector(ast.NodeVisitor):
    """Find divisions by values proven zero through ``expr - expr`` cancellation.

    Traverses functions and control flow blocks, updating and propagating flow facts
    to identify divisions or modulo operations where the divisor evaluates to zero.
    Discovered findings are appended to `issues`.

    Attributes:
        issues: List of discovered division-by-zero issue records.
    """

    def __init__(self) -> None:
        """Initialize the SelfCancelingZeroDivisionCollector instance."""
        self.issues: list[IssueRecord] = []
        self._class_stack: list[str] = []
        self._function_stack: list[str] = []
        self._seen: set[tuple[int, str, str]] = set()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class definition node and traverse its body.

        Args:
            node (ast.ClassDef): The class definition AST node.
        """
        self._class_stack.append(node.name)
        for child in node.body:
            self.visit(child)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Visit a function definition node and scan its body statements.

        Args:
            node (ast.FunctionDef | ast.AsyncFunctionDef): The function definition AST node.
        """
        self._function_stack.append(node.name)
        self._scan_statements(node.body, _FlowFacts())
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _scan_statements(self, statements: list[ast.stmt], facts: _FlowFacts) -> _FlowFacts:
        """Scan a sequence of statements sequentially, updating flow facts.

        Args:
            statements (list[ast.stmt]): The list of statements to scan.
            facts (_FlowFacts): The initial flow facts.

        Returns:
            _FlowFacts: The updated flow facts after scanning the statements.
        """
        current = facts.fork()
        for statement in statements:
            current = self._scan_statement(statement, current)
        return current

    def _scan_statement(self, statement: ast.stmt, facts: _FlowFacts) -> _FlowFacts:
        """Scan a single statement and update flow facts.

        Args:
            statement (ast.stmt): The statement AST node.
            facts (_FlowFacts): The current flow facts.

        Returns:
            _FlowFacts: The updated flow facts.
        """
        current = facts.fork()
        if isinstance(statement, ast.Assign):
            self._scan_expr(statement.value, current)
            self._apply_assignment(statement.targets, statement.value, current)
            return current
        if isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                self._scan_expr(statement.value, current)
                self._apply_assignment([statement.target], statement.value, current)
            return current
        if isinstance(statement, ast.AugAssign):
            self._scan_expr(statement.value, current)
            self._clear_target(statement.target, current)
            return current
        if isinstance(statement, ast.If):
            self._scan_expr(statement.test, current)
            body_facts = self._scan_statements(statement.body, current)
            else_facts = self._scan_statements(statement.orelse, current)
            return self._merge_branch_facts(current, body_facts, else_facts)
        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            self._scan_expr(getattr(statement, "test", None), current)
            body_facts = self._scan_statements(statement.body, current)
            else_facts = self._scan_statements(statement.orelse, current)
            return self._merge_branch_facts(current, body_facts, else_facts)
        if isinstance(statement, ast.Return):
            self._scan_expr(statement.value, current)
            return current
        if isinstance(statement, ast.Expr):
            self._scan_expr(statement.value, current)
            return current
        if isinstance(statement, ast.Try):
            self._scan_try(statement, current)
            return current
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.visit(statement)
            return current
        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.expr):
                self._scan_expr(child, current)
        return current

    def _scan_try(self, statement: ast.Try, facts: _FlowFacts) -> None:
        """Scan a try statement, checking all its constituent bodies with the current flow facts.

        Args:
            statement (ast.Try): The try AST node.
            facts (_FlowFacts): The current flow facts.
        """
        if not try_suppresses_exception(statement, "ZeroDivisionError"):
            self._scan_statements(statement.body, facts)
        for handler in statement.handlers:
            self._scan_statements(handler.body, facts)
        self._scan_statements(statement.orelse, facts)
        self._scan_statements(statement.finalbody, facts)

    def _scan_expr(self, expression: ast.AST | None, facts: _FlowFacts) -> None:
        """Scan an expression node for potential division-by-zero occurrences.

        Args:
            expression (ast.AST | None): The expression node to scan.
            facts (_FlowFacts): The current flow facts.
        """
        if expression is None:
            return
        if isinstance(expression, ast.BinOp) and isinstance(
            expression.op, (ast.Div, ast.FloorDiv, ast.Mod)
        ):
            if self._expr_is_zero(expression.right, facts):
                self._report(expression, self._zero_reason(expression.right, facts))
        for child in ast.iter_child_nodes(expression):
            if isinstance(child, ast.expr):
                self._scan_expr(child, facts)

    def _apply_assignment(
        self, targets: list[ast.expr], value: ast.expr, facts: _FlowFacts
    ) -> None:
        """Apply an assignment value to targets, updating tracked zero variables and dictionary literals.

        Args:
            targets (list[ast.expr]): The assignment targets.
            value (ast.expr): The value being assigned.
            facts (_FlowFacts): The current flow facts.
        """
        for target in targets:
            if not isinstance(target, ast.Name):
                self._clear_target(target, facts)
                continue
            if self._expr_is_zero(value, facts):
                facts.zero_vars.add(target.id)
            else:
                facts.zero_vars.discard(target.id)
            dict_values = self._dict_literal_values(value)
            if dict_values is None:
                facts.dict_values.pop(target.id, None)
            else:
                facts.dict_values[target.id] = dict_values

    def _clear_target(self, target: ast.expr, facts: _FlowFacts) -> None:
        """Clear any tracked zero or dictionary facts for a target when it is reassigned or modified.

        Args:
            target (ast.expr): The target node to clear.
            facts (_FlowFacts): The current flow facts.
        """
        if isinstance(target, ast.Name):
            facts.zero_vars.discard(target.id)
            facts.dict_values.pop(target.id, None)

    def _merge_branch_facts(
        self, before: _FlowFacts, body: _FlowFacts, orelse: _FlowFacts
    ) -> _FlowFacts:
        """Merge facts from branch paths (such as the body and else block of an if statement).

        Args:
            before (_FlowFacts): Flow facts before the branch.
            body (_FlowFacts): Flow facts from the body branch.
            orelse (_FlowFacts): Flow facts from the else branch.

        Returns:
            _FlowFacts: The merged flow facts.
        """
        merged = before.fork()
        merged.zero_vars = before.zero_vars | body.zero_vars | orelse.zero_vars
        merged.dict_values = {
            name: values
            for name, values in before.dict_values.items()
            if body.dict_values.get(name) == values and orelse.dict_values.get(name) == values
        }
        return merged

    def _dict_literal_values(self, value: ast.expr) -> dict[str, ast.expr] | None:
        """Extract constant string keys and item values from a dict literal node.

        Args:
            value (ast.expr): The dictionary AST expression node.

        Returns:
            dict[str, ast.expr] | None: A dictionary mapping keys to expression nodes, or None if not a dict literal.
        """
        if not isinstance(value, ast.Dict):
            return None
        result: dict[str, ast.expr] = {}
        for key, item in zip(value.keys, value.values, strict=False):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                return None
            result[key.value] = item
        return result

    def _expr_is_zero(self, expression: ast.expr, facts: _FlowFacts) -> bool:
        """Determine if an expression resolves to zero (either a tracked zero variable or a self-canceling subtraction).

        Args:
            expression (ast.expr): The expression to evaluate.
            facts (_FlowFacts): The current flow facts.

        Returns:
            bool: True if the expression is proven to evaluate to zero, False otherwise.
        """
        if isinstance(expression, ast.Name):
            return expression.id in facts.zero_vars
        if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Sub):
            return self._expr_equivalent(expression.left, expression.right, facts)
        return False

    def _expr_equivalent(self, left: ast.expr, right: ast.expr, facts: _FlowFacts) -> bool:
        """Check if two expressions are structurally equivalent after resolving variables to their literal values.

        Args:
            left (ast.expr): The left expression.
            right (ast.expr): The right expression.
            facts (_FlowFacts): The current flow facts.

        Returns:
            bool: True if the expressions are equivalent, False otherwise.
        """
        return ast.dump(self._resolve_expr(left, facts)) == ast.dump(
            self._resolve_expr(right, facts)
        )

    def _resolve_expr(self, expression: ast.expr, facts: _FlowFacts) -> ast.expr:
        """Resolve a variable subscript reference to its dictionary literal value if tracked.

        Args:
            expression (ast.expr): The expression to resolve.
            facts (_FlowFacts): The current flow facts.

        Returns:
            ast.expr: The resolved expression, or the original expression if it cannot be resolved.
        """
        if not isinstance(expression, ast.Subscript) or not isinstance(expression.value, ast.Name):
            return expression
        key = expression.slice
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            return expression
        return facts.dict_values.get(expression.value.id, {}).get(key.value, expression)

    def _zero_reason(self, expression: ast.expr, facts: _FlowFacts) -> str:
        """Get a user-friendly string representing the reason an expression evaluates to zero.

        Args:
            expression (ast.expr): The expression evaluated to zero.
            facts (_FlowFacts): The current flow facts.

        Returns:
            str: The description string.
        """
        if isinstance(expression, ast.Name):
            return expression.id
        if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Sub):
            if self._expr_equivalent(expression.left, expression.right, facts):
                return ast.unparse(expression)
        return ast.unparse(expression)

    def _report(self, node: ast.BinOp, reason: str) -> None:
        """Record a self-canceling division by zero issue.

        Args:
            node (ast.BinOp): The binary operation causing the division by zero.
            reason (str): The reason or expression that evaluated to zero.
        """
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
                "message": f"Possible division by zero: {reason} is self-canceling zero",
                "line": node.lineno,
                "pc": 0,
                "function_name": function_name,
                "class_name": class_name,
                "full_path": full_path or None,
                "counterexample": None,
            }
        )


def collect_self_canceling_zero_division_diagnostics(content: str) -> list[IssueRecord]:
    """Parse Python source code and identify occurrences of divisions where the divisor evaluates to zero.

    Args:
        content: The Python source code string to analyze.

    Returns:
        A list of collected division by zero issue records.
    """
    tree = ast.parse(content)
    collector = SelfCancelingZeroDivisionCollector()
    collector.visit(tree)
    return collector.issues
