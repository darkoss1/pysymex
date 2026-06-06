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
from dataclasses import dataclass, field

from pysymex.analysis.scan.records import IssueRecord


@dataclass(frozen=True, slots=True)
class _UpperBound:
    """A syntactic upper bound for one sequence index variable."""

    container_key: str
    margin: int


def _empty_lengths() -> dict[str, int]:
    return {}


def _empty_bounds() -> dict[str, list[_UpperBound]]:
    return {}


@dataclass(slots=True)
class _IndexFacts:
    """Sequence lengths and active guarded index bounds."""

    sequence_lengths: dict[str, int] = field(default_factory=_empty_lengths)
    upper_bounds: dict[str, list[_UpperBound]] = field(default_factory=_empty_bounds)

    def fork(self) -> "_IndexFacts":
        """Return an isolated branch-local copy."""
        return _IndexFacts(
            sequence_lengths=dict(self.sequence_lengths),
            upper_bounds={name: list(bounds) for name, bounds in self.upper_bounds.items()},
        )

    def add_upper_bound(self, index_name: str, container_key: str, margin: int) -> None:
        """Record ``index < len(container) - margin`` for the current branch."""
        if margin < 0:
            return
        self.upper_bounds.setdefault(index_name, []).append(_UpperBound(container_key, margin))

    def clear_name(self, name: str) -> None:
        """Drop facts invalidated by assigning *name*."""
        self.upper_bounds.pop(name, None)
        prefixes = (f"name:{name}", f"subscr:name:{name}[")
        for key in list(self.sequence_lengths):
            if key.startswith(prefixes):
                self.sequence_lengths.pop(key, None)


class GuardedIndexOffsetCollector(ast.NodeVisitor):
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
        self._scan_statements(node.body, _IndexFacts())
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _scan_statements(self, statements: list[ast.stmt], facts: _IndexFacts) -> None:
        current = facts.fork()
        for statement in statements:
            self._scan_statement(statement, current)

    def _scan_statement(self, statement: ast.stmt, facts: _IndexFacts) -> None:
        if isinstance(statement, ast.Assign):
            self._scan_expr(statement.value, facts)
            self._apply_assignment(statement.targets, statement.value, facts)
            return
        if isinstance(statement, ast.AnnAssign):
            self._scan_expr(statement.value, facts)
            if statement.value is not None:
                self._apply_assignment([statement.target], statement.value, facts)
            return
        if isinstance(statement, ast.AugAssign):
            self._scan_expr(statement.value, facts)
            self._clear_target(statement.target, facts)
            return
        if isinstance(statement, ast.If):
            self._scan_expr(statement.test, facts)
            body_facts = facts.fork()
            _add_upper_bounds_from_test(statement.test, body_facts)
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

    def _scan_expr(self, expression: ast.AST | None, facts: _IndexFacts) -> None:
        if expression is None:
            return
        if isinstance(expression, ast.Subscript):
            self._check_subscript(expression, facts)
        for child in ast.iter_child_nodes(expression):
            if isinstance(child, ast.expr):
                self._scan_expr(child, facts)

    def _apply_assignment(
        self,
        targets: list[ast.expr],
        value: ast.expr,
        facts: _IndexFacts,
    ) -> None:
        for target in targets:
            self._clear_target(target, facts)
            if not isinstance(target, ast.Name):
                continue
            target_key = f"name:{target.id}"
            length = _sequence_length(value, facts)
            if length is not None:
                facts.sequence_lengths[target_key] = length
            self._record_dict_sequence_aliases(target.id, value, facts)

    def _record_dict_sequence_aliases(
        self,
        target_name: str,
        value: ast.expr,
        facts: _IndexFacts,
    ) -> None:
        if not isinstance(value, ast.Dict):
            return
        for key, item in zip(value.keys, value.values, strict=False):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue
            item_length = _sequence_length(item, facts)
            if item_length is None:
                continue
            subscript_key = f"subscr:name:{target_name}[const:{key.value!r}]"
            facts.sequence_lengths[subscript_key] = item_length

    def _clear_target(self, target: ast.expr, facts: _IndexFacts) -> None:
        if isinstance(target, ast.Name):
            facts.clear_name(target.id)

    def _check_subscript(self, node: ast.Subscript, facts: _IndexFacts) -> None:
        container_key = _stable_expr_key(node.value)
        if container_key is None or container_key not in facts.sequence_lengths:
            return
        index_offset = _index_name_plus_offset(node.slice)
        if index_offset is None:
            return
        index_name, offset = index_offset
        for upper_bound in facts.upper_bounds.get(index_name, ()):
            if upper_bound.container_key != container_key:
                continue
            if offset >= upper_bound.margin + 1:
                self._report(node, index_name, offset)
                return

    def _report(self, node: ast.Subscript, index_name: str, offset: int) -> None:
        function_name = self._function_stack[-1] if self._function_stack else None
        class_name = self._class_stack[-1] if self._class_stack else None
        full_path = ".".join([*self._class_stack, *self._function_stack])
        expression = ast.unparse(node)
        key = (node.lineno, full_path, expression)
        if key in self._seen:
            return
        self._seen.add(key)
        self.issues.append(
            {
                "kind": "INDEX_ERROR",
                "message": (
                    f"Possible index out of bounds: {expression} uses {index_name}+{offset} "
                    "beyond its active length guard"
                ),
                "line": node.lineno,
                "pc": 0,
                "function_name": function_name,
                "class_name": class_name,
                "full_path": full_path or None,
                "counterexample": None,
            }
        )


def _sequence_length(expression: ast.expr, facts: _IndexFacts) -> int | None:
    if isinstance(expression, ast.List | ast.Tuple):
        return len(expression.elts)
    if isinstance(expression, ast.Constant) and isinstance(expression.value, (str, bytes)):
        return len(expression.value)
    key = _stable_expr_key(expression)
    if key is None:
        return None
    return facts.sequence_lengths.get(key)


def _add_upper_bounds_from_test(test: ast.AST, facts: _IndexFacts) -> None:
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        for value in test.values:
            _add_upper_bounds_from_test(value, facts)
        return
    if not isinstance(test, ast.Compare):
        return
    operands = [test.left, *test.comparators]
    for left, op, right in zip(operands, test.ops, operands[1:], strict=False):
        bound = _upper_bound_from_comparison(left, op, right)
        if bound is not None:
            index_name, container_key, margin = bound
            facts.add_upper_bound(index_name, container_key, margin)


def _upper_bound_from_comparison(
    left: ast.expr,
    op: ast.cmpop,
    right: ast.expr,
) -> tuple[str, str, int] | None:
    if not isinstance(op, ast.Lt) or not isinstance(left, ast.Name):
        return None
    len_margin = _len_minus_margin(right)
    if len_margin is None:
        return None
    container_key, margin = len_margin
    return left.id, container_key, margin


def _len_minus_margin(expression: ast.expr) -> tuple[str, int] | None:
    if isinstance(expression, ast.Call):
        container_key = _len_call_container_key(expression)
        if container_key is None:
            return None
        return container_key, 0
    if not isinstance(expression, ast.BinOp):
        return None
    if not isinstance(expression.op, (ast.Sub, ast.Add)):
        return None
    container_key = _len_call_container_key(expression.left)
    if container_key is None:
        return None
    if not isinstance(expression.right, ast.Constant) or not isinstance(
        expression.right.value, int
    ):
        return None
    margin = (
        expression.right.value if isinstance(expression.op, ast.Sub) else -expression.right.value
    )
    return container_key, margin


def _len_call_container_key(expression: ast.expr) -> str | None:
    if not isinstance(expression, ast.Call) or len(expression.args) != 1 or expression.keywords:
        return None
    if not isinstance(expression.func, ast.Name) or expression.func.id != "len":
        return None
    return _stable_expr_key(expression.args[0])


def _index_name_plus_offset(expression: ast.expr) -> tuple[str, int] | None:
    if isinstance(expression, ast.Name):
        return expression.id, 0
    if not isinstance(expression, ast.BinOp) or not isinstance(expression.right, ast.Constant):
        return None
    if not isinstance(expression.right.value, int) or not isinstance(expression.left, ast.Name):
        return None
    if isinstance(expression.op, ast.Add):
        return expression.left.id, expression.right.value
    if isinstance(expression.op, ast.Sub):
        return expression.left.id, -expression.right.value
    return None


def _stable_expr_key(expression: ast.expr) -> str | None:
    if isinstance(expression, ast.Name):
        return f"name:{expression.id}"
    if isinstance(expression, ast.Subscript):
        owner = _stable_expr_key(expression.value)
        index = _stable_expr_key(expression.slice)
        if owner is None or index is None:
            return None
        return f"subscr:{owner}[{index}]"
    if isinstance(expression, ast.Constant):
        return f"const:{expression.value!r}"
    return None


def collect_guarded_index_offset_diagnostics(content: str) -> list[IssueRecord]:
    """Return guarded offset subscripts that can exceed a known sequence length."""
    tree = ast.parse(content)
    collector = GuardedIndexOffsetCollector()
    collector.visit(tree)
    return collector.issues


__all__ = ["GuardedIndexOffsetCollector", "collect_guarded_index_offset_diagnostics"]
