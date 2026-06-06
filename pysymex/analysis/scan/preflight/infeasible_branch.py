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

"""Infeasible-branch suppressions for value-range division warnings.

Detects statically contradictory ``if`` guards whose bodies contain literal
``// 0`` divisions that abstract range analysis may still warn on.
"""

from __future__ import annotations

import ast


def _single_compare(test: ast.AST, op_type: type[ast.cmpop]) -> tuple[ast.expr, ast.expr] | None:
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return None
    if not isinstance(test.ops[0], op_type):
        return None
    return test.left, test.comparators[0]


def _zero_constant(expression: ast.AST) -> bool:
    return isinstance(expression, ast.Constant) and expression.value == 0


def _stable_expr_key(expression: ast.expr) -> str | None:
    if isinstance(expression, ast.Name):
        return f"name:{expression.id}"
    if isinstance(expression, ast.BinOp) and isinstance(
        expression.op, (ast.BitAnd, ast.BitOr, ast.BitXor, ast.Add, ast.Sub)
    ):
        left = _stable_expr_key(expression.left)
        right = _stable_expr_key(expression.right)
        if left is None or right is None:
            return None
        return f"binop:{type(expression.op).__name__}:{left}:{right}"
    return None


def _nonzero_guard(test: ast.AST) -> str | None:
    operands = _single_compare(test, ast.NotEq)
    if operands is None:
        return None
    left, right = operands
    if _zero_constant(right):
        return _stable_expr_key(left)
    if _zero_constant(left):
        return _stable_expr_key(right)
    return None


def _zero_bin_count_guard(test: ast.AST) -> str | None:
    operands = _single_compare(test, ast.Eq)
    if operands is None:
        return None
    left, right = operands
    if _zero_constant(right):
        call = left
    elif _zero_constant(left):
        call = right
    else:
        return None
    if not isinstance(call, ast.Call):
        return None
    if not (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "count"
        and isinstance(call.func.value, ast.Call)
        and isinstance(call.func.value.func, ast.Name)
        and call.func.value.func.id == "bin"
        and len(call.func.value.args) == 1
        and not call.func.value.keywords
        and not call.keywords
    ):
        return None
    if not (
        len(call.args) == 1
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value in {"1", "0"}
    ):
        return None
    return _stable_expr_key(call.func.value.args[0])


def _endswith_truthy_guard(test: ast.AST) -> tuple[str, str] | None:
    call = test
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "endswith"
        and len(call.args) == 1
        and not call.keywords
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    ):
        return None
    receiver = _stable_expr_key(call.func.value)
    if receiver is None:
        return None
    return receiver, call.args[0].value


def _negative_one_constant(expression: ast.AST) -> bool:
    if isinstance(expression, ast.Constant) and expression.value == -1:
        return True
    return (
        isinstance(expression, ast.UnaryOp)
        and isinstance(expression.op, ast.USub)
        and isinstance(expression.operand, ast.Constant)
        and expression.operand.value == 1
    )


def _missing_rfind_guard(test: ast.AST) -> str | None:
    operands = _single_compare(test, ast.Eq)
    if operands is None:
        return None
    left, right = operands
    if _negative_one_constant(right) and isinstance(left, ast.Name):
        return left.id
    if _negative_one_constant(left) and isinstance(right, ast.Name):
        return right.id
    return None


def _iter_and_clauses(test: ast.AST) -> list[ast.AST]:
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        clauses: list[ast.AST] = []
        for value in test.values:
            clauses.extend(_iter_and_clauses(value))
        return clauses
    return [test]


def _literal_zero_division_lines(body: list[ast.stmt]) -> set[int]:
    class _LiteralZeroDivisionCollector(ast.NodeVisitor):
        def __init__(self) -> None:
            self.lines: set[int] = set()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            _ = node

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            _ = node

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            _ = node

        def visit_BinOp(self, node: ast.BinOp) -> None:
            if isinstance(node.op, ast.FloorDiv) and _zero_constant(node.right):
                self.lines.add(node.lineno)
            self.generic_visit(node)

    collector = _LiteralZeroDivisionCollector()
    for statement in body:
        collector.visit(statement)
    return collector.lines


def _bin_count_contradiction(test: ast.AST) -> bool:
    clauses = _iter_and_clauses(test)
    nonzero_keys = {_nonzero_guard(clause) for clause in clauses}
    count_keys = {_zero_bin_count_guard(clause) for clause in clauses}
    nonzero_keys.discard(None)
    count_keys.discard(None)
    return bool(nonzero_keys & count_keys)


def _endswith_rfind_contradiction(
    test: ast.AST, rfind_bindings: dict[str, tuple[str, str]]
) -> bool:
    clauses = _iter_and_clauses(test)
    endswith_targets: set[tuple[str, str]] = set()
    missing_index_names: set[str] = set()
    for clause in clauses:
        endswith = _endswith_truthy_guard(clause)
        if endswith is not None:
            endswith_targets.add(endswith)
        missing = _missing_rfind_guard(clause)
        if missing is not None:
            missing_index_names.add(missing)
    for index_name in missing_index_names:
        binding = rfind_bindings.get(index_name)
        if binding is not None and binding in endswith_targets:
            return True
    return False


class InfeasibleBranchSuppressionCollector(ast.NodeVisitor):
    """Collect source lines whose literal zero divisions sit on infeasible branches."""

    def __init__(self) -> None:
        self.suppressed_lines: set[int] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._scan_function(node.body)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _scan_function(self, statements: list[ast.stmt]) -> None:
        rfind_bindings: dict[str, tuple[str, str]] = {}
        for statement in statements:
            self._scan_statement(statement, rfind_bindings)

    def _scan_statement(
        self, statement: ast.stmt, rfind_bindings: dict[str, tuple[str, str]]
    ) -> None:
        _update_rfind_bindings(statement, rfind_bindings)
        if isinstance(statement, ast.If):
            if _bin_count_contradiction(statement.test) or _endswith_rfind_contradiction(
                statement.test, rfind_bindings
            ):
                self.suppressed_lines.update(_literal_zero_division_lines(statement.body))
            self._scan_statements(statement.body, dict(rfind_bindings))
            self._scan_statements(statement.orelse, dict(rfind_bindings))
            return
        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            body_bindings = dict(rfind_bindings)
            if isinstance(statement, (ast.For, ast.AsyncFor)):
                _remove_target_bindings(statement.target, body_bindings)
            self._scan_statements(statement.body, body_bindings)
            self._scan_statements(statement.orelse, dict(rfind_bindings))
            return
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            body_bindings = dict(rfind_bindings)
            for item in statement.items:
                if item.optional_vars is not None:
                    _remove_target_bindings(item.optional_vars, body_bindings)
            self._scan_statements(statement.body, body_bindings)
            return
        if isinstance(statement, ast.Try):
            self._scan_statements(statement.body, dict(rfind_bindings))
            for handler in statement.handlers:
                handler_bindings = dict(rfind_bindings)
                if handler.name is not None:
                    handler_bindings.pop(handler.name, None)
                self._scan_statements(handler.body, handler_bindings)
            self._scan_statements(statement.orelse, dict(rfind_bindings))
            self._scan_statements(statement.finalbody, dict(rfind_bindings))
            return
        if isinstance(statement, ast.Match):
            for case in statement.cases:
                self._scan_statements(case.body, dict(rfind_bindings))
            return
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.visit(statement)

    def _scan_statements(
        self,
        statements: list[ast.stmt],
        rfind_bindings: dict[str, tuple[str, str]],
    ) -> None:
        for statement in statements:
            self._scan_statement(statement, rfind_bindings)


def _remove_target_bindings(target: ast.expr, bindings: dict[str, tuple[str, str]]) -> None:
    if isinstance(target, ast.Name):
        bindings.pop(target.id, None)
        return
    if isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            _remove_target_bindings(element, bindings)
        return
    if isinstance(target, ast.Starred):
        _remove_target_bindings(target.value, bindings)


def _rfind_binding_from_assignment(value: ast.AST) -> tuple[str, str] | None:
    if not (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr == "rfind"
        and len(value.args) == 1
        and not value.keywords
        and isinstance(value.args[0], ast.Constant)
        and isinstance(value.args[0].value, str)
    ):
        return None
    receiver = _stable_expr_key(value.func.value)
    if receiver is None:
        return None
    return receiver, value.args[0].value


def _update_rfind_bindings(statement: ast.stmt, bindings: dict[str, tuple[str, str]]) -> None:
    if isinstance(statement, ast.Assign):
        binding = _rfind_binding_from_assignment(statement.value)
        for target in statement.targets:
            _remove_target_bindings(target, bindings)
        if (
            binding is not None
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            bindings[statement.targets[0].id] = binding
        return
    if isinstance(statement, ast.AnnAssign):
        _remove_target_bindings(statement.target, bindings)
        binding = _rfind_binding_from_assignment(statement.value) if statement.value else None
        if binding is not None and isinstance(statement.target, ast.Name):
            bindings[statement.target.id] = binding
        return
    if isinstance(statement, ast.AugAssign):
        _remove_target_bindings(statement.target, bindings)
        return
    if isinstance(statement, ast.Delete):
        for target in statement.targets:
            _remove_target_bindings(target, bindings)


def collect_infeasible_branch_division_suppressions(content: str) -> frozenset[int]:
    """Return source lines whose literal ``// 0`` sits on a statically dead branch."""
    tree = ast.parse(content)
    collector = InfeasibleBranchSuppressionCollector()
    collector.visit(tree)
    return frozenset(collector.suppressed_lines)


__all__ = [
    "InfeasibleBranchSuppressionCollector",
    "collect_infeasible_branch_division_suppressions",
]
