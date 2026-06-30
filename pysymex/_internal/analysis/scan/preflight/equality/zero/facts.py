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

"""Guard facts for equality-guarded zero-division preflight diagnostics."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


def _empty_equalities() -> set[frozenset[str]]:
    return set()


def _empty_names_by_key() -> dict[str, frozenset[str]]:
    return {}


@dataclass(slots=True)
class EqualityGuardFacts:
    """Equality facts active in the current syntactic path."""

    equalities: set[frozenset[str]] = field(default_factory=_empty_equalities)
    names_by_key: dict[str, frozenset[str]] = field(default_factory=_empty_names_by_key)

    def fork(self) -> EqualityGuardFacts:
        """Return an isolated copy for branch-local scanning."""
        return EqualityGuardFacts(
            equalities=set(self.equalities),
            names_by_key=dict(self.names_by_key),
        )

    def add_equality(self, left: ast.expr, right: ast.expr) -> None:
        """Add a stable equality relation when both sides are side-effect-free."""
        left_key = _stable_expr_key(left)
        right_key = _stable_expr_key(right)
        if left_key is None or right_key is None or left_key == right_key:
            return
        self.equalities.add(frozenset((left_key, right_key)))
        self.names_by_key[left_key] = frozenset(_referenced_names(left))
        self.names_by_key[right_key] = frozenset(_referenced_names(right))

    def clear_name(self, name: str) -> None:
        """Remove equality facts invalidated by assigning *name*."""
        stale_keys = {key for key, names in self.names_by_key.items() if name in names}
        if not stale_keys:
            return
        self.equalities = {
            equality for equality in self.equalities if not equality.intersection(stale_keys)
        }
        for key in stale_keys:
            self.names_by_key.pop(key, None)


def clear_equality_target(target: ast.expr, facts: EqualityGuardFacts) -> None:
    """Clear equality facts invalidated by a simple assignment target."""
    if isinstance(target, ast.Name):
        facts.clear_name(target.id)


def expr_is_equality_guarded_zero(
    expression: ast.expr,
    facts: EqualityGuardFacts,
) -> bool:
    """Return whether an expression is zero under active equality facts."""
    if not isinstance(expression, ast.BinOp) or not isinstance(expression.op, ast.Sub):
        return False
    left_key = _stable_expr_key(expression.left)
    right_key = _stable_expr_key(expression.right)
    if left_key is None or right_key is None:
        return False
    return left_key == right_key or frozenset((left_key, right_key)) in facts.equalities


def add_equalities_from_test(test: ast.AST, facts: EqualityGuardFacts) -> None:
    """Add branch-local equality facts proven by a syntactic condition."""
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        for value in test.values:
            add_equalities_from_test(value, facts)
        return
    if not isinstance(test, ast.Compare):
        return
    operands = [test.left, *test.comparators]
    for left, op, right in zip(operands, test.ops, operands[1:], strict=False):
        if isinstance(op, ast.Eq):
            facts.add_equality(left, right)


def _stable_expr_key(expression: ast.expr) -> str | None:
    if isinstance(expression, ast.Name):
        return f"name:{expression.id}"
    if isinstance(expression, ast.Attribute):
        owner = _stable_expr_key(expression.value)
        if owner is None:
            return None
        return f"attr:{owner}.{expression.attr}"
    if isinstance(expression, ast.Subscript):
        owner = _stable_expr_key(expression.value)
        index = _stable_expr_key(expression.slice)
        if owner is None or index is None:
            return None
        return f"subscr:{owner}[{index}]"
    if isinstance(expression, ast.Constant):
        return f"const:{expression.value!r}"
    return None


def _referenced_names(expression: ast.AST) -> set[str]:
    return {node.id for node in ast.walk(expression) if isinstance(node, ast.Name)}
