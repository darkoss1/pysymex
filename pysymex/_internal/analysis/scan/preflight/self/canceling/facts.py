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

"""Flow facts for self-canceling zero-division preflight diagnostics."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class FlowFacts:
    """Branch-local facts for self-canceling zero analysis."""

    zero_vars: set[str] = field(default_factory=set[str])
    dict_values: dict[str, dict[str, ast.expr]] = field(
        default_factory=dict[str, dict[str, ast.expr]],
    )

    def fork(self) -> FlowFacts:
        """Create an isolated copy of tracked zero and dictionary facts."""
        return FlowFacts(
            zero_vars=set(self.zero_vars),
            dict_values={name: dict(values) for name, values in self.dict_values.items()},
        )


def apply_assignment(targets: list[ast.expr], value: ast.expr, facts: FlowFacts) -> None:
    """Apply one assignment value to tracked zero and dictionary facts."""
    for target in targets:
        if not isinstance(target, ast.Name):
            clear_target(target, facts)
            continue
        if expr_is_zero(value, facts):
            facts.zero_vars.add(target.id)
        else:
            facts.zero_vars.discard(target.id)
        dict_values = _dict_literal_values(value)
        if dict_values is None:
            facts.dict_values.pop(target.id, None)
        else:
            facts.dict_values[target.id] = dict_values


def clear_target(target: ast.expr, facts: FlowFacts) -> None:
    """Clear tracked facts for a simple reassigned target."""
    if isinstance(target, ast.Name):
        facts.zero_vars.discard(target.id)
        facts.dict_values.pop(target.id, None)


def merge_branch_facts(before: FlowFacts, body: FlowFacts, orelse: FlowFacts) -> FlowFacts:
    """Merge facts from branch paths using the existing preflight policy."""
    merged = before.fork()
    merged.zero_vars = before.zero_vars | body.zero_vars | orelse.zero_vars
    merged.dict_values = {
        name: values
        for name, values in before.dict_values.items()
        if body.dict_values.get(name) == values and orelse.dict_values.get(name) == values
    }
    return merged


def expr_is_zero(expression: ast.expr, facts: FlowFacts) -> bool:
    """Return whether an expression is known to evaluate to zero."""
    if isinstance(expression, ast.Name):
        return expression.id in facts.zero_vars
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Sub):
        return _expr_equivalent(expression.left, expression.right, facts)
    return False


def zero_reason(expression: ast.expr, facts: FlowFacts) -> str:
    """Return the diagnostic reason for a self-canceling zero expression."""
    if isinstance(expression, ast.Name):
        return expression.id
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Sub):
        if _expr_equivalent(expression.left, expression.right, facts):
            return ast.unparse(expression)
    return ast.unparse(expression)


def _dict_literal_values(value: ast.expr) -> dict[str, ast.expr] | None:
    """Return string-keyed dict literal values, or None for unsupported dicts."""
    if not isinstance(value, ast.Dict):
        return None
    result: dict[str, ast.expr] = {}
    for key, item in zip(value.keys, value.values, strict=False):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            return None
        result[key.value] = item
    return result


def _expr_equivalent(left: ast.expr, right: ast.expr, facts: FlowFacts) -> bool:
    """Compare expressions after resolving tracked dictionary literal aliases."""
    return ast.dump(_resolve_expr(left, facts)) == ast.dump(_resolve_expr(right, facts))


def _resolve_expr(expression: ast.expr, facts: FlowFacts) -> ast.expr:
    """Resolve tracked string-key dictionary lookups to their literal values."""
    if not isinstance(expression, ast.Subscript) or not isinstance(expression.value, ast.Name):
        return expression
    key = expression.slice
    if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
        return expression
    return facts.dict_values.get(expression.value.id, {}).get(key.value, expression)
