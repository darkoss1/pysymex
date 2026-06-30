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

"""Branch-local fact state for guarded-index preflight diagnostics."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from pysymex._internal.analysis.scan.preflight.guarded.index.syntax import (
    iter_upper_bounds_from_test,
    literal_sequence_length,
    stable_expr_key,
)


@dataclass(frozen=True, slots=True)
class UpperBound:
    """A syntactic upper bound for one sequence index variable."""

    container_key: str
    margin: int


def _empty_lengths() -> dict[str, int]:
    return {}


def _empty_bounds() -> dict[str, list[UpperBound]]:
    return {}


@dataclass(slots=True)
class IndexFacts:
    """Sequence lengths and active guarded index bounds for one scan branch."""

    sequence_lengths: dict[str, int] = field(default_factory=_empty_lengths)
    upper_bounds: dict[str, list[UpperBound]] = field(default_factory=_empty_bounds)

    def fork(self) -> IndexFacts:
        """Return an isolated branch-local copy."""
        return IndexFacts(
            sequence_lengths=dict(self.sequence_lengths),
            upper_bounds={name: list(bounds) for name, bounds in self.upper_bounds.items()},
        )

    def add_upper_bound(self, index_name: str, container_key: str, margin: int) -> None:
        """Record ``index < len(container) - margin`` for the current branch."""
        if margin < 0:
            return
        self.upper_bounds.setdefault(index_name, []).append(UpperBound(container_key, margin))

    def clear_name(self, name: str) -> None:
        """Drop facts invalidated by assigning *name*."""
        self.upper_bounds.pop(name, None)
        prefixes = (f"name:{name}", f"subscr:name:{name}[")
        for key in list(self.sequence_lengths):
            if key.startswith(prefixes):
                self.sequence_lengths.pop(key, None)


def clear_target(target: ast.expr, facts: IndexFacts) -> None:
    """Clear sequence facts invalidated by assigning a simple name."""
    if isinstance(target, ast.Name):
        facts.clear_name(target.id)


def apply_assignment(
    targets: list[ast.expr],
    value: ast.expr,
    facts: IndexFacts,
) -> None:
    """Apply sequence-length and alias facts from an assignment."""
    for target in targets:
        clear_target(target, facts)
        if not isinstance(target, ast.Name):
            continue
        target_key = f"name:{target.id}"
        length = _sequence_length(value, facts)
        if length is not None:
            facts.sequence_lengths[target_key] = length
        _record_dict_sequence_aliases(target.id, value, facts)


def _record_dict_sequence_aliases(
    target_name: str,
    value: ast.expr,
    facts: IndexFacts,
) -> None:
    """Track dictionary entries that alias known sequence lengths."""
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


def _sequence_length(expression: ast.expr, facts: IndexFacts) -> int | None:
    length = literal_sequence_length(expression)
    if length is not None:
        return length
    key = stable_expr_key(expression)
    if key is None:
        return None
    return facts.sequence_lengths.get(key)


def add_upper_bounds_from_test(test: ast.AST, facts: IndexFacts) -> None:
    """Record all syntactic upper bounds discovered in a branch condition."""
    for index_name, container_key, margin in iter_upper_bounds_from_test(test):
        facts.add_upper_bound(index_name, container_key, margin)
