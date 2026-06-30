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

"""Issue construction for guarded-index preflight diagnostics."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from pysymex._internal.analysis.scan.preflight.guarded.index.syntax import (
    index_name_plus_offset,
    stable_expr_key,
)

if TYPE_CHECKING:
    from pysymex._internal.analysis.records import IssueRecord
    from pysymex._internal.analysis.scan.preflight.guarded.index.facts import IndexFacts


def check_subscript(
    issues: list[IssueRecord],
    seen: set[tuple[int, str, str]],
    node: ast.Subscript,
    facts: IndexFacts,
    class_stack: list[str],
    function_stack: list[str],
) -> None:
    """Report guarded offset subscripts that can exceed their own guard."""
    container_key = stable_expr_key(node.value)
    if container_key is None or container_key not in facts.sequence_lengths:
        return
    index_offset = index_name_plus_offset(node.slice)
    if index_offset is None:
        return
    index_name, offset = index_offset
    for upper_bound in facts.upper_bounds.get(index_name, ()):
        if upper_bound.container_key != container_key:
            continue
        if offset >= upper_bound.margin + 1:
            _append_guarded_index_issue(
                issues,
                seen,
                node,
                index_name,
                offset,
                class_stack,
                function_stack,
            )
            return


def _append_guarded_index_issue(
    issues: list[IssueRecord],
    seen: set[tuple[int, str, str]],
    node: ast.Subscript,
    index_name: str,
    offset: int,
    class_stack: list[str],
    function_stack: list[str],
) -> None:
    """Append a stable guarded-index offset diagnostic."""
    function_name = function_stack[-1] if function_stack else None
    class_name = class_stack[-1] if class_stack else None
    full_path = ".".join([*class_stack, *function_stack])
    expression = ast.unparse(node)
    key = (node.lineno, full_path, expression)
    if key in seen:
        return
    seen.add(key)
    issues.append(
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
        },
    )
