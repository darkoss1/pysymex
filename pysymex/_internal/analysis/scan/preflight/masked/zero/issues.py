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

"""Issue construction for masked zero-division preflight diagnostics."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import ast

    from pysymex._internal.analysis.records import IssueRecord


def append_masked_zero_issue(
    issues: list[IssueRecord],
    seen: set[tuple[int, str, str]],
    node: ast.BinOp,
    name: str,
    class_stack: list[str],
    function_stack: list[str],
) -> None:
    """Append a stable masked-zero division diagnostic."""
    function_name, class_name, full_path = _current_scope(class_stack, function_stack)
    key = (node.lineno, full_path, name)
    if key in seen:
        return
    seen.add(key)
    issues.append(
        {
            "kind": "DIVISION_BY_ZERO",
            "message": f"Possible division by zero: {name} is guarded equal to 0",
            "line": node.lineno,
            "column": node.col_offset,
            "pc": 0,
            "function_name": function_name,
            "class_name": class_name,
            "full_path": full_path or None,
            "counterexample": None,
        },
    )


def _current_scope(
    class_stack: list[str],
    function_stack: list[str],
) -> tuple[str | None, str | None, str]:
    """Return current function name, class name, and dotted full path."""
    function_name = function_stack[-1] if function_stack else None
    class_name = class_stack[-1] if class_stack else None
    full_path = ".".join([*class_stack, *function_stack])
    return function_name, class_name, full_path
