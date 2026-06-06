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

"""Code-object traversal facts shared by scan and static analysis."""

from __future__ import annotations

import types


def get_code_objects_with_context(
    code: types.CodeType, parent_path: str | None = None
) -> list[tuple[types.CodeType, str | None, str | None]]:
    """Recursively extract nested code objects with hierarchical path context.

    Traverses ``co_consts`` to find nested callable definitions such as class
    bodies, methods, and nested functions.

    Args:
        code: Root compiled bytecode object to traverse.
        parent_path: Dotted parent hierarchy path.

    Returns:
        Tuples of ``(code_object, immediate_parent, full_path)`` where
        ``full_path`` is relative to the module root.
    """
    current_name = code.co_name
    if current_name == "<module>":
        full_path: str | None = None
        immediate_parent: str | None = None
    else:
        full_path = f"{parent_path}.{current_name}" if parent_path else current_name
        immediate_parent = parent_path

    results: list[tuple[types.CodeType, str | None, str | None]] = [
        (code, immediate_parent, full_path)
    ]
    child_parent = full_path if current_name != "<module>" else None
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            results.extend(get_code_objects_with_context(const, child_parent))
    return results


__all__ = ["get_code_objects_with_context"]
