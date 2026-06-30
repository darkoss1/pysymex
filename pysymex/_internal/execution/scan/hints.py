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

"""Callable type-hint selection for source-file execution scans."""

from __future__ import annotations


def callable_type_hints(
    *,
    source_type_hints: dict[tuple[str, str | None], dict[str, str]],
    code_name: str,
    class_name: str | None,
) -> dict[str, str]:
    """Return source hints for one callable code object."""
    hints: dict[str, str] = dict(source_type_hints.get((code_name, class_name), {}))
    if class_name:
        for param, hint in source_type_hints.get(("__init__", class_name), {}).items():
            if param not in {"self", "cls"}:
                hints[f"__init__.{param}"] = hint
    return hints
