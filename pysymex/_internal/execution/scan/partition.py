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

"""Code-object partitioning for source-file execution scans."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.execution.scan.types import CodeContext


def split_module_item(
    scan_code_with_context: list[CodeContext],
) -> tuple[CodeContext | None, list[CodeContext]]:
    """Return the module code object, if any, and all non-module code objects."""
    module_item: CodeContext | None = None
    other_items: list[CodeContext] = []
    for item in scan_code_with_context:
        if item[0].co_name == "<module>":
            module_item = item
        else:
            other_items.append(item)
    return module_item, other_items
