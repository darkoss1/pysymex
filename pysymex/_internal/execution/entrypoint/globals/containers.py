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

"""Mutable container global selection for function entrypoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.entrypoint.globals.inspection import (
    GlobalsInspection,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import CodeType


class EntrypointContainerGlobals:
    """Domain owner for referenced mutable container global selection."""

    @staticmethod
    def select(
        func: Callable[..., object],
        code: CodeType,
    ) -> dict[str, object]:
        """Return referenced built-in mutable container globals safe to model."""
        globals_map = GlobalsInspection.globals_for(func)
        selected: dict[str, object] = {}
        for name in GlobalsInspection.referenced_names(code):
            value = globals_map.get(name)
            if isinstance(value, (list, dict, set)):
                selected[name] = value
        return selected
