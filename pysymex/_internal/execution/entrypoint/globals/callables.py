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

"""Same-module function and class global selection."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING

from pysymex._internal.execution.entrypoint.globals.inspection import (
    GlobalsInspection,
)

if TYPE_CHECKING:
    from collections.abc import Callable


class CallableGlobals:
    """Domain owner for same-module callable and class global selection."""

    @staticmethod
    def select(func: Callable[..., object]) -> dict[str, object]:
        """Return same-module function and class globals visible to nested calls."""
        target_module = getattr(func, "__module__", None)
        if not isinstance(target_module, str):
            return {}
        return {
            name: value
            for name, value in GlobalsInspection.globals_for(func).items()
            if CallableGlobals.matches_module(value, target_module)
        }

    @staticmethod
    def matches_module(value: object, target_module: str) -> bool:
        """Return whether ``value`` is a function or class from ``target_module``."""
        return (inspect.isfunction(value) or inspect.isclass(value)) and getattr(
            value,
            "__module__",
            None,
        ) == target_module
