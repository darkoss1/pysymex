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

"""Same-module object-instance global selection for function entrypoints."""

from __future__ import annotations

import inspect
import types
from types import CodeType
from typing import TYPE_CHECKING

from pysymex._internal.execution.entrypoint.globals.inspection import (
    GlobalsInspection,
)

if TYPE_CHECKING:
    from collections.abc import Callable


class InstanceGlobals:
    """Domain owner for same-module instance global selection."""

    @staticmethod
    def select(
        func: Callable[..., object],
        code: CodeType,
    ) -> dict[str, object]:
        """Return referenced same-module instances safe to expose as globals."""
        target_module = getattr(func, "__module__", None)
        if not isinstance(target_module, str):
            return {}

        globals_map = GlobalsInspection.globals_for(func)
        selected: dict[str, object] = {}
        for name in dict.fromkeys(code.co_names):
            value = globals_map.get(name)
            if InstanceGlobals.is_seedable(value, target_module):
                selected[name] = value
        return selected

    @staticmethod
    def is_seedable(value: object, target_module: str) -> bool:
        """Return whether an existing object instance may be seeded as a global."""
        if value is None or isinstance(
            value,
            (
                bool,
                int,
                float,
                str,
                bytes,
                tuple,
                list,
                dict,
                set,
                frozenset,
                type,
                types.ModuleType,
            ),
        ):
            return False
        if (
            callable(value)
            or inspect.isfunction(value)
            or inspect.isclass(value)
            or inspect.ismethod(value)
        ):
            return False

        cls = type(value)
        return getattr(cls, "__module__", None) == target_module and not (
            InstanceGlobals.has_dynamic_attribute_hook(cls)
        )

    @staticmethod
    def has_dynamic_attribute_hook(class_obj: type[object]) -> bool:
        """Return whether instances of ``cls`` have dynamic attribute lookup hooks."""
        try:
            if inspect.getattr_static(class_obj, "__getattr__", None) is not None:
                return True
            getattribute = inspect.getattr_static(
                class_obj,
                "__getattribute__",
                object.__getattribute__,
            )
        except (AttributeError, TypeError):
            return True
        return getattribute is not object.__getattribute__
