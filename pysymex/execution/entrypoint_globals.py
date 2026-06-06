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

"""Select concrete function globals admitted into ``execute_function`` runs.

Owns the trust boundary for globals copied from ``func.__globals__`` into the
initial VM state and cache dependency fingerprints. The selector never imports
or executes target code; it only inspects globals already present on the Python
function object.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import inspect
import types
from types import CodeType
from typing import cast

__all__ = [
    "referenced_same_module_instance_globals",
    "same_module_function_or_class_globals",
]


def same_module_function_or_class_globals(func: Callable[..., object]) -> dict[str, object]:
    """Return same-module function and class globals visible to nested calls."""
    target_module = getattr(func, "__module__", None)
    if not isinstance(target_module, str):
        return {}
    return {
        name: value
        for name, value in _function_globals(func).items()
        if _is_same_module_function_or_class(value, target_module)
    }


def referenced_same_module_instance_globals(
    func: Callable[..., object],
    code: CodeType,
) -> dict[str, object]:
    """Return referenced same-module instances safe to expose as globals."""
    target_module = getattr(func, "__module__", None)
    if not isinstance(target_module, str):
        return {}

    globals_map = _function_globals(func)
    selected: dict[str, object] = {}
    for name in dict.fromkeys(code.co_names):
        value = globals_map.get(name)
        if _is_seedable_same_module_instance(value, target_module):
            selected[name] = value
    return selected


def _function_globals(func: Callable[..., object]) -> Mapping[str, object]:
    raw_globals = getattr(func, "__globals__", {})
    if isinstance(raw_globals, dict):
        return cast("Mapping[str, object]", raw_globals)
    if isinstance(raw_globals, Mapping):
        return cast("Mapping[str, object]", raw_globals)
    return {}


def _is_same_module_function_or_class(value: object, target_module: str) -> bool:
    return (inspect.isfunction(value) or inspect.isclass(value)) and getattr(
        value, "__module__", None
    ) == target_module


def _is_seedable_same_module_instance(value: object, target_module: str) -> bool:
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
    return getattr(cls, "__module__", None) == target_module and not _has_dynamic_attribute_hook(
        cls
    )


def _has_dynamic_attribute_hook(cls: type[object]) -> bool:
    try:
        if inspect.getattr_static(cls, "__getattr__", None) is not None:
            return True
        getattribute = inspect.getattr_static(cls, "__getattribute__", object.__getattribute__)
    except (AttributeError, TypeError):
        return True
    return getattribute is not object.__getattribute__
