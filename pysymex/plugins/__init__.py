# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Plugin package for pysymex.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.

Provides an extensible plugin architecture for custom detectors,
handlers, reporters, and analysis passes.
"""

from __future__ import annotations

from importlib import import_module

_EXPORTS: dict[str, tuple[str, str]] = {
    "HOOKS": ("pysymex.plugins.base", "HOOKS"),
    "DetectorPlugin": ("pysymex.plugins.base", "DetectorPlugin"),
    "HandlerPlugin": ("pysymex.plugins.base", "HandlerPlugin"),
    "HookPlugin": ("pysymex.plugins.base", "HookPlugin"),
    "HookPoint": ("pysymex.plugins.base", "HookPoint"),
    "Plugin": ("pysymex.plugins.base", "Plugin"),
    "PluginConfig": ("pysymex.plugins.base", "PluginConfig"),
    "PluginLoader": ("pysymex.plugins.base", "PluginLoader"),
    "PluginManager": ("pysymex.plugins.base", "PluginManager"),
    "PluginManagerConfig": ("pysymex.plugins.base", "PluginManagerConfig"),
    "PluginMetadata": ("pysymex.plugins.base", "PluginMetadata"),
    "PluginPriority": ("pysymex.plugins.base", "PluginPriority"),
    "PluginRegistry": ("pysymex.plugins.base", "PluginRegistry"),
    "PluginType": ("pysymex.plugins.base", "PluginType"),
}


from typing import Any

def __getattr__(name: str) -> Any:
    """Getattr."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pysymex.plugins' has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Dir."""
    return list(_EXPORTS.keys())


__all__: list[str] = [
    "HOOKS",
    "DetectorPlugin",
    "HandlerPlugin",
    "HookPlugin",
    "HookPoint",
    "Plugin",
    "PluginConfig",
    "PluginLoader",
    "PluginManager",
    "PluginManagerConfig",
    "PluginMetadata",
    "PluginPriority",
    "PluginRegistry",
    "PluginType",
]
