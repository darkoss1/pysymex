# pysymex: Python Symbolic Execution & Formal Verification
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

"""Plugin package for pysymex.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.

Provides an extensible plugin architecture for custom detectors,
handlers, reporters, and analysis passes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from pysymex._lazy import lazy_dir, lazy_getattr

if TYPE_CHECKING:
    from pysymex.plugins.base import (
        HOOKS as HOOKS,
        DetectorPlugin as DetectorPlugin,
        HandlerPlugin as HandlerPlugin,
        HookPlugin as HookPlugin,
        HookPoint as HookPoint,
        Plugin as Plugin,
        PluginConfig as PluginConfig,
        PluginLoader as PluginLoader,
        PluginManager as PluginManager,
        PluginManagerConfig as PluginManagerConfig,
        PluginMetadata as PluginMetadata,
        PluginPriority as PluginPriority,
        PluginRegistry as PluginRegistry,
        PluginType as PluginType,
    )

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


def __getattr__(name: str) -> object:
    """Getattr."""
    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    """Dir."""
    return lazy_dir(_EXPORTS, globals(), include_namespace=False)


__all__ = [
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
