"""Plugin package for PySpectre.
Provides an extensible plugin architecture for custom detectors,
handlers, reporters, and analysis passes.
"""

from pyspectre.plugins.base import (
    HOOKS,
    DetectorPlugin,
    HandlerPlugin,
    HookPlugin,
    HookPoint,
    Plugin,
    PluginConfig,
    PluginLoader,
    PluginManager,
    PluginManagerConfig,
    PluginMetadata,
    PluginPriority,
    PluginRegistry,
    PluginType,
)

__all__ = [
    "PluginType",
    "PluginPriority",
    "PluginMetadata",
    "Plugin",
    "DetectorPlugin",
    "HandlerPlugin",
    "HookPlugin",
    "HookPoint",
    "HOOKS",
    "PluginRegistry",
    "PluginLoader",
    "PluginConfig",
    "PluginManagerConfig",
    "PluginManager",
]
