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


def __getattr__(name: str) -> object:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pysymex.plugins' has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
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
