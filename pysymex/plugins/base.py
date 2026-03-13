"""Plugin system for pysymex.
This module provides an extensible plugin architecture that allows users
to add custom detectors, opcode handlers, reporters, and analysis passes.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from types import MappingProxyType
from typing import (
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from pysymex.analysis.detectors import Detector
    from pysymex.execution.executor import SymbolicExecutor as SymbolicEngine


class PluginType(Enum):
    """Types of plugins supported by pysymex."""

    DETECTOR = auto()
    HANDLER = auto()
    REPORTER = auto()
    ANALYZER = auto()
    TRANSFORMER = auto()
    HOOK = auto()


class PluginPriority(Enum):
    """Plugin execution priority."""

    HIGHEST = 0
    HIGH = 25
    NORMAL = 50
    LOW = 75
    LOWEST = 100


@dataclass(frozen=True, slots=True)
class PluginMetadata:
    """Metadata describing a plugin."""

    name: str
    version: str
    description: str = ""
    author: str = ""
    plugin_type: PluginType = PluginType.DETECTOR
    priority: PluginPriority = PluginPriority.NORMAL
    dependencies: list[str] = field(default_factory=list[str])
    conflicts: list[str] = field(default_factory=list[str])
    tags: set[str] = field(default_factory=set[str])

    @property
    def qualified_name(self) -> str:
        """Get fully qualified plugin name."""
        return f"{self .name }@{self .version }"


class Plugin(ABC):
    """Base class for all PySyMex plugins.
    Plugins extend PySyMex functionality by providing custom
    detectors, handlers, reporters, or analysis passes.
    """

    metadata: PluginMetadata

    def __init__(self):
        """Init."""
        """Initialize the class instance."""
        self._enabled: bool = True
        self._config: dict[str, object] = {}

    @property
    def enabled(self) -> bool:
        """Check if plugin is enabled."""
        return self._enabled

    def enable(self) -> None:
        """Enable the plugin."""
        self._enabled = True

    def disable(self) -> None:
        """Disable the plugin."""
        self._enabled = False

    def configure(self, **options: object) -> None:
        """Configure plugin options."""
        self._config.update(options)

    def get_option(self, key: str, default: object = None) -> object:
        """Get a configuration option."""
        return self._config.get(key, default)

    @abstractmethod
    def activate(self, engine: SymbolicEngine) -> None:
        """Called when plugin is activated.
        Use this to register handlers, detectors, etc. with the engine.
        """

    def deactivate(self, engine: SymbolicEngine) -> None:
        """Called when plugin is deactivated."""


class DetectorPlugin(Plugin):
    """Plugin that provides a custom detector."""

    @abstractmethod
    def get_detector(self) -> Detector:
        """Get the detector instance."""

    def activate(self, engine: SymbolicEngine) -> None:
        """Register detector with engine."""
        detector = self.get_detector()
        if hasattr(engine, "add_detector"):
            engine.add_detector(detector)


class HandlerPlugin(Plugin):
    """Plugin that provides custom opcode handlers."""

    @abstractmethod
    def get_handlers(self) -> dict[str, Callable[..., object]]:
        """Get opcode handlers.
        Returns:
            Dict mapping opcode names to handler functions.
            Handler signature: (engine, state, instruction) -> None
        """

    def activate(self, engine: SymbolicEngine) -> None:
        """Register handlers with engine."""
        handlers: dict[str, Callable[..., object]] = self.get_handlers()
        for opcode, handler in handlers.items():
            if hasattr(engine, "register_handler"):
                engine.register_handler(opcode, handler)


@dataclass(frozen=True, slots=True)
class HookPoint:
    """Defines a hook point in the execution flow."""

    name: str
    description: str = ""


HOOKS: MappingProxyType[str, HookPoint] = MappingProxyType(
    {
        "pre_execute": HookPoint("pre_execute", "Before executing an instruction"),
        "post_execute": HookPoint("post_execute", "After executing an instruction"),
        "pre_call": HookPoint("pre_call", "Before a function call"),
        "post_call": HookPoint("post_call", "After a function call"),
        "pre_branch": HookPoint("pre_branch", "Before a branch decision"),
        "post_branch": HookPoint("post_branch", "After a branch is taken"),
        "exception": HookPoint("exception", "When an exception is raised"),
        "path_complete": HookPoint("path_complete", "When a path completes"),
        "state_fork": HookPoint("state_fork", "When state is forked"),
        "state_merge": HookPoint("state_merge", "When states are merged"),
    }
)


class HookPlugin(Plugin):
    """Plugin that hooks into execution points."""

    @abstractmethod
    def get_hooks(self) -> dict[str, Callable[..., object]]:
        """Get hook handlers.
        Returns:
            Dict mapping hook names to handler functions.
        """

    def activate(self, engine: SymbolicEngine) -> None:
        """Register hooks with engine."""
        hooks: dict[str, Callable[..., object]] = self.get_hooks()
        for hook_name, handler in hooks.items():
            if hasattr(engine, "register_hook"):
                engine.register_hook(hook_name, handler)


class PluginRegistry:
    """Central registry for all plugins.
    Manages plugin discovery, loading, and lifecycle.
    """

    def __init__(self):
        """Init."""
        """Initialize the class instance."""
        self._plugins: dict[str, Plugin] = {}
        self._plugin_types: dict[PluginType, list[Plugin]] = {pt: [] for pt in PluginType}
        self._hooks: dict[str, list[Callable[..., object]]] = {name: [] for name in HOOKS}
        self._load_order: list[str] = []

    def register(self, plugin: Plugin) -> None:
        """Register a plugin.
        Args:
            plugin: Plugin instance to register.
        Raises:
            ValueError: If plugin with same name already exists.
        """
        name = plugin.metadata.qualified_name
        if name in self._plugins:
            raise ValueError(f"Plugin already registered: {name }")
        for dep in plugin.metadata.dependencies:
            if dep not in self._plugins:
                raise ValueError(f"Missing dependency: {dep }")
        for conflict in plugin.metadata.conflicts:
            if conflict in self._plugins:
                raise ValueError(f"Conflicting plugin: {conflict }")
        self._plugins[name] = plugin
        self._plugin_types[plugin.metadata.plugin_type].append(plugin)
        self._load_order.append(name)

    def unregister(self, name: str) -> bool:
        """Unregister a plugin by name."""
        if name not in self._plugins:
            return False
        plugin = self._plugins.pop(name)
        self._plugin_types[plugin.metadata.plugin_type].remove(plugin)
        self._load_order.remove(name)
        return True

    def get(self, name: str) -> Plugin | None:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def get_by_type(self, plugin_type: PluginType) -> list[Plugin]:
        """Get all plugins of a specific type."""
        return list(self._plugin_types[plugin_type])

    def get_all(self) -> list[Plugin]:
        """Get all registered plugins in load order."""
        return [self._plugins[name] for name in self._load_order]

    def get_enabled(self) -> list[Plugin]:
        """Get all enabled plugins."""
        return [p for p in self.get_all() if p.enabled]

    def activate_all(self, engine: SymbolicEngine) -> None:
        """Activate all enabled plugins."""
        for plugin in self.get_enabled():
            plugin.activate(engine)

    def deactivate_all(self, engine: SymbolicEngine) -> None:
        """Deactivate all plugins."""
        for plugin in reversed(self.get_enabled()):
            plugin.deactivate(engine)

    def register_hook(self, hook_name: str, handler: Callable[..., object]) -> None:
        """Register a hook handler."""
        if hook_name in self._hooks:
            self._hooks[hook_name].append(handler)

    def trigger_hook(self, hook_name: str, *args: object, **kwargs: object) -> list[object]:
        """Trigger all handlers for a hook."""
        if hook_name not in self._hooks:
            return []
        results: list[object] = []
        for handler in self._hooks[hook_name]:
            try:
                result = handler(*args, **kwargs)
                results.append(result)
            except Exception as e:
                results.append(e)
        return results


class PluginLoader:
    """Loads plugins from various sources."""

    def __init__(self, registry: PluginRegistry):
        """Init."""
        """Initialize the class instance."""
        self.registry = registry
        self._search_paths: list[Path] = []

    def add_search_path(self, path: Path) -> None:
        """Add a directory to search for plugins."""
        if path not in self._search_paths:
            self._search_paths.append(path)

    def load_from_module(self, module_name: str) -> Plugin | None:
        """Load a plugin from a Python module."""
        try:
            module = importlib.import_module(module_name)
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, Plugin)
                    and attr is not Plugin
                    and not attr.__name__.startswith("_")
                ):
                    plugin = attr()
                    self.registry.register(plugin)
                    return plugin
            return None
        except Exception as e:
            print(f"Failed to load plugin from {module_name }: {e }")
            return None

    def load_from_file(self, path: Path) -> Plugin | None:
        """Load a plugin from a Python file."""
        try:
            spec = importlib.util.spec_from_file_location(
                path.stem,
                path,
            )
            if spec is None or spec.loader is None:
                return None
            module = importlib.util.module_from_spec(spec)
            sys.modules[path.stem] = module
            spec.loader.exec_module(module)
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, Plugin)
                    and attr is not Plugin
                    and not attr.__name__.startswith("_")
                ):
                    plugin = attr()
                    self.registry.register(plugin)
                    return plugin
            return None
        except Exception as e:
            print(f"Failed to load plugin from {path }: {e }")
            return None

    def discover_plugins(self) -> list[Plugin]:
        """Discover and load all plugins from search paths."""
        discovered: list[Plugin] = []
        for search_path in self._search_paths:
            if not search_path.exists():
                continue
            for py_file in search_path.glob("*.py"):
                if py_file.name.startswith("_"):
                    continue
                plugin = self.load_from_file(py_file)
                if plugin:
                    discovered.append(plugin)
        return discovered


@dataclass(frozen=True, slots=True)
class PluginConfig:
    """Configuration for a single plugin."""

    name: str
    enabled: bool = True
    options: dict[str, object] = field(default_factory=dict[str, object])


@dataclass(frozen=True, slots=True)
class PluginManagerConfig:
    """Configuration for the plugin manager."""

    search_paths: list[str] = field(default_factory=list[str])
    plugins: list[PluginConfig] = field(default_factory=list[PluginConfig])
    auto_discover: bool = True


class PluginManager:
    """High-level plugin management interface.
    Provides a unified API for working with plugins.
    """

    def __init__(self, config: PluginManagerConfig | None = None):
        """Init."""
        """Initialize the class instance."""
        self.config = config or PluginManagerConfig()
        self.registry = PluginRegistry()
        self.loader = PluginLoader(self.registry)
        for path_str in self.config.search_paths:
            self.loader.add_search_path(Path(path_str))

    def initialize(self) -> None:
        """Initialize the plugin system."""
        if self.config.auto_discover:
            self.loader.discover_plugins()
        for plugin_config in self.config.plugins:
            plugin = self.registry.get(plugin_config.name)
            if plugin:
                if not plugin_config.enabled:
                    plugin.disable()
                plugin.configure(**plugin_config.options)

    def load(self, name: str) -> Plugin | None:
        """Load a plugin by module name or file path."""
        path = Path(name)
        if path.exists() and path.suffix == ".py":
            return self.loader.load_from_file(path)
        return self.loader.load_from_module(name)

    def get(self, name: str) -> Plugin | None:
        """Get a plugin by name."""
        return self.registry.get(name)

    def enable(self, name: str) -> bool:
        """Enable a plugin by name."""
        plugin = self.registry.get(name)
        if plugin:
            plugin.enable()
            return True
        return False

    def disable(self, name: str) -> bool:
        """Disable a plugin by name."""
        plugin = self.registry.get(name)
        if plugin:
            plugin.disable()
            return True
        return False

    def list_plugins(self) -> list[PluginMetadata]:
        """List all registered plugins."""
        return [p.metadata for p in self.registry.get_all()]

    def activate(self, engine: SymbolicEngine) -> None:
        """Activate all enabled plugins on an engine."""
        self.registry.activate_all(engine)

    def deactivate(self, engine: SymbolicEngine) -> None:
        """Deactivate all plugins from an engine."""
        self.registry.deactivate_all(engine)


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
