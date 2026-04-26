from pathlib import Path
from unittest.mock import MagicMock
from typing import TYPE_CHECKING, cast

from pysymex.plugins.base import (
    PluginType,
    PluginPriority,
    PluginMetadata,
    Plugin,
    DetectorPlugin,
    HandlerPlugin,
    HookPoint,
    HookPlugin,
    PluginRegistry,
    PluginLoader,
    PluginConfig,
    PluginManagerConfig,
    PluginManager,
)

if TYPE_CHECKING:
    from pysymex.execution.executors import SymbolicExecutor


class DummyPlugin(Plugin):
    """Dummy plugin for testing."""

    def __init__(self) -> None:
        super().__init__()
        self.metadata = PluginMetadata(name="dummy", version="1.0")

    def activate(self, engine: "SymbolicExecutor") -> None:
        """Activate the plugin."""
        pass


class DummyDetectorPlugin(DetectorPlugin):
    """Dummy detector plugin for testing."""

    def __init__(self) -> None:
        super().__init__()
        self.metadata = PluginMetadata(name="detector", version="1.0")

    def get_detector(self) -> object:
        """Get the dummy detector."""
        return "dummy_detector"


class DummyHandlerPlugin(HandlerPlugin):
    """Dummy handler plugin for testing."""

    def __init__(self) -> None:
        super().__init__()
        self.metadata = PluginMetadata(name="handler", version="1.0")

    def get_handlers(self) -> dict[str, object]:
        """Get the dummy handlers."""
        return {"OPCODE": "dummy_handler"}


class DummyHookPlugin(HookPlugin):
    """Dummy hook plugin for testing."""

    def __init__(self) -> None:
        super().__init__()
        self.metadata = PluginMetadata(name="hook", version="1.0")

    def get_hooks(self) -> dict[str, object]:
        """Get the dummy hooks."""
        return {"hook_name": "dummy_hook"}


class TestPluginType:
    """Test suite for pysymex.plugins.base.PluginType."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert isinstance(PluginType.DETECTOR, PluginType)
        assert PluginType.DETECTOR.name == "DETECTOR"


class TestPluginPriority:
    """Test suite for pysymex.plugins.base.PluginPriority."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert isinstance(PluginPriority.NORMAL, PluginPriority)
        assert PluginPriority.NORMAL.value == 50


class TestPluginMetadata:
    """Test suite for pysymex.plugins.base.PluginMetadata."""

    def test_qualified_name(self) -> None:
        """Test qualified_name behavior."""
        meta = PluginMetadata(name="test_plugin", version="1.0.0")
        assert meta.qualified_name == "test_plugin@1.0.0"


class TestPlugin:
    """Test suite for pysymex.plugins.base.Plugin."""

    def test_enabled(self) -> None:
        """Test enabled behavior."""
        plugin = DummyPlugin()
        assert plugin.enabled is True

    def test_enabled_setter(self) -> None:
        """Test enabled setter behavior."""
        plugin = DummyPlugin()
        plugin.enabled = False
        assert plugin.enabled is False

    def test_enable(self) -> None:
        """Test enable behavior."""
        plugin = DummyPlugin()
        plugin.enabled = False
        plugin.enable()
        assert plugin.enabled is True

    def test_disable(self) -> None:
        """Test disable behavior."""
        plugin = DummyPlugin()
        plugin.disable()
        assert plugin.enabled is False

    def test_configure(self) -> None:
        """Test configure behavior."""
        plugin = DummyPlugin()
        plugin.configure(key="value")
        assert plugin.context == {"key": "value"}

    def test_get_option(self) -> None:
        """Test get_option behavior."""
        plugin = DummyPlugin()
        plugin.configure(key="value")
        assert plugin.get_option("key") == "value"
        assert plugin.get_option("missing", "default") == "default"

    def test_activate(self) -> None:
        """Test activate behavior."""
        plugin = DummyPlugin()
        engine = cast("SymbolicExecutor", MagicMock())
        plugin.activate(engine)

    def test_deactivate(self) -> None:
        """Test deactivate behavior."""
        plugin = DummyPlugin()
        engine = cast("SymbolicExecutor", MagicMock())
        plugin.deactivate(engine)


class TestDetectorPlugin:
    """Test suite for pysymex.plugins.base.DetectorPlugin."""

    def test_get_detector(self) -> None:
        """Test get_detector behavior."""
        plugin = DummyDetectorPlugin()
        assert plugin.get_detector() == "dummy_detector"

    def test_activate(self) -> None:
        """Test activate behavior."""
        plugin = DummyDetectorPlugin()
        engine = MagicMock()
        plugin.activate(cast("SymbolicExecutor", engine))
        engine.add_detector.assert_called_once_with("dummy_detector")


class TestHandlerPlugin:
    """Test suite for pysymex.plugins.base.HandlerPlugin."""

    def test_get_handlers(self) -> None:
        """Test get_handlers behavior."""
        plugin = DummyHandlerPlugin()
        assert plugin.get_handlers() == {"OPCODE": "dummy_handler"}

    def test_activate(self) -> None:
        """Test activate behavior."""
        plugin = DummyHandlerPlugin()
        engine = MagicMock()
        plugin.activate(cast("SymbolicExecutor", engine))
        engine.register_handler.assert_called_once_with("OPCODE", "dummy_handler")


class TestHookPoint:
    """Test suite for pysymex.plugins.base.HookPoint."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        hp = HookPoint(name="test", description="desc")
        assert hp.name == "test"
        assert hp.description == "desc"


class TestHookPlugin:
    """Test suite for pysymex.plugins.base.HookPlugin."""

    def test_get_hooks(self) -> None:
        """Test get_hooks behavior."""
        plugin = DummyHookPlugin()
        assert plugin.get_hooks() == {"hook_name": "dummy_hook"}

    def test_activate(self) -> None:
        """Test activate behavior."""
        plugin = DummyHookPlugin()
        engine = MagicMock()
        plugin.activate(cast("SymbolicExecutor", engine))
        engine.register_hook.assert_called_once_with("hook_name", "dummy_hook")


class TestPluginRegistry:
    """Test suite for pysymex.plugins.base.PluginRegistry."""

    def test_register(self) -> None:
        """Test register behavior."""
        registry = PluginRegistry()
        plugin = DummyPlugin()
        registry.register(plugin)
        assert registry.get(plugin.metadata.qualified_name) is plugin

    def test_unregister(self) -> None:
        """Test unregister behavior."""
        registry = PluginRegistry()
        plugin = DummyPlugin()
        registry.register(plugin)
        assert registry.unregister(plugin.metadata.qualified_name) is True
        assert registry.get(plugin.metadata.qualified_name) is None
        assert registry.unregister("nonexistent") is False

    def test_get(self) -> None:
        """Test get behavior."""
        registry = PluginRegistry()
        plugin = DummyPlugin()
        registry.register(plugin)
        assert registry.get(plugin.metadata.qualified_name) is plugin

    def test_get_by_type(self) -> None:
        """Test get_by_type behavior."""
        registry = PluginRegistry()
        plugin = DummyPlugin()
        registry.register(plugin)
        assert registry.get_by_type(PluginType.DETECTOR) == [plugin]

    def test_get_all(self) -> None:
        """Test get_all behavior."""
        registry = PluginRegistry()
        plugin1 = DummyPlugin()
        plugin2 = DummyPlugin()
        plugin2.metadata = PluginMetadata(name="dummy2", version="1.0")
        registry.register(plugin1)
        registry.register(plugin2)
        assert registry.get_all() == [plugin1, plugin2]

    def test_get_enabled(self) -> None:
        """Test get_enabled behavior."""
        registry = PluginRegistry()
        plugin1 = DummyPlugin()
        plugin2 = DummyPlugin()
        plugin2.metadata = PluginMetadata(name="dummy2", version="1.0")
        plugin2.disable()
        registry.register(plugin1)
        registry.register(plugin2)
        assert registry.get_enabled() == [plugin1]

    def test_activate_all(self) -> None:
        """Test activate_all behavior."""
        registry = PluginRegistry()
        plugin = DummyPlugin()
        plugin.activate = MagicMock()
        registry.register(plugin)
        engine = cast("SymbolicExecutor", MagicMock())
        registry.activate_all(engine)
        plugin.activate.assert_called_once_with(engine)

    def test_deactivate_all(self) -> None:
        """Test deactivate_all behavior."""
        registry = PluginRegistry()
        plugin = DummyPlugin()
        plugin.deactivate = MagicMock()
        registry.register(plugin)
        engine = cast("SymbolicExecutor", MagicMock())
        registry.deactivate_all(engine)
        plugin.deactivate.assert_called_once_with(engine)

    def test_register_hook(self) -> None:
        """Test register_hook behavior."""
        registry = PluginRegistry()
        handler = MagicMock()
        registry.register_hook("custom_hook", handler)
        assert "custom_hook" in registry._hooks
        assert registry._hooks["custom_hook"] == [handler]

    def test_trigger_hook(self) -> None:
        """Test trigger_hook behavior."""
        registry = PluginRegistry()
        handler1 = MagicMock(return_value=1)
        handler2 = MagicMock(return_value=2)
        registry.register_hook("custom_hook", handler1)
        registry.register_hook("custom_hook", handler2)
        results = registry.trigger_hook("custom_hook", "arg")
        assert results == [1, 2]
        handler1.assert_called_once_with("arg")
        handler2.assert_called_once_with("arg")


class TestPluginLoader:
    """Test suite for pysymex.plugins.base.PluginLoader."""

    def test_add_search_path(self) -> None:
        """Test add_search_path behavior."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)
        p = Path("/tmp")
        loader.add_search_path(p)
        assert p in loader._search_paths

    def test_load_from_module(self) -> None:
        """Test load_from_module behavior."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)
        assert loader.load_from_module("nonexistent_module") is None

    def test_load_from_file(self) -> None:
        """Test load_from_file behavior."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)
        p = Path("/nonexistent/file.py")
        assert loader.load_from_file(p) is None

    def test_discover_plugins(self) -> None:
        """Test discover_plugins behavior."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)
        assert loader.discover_plugins() == []


class TestPluginConfig:
    """Test suite for pysymex.plugins.base.PluginConfig."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        config = PluginConfig(name="test_plugin", enabled=False, options={"k": "v"})
        assert config.name == "test_plugin"
        assert config.enabled is False
        assert config.options == {"k": "v"}


class TestPluginManagerConfig:
    """Test suite for pysymex.plugins.base.PluginManagerConfig."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        config = PluginManagerConfig(search_paths=["/tmp"], auto_discover=False)
        assert config.search_paths == ["/tmp"]
        assert config.auto_discover is False
        assert config.plugins == []


class TestPluginManager:
    """Test suite for pysymex.plugins.base.PluginManager."""

    def test_initialize(self) -> None:
        """Test initialize behavior."""
        config = PluginManagerConfig(auto_discover=False, plugins=[PluginConfig(name="dummy")])
        manager = PluginManager(config)
        plugin = DummyPlugin()
        manager.registry.register(plugin)
        manager.initialize()

    def test_load(self) -> None:
        """Test load behavior."""
        manager = PluginManager()
        assert manager.load("nonexistent_module") is None

    def test_get(self) -> None:
        """Test get behavior."""
        manager = PluginManager()
        plugin = DummyPlugin()
        manager.registry.register(plugin)
        assert manager.get(plugin.metadata.qualified_name) is plugin

    def test_enable(self) -> None:
        """Test enable behavior."""
        manager = PluginManager()
        plugin = DummyPlugin()
        plugin.disable()
        manager.registry.register(plugin)
        assert manager.enable(plugin.metadata.qualified_name) is True
        assert plugin.enabled is True
        assert manager.enable("nonexistent") is False

    def test_disable(self) -> None:
        """Test disable behavior."""
        manager = PluginManager()
        plugin = DummyPlugin()
        manager.registry.register(plugin)
        assert manager.disable(plugin.metadata.qualified_name) is True
        assert plugin.enabled is False
        assert manager.disable("nonexistent") is False

    def test_list_plugins(self) -> None:
        """Test list_plugins behavior."""
        manager = PluginManager()
        plugin = DummyPlugin()
        manager.registry.register(plugin)
        assert manager.list_plugins() == [plugin.metadata]

    def test_activate(self) -> None:
        """Test activate behavior."""
        manager = PluginManager()
        plugin = DummyPlugin()
        plugin.activate = MagicMock()
        manager.registry.register(plugin)
        engine = cast("SymbolicExecutor", MagicMock())
        manager.activate(engine)
        plugin.activate.assert_called_once_with(engine)

    def test_deactivate(self) -> None:
        """Test deactivate behavior."""
        manager = PluginManager()
        plugin = DummyPlugin()
        plugin.deactivate = MagicMock()
        manager.registry.register(plugin)
        engine = cast("SymbolicExecutor", MagicMock())
        manager.deactivate(engine)
        plugin.deactivate.assert_called_once_with(engine)
