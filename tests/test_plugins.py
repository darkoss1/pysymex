"""Tests for plugin system."""

from pathlib import Path

import pytest

from pysymex.plugins import (
    HOOKS,
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


class SamplePlugin(Plugin):
    """Sample plugin for testing."""

    metadata = PluginMetadata(
        name="sample",
        version="1.0.0",
        description="A sample plugin",
        plugin_type=PluginType.DETECTOR,
    )

    def activate(self, engine):
        self.activated = True

    def deactivate(self, engine):
        self.activated = False


class AnotherPlugin(Plugin):
    """Another sample plugin."""

    metadata = PluginMetadata(
        name="another",
        version="1.0.0",
        plugin_type=PluginType.HOOK,
        priority=PluginPriority.HIGH,
    )

    def activate(self, engine):
        pass


class DependentPlugin(Plugin):
    """Plugin with dependency."""

    metadata = PluginMetadata(
        name="dependent",
        version="1.0.0",
        dependencies=["sample@1.0.0"],
    )

    def activate(self, engine):
        pass


class TestPluginMetadata:
    """Tests for PluginMetadata."""

    def test_create_metadata(self):
        """Test creating plugin metadata."""
        meta = PluginMetadata(
            name="test",
            version="1.0.0",
            description="Test plugin",
            author="Test Author",
        )

        assert meta.name == "test"
        assert meta.version == "1.0.0"
        assert meta.description == "Test plugin"

    def test_qualified_name(self):
        """Test qualified name generation."""
        meta = PluginMetadata(name="myplugin", version="2.0.0")

        assert meta.qualified_name == "myplugin@2.0.0"

    def test_default_values(self):
        """Test default metadata values."""
        meta = PluginMetadata(name="x", version="1.0")

        assert meta.plugin_type == PluginType.DETECTOR
        assert meta.priority == PluginPriority.NORMAL
        assert len(meta.dependencies) == 0


class TestPlugin:
    """Tests for Plugin base class."""

    def test_enable_disable(self):
        """Test enabling and disabling plugin."""
        plugin = SamplePlugin()

        assert plugin.enabled

        plugin.disable()
        assert not plugin.enabled

        plugin.enable()
        assert plugin.enabled

    def test_configure(self):
        """Test plugin configuration."""
        plugin = SamplePlugin()

        plugin.configure(option1=True, option2="value")

        assert plugin.get_option("option1") == True
        assert plugin.get_option("option2") == "value"
        assert plugin.get_option("missing", "default") == "default"


class TestPluginRegistry:
    """Tests for PluginRegistry."""

    def test_register_plugin(self):
        """Test registering a plugin."""
        registry = PluginRegistry()
        plugin = SamplePlugin()

        registry.register(plugin)

        assert registry.get("sample@1.0.0") == plugin

    def test_register_duplicate_raises(self):
        """Test registering duplicate plugin raises."""
        registry = PluginRegistry()
        plugin1 = SamplePlugin()
        plugin2 = SamplePlugin()

        registry.register(plugin1)

        with pytest.raises(ValueError):
            registry.register(plugin2)

    def test_unregister_plugin(self):
        """Test unregistering a plugin."""
        registry = PluginRegistry()
        plugin = SamplePlugin()

        registry.register(plugin)
        result = registry.unregister("sample@1.0.0")

        assert result
        assert registry.get("sample@1.0.0") is None

    def test_get_by_type(self):
        """Test getting plugins by type."""
        registry = PluginRegistry()
        sample = SamplePlugin()
        another = AnotherPlugin()

        registry.register(sample)
        registry.register(another)

        detectors = registry.get_by_type(PluginType.DETECTOR)
        hooks = registry.get_by_type(PluginType.HOOK)

        assert sample in detectors
        assert another in hooks

    def test_get_all(self):
        """Test getting all plugins."""
        registry = PluginRegistry()
        sample = SamplePlugin()
        another = AnotherPlugin()

        registry.register(sample)
        registry.register(another)

        all_plugins = registry.get_all()

        assert len(all_plugins) == 2
        assert sample in all_plugins
        assert another in all_plugins

    def test_get_enabled(self):
        """Test getting only enabled plugins."""
        registry = PluginRegistry()
        sample = SamplePlugin()
        another = AnotherPlugin()

        registry.register(sample)
        registry.register(another)

        sample.disable()

        enabled = registry.get_enabled()

        assert another in enabled
        assert sample not in enabled

    def test_dependency_check(self):
        """Test dependency checking on register."""
        registry = PluginRegistry()
        dependent = DependentPlugin()

        # Should fail - dependency not met
        with pytest.raises(ValueError, match="Missing dependency"):
            registry.register(dependent)

    def test_dependency_satisfied(self):
        """Test registering with satisfied dependency."""
        registry = PluginRegistry()
        sample = SamplePlugin()
        dependent = DependentPlugin()

        registry.register(sample)
        registry.register(dependent)  # Should succeed

        assert registry.get("dependent@1.0.0") is not None


class TestPluginHooks:
    """Tests for plugin hooks."""

    def test_predefined_hooks(self):
        """Test predefined hook points exist."""
        assert "pre_execute" in HOOKS
        assert "post_execute" in HOOKS
        assert "pre_call" in HOOKS
        assert "post_call" in HOOKS
        assert "exception" in HOOKS

    def test_register_hook(self):
        """Test registering a hook handler."""
        registry = PluginRegistry()

        results = []

        def handler(x):
            results.append(x)

        registry.register_hook("pre_execute", handler)
        registry.trigger_hook("pre_execute", 42)

        assert 42 in results

    def test_trigger_multiple_hooks(self):
        """Test triggering multiple hook handlers."""
        registry = PluginRegistry()

        results = []
        registry.register_hook("pre_execute", lambda x: results.append(x * 2))
        registry.register_hook("pre_execute", lambda x: results.append(x * 3))

        registry.trigger_hook("pre_execute", 10)

        assert 20 in results
        assert 30 in results


class TestPluginLoader:
    """Tests for PluginLoader."""

    def test_add_search_path(self):
        """Test adding search path."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        loader.add_search_path(Path("/some/path"))

        assert Path("/some/path") in loader._search_paths

    def test_search_path_dedup(self):
        """Test search paths are deduplicated."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        loader.add_search_path(Path("/path"))
        loader.add_search_path(Path("/path"))

        assert len(loader._search_paths) == 1


class TestPluginManager:
    """Tests for PluginManager."""

    def test_create_manager(self):
        """Test creating plugin manager."""
        manager = PluginManager()

        assert manager.registry is not None
        assert manager.loader is not None

    def test_create_with_config(self):
        """Test creating manager with config."""
        config = PluginManagerConfig(
            auto_discover=False,
            search_paths=["/plugins"],
        )
        manager = PluginManager(config)

        assert not manager.config.auto_discover

    def test_list_plugins(self):
        """Test listing plugins."""
        manager = PluginManager()
        sample = SamplePlugin()

        manager.registry.register(sample)

        plugins = manager.list_plugins()

        names = [p.name for p in plugins]
        assert "sample" in names

    def test_enable_disable_by_name(self):
        """Test enabling/disabling by name."""
        manager = PluginManager()
        sample = SamplePlugin()
        manager.registry.register(sample)

        manager.disable("sample@1.0.0")
        assert not sample.enabled

        manager.enable("sample@1.0.0")
        assert sample.enabled


class TestPluginConfig:
    """Tests for plugin configuration."""

    def test_create_plugin_config(self):
        """Test creating plugin config."""
        config = PluginConfig(
            name="test",
            enabled=False,
            options={"key": "value"},
        )

        assert config.name == "test"
        assert not config.enabled
        assert config.options["key"] == "value"

    def test_manager_applies_config(self):
        """Test manager applies plugin configs."""
        plugin_config = PluginConfig(
            name="sample@1.0.0",
            enabled=False,
            options={"debug": True},
        )
        manager_config = PluginManagerConfig(
            plugins=[plugin_config],
            auto_discover=False,
        )

        manager = PluginManager(manager_config)
        sample = SamplePlugin()
        manager.registry.register(sample)

        manager.initialize()

        assert not sample.enabled
        assert sample.get_option("debug") == True
