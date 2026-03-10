"""Tests for the plugin system architecture (Task 3.5)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pysymex.plugins.base import (
    HookPlugin,
    Plugin,
    PluginRegistry,
    PluginType,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeEngine:
    """Minimal stand-in for SymbolicExecutor in plugin tests."""

    def __init__(self) -> None:
        self.hooks: dict[str, list[Callable[..., Any]]] = {}

    def register_hook(self, hook_name: str, handler: Any) -> None:
        self.hooks.setdefault(hook_name, []).append(handler)


# ---------------------------------------------------------------------------
# RealtimeVisualizationPlugin tests
# ---------------------------------------------------------------------------


class TestRealtimeVisualizationPlugin:
    """Tests for the RealtimeVisualizationPlugin wrapper."""

    def test_is_hook_plugin(self) -> None:
        from pysymex.reporting.realtime import RealtimeVisualizationPlugin

        plugin = RealtimeVisualizationPlugin()
        assert isinstance(plugin, HookPlugin)
        assert isinstance(plugin, Plugin)

    def test_metadata(self) -> None:
        from pysymex.reporting.realtime import RealtimeVisualizationPlugin

        plugin = RealtimeVisualizationPlugin()
        assert plugin.metadata.name == "realtime-visualization"
        assert plugin.metadata.plugin_type == PluginType.HOOK

    def test_get_hooks_returns_pre_step(self) -> None:
        from pysymex.reporting.realtime import RealtimeVisualizationPlugin

        plugin = RealtimeVisualizationPlugin()
        hooks = plugin.get_hooks()
        assert "pre_step" in hooks
        assert callable(hooks["pre_step"])

    def test_activate_registers_hook(self) -> None:
        from pysymex.reporting.realtime import RealtimeVisualizationPlugin

        plugin = RealtimeVisualizationPlugin()
        engine = _FakeEngine()
        plugin.activate(engine)  # type: ignore[arg-type]

        assert "pre_step" in engine.hooks
        assert len(engine.hooks["pre_step"]) == 1

    def test_start_realtime_visualization_compat(self) -> None:
        """start_realtime_visualization() returns a plugin and registers hooks."""
        from pysymex.reporting.realtime import (
            RealtimeVisualizationPlugin,
            start_realtime_visualization,
        )

        engine = _FakeEngine()
        plugin = start_realtime_visualization(engine)

        assert isinstance(plugin, RealtimeVisualizationPlugin)
        assert "pre_step" in engine.hooks

    def test_plugin_can_be_registered_in_registry(self) -> None:
        from pysymex.reporting.realtime import RealtimeVisualizationPlugin

        registry = PluginRegistry()
        plugin = RealtimeVisualizationPlugin()
        registry.register(plugin)

        found = registry.get("realtime-visualization@1.0.0")
        assert found is plugin

    def test_hook_updates_global_state(self) -> None:
        """The pre_step hook should update global_state stats."""
        from types import SimpleNamespace

        from pysymex.reporting.realtime import (
            RealtimeVisualizationPlugin,
            global_state,
        )

        plugin = RealtimeVisualizationPlugin(throttle_every=9999, sleep_ms=0)

        fake_executor = SimpleNamespace(
            _instructions=[SimpleNamespace(opname="LOAD_FAST")],
            _paths_explored=42,
        )
        fake_state = SimpleNamespace(pc=0)

        hook_fn = plugin.get_hooks()["pre_step"]
        hook_fn(fake_executor, fake_state)

        with global_state.lock:
            assert global_state.stats["pc"] == 0
            assert global_state.stats["opname"] == "LOAD_FAST"
            assert global_state.stats["paths"] == 42
