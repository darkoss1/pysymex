"""Tests for realtime visualization module."""

from __future__ import annotations

from pysymex.reporting.realtime import (
    GlobalState,
    RealtimeVisualizationPlugin,
    start_realtime_visualization,
)


class TestGlobalState:
    """Tests for GlobalState datastore."""

    def test_initial_stats(self) -> None:
        gs = GlobalState()
        assert gs.stats["paths"] == 0
        assert gs.stats["total_issues"] == 0

    def test_get_json_returns_valid_json(self) -> None:
        import json

        gs = GlobalState()
        data = json.loads(gs.get_json())
        assert "nodes" in data
        assert "edges" in data
        assert "stats" in data


class TestRealtimePlugin:
    """Tests for RealtimeVisualizationPlugin (Task 3.5)."""

    def test_plugin_inherits_hook_plugin(self) -> None:
        from pysymex.plugins.base import HookPlugin

        plugin = RealtimeVisualizationPlugin()
        assert isinstance(plugin, HookPlugin)

    def test_get_hooks_keys(self) -> None:
        plugin = RealtimeVisualizationPlugin()
        hooks = plugin.get_hooks()
        assert set(hooks.keys()) == {"pre_step"}

    def test_activate_idempotent(self) -> None:
        """Activating twice just adds another hook copy."""

        class _Eng:
            def __init__(self):
                self.hooks: dict[str, list] = {}

            def register_hook(self, name, fn):
                self.hooks.setdefault(name, []).append(fn)

        engine = _Eng()
        plugin = RealtimeVisualizationPlugin()
        plugin.activate(engine)  # type: ignore[arg-type]
        plugin.activate(engine)  # type: ignore[arg-type]
        assert len(engine.hooks["pre_step"]) == 2

    def test_start_realtime_visualization_backward_compat(self) -> None:

        class _Eng:
            def __init__(self):
                self.hooks: dict[str, list] = {}

            def register_hook(self, name, fn):
                self.hooks.setdefault(name, []).append(fn)

        engine = _Eng()
        plugin = start_realtime_visualization(engine)
        assert isinstance(plugin, RealtimeVisualizationPlugin)
        assert "pre_step" in engine.hooks
