from __future__ import annotations

import json
from typing import Any, cast

from pysymex.reporting.realtime import GlobalState, RealtimeVisualizationPlugin, start_realtime_visualization


class _Engine:
    def __init__(self) -> None:
        self.hooks: dict[str, object] = {}

    def register_hook(self, name: str, handler: object) -> None:
        self.hooks[name] = handler


def test_global_state_get_json_contains_expected_keys() -> None:
    state = GlobalState()
    payload = json.loads(state.get_json())
    assert "nodes" in payload
    assert "stats" in payload


def test_realtime_plugin_registers_pre_step_hook() -> None:
    plugin = RealtimeVisualizationPlugin()
    hooks = plugin.get_hooks()
    assert "pre_step" in hooks

    engine = _Engine()
    plugin.activate(cast("Any", engine))
    assert "pre_step" in engine.hooks


def test_start_realtime_visualization_returns_plugin_and_registers_hook() -> None:
    engine = _Engine()
    plugin = start_realtime_visualization(cast("Any", engine))
    assert isinstance(plugin, RealtimeVisualizationPlugin)
    assert "pre_step" in engine.hooks

