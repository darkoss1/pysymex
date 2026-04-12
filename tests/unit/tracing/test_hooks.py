from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from pysymex.tracing.hooks import TracingHookPlugin


@dataclass
class _FakeTracer:
    install_called: bool = False
    fork_calls: int = 0

    def pre_step(self, *_: object) -> None:
        return None

    def post_step(self, *_: object) -> None:
        return None

    def on_fork(self, *_: object) -> None:
        self.fork_calls += 1

    def on_prune(self, *_: object) -> None:
        return None

    def on_issue(self, *_: object) -> None:
        return None

    def install(self, _: object) -> None:
        self.install_called = True


def test_tracing_hook_plugin_exposes_both_hook_name_styles() -> None:
    tracer = _FakeTracer()
    plugin = TracingHookPlugin(cast("Any", tracer))
    hooks = plugin.get_hooks()

    assert "pre_step" in hooks
    assert "pre_execute" in hooks
    assert "state_fork" in hooks

    class _State:
        path_id = 1

    hooks["state_fork"](object(), _State())
    assert tracer.fork_calls == 1


def test_tracing_hook_plugin_activate_delegates_to_tracer_install() -> None:
    tracer = _FakeTracer()
    plugin = TracingHookPlugin(cast("Any", tracer))
    plugin.activate(cast("Any", object()))
    assert tracer.install_called is True

