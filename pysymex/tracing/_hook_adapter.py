"""Compatibility bridge between the pysymex plugin system and ExecutionTracer.

:class:`TracingHookPlugin` adapts the :class:`~pysymex.tracing.tracer.ExecutionTracer`
hook interface to the :class:`~pysymex.plugins.base.HookPlugin` contract so
the tracer can be installed via the standard plugin mechanism:

.. code-block:: python

    from pysymex.tracing import ExecutionTracer, TracerConfig
    from pysymex.tracing._hook_adapter import TracingHookPlugin

    tracer = ExecutionTracer(TracerConfig())
    tracer.start_session("my_func", "(x: int) -> int", {"x": "int"})

    plugin = TracingHookPlugin(tracer)
    executor.load_plugins([plugin])   # plugin-manager path

Alternatively, :meth:`ExecutionTracer.install` can be called directly on
the executor (the recommended fast-path):

.. code-block:: python

    tracer.install(executor)   # direct registration, same result

Both paths are equivalent.  The plugin path is provided for compatibility
with plugin-manager-based setups where plugins are discovered and activated
in bulk via :class:`~pysymex.plugins.base.PluginRegistry`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from pysymex.plugins.base import HookPlugin, PluginMetadata, PluginPriority, PluginType

if TYPE_CHECKING:
    from pysymex.execution.executor_core import SymbolicExecutor as SymbolicEngine
    from pysymex.tracing.tracer import ExecutionTracer


class TracingHookPlugin(HookPlugin):
    """A :class:`~pysymex.plugins.base.HookPlugin` that delegates to an :class:`~pysymex.tracing.tracer.ExecutionTracer`.

    Installing this plugin via :class:`~pysymex.plugins.base.PluginRegistry`
    achieves the same result as calling :meth:`ExecutionTracer.install`
    directly:  all hooks are registered and the solver is wrapped.

    Args:
        tracer: A fully constructed :class:`~pysymex.tracing.tracer.ExecutionTracer`
                whose :meth:`~pysymex.tracing.tracer.ExecutionTracer.start_session`
                has already been called.
    """

    metadata: PluginMetadata = PluginMetadata(
        name="pysymex-execution-tracer",
        version="0.1.0",
        description="LLM-optimised observability layer for SymbolicExecutor",
        author="pysymex",
        plugin_type=PluginType.HOOK,
        priority=PluginPriority.HIGHEST,
    )

    def __init__(self, tracer: ExecutionTracer) -> None:
        """Init."""
        """Initialize the class instance."""
        super().__init__()
        self._tracer = tracer

    def get_hooks(self) -> dict[str, Callable[..., Any]]:
        """Return the mapping of executor hook names to tracer callbacks.

        The pysymex plugin system uses its own hook names (``"pre_execute"``,
        ``"state_fork"``, etc.) which differ from the new hook names used in
        the patched executor (``"pre_step"``, ``"on_fork"``, etc.).  This
        method maps *both* sets so the plugin works regardless of whether the
        executor was patched.

        Returns:
            Dict of ``{hook_name: handler}``.
        """
        t = self._tracer
        return {
            "pre_step": t.pre_step,
            "post_step": t.post_step,
            "on_fork": t.on_fork,
            "on_prune": t.on_prune,
            "on_issue": t.on_issue,
            "pre_execute": t.pre_step,
            "state_fork": _wrap_on_fork(t),
        }

    def activate(self, engine: SymbolicEngine) -> None:
        """Register all hooks and wrap the solver.

        Delegates to :meth:`ExecutionTracer.install` so both registration
        paths (direct and plugin) stay in sync.

        Args:
            engine: The :class:`~pysymex.execution.executor_core.SymbolicExecutor`
                    to instrument.
        """
        self._tracer.install(engine)


def _wrap_on_fork(tracer: ExecutionTracer) -> Callable[..., None]:
    """Return a shim that adapts the ``state_fork`` hook to :meth:`ExecutionTracer.on_fork`.

    The legacy hook is called as ``handler(executor, state)`` where ``state``
    is the *single* new forked state.  The tracer's ``on_fork`` expects
    ``(executor, parent_state, child_states)``.  This wrapper bridges the gap
    by synthesising a one-element child list.

    Args:
        tracer: The tracer to forward calls to.

    Returns:
        A callable with the legacy signature.
    """

    def _adapter(executor: Any, state: Any) -> None:
        """Adapter."""

        try:
            tracer.on_fork(executor, state, [state])
        except Exception:
            pass

    return _adapter
