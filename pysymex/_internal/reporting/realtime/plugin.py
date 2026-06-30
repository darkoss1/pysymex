# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Realtime visualizer plugin."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from pysymex._internal.reporting.realtime.state import global_state

if TYPE_CHECKING:
    import types
    from collections.abc import Callable
    from pathlib import Path

    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.executors.core import SymbolicExecutor


class RealtimePlugin:
    """Plugin that feeds live execution data to the realtime visualizer.

    Registers hooks that update :data:`global_state` with the execution tree structure
    as the engine explores path options.

    Usage::

        from pysymex._internal.reporting.realtime import RealtimeVisualizationPlugin
        plugin = RealtimeVisualizationPlugin()
        plugin.activate(engine)

    """

    def __init__(self, throttle_every: int = 25, sleep_ms: float = 0.0) -> None:
        """Initialize the real-time visualization plugin.

        Args:
            throttle_every: Step frequency interval to update visualizer states.
                For example, 25 updates every twenty-fifth VM step. Defaults to 25.
            sleep_ms: Optional cooldown sleep duration in milliseconds after updating
                the state. Defaults to ``0.0`` so visualization does not pace the engine.

        """
        self._throttle_every = max(1, throttle_every)
        self._sleep_seconds = sleep_ms / 1000.0
        self._path_parents: dict[int, str] = {}
        self._active_file_id: str | None = None

    def get_hooks(self) -> dict[str, Callable[..., object]]:
        """Return the hooks used by the visualizer."""
        return {
            "pre_step": self._pre_step_hook,
            "on_fork": self._on_fork_hook,
            "on_prune": self._on_prune_hook,
            "on_issue": self._on_issue_hook,
        }

    def activate(self, engine: SymbolicExecutor) -> None:
        """Register hooks with *engine*."""
        hooks = self.get_hooks()
        for hook_name, handler in hooks.items():
            if hasattr(engine, "register_hook"):
                engine.register_hook(hook_name, handler)

    def begin_code(self, code: types.CodeType) -> None:
        """Record the callable currently executing in the canonical scanner."""
        with global_state.lock:
            global_state.stats["active_func"] = code.co_name
            self._path_parents = {}
            if global_state.active_file:
                file_id = str(global_state.active_file.resolve())
                self._active_file_id = file_id
                func_id = self._ensure_function_node(file_id, code.co_name)
                global_state.set_node_status(func_id, "active")

                if code.co_name not in global_state.visited_functions:
                    global_state.visited_functions.append(code.co_name)
            else:
                self._active_file_id = None
            global_state.touch_stats()

    def _resolve_active_file_id(self, active_file: Path) -> str:
        """Return the cached resolved graph id for the current active file."""
        if self._active_file_id is None:
            self._active_file_id = str(active_file.resolve())
        return self._active_file_id

    def _should_refresh_step(self, state: VMState) -> bool:
        """Return whether live VM fields should be refreshed for this step."""
        return state.pc % self._throttle_every == 0

    def _ensure_function_node(self, file_id: str, func_name: str) -> str:
        """Ensure the active function node exists.

        Callers must hold :data:`global_state.lock`.
        """
        func_id = f"{file_id}::{func_name}"
        if global_state.add_node(
            {
                "id": func_id,
                "label": f"def {func_name}()",
                "type": "function",
                "status": "active",
            },
        ):
            global_state.add_edge(file_id, func_id)
        return func_id

    def _update_live_stats(
        self,
        executor_self: SymbolicExecutor,
        state: VMState,
        opname: str,
    ) -> None:
        """Refresh the lightweight live VM counters.

        Callers must hold :data:`global_state.lock`.
        """
        global_state.stats["pc"] = state.pc
        global_state.stats["opname"] = opname
        global_state.stats["paths"] = getattr(executor_self, "_paths_explored", 0)
        global_state.touch_stats()

    def _ensure_path_node(self, func_id: str, state: VMState) -> bool:
        """Ensure a path node exists and is connected to its parent.

        Returns:
            ``True`` when a new path node was inserted.

        Callers must hold :data:`global_state.lock`.

        """
        path_node_id = self._path_node_id(func_id, state)
        path_node = global_state.get_node(path_node_id)
        if path_node is None:
            parent_node_id = self._path_parents.get(state.path_id, func_id)
            global_state.add_node(
                {
                    "id": path_node_id,
                    "label": f"Path {state.path_id}",
                    "type": "path_node",
                    "status": "active",
                },
            )
            global_state.add_edge(parent_node_id, path_node_id)
            return True
        if path_node["type"] != "dead_path":
            global_state.set_node_status(path_node_id, "active")
        return False

    def _set_path_pruned(self, func_id: str, state: VMState, reason: str) -> None:
        """Mark a path node as pruned.

        Callers must hold :data:`global_state.lock`.
        """
        path_node_id = self._path_node_id(func_id, state)
        global_state.set_node_type_and_status(path_node_id, "dead_path", f"pruned ({reason})")

    def _path_node_id(self, func_id: str, state: VMState) -> str:
        """Return the graph id for a VM path under a function node."""
        return f"{func_id}::path_{state.path_id}"

    def _pre_step_hook(self, executor_self: SymbolicExecutor, state: VMState) -> None:
        """Update :data:`global_state` before each execution step."""
        instrs = getattr(executor_self, "instructions", [])
        instr = instrs[state.pc] if state.pc < len(instrs) else None
        opname: str = getattr(instr, "opname", "OOB") if instr else "EOF"
        refresh_step = self._should_refresh_step(state)

        with global_state.lock:
            active_file = global_state.active_file
            if active_file:
                file_id = self._resolve_active_file_id(active_file)
                func_name = global_state.stats["active_func"]
                func_id = self._ensure_function_node(file_id, func_name)
                new_path_node = self._ensure_path_node(func_id, state)
                if refresh_step or new_path_node:
                    self._update_live_stats(executor_self, state, opname)
            elif refresh_step:
                self._update_live_stats(executor_self, state, opname)

        if refresh_step and self._sleep_seconds > 0:
            time.sleep(self._sleep_seconds)

    def _on_fork_hook(
        self,
        executor_self: SymbolicExecutor,
        parent_state: VMState,
        child_states: list[VMState],
    ) -> None:
        """Handle path forks during symbolic execution."""
        with global_state.lock:
            active_file = global_state.active_file
            if active_file:
                file_id = self._resolve_active_file_id(active_file)
                func_name = global_state.stats["active_func"]
                func_id = self._ensure_function_node(file_id, func_name)
                parent_path_node_id = f"{func_id}::path_{parent_state.path_id}"

                for child in child_states:
                    self._path_parents[child.path_id] = parent_path_node_id

    def _on_prune_hook(
        self,
        executor_self: SymbolicExecutor,
        state: VMState,
        reason: str,
    ) -> None:
        """Handle state pruning during symbolic execution."""
        with global_state.lock:
            active_file = global_state.active_file
            if active_file:
                file_id = self._resolve_active_file_id(active_file)
                func_name = global_state.stats["active_func"]
                func_id = self._ensure_function_node(file_id, func_name)
                self._set_path_pruned(func_id, state, reason)

    def _on_issue_hook(
        self,
        executor_self: SymbolicExecutor,
        state: VMState,
        issue: Issue,
    ) -> None:
        """Handle issue emission when a bug is detected."""
        issue_dict = issue.to_dict()
        with global_state.lock:
            global_state.issues_list.append(issue_dict)

            active_file = global_state.active_file
            if active_file:
                file_id = self._resolve_active_file_id(active_file)
                func_name = global_state.stats["active_func"]
                func_id = self._ensure_function_node(file_id, func_name)
                path_node_id = self._path_node_id(func_id, state)

                issue_node_id = f"issue_{id(issue)}"
                global_state.add_node(
                    {
                        "id": issue_node_id,
                        "label": f"Bug: {issue.kind.name}",
                        "type": "issue",
                        "status": "active",
                    },
                )
                global_state.add_edge(path_node_id, issue_node_id)
            global_state.touch_stats()
