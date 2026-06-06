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

"""Dynamic Partial Order Reduction for thread interleaving exploration."""

from __future__ import annotations

from pysymex.analysis.domains.concurrency.happens_before import HappensBeforeGraph
from pysymex.analysis.domains.concurrency.interleaving_state import InterleavingState, Transition


class DPORExplorer:
    """Explores thread interleavings using Dynamic Partial Order Reduction.

    Prunes equivalent schedules by computing persistent sets from the
    happens-before graph, exploring only interleavings that differ on
    conflicting operations.
    """

    def __init__(
        self,
        hb_graph: HappensBeforeGraph,
        thread_operations: dict[str, list[int]],
        max_interleavings: int = 1000,
    ) -> None:
        """Initialize a DPORExplorer instance.

        Args:
            hb_graph (HappensBeforeGraph): Happens-before relation.
            thread_operations (dict[str, list[int]]): Operations mapped by thread.
            max_interleavings (int): Limit on generated schedules. Defaults to 1000.
        """
        self.hb_graph = hb_graph
        self._thread_ops = thread_operations
        self._max_interleavings = max_interleavings
        self._complete_schedules: list[list[Transition]] = []

    def _are_dependent(self, op1_id: int, op2_id: int) -> bool:
        """Check if two operations are dependent."""
        op1 = self.hb_graph.get_operation(op1_id)
        op2 = self.hb_graph.get_operation(op2_id)
        if op1 is None or op2 is None:
            return False
        return op1.conflicts_with(op2)

    def _get_enabled_threads(self, state: InterleavingState) -> list[str]:
        """Get threads that have remaining operations and are not in sleep set."""
        enabled: list[str] = []
        for thread_id, ops in self._thread_ops.items():
            idx = state.thread_states.get(thread_id, 0)
            if idx < len(ops) and thread_id not in state.sleep_set:
                enabled.append(thread_id)
        return enabled

    def _compute_backtrack_set(self, state: InterleavingState, new_transition: Transition) -> None:
        """Compute backtrack set using DPOR."""
        for existing in state.schedule:
            if existing.thread_id == new_transition.thread_id:
                continue
            if not self._are_dependent(existing.op_id, new_transition.op_id):
                continue
            if not self.hb_graph.happens_before(existing.op_id, new_transition.op_id):
                state.backtrack_set.add(existing.thread_id)

    def _execute_transition(
        self, state: InterleavingState, thread_id: str
    ) -> tuple[InterleavingState, Transition | None]:
        """Execute the next operation of a given thread."""
        ops = self._thread_ops.get(thread_id, [])
        idx = state.thread_states.get(thread_id, 0)
        if idx >= len(ops):
            return state, None

        op_id = ops[idx]
        operation = self.hb_graph.get_operation(op_id)
        if operation is None:
            return state, None

        transition = Transition(thread_id=thread_id, operation=operation, op_id=op_id)
        new_state = state.clone()
        new_state.schedule.append(transition)
        new_state.thread_states[thread_id] = idx + 1
        return new_state, transition

    def explore(self) -> list[list[Transition]]:
        """Run DPOR exploration and return complete schedules."""
        self._complete_schedules = []
        initial = InterleavingState(thread_states=dict.fromkeys(self._thread_ops, 0))
        initial.backtrack_set = set(self._thread_ops.keys())
        worklist: list[InterleavingState] = [initial]

        while worklist and len(self._complete_schedules) < self._max_interleavings:
            state = worklist.pop()
            enabled = self._get_enabled_threads(state)
            if not enabled:
                if state.schedule:
                    self._complete_schedules.append(list(state.schedule))
                continue

            to_explore = state.backtrack_set - state.done_set
            if not to_explore:
                to_explore = {enabled[0]} if enabled else set[str]()

            for thread_id in to_explore:
                if thread_id not in enabled:
                    continue
                if len(self._complete_schedules) >= self._max_interleavings:
                    break

                new_state, transition = self._execute_transition(state, thread_id)
                if transition is None:
                    continue
                state.done_set.add(thread_id)
                self._compute_backtrack_set(new_state, transition)

                new_enabled = self._get_enabled_threads(new_state)
                if new_enabled:
                    new_state.backtrack_set = {new_enabled[0]}
                    new_state.done_set = set()
                    new_state.sleep_set = set()
                worklist.append(new_state)

        return self._complete_schedules

    def get_race_candidates(self) -> list[tuple[int, int]]:
        """Return operation ID pairs that are concurrent and conflicting."""
        candidates: list[tuple[int, int]] = []
        all_ops = list(self.hb_graph.operations.items())
        for i, (id1, op1) in enumerate(all_ops):
            for id2, op2 in all_ops[i + 1 :]:
                if op1.conflicts_with(op2) and self.hb_graph.are_concurrent(id1, id2):
                    candidates.append((id1, id2))
        return candidates


def explore_interleavings(
    hb_graph: HappensBeforeGraph,
    thread_operations: dict[str, list[int]],
    max_interleavings: int = 1000,
) -> list[list[Transition]]:
    """Explore interleavings with DPOR."""
    explorer = DPORExplorer(hb_graph, thread_operations, max_interleavings)
    return explorer.explore()


__all__ = ["DPORExplorer", "explore_interleavings"]
