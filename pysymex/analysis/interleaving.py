"""Dynamic Partial Order Reduction (DPOR) for thread interleaving exploration.

Implements the DPOR algorithm to efficiently explore thread interleavings
by identifying independent transitions and only exploring one ordering for
each set of independent transitions.

Builds on the HappensBeforeGraph from pysymex.analysis.concurrency.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pysymex.analysis.concurrency import (
    HappensBeforeGraph,
    MemoryOperation,
)


@dataclass(frozen=True)
class Transition:
    """A single thread transition (one operation executed by one thread)."""

    thread_id: str
    operation: MemoryOperation
    op_id: int
    enabled: bool = True


@dataclass
class InterleavingState:
    """State of the interleaving exploration."""

    schedule: list[Transition] = field(default_factory=list[Transition])
    thread_states: dict[str, int] = field(default_factory=dict[str, int])
    backtrack_set: set[str] = field(default_factory=set[str])
    done_set: set[str] = field(default_factory=set[str])
    sleep_set: set[str] = field(default_factory=set[str])

    def clone(self) -> InterleavingState:
        """Create a deep copy of this state."""
        return InterleavingState(
            schedule=list(self.schedule),
            thread_states=dict(self.thread_states),
            backtrack_set=set(self.backtrack_set),
            done_set=set(self.done_set),
            sleep_set=set(self.sleep_set),
        )


class DPORExplorer:
    """Explores thread interleavings using Dynamic Partial Order Reduction.

    DPOR identifies independent transitions (different threads, no shared
    variable conflict) and only explores one ordering. For dependent
    transitions, both orderings are explored. This exponentially reduces
    the interleaving space.

    Args:
        hb_graph: The happens-before graph with all recorded operations.
        thread_operations: Maps thread_id to its list of operation IDs
                           in program order.
        max_interleavings: Maximum number of complete schedules to generate.
    """

    def __init__(
        self,
        hb_graph: HappensBeforeGraph,
        thread_operations: dict[str, list[int]],
        max_interleavings: int = 1000,
    ) -> None:
        """Init."""
        """Initialize the class instance."""
        self._hb_graph = hb_graph
        self._thread_ops = thread_operations
        self._max_interleavings = max_interleavings
        self._complete_schedules: list[list[Transition]] = []

    def _are_dependent(self, op1_id: int, op2_id: int) -> bool:
        """Check if two operations are dependent.

        Two operations are dependent if they access the same address
        and at least one is a write, and they are from different threads.
        """
        op1 = self._hb_graph.get_operation(op1_id)
        op2 = self._hb_graph.get_operation(op2_id)
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

    def _compute_backtrack_set(
        self,
        state: InterleavingState,
        new_transition: Transition,
    ) -> None:
        """Compute backtrack set using DPOR algorithm.

        For each transition in the current schedule that is dependent
        with the new transition and from a different thread, add the
        dependent transition's thread to the backtrack set.
        """
        for _i, existing in enumerate(state.schedule):
            if existing.thread_id == new_transition.thread_id:
                continue
            if not self._are_dependent(existing.op_id, new_transition.op_id):
                continue

            if not self._hb_graph.happens_before(existing.op_id, new_transition.op_id):
                state.backtrack_set.add(existing.thread_id)

    def _execute_transition(
        self,
        state: InterleavingState,
        thread_id: str,
    ) -> tuple[InterleavingState, Transition | None]:
        """Execute the next operation of a given thread.

        Returns the new state and the transition, or (state, None)
        if the thread has no remaining operations.
        """
        ops = self._thread_ops.get(thread_id, [])
        idx = state.thread_states.get(thread_id, 0)
        if idx >= len(ops):
            return state, None

        op_id = ops[idx]
        operation = self._hb_graph.get_operation(op_id)
        if operation is None:
            return state, None

        transition = Transition(
            thread_id=thread_id,
            operation=operation,
            op_id=op_id,
        )

        new_state = state.clone()
        new_state.schedule.append(transition)
        new_state.thread_states[thread_id] = idx + 1
        return new_state, transition

    def explore(self) -> list[list[Transition]]:
        """Run DPOR exploration and return complete schedules.

        Uses iterative DFS (not recursive) to avoid stack overflow.
        Returns up to max_interleavings complete schedules.
        """
        self._complete_schedules = []

        initial = InterleavingState(
            thread_states=dict.fromkeys(self._thread_ops, 0),
        )
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
        """Return pairs of operation IDs that are concurrent and conflicting.

        These are potential data race candidates identified during exploration.
        """
        candidates: list[tuple[int, int]] = []
        all_ops = list(self._hb_graph._operations.items())
        for i, (id1, op1) in enumerate(all_ops):
            for id2, op2 in all_ops[i + 1 :]:
                if op1.conflicts_with(op2) and self._hb_graph.are_concurrent(id1, id2):
                    candidates.append((id1, id2))
        return candidates


def explore_interleavings(
    hb_graph: HappensBeforeGraph,
    thread_operations: dict[str, list[int]],
    max_interleavings: int = 1000,
) -> list[list[Transition]]:
    """Convenience function to explore interleavings with DPOR.

    Args:
        hb_graph: Happens-before graph with all operations.
        thread_operations: Maps thread_id to list of operation IDs.
        max_interleavings: Maximum schedules to generate.

    Returns:
        List of complete schedules (each a list of Transitions).
    """
    explorer = DPORExplorer(hb_graph, thread_operations, max_interleavings)
    return explorer.explore()
