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

"""Memory-pressure policy helpers for the POLAR runtime frontier."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.execution.strategies.manager.constants import TOPOLOGICAL_MULTIPLIER

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.frontier.runtime.features import FrontierRuntimeFeatures
    from pysymex._internal.execution.strategies.manager.types import PrioritizedState


@dataclass(frozen=True, slots=True)
class PressureCompactionPolicy:
    """Bounded compaction gate for high-pressure resident frontiers."""

    entry_threshold: int = 1024
    resident_unit_threshold: int = 32768
    check_interval: int = 64
    batch_size: int = 32

    def should_check(self, live_entry_count: int, resident_units: int) -> bool:
        """Return whether the frontier is large enough to justify compaction work."""
        if self.batch_size <= 0:
            return False
        over_entries = live_entry_count >= self.entry_threshold
        over_units = resident_units >= self.resident_unit_threshold
        if not over_entries and not over_units:
            return False
        if live_entry_count == self.entry_threshold:
            return True
        return self.check_interval <= 1 or live_entry_count % self.check_interval == 0


def runtime_native_priority(
    *,
    state: VMState,
    branch_degree: int,
    features: FrontierRuntimeFeatures | None,
    estimated_resident_units: int,
) -> float:
    """Return deterministic POLAR runtime priority for one resident state."""
    if features is None:
        detector_count = len(state.deferred_detector_issues)
        resident_units = estimated_resident_units
        unsupported_live_count = 0
        havoc_live_count = 0
    else:
        detector_count = features.detector_obligation_count
        resident_units = max(1, features.estimated_resident_units)
        unsupported_live_count = features.unsupported_live_count
        havoc_live_count = features.havoc_live_count

    return (
        (detector_count * 1_000_000.0)
        + (branch_degree * TOPOLOGICAL_MULTIPLIER)
        + float(state.depth)
        - (state.pending_constraint_count * 0.25)
        - (resident_units * 0.01)
        - ((unsupported_live_count + havoc_live_count) * 10.0)
    )


def cold_compaction_state_ids(
    heap_entries: Iterable[PrioritizedState[int]],
    live_state_ids: Iterable[int],
    resident_units_by_state_id: Mapping[int, int],
    *,
    batch_size: int,
) -> tuple[int, ...]:
    """Return low-priority resident state IDs to compact under pressure."""
    live_ids = set(live_state_ids)
    seen: set[int] = set()
    candidates: list[tuple[float, int, int]] = []
    for entry in heap_entries:
        state_id = entry.state
        if state_id in seen:
            continue
        seen.add(state_id)
        if state_id not in live_ids or state_id not in resident_units_by_state_id:
            continue
        candidates.append((entry.priority, entry.counter, state_id))
    candidates.sort(key=lambda candidate: (candidate[0], -candidate[1]))
    return tuple(state_id for _priority, _counter, state_id in candidates[:batch_size])
