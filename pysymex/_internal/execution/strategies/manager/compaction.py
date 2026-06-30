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

"""Pressure-triggered compaction methods for POLAR path managers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.strategies.manager.pressure import (
    PressureCompactionPolicy,
    cold_compaction_state_ids,
)

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
    from pysymex._internal.execution.frontier.store.core import FrontierWorkStore
    from pysymex._internal.execution.strategies.manager.types import PrioritizedState


class PolarPressureCompactionMixin:
    """Manager methods that compact cold resident frontier entries under pressure."""

    if TYPE_CHECKING:
        _frontier: FrontierWorkStore
        _frontier_runtime_mode: FrontierRuntimeMode
        _pressure_policy: PressureCompactionPolicy
        _heap_polar_native: list[PrioritizedState[int]]
        _resident_units_by_state_id: dict[int, int]
        _estimated_resident_units_total: int
        _pressure_compaction_count: int
        _pressure_compaction_trigger_count: int

        def _drop_resident_units(self, state_id: int) -> None: ...

    def _compact_frontier_under_pressure(self) -> None:
        """Compact a bounded cold batch when resident frontier pressure is high."""
        if not self._frontier_runtime_mode.certificate_pruning_enabled:
            return
        if not self._pressure_policy.should_check(
            len(self._frontier),
            self._estimated_resident_units_total,
        ):
            return

        self._pressure_compaction_trigger_count += 1
        for state_id in cold_compaction_state_ids(
            self._heap_polar_native,
            self._frontier.live_state_ids,
            self._resident_units_by_state_id,
            batch_size=self._pressure_policy.batch_size,
        ):
            if self._request_state_compaction(state_id):
                self._pressure_compaction_count += 1

    def _request_state_compaction(self, state_id: int) -> bool:
        """Compact one state and update resident-unit pressure accounting."""
        decision = self._frontier.request_compaction(state_id)
        if not decision.can_compact:
            return False
        self._drop_resident_units(state_id)
        return True
