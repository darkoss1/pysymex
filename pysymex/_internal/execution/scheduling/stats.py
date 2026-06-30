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

"""Execution scheduling diagnostic stat projection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, TypeGuard

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.strategies.manager.types import PathManager
    from pysymex._internal.execution.strategies.merger.state import StateMerger


class _WorklistStatsProvider(Protocol):
    """Worklist interface extension for optional diagnostic stats."""

    def get_stats(self) -> dict[str, object]:
        """Return bounded diagnostic stats for the active worklist."""
        ...


def collect_state_merger_stats(state_merger: StateMerger | None) -> dict[str, object]:
    """Return fixed-schema state-merger statistics for execution results."""
    if state_merger is None:
        return {
            "enabled": False,
            "states_before_merge": 0,
            "states_after_merge": 0,
            "merge_operations": 0,
            "subsumption_hits": 0,
            "reduction_ratio": 0.0,
        }
    stats = state_merger.stats
    return {
        "enabled": True,
        "states_before_merge": stats.states_before_merge,
        "states_after_merge": stats.states_after_merge,
        "merge_operations": stats.merge_operations,
        "subsumption_hits": stats.subsumption_hits,
        "reduction_ratio": stats.reduction_ratio,
    }


def collect_worklist_stats(worklist: PathManager[VMState] | None) -> dict[str, object]:
    """Return fixed-schema worklist diagnostics for execution results."""
    if worklist is None:
        return {
            "enabled": False,
            "pending_states": 0,
        }
    stats: dict[str, object] = {
        "enabled": True,
        "pending_states": worklist.size(),
    }
    if _is_worklist_stats_provider(worklist):
        stats.update(worklist.get_stats())
    return stats


def _is_worklist_stats_provider(value: object) -> TypeGuard[_WorklistStatsProvider]:
    """Return whether ``value`` exposes bounded worklist diagnostics."""
    get_stats = getattr(value, "get_stats", None)
    return callable(get_stats)
