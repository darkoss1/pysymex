"""Tests for execution scheduling policy helpers."""

from __future__ import annotations

from typing import cast

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
from pysymex._internal.execution.scheduling.factory import create_path_manager
from pysymex._internal.execution.scheduling.rewards import calculate_path_reward
from pysymex._internal.execution.scheduling.stats import (
    collect_state_merger_stats,
    collect_worklist_stats,
)
from pysymex._internal.execution.strategies.manager.types import ExplorationStrategy, PathManager
from pysymex._internal.execution.strategies.merger.state import StateMerger


class _StatsWorklist(PathManager[VMState]):
    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        _ = state
        _ = priority

    def get_next_state(self) -> VMState | None:
        return None

    def is_empty(self) -> bool:
        return False

    def size(self) -> int:
        return 2

    def get_stats(self) -> dict[str, object]:
        return {
            "total_rewards": 1.0,
            "shadow_frontier": {"capsule_count": 2},
            "shadow_cegis": {"bid_count": 3},
        }


def test_calculate_path_reward_prefers_issues_over_coverage() -> None:
    assert calculate_path_reward(new_coverage=0, new_issues=2) == 20.0


def test_calculate_path_reward_counts_new_coverage() -> None:
    assert calculate_path_reward(new_coverage=3, new_issues=0) == 9.0


def test_calculate_path_reward_combines_issue_and_coverage_signal() -> None:
    assert calculate_path_reward(new_coverage=2, new_issues=1) == 16.0


def test_calculate_path_reward_penalizes_no_progress() -> None:
    assert calculate_path_reward(new_coverage=0, new_issues=0) == -0.5


def test_collect_state_merger_stats_reports_disabled_schema() -> None:
    assert collect_state_merger_stats(None) == {
        "enabled": False,
        "states_before_merge": 0,
        "states_after_merge": 0,
        "merge_operations": 0,
        "subsumption_hits": 0,
        "reduction_ratio": 0.0,
    }


def test_collect_state_merger_stats_reports_enabled_schema() -> None:
    merger = StateMerger()
    merger.stats.states_before_merge = 10
    merger.stats.states_after_merge = 4
    merger.stats.merge_operations = 3
    merger.stats.subsumption_hits = 2

    assert collect_state_merger_stats(merger) == {
        "enabled": True,
        "states_before_merge": 10,
        "states_after_merge": 4,
        "merge_operations": 3,
        "subsumption_hits": 2,
        "reduction_ratio": 0.6,
    }


def test_collect_worklist_stats_reports_disabled_schema() -> None:
    assert collect_worklist_stats(None) == {
        "enabled": False,
        "pending_states": 0,
    }


def test_collect_worklist_stats_merges_provider_diagnostics() -> None:
    stats = collect_worklist_stats(_StatsWorklist())

    assert stats["enabled"] is True
    assert stats["pending_states"] == 2
    assert stats["total_rewards"] == 1.0
    assert stats["shadow_frontier"] == {"capsule_count": 2}
    assert stats["shadow_cegis"] == {"bid_count": 3}


def test_frontier_runtime_mode_constructs_runtime_manager() -> None:
    worklist = create_path_manager(
        ExplorationStrategy.ADAPTIVE,
        frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
    )

    stats = collect_worklist_stats(worklist)
    shadow_frontier = cast("dict[str, object]", stats["shadow_frontier"])
    shadow_cegis = cast("dict[str, object]", stats["shadow_cegis"])

    assert stats["frontier_mode"] == FrontierRuntimeMode.POLAR_CEGIS_RUNTIME.value
    assert shadow_frontier["enabled"] is True
    assert shadow_frontier["compact_queueing_enabled"] is False
    assert shadow_cegis["enabled"] is True


def test_frontier_runtime_mode_certificate_pruning_gate_is_explicit() -> None:
    assert FrontierRuntimeMode.POLAR_CEGIS_SHADOW.certificate_pruning_enabled is False
    assert FrontierRuntimeMode.POLAR_CEGIS_RUNTIME.certificate_pruning_enabled is True
    assert FrontierRuntimeMode.POLAR_CEGIS_RUNTIME.compact_queueing_enabled is False
