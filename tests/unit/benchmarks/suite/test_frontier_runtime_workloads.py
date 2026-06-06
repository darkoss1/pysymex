from __future__ import annotations

from collections.abc import Callable, Mapping
from types import SimpleNamespace
from typing import cast

import pytest

from pysymex.benchmarks.suite.workload.frontier import runtime as frontier_runtime_mod
from pysymex.benchmarks.suite.workload.frontier.runtime import (
    bench_frontier_runtime_cegis_core_reuse_pruning,
    bench_frontier_runtime_cegis_dominance_pruning,
    bench_frontier_runtime_cegis_exact_pruning,
    bench_frontier_runtime_pressure_compaction,
)
from pysymex.execution.strategies.manager.path import AdaptivePathManager


class _ZeroRemovalManager:
    def __init__(self) -> None:
        self._size = 1

    def size(self) -> int:
        return self._size

    def preview_shadow_cegis_frontier(self, _budget: object) -> SimpleNamespace:
        return SimpleNamespace(outcome=object(), can_remove=True)

    def apply_evidence_outcome(self, _outcome: object) -> int:
        self._size = 0
        return 0


class _NoneSelectingManager:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self._empty_checks = 0

    def add_state(self, _state: object) -> None:
        return None

    def size(self) -> int:
        return 0

    def preview_shadow_cegis_frontier(self, _budget: object) -> SimpleNamespace:
        return SimpleNamespace(outcome=None, can_remove=False)

    def apply_evidence_outcome(self, _outcome: object) -> int:
        return 0

    def is_empty(self) -> bool:
        if self._empty_checks == 0:
            self._empty_checks += 1
            return False
        return True

    def get_next_state(self) -> None:
        return None


def test_frontier_runtime_cegis_exact_pruning_reports_solver_owned_removals() -> None:
    result = bench_frontier_runtime_cegis_exact_pruning()

    assert result["instructions"] == 64
    assert result["paths"] == 32
    assert result["solver_calls"] > 0
    assert result["solver_unsat"] == result["solver_calls"]
    assert result["solver_sat"] == 0


def test_frontier_runtime_cegis_dominance_pruning_reports_solver_free_removals() -> None:
    result = bench_frontier_runtime_cegis_dominance_pruning()

    assert result["instructions"] == 64
    assert result["paths"] == 32
    assert result["solver_calls"] == 0
    assert result["solver_sat"] == 0
    assert result["solver_unsat"] == 0


def test_frontier_runtime_cegis_core_reuse_pruning_reports_full_unsat_removal() -> None:
    result = bench_frontier_runtime_cegis_core_reuse_pruning()

    assert result["instructions"] == 64
    assert result["paths"] == 0
    assert result["solver_calls"] > 0
    assert result["solver_unsat"] == result["solver_calls"]
    assert result["solver_sat"] == 0


def test_frontier_runtime_pressure_compaction_reports_default_threshold_work() -> None:
    result = bench_frontier_runtime_pressure_compaction()

    assert result["solver_calls"] == 0
    assert result["paths"] == result["instructions"]
    assert result["pressure_triggers"] > 0
    assert result["pressure_compactions"] > 0
    assert result["compacted_entries"] == result["pressure_compactions"]
    assert result["resident_units"] > 0


def test_frontier_runtime_pressure_compaction_rejects_missing_pressure_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_stat(_stats: object, _key: str) -> int:
        return 0

    monkeypatch.setattr(frontier_runtime_mod, "_shadow_stats_int", fake_stat)

    with pytest.raises(RuntimeError, match="did not cross"):
        bench_frontier_runtime_pressure_compaction()


def test_frontier_runtime_pressure_compaction_rejects_inconsistent_counters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_stats = {
        "pressure_compaction_count": 2,
        "pressure_compaction_trigger_count": 1,
        "compacted_entry_count": 1,
        "runtime_estimated_resident_units": 10,
    }

    def fake_stat(_stats: object, key: str) -> int:
        return fake_stats[key]

    monkeypatch.setattr(frontier_runtime_mod, "_shadow_stats_int", fake_stat)

    with pytest.raises(RuntimeError, match="inconsistent compaction counters"):
        bench_frontier_runtime_pressure_compaction()


def test_frontier_runtime_stat_helpers_reject_malformed_payloads() -> None:
    shadow_frontier_stats = cast(
        "Callable[[dict[str, object]], Mapping[object, object]]",
        getattr(frontier_runtime_mod, "_shadow_frontier_stats"),
    )
    shadow_stats_int = cast(
        "Callable[[Mapping[object, object], str], int]",
        getattr(frontier_runtime_mod, "_shadow_stats_int"),
    )

    with pytest.raises(RuntimeError, match="did not expose"):
        shadow_frontier_stats({})

    assert shadow_stats_int({"flag": True}, "flag") == 0
    with pytest.raises(RuntimeError, match="not an integer"):
        shadow_stats_int({"bad": "value"}, "bad")


def test_frontier_runtime_cegis_benchmark_rejects_unexpected_prune_count() -> None:
    bench_frontier_runtime_cegis = cast(
        "Callable[..., dict[str, int]]",
        getattr(frontier_runtime_mod, "_bench_frontier_runtime_cegis"),
    )

    with pytest.raises(RuntimeError, match="unexpected exact-prune count"):
        bench_frontier_runtime_cegis(
            states=[],
            expected_removed=1,
            solver_owned=False,
        )


def test_frontier_runtime_cegis_apply_stops_on_zero_removal() -> None:
    apply_explicit_cegis = cast(
        "Callable[[AdaptivePathManager], tuple[int, int]]",
        getattr(frontier_runtime_mod, "_apply_explicit_cegis"),
    )

    removed, previews = apply_explicit_cegis(cast(AdaptivePathManager, _ZeroRemovalManager()))

    assert removed == 0
    assert previews == 1


def test_frontier_runtime_cegis_benchmark_tolerates_stale_empty_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pysymex.execution.strategies.manager.path as path_mod

    monkeypatch.setattr(path_mod, "AdaptivePathManager", _NoneSelectingManager)
    bench_frontier_runtime_cegis = cast(
        "Callable[..., dict[str, int]]",
        getattr(frontier_runtime_mod, "_bench_frontier_runtime_cegis"),
    )

    result = bench_frontier_runtime_cegis(
        states=[],
        expected_removed=0,
        solver_owned=False,
    )

    assert result["paths"] == 0
