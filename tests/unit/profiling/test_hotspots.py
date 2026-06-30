from __future__ import annotations

import cProfile
from pathlib import Path

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.profiling.hotspots import (
    ProfileHotspot,
    collect_python_profile,
    collect_sampling_profile,
)


def test_profile_hotspots_exclude_runtime_frames_from_engine_rankings() -> None:
    profile = cProfile.Profile()
    value = z3.Int("profile_value")

    profile.enable()
    for _ in range(5):
        simplify_expr(value + 0)
    profile.disable()

    project_root = Path(__file__).parents[3]
    summary = collect_python_profile(
        profile,
        project_root=project_root,
        target_path=Path(__file__),
        limit=25,
    )

    assert summary.cumulative_hotspots
    assert all(item.origin in {"engine", "target"} for item in summary.cumulative_hotspots)
    assert all(item.file_path != "~" for item in summary.cumulative_hotspots)
    assert any(item.phase == "formula_and_evidence" for item in summary.phase_breakdown)
    assert any(item.origin == "runtime" for item in summary.origin_breakdown)


def test_profile_hotspot_reports_exclusive_cost_per_call() -> None:
    hotspot = ProfileHotspot(
        file_path="pysymex/example.py",
        line_number=10,
        function_name="work",
        primitive_calls=2,
        total_calls=4,
        internal_time_seconds=0.002,
        cumulative_time_seconds=0.01,
    )

    assert hotspot.internal_microseconds_per_call == 500.0
    assert hotspot.to_dict()["internal_microseconds_per_call"] == 500.0


def test_sampling_profile_converts_samples_to_time_and_phases() -> None:
    project_root = Path(__file__).parents[3]
    engine_file = project_root / "pysymex" / "_internal" / "execution" / "sampled.py"
    runtime_key = ("<built-in>", 0, "z3_check")
    engine_key = (str(engine_file), 42, "execute")

    summary = collect_sampling_profile(
        leaf_counts={engine_key: 3, runtime_key: 1},
        cumulative_counts={engine_key: 4, runtime_key: 1},
        project_root=project_root,
        target_path=project_root / "examples",
        profiled_seconds=0.2,
        limit=10,
    )

    assert summary.total_calls == 4
    assert summary.internal_hotspots[0].function_name == "execute"
    assert abs(summary.internal_hotspots[0].internal_time_seconds - 0.15) < 1e-9
    assert abs(summary.cumulative_hotspots[0].cumulative_time_seconds - 0.2) < 1e-9
    assert summary.phase_breakdown[0].phase == "execution"
