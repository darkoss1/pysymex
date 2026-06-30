from __future__ import annotations

import json
from pathlib import Path

from pysymex._internal.profiling.hotspots import ProfileHotspot, ProfilePhaseBreakdown
from pysymex._internal.profiling.model import ScanProfileReport
from pysymex._internal.profiling.rendering import ScanProfileReports
from pysymex._internal.profiling.session import ProfileRun
from pysymex._internal.scanner.types import ScanResult


def test_scan_profile_report_diagnoses_bottleneck_families(tmp_path: Path) -> None:
    result = ScanResult(
        file_path="slow.py",
        timestamp="2026-06-14T00:00:00",
        issues=[{"kind": "TYPE_ERROR"}],
        code_objects=3,
        paths_explored=1200,
        paths_pruned=800,
        elapsed_time=2.0,
        avg_memory_mb=600.0,
        degraded_passes=["unsupported_opcode"],
        solver_stats={
            "logical_queries": 140,
            "z3_check_calls": 100,
            "sat_results": 80,
            "unsat_results": 19,
            "unknown_results": 1,
            "cache_hits": 40,
            "z3_ast_cache_hits": 300,
            "z3_ast_cache_misses": 100,
            "detector_query_cache_hits": 45,
            "detector_query_cache_misses": 15,
            "solver_time_ms": 900.0,
            "detector_sink_attempts": 60,
        },
    )
    hotspot = ProfileHotspot(
        file_path="pysymex/_internal/execution/engine/worklist.py",
        line_number=97,
        function_name="drain_worklist",
        primitive_calls=1,
        total_calls=5,
        internal_time_seconds=0.1,
        cumulative_time_seconds=1.2,
    )
    profile_run = ProfileRun(
        stats_path=tmp_path / "scan.pstats",
        profiled_seconds=2.0,
        cumulative_hotspots=(hotspot,),
        internal_hotspots=(hotspot,),
        phase_breakdown=(
            ProfilePhaseBreakdown(
                phase="formula_and_evidence",
                internal_time_seconds=0.4,
                profile_share=0.2,
                primitive_calls=12_000,
                total_calls=12_000,
                frame_count=10,
            ),
        ),
    )

    report = ScanProfileReport.from_scan_results(
        [result],
        trace_output_dir=".pysymex/traces",
        profile_run=profile_run,
        stats_metrics={"max_memory_mb": 700.0},
        wall_time_seconds=2.0,
    )

    assert report.aggregate.paths_explored == 1200
    assert report.aggregate.candidate_issues == 1
    assert report.aggregate.solver_ms_per_call == 9.0
    assert report.aggregate.solver_time_ratio == 0.45
    assert report.aggregate.solver_cache_hit_rate == 40 / 140
    assert report.aggregate.z3_ast_cache_hit_rate == 0.75
    assert report.aggregate.detector_cache_hit_rate == 0.75
    assert report.degraded_labels == (("unsupported_opcode", 1),)
    kinds = {item.kind for item in report.bottlenecks}
    assert "solver pressure" in kinds
    assert "solver uncertainty" in kinds
    assert "path explosion" in kinds
    assert "degraded analysis" in kinds
    assert "memory pressure" in kinds
    assert "python hotspot" in kinds
    assert "formula and evidence amplification" in kinds

    rendered = ScanProfileReports.format(report)

    assert "Developer Profile" in rendered
    assert "Bottleneck Signals" in rendered
    assert "paths explored: 1200" in rendered
    assert "logical solver queries: 140" in rendered
    assert "Self-Time Engine Hotspots" in rendered
    assert "pysymex/_internal/execution/engine/worklist.py:97 drain_worklist" in rendered


def test_scan_profile_summary_is_machine_readable(tmp_path: Path) -> None:
    result = ScanResult(
        file_path="target.py",
        timestamp="2026-06-14T00:00:00",
        paths_explored=2,
        elapsed_time=0.5,
    )
    report = ScanProfileReport.from_scan_results([result], trace_output_dir="traces")

    summary_path = ScanProfileReports.write_summary(report, tmp_path)
    data = json.loads(summary_path.read_text(encoding="utf-8"))

    assert data["profile_summary_path"] == str(summary_path)
    assert data["aggregate"]["files_scanned"] == 1
    assert data["aggregate"]["paths_explored"] == 2


def test_scan_profile_summary_does_not_overwrite_sample_artifact(tmp_path: Path) -> None:
    profile_run = ProfileRun(
        stats_path=tmp_path / "scan-target.samples.json",
        profiled_seconds=0.01,
        cumulative_hotspots=(),
        internal_hotspots=(),
    )
    profile_run.stats_path.write_text("{}", encoding="utf-8")
    report = ScanProfileReport.from_scan_results(
        [],
        trace_output_dir="traces",
        profile_run=profile_run,
    )

    summary_path = ScanProfileReports.write_summary(report, tmp_path)

    assert summary_path != profile_run.stats_path
    assert summary_path.name == "scan-target.samples.summary.json"
    assert profile_run.stats_path.read_text(encoding="utf-8") == "{}"
