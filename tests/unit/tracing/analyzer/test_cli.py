"""Tests for pysymex.tracing.analyzer.cli — build_parser."""

from __future__ import annotations

from pysymex.tracing.analyzer.cli import build_parser


def test_build_parser_defaults() -> None:
    """build_parser builds parser with correct argument structure."""
    parser = build_parser()
    assert parser is not None
    # Verify some key arguments exist
    args = parser.parse_args(["--event-type", "step", "--depth-min", "5"])
    assert args.event_type == ["step"]
    assert args.depth_min == 5


def test_build_parser_accepts_diagnostic_event_types() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "--event-type",
            "detector_query",
            "--event-type",
            "path_feasibility",
            "--event-type",
            "scheduler",
            "--event-type",
            "fallback",
        ]
    )

    assert args.event_type == ["detector_query", "path_feasibility", "scheduler", "fallback"]


def test_build_parser_accepts_representative_filter_groups() -> None:
    """build_parser wires every extracted filter group into the same parser."""
    parser = build_parser()

    args = parser.parse_args(
        [
            "--seq-range",
            "10:20",
            "--path-id-list",
            "1,2",
            "--opcode",
            "CALL",
            "--step-latency-min",
            "0.25",
            "--trigger",
            "fork",
            "--solve-result",
            "unknown",
            "--cache-miss",
            "--confidence",
            "0.5:1.0",
            "--function-name",
            "target",
            "--touches-var",
            "x",
            "--format",
            "summary",
            "--fields",
            "event_type,seq",
        ]
    )

    assert args.seq_range == (10, 20)
    assert args.path_id_list == [1, 2]
    assert args.opcode == "CALL"
    assert args.step_latency_min == 0.25
    assert args.trigger == "fork"
    assert args.solve_result == "unknown"
    assert args.cache_miss is True
    assert args.confidence == (0.5, 1.0)
    assert args.function_name == "target"
    assert args.touches_var == "x"
    assert args.format == "summary"
    assert args.fields == "event_type,seq"
