"""Tests for pysymex._internal.cli.commands.trace_analyze — build_parser."""

from __future__ import annotations

from io import StringIO

import pytest

from pysymex._internal.cli.commands.trace_analyze.command import (
    build_parser,
    run_trace_analyze_command,
)


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


@pytest.mark.parametrize(
    ("argv", "fragment"),
    [
        (["--seq", "-1"], "--seq"),
        (["--seq-range", "20:10"], "START"),
        (["--path-id-list", ""], "path-id-list"),
        (["--pc", "-1"], "--pc"),
        (["--source-line", "-1"], "--source-line"),
        (["--solver-latency-min", "-1"], "--solver-latency-min"),
        (["--confidence", "1.2:1.3"], "confidence"),
        (["--head", "0"], "--head"),
    ],
)
def test_build_parser_rejects_invalid_filter_bounds(
    argv: list[str],
    fragment: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Trace filters should reject impossible bounds before streaming input."""
    parser = build_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(argv)

    assert exc_info.value.code == 2
    assert fragment in capsys.readouterr().err


def test_run_trace_analyze_reads_stdin_only_in_cli(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = build_parser()
    args = parser.parse_args(["--count"])
    monkeypatch.setattr("sys.stdin", StringIO('{"event_type":"step","seq":1}\n'))

    assert run_trace_analyze_command(args) == 0

    assert capsys.readouterr().out.strip() == "1"


def test_run_trace_analyze_prints_ai_manual_from_cli(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = build_parser()
    args = parser.parse_args(["--ai-manual"])

    assert run_trace_analyze_command(args) == 0

    output = capsys.readouterr().out
    assert "pysymex Trace Analyzer" in output
    assert "LLM Diagnostic Manual" in output
