import argparse

import pysymex.cli.parser
from pysymex.config import (
    DEFAULT_ANALYZE_MAX_PATHS,
    DEFAULT_ANALYZE_TIMEOUT_SECONDS,
    DEFAULT_SCAN_MAX_ITERATIONS,
    DEFAULT_SCAN_MAX_PATHS,
    DEFAULT_SCAN_OUTPUT_FORMAT,
    DEFAULT_SCAN_TIMEOUT_SECONDS,
    DEFAULT_SCAN_WORKERS,
    DEFAULT_TRACE_OUTPUT_DIR,
    DEFAULT_TRACE_VERBOSITY,
)
from pysymex.config.defaults import DEFAULT_BENCHMARK_ITERATIONS


def test_create_parser() -> None:
    """Test create_parser behavior."""
    parser = pysymex.cli.parser.create_parser()
    assert isinstance(parser, argparse.ArgumentParser)


def test_parser_exposes_global_diagnostic_options() -> None:
    """Global diagnostic options should parse before subcommands."""
    parser = pysymex.cli.parser.create_parser()
    args = parser.parse_args(
        [
            "--debug",
            "--log-category",
            "solver",
            "--log-jsonl",
            "diag.jsonl",
            "--log-history",
            "20",
            "scan",
            "target.py",
        ]
    )

    assert args.debug is True
    assert args.log_category == ["solver"]
    assert args.log_jsonl == "diag.jsonl"
    assert args.log_history == 20


def test_scan_parser_default_timeout_is_bounded_for_stress_scans() -> None:
    """Default symbolic scans should not spend 30 seconds per function before reporting."""
    parser = pysymex.cli.parser.create_parser()
    args = parser.parse_args(["scan", "target.py"])

    assert args.timeout == DEFAULT_SCAN_TIMEOUT_SECONDS


def test_scan_parser_defaults_are_config_owned() -> None:
    parser = pysymex.cli.parser.create_parser()
    args = parser.parse_args(["scan", "target.py"])

    assert args.format == DEFAULT_SCAN_OUTPUT_FORMAT
    assert args.max_paths == DEFAULT_SCAN_MAX_PATHS
    assert args.timeout == DEFAULT_SCAN_TIMEOUT_SECONDS
    assert args.workers == DEFAULT_SCAN_WORKERS
    assert args.max_iterations == DEFAULT_SCAN_MAX_ITERATIONS
    assert args.no_sandbox is False
    assert args.trace_output_dir == DEFAULT_TRACE_OUTPUT_DIR
    assert args.trace_verbosity == DEFAULT_TRACE_VERBOSITY


def test_scan_parser_accepts_no_sandbox_escape_hatch() -> None:
    parser = pysymex.cli.parser.create_parser()
    args = parser.parse_args(["scan", "target.py", "--no-sandbox"])

    assert args.no_sandbox is True


def test_analyze_parser_defaults_are_config_owned() -> None:
    parser = pysymex.cli.parser.create_parser()
    args = parser.parse_args(["analyze", "target.py", "-f", "func"])

    assert args.max_paths == DEFAULT_ANALYZE_MAX_PATHS
    assert args.timeout == DEFAULT_ANALYZE_TIMEOUT_SECONDS


def test_benchmark_parser_exposes_modes_filters_and_thresholds() -> None:
    parser = pysymex.cli.parser.create_parser()
    args = parser.parse_args(
        [
            "benchmark",
            "--mode",
            "full",
            "--category",
            "cli",
            "--warmup",
            "0",
            "--threshold",
            "15",
            "--list",
        ]
    )

    assert args.mode == "full"
    assert args.category == "cli"
    assert args.iterations == DEFAULT_BENCHMARK_ITERATIONS
    assert args.warmup == 0
    assert args.threshold == 15.0
    assert args.list is True


def test_benchmark_parser_leaves_mode_unset_for_focused_default() -> None:
    parser = pysymex.cli.parser.create_parser()
    args = parser.parse_args(["benchmark", "--category", "sandbox"])

    assert args.mode is None
    assert args.category == "sandbox"


def test_benchmark_parser_accepts_all_mode() -> None:
    parser = pysymex.cli.parser.create_parser()
    args = parser.parse_args(["benchmark", "--mode", "all"])

    assert args.mode == "all"


def test_verify_parser_exposes_shared_report_options() -> None:
    """Verify should expose the same report shape controls as scan-like commands."""
    parser = pysymex.cli.parser.create_parser()
    args = parser.parse_args(["verify", "target.py", "--format", "json", "-o", "report.json"])

    assert args.format == "json"
    assert args.output == "report.json"


def test_verify_parser_accepts_symbolic_args() -> None:
    """Verify should parse declared symbolic argument types."""
    parser = pysymex.cli.parser.create_parser()
    args = parser.parse_args(["verify", "target.py", "--args", "value:int", "flag:bool"])

    assert args.args == ["value:int", "flag:bool"]
