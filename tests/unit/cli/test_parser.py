import argparse
import subprocess
import sys
from unittest.mock import patch

import pytest

from pysymex._internal.cli.commands.validation import symbolic_args_from_specs
from pysymex._internal.cli.entrypoint import main
from pysymex._internal.cli.parser.builder import create_parser
from pysymex._internal.config.defaults import (
    DEFAULT_BENCHMARK_ITERATIONS,
    DEFAULT_PROFILE_MODE,
    DEFAULT_PROFILE_OUTPUT_DIR,
    DEFAULT_PROFILE_SAMPLE_INTERVAL_MS,
    DEFAULT_SCAN_MAX_DEPTH,
    DEFAULT_SCAN_MAX_ITERATIONS,
    DEFAULT_SCAN_MAX_PATHS,
    DEFAULT_SCAN_OUTPUT_FORMAT,
    DEFAULT_SCAN_TIMEOUT_SECONDS,
    DEFAULT_SCAN_WORKERS,
    DEFAULT_TRACE_OUTPUT_DIR,
    DEFAULT_TRACE_VERBOSITY,
)


def test_create_parser() -> None:
    """Test create_parser behavior."""
    parser = create_parser()
    assert isinstance(parser, argparse.ArgumentParser)


def test_selected_scan_parser_does_not_import_unrelated_command_modules() -> None:
    """Scan startup should not load other command parser/runtime modules."""
    code = (
        "import sys\n"
        "from pysymex._internal.cli.parser.builder import create_parser\n"
        "create_parser(selected_command='scan')\n"
        "print('pysymex._internal.cli.commands.trace_analyze' in sys.modules)\n"
        "print('z3' in sys.modules)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.splitlines() == ["False", "False"]


def test_root_help_has_terminal_spacer_and_short_usage() -> None:
    """Root help should not start hard against the prompt or wrap the usage line."""
    parser = create_parser()

    help_text = parser.format_help()

    assert help_text.startswith(
        "\nUsage:\n  pysymex [global-options] <command> [command-options]\n"
    )
    assert "\nOptions:\n" in help_text
    assert "\nCommands:\n" in help_text
    assert "\n  <command>\n" not in help_text
    assert "\n  scan" in help_text
    assert "Scan files for supported runtime issues" in help_text
    assert "Show this help message and exit" in help_text
    assert "command ..." not in help_text


def test_command_help_has_terminal_spacer_and_short_usage(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Command help should use the same spacer and compact Usage presentation."""
    parser = create_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["contracts", "--help"])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("\nUsage:\n  pysymex contracts PATH [-f NAME] [options]\n")
    assert "\nArguments:\n" in captured.out
    assert "\nOptions:\n" in captured.out
    assert "Show this help message and exit" in captured.out
    assert "Choices: text, json, sarif, rich, html," in captured.out
    assert "markdown (default: text)" in captured.out


def test_benchmark_help_keeps_choices_in_help_body(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Choice-heavy options should stay compact while still showing valid values."""
    parser = create_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["benchmark", "--help"])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "--category CATEGORY" in captured.out
    assert "choices: quick, full," in captured.out
    assert "stress, all)" in captured.out
    for category in ("opcodes", "paths", "solving", "analysis", "sandbox", "cli"):
        assert category in captured.out


def test_parser_exposes_global_diagnostic_options() -> None:
    """Global diagnostic options should parse before subcommands."""
    parser = create_parser()
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


@pytest.mark.parametrize(
    ("argv", "option"),
    [
        (["--log-history", "-1", "scan", "target.py"], "--log-history"),
        (["scan", "target.py", "--max-paths", "0"], "--max-paths"),
        (["scan", "target.py", "--max-depth", "0"], "--max-depth"),
        (["scan", "target.py", "--timeout", "0"], "--timeout"),
        (["scan", "target.py", "--workers", "-1"], "--workers"),
        (["scan", "target.py", "--max-iterations", "-1"], "--max-iterations"),
        (["contracts", "target.py", "-f", "func", "--args", "badarg"], "--args"),
        (["contracts", "target.py", "-f", "func", "--args", ":int"], "--args"),
        (["contracts", "target.py", "-f", "func", "--args", "class:int"], "--args"),
        (["benchmark", "--iterations", "0"], "--iterations"),
        (["benchmark", "--warmup", "-1"], "--warmup"),
        (["benchmark", "--threshold", "-1"], "--threshold"),
        (["trace-analyze", "--head", "0"], "--head"),
        (["trace-analyze", "--tail", "-1"], "--tail"),
    ],
)
def test_parser_rejects_invalid_numeric_and_symbolic_inputs(
    argv: list[str],
    option: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Parser-level validation should reject invalid values before command execution."""
    parser = create_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(argv)

    assert exc_info.value.code == 2
    assert option in capsys.readouterr().err


def test_symbolic_arg_specs_preserve_type_strings_and_reject_duplicates() -> None:
    """Symbolic arg parsing should be strict on names without narrowing type syntax."""
    assert symbolic_args_from_specs(["value:optional:int"]) == {"value": "optional:int"}

    with pytest.raises(ValueError, match="duplicate symbolic argument"):
        symbolic_args_from_specs(["value:int", "value:bool"])


def test_scan_parser_exposes_max_depth() -> None:
    parser = create_parser()

    args = parser.parse_args(["scan", "target.py", "--max-depth", "321"])

    assert args.max_depth == 321
    assert DEFAULT_SCAN_MAX_DEPTH is None


def test_main_rejects_missing_command(capsys: pytest.CaptureFixture[str]) -> None:
    """Running the CLI without a command is an invalid invocation."""
    with (
        patch("pysymex._internal.cli.entrypoint.ensure_z3_ready"),
        pytest.raises(SystemExit) as exc_info,
    ):
        main([])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "a command is required" in captured.err
    assert "pysymex --help" in captured.err


def test_generate_completion_does_not_require_command(capsys: pytest.CaptureFixture[str]) -> None:
    """Global completion generation remains command-free."""
    with patch("pysymex._internal.cli.entrypoint.ensure_z3_ready") as ensure_z3_ready:
        assert main(["--generate-completion", "bash"]) == 0

    ensure_z3_ready.assert_not_called()
    assert "scan" in capsys.readouterr().out


def test_root_help_does_not_validate_z3(capsys: pytest.CaptureFixture[str]) -> None:
    """Root help should stay on the lightweight parser path."""
    with patch("pysymex._internal.cli.entrypoint.ensure_z3_ready") as ensure_z3_ready:
        assert main(["--help"]) == 0

    ensure_z3_ready.assert_not_called()
    assert "Usage:" in capsys.readouterr().out


def test_version_output_has_terminal_spacer(capsys: pytest.CaptureFixture[str]) -> None:
    """Version output should start on a new line like other human terminal output."""
    with patch("pysymex._internal.cli.entrypoint.ensure_z3_ready") as ensure_z3_ready:
        assert main(["--version"]) == 0

    ensure_z3_ready.assert_not_called()
    assert capsys.readouterr().out.startswith("\npysymex ")


def test_scan_parser_default_timeout_is_automatic() -> None:
    """Default symbolic scans should not synthesize a host wall-clock stop."""
    parser = create_parser()
    args = parser.parse_args(["scan", "target.py"])

    assert args.timeout is DEFAULT_SCAN_TIMEOUT_SECONDS is None


def test_scan_parser_defaults_are_config_owned() -> None:
    parser = create_parser()
    args = parser.parse_args(["scan", "target.py"])

    assert args.format == DEFAULT_SCAN_OUTPUT_FORMAT
    assert args.max_paths == DEFAULT_SCAN_MAX_PATHS
    assert args.timeout == DEFAULT_SCAN_TIMEOUT_SECONDS
    assert args.workers == DEFAULT_SCAN_WORKERS
    assert args.max_iterations == DEFAULT_SCAN_MAX_ITERATIONS
    assert args.no_sandbox is False
    assert args.detect_overflow is False
    assert args.profile is False
    assert args.profile_output_dir == DEFAULT_PROFILE_OUTPUT_DIR
    assert args.profile_mode == DEFAULT_PROFILE_MODE
    assert args.profile_sample_interval_ms == DEFAULT_PROFILE_SAMPLE_INTERVAL_MS
    assert args.profile_baseline is None
    assert args.trace_output_dir == DEFAULT_TRACE_OUTPUT_DIR
    assert args.trace_verbosity == DEFAULT_TRACE_VERBOSITY


def test_scan_parser_accepts_developer_profile() -> None:
    parser = create_parser()
    args = parser.parse_args(["scan", "target.py", "--profile"])

    assert args.profile is True


def test_scan_parser_accepts_profile_mode() -> None:
    parser = create_parser()
    args = parser.parse_args(["scan", "target.py", "--profile-mode", "cprofile"])

    assert args.profile_mode == "cprofile"


def test_scan_parser_accepts_profile_sample_interval() -> None:
    parser = create_parser()
    args = parser.parse_args(["scan", "target.py", "--profile-sample-interval-ms", "10"])

    assert args.profile_sample_interval_ms == 10.0


def test_scan_parser_accepts_profile_output_dir() -> None:
    parser = create_parser()
    args = parser.parse_args(["scan", "target.py", "--profile-output-dir", "profiles"])

    assert args.profile_output_dir == "profiles"


def test_scan_parser_accepts_profile_baseline() -> None:
    parser = create_parser()
    args = parser.parse_args(["scan", "target.py", "--profile-baseline", "before.json"])

    assert args.profile_baseline == "before.json"


def test_scan_parser_accepts_no_sandbox_escape_hatch() -> None:
    parser = create_parser()
    args = parser.parse_args(["scan", "target.py", "--no-sandbox"])

    assert args.no_sandbox is True


def test_scan_parser_accepts_explicit_bounded_overflow_policy() -> None:
    parser = create_parser()
    args = parser.parse_args(["scan", "target.py", "--detect-overflow"])

    assert args.detect_overflow is True


def test_benchmark_parser_exposes_modes_filters_and_thresholds() -> None:
    parser = create_parser()
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
    parser = create_parser()
    args = parser.parse_args(["benchmark", "--category", "sandbox"])

    assert args.mode is None
    assert args.category == "sandbox"


def test_benchmark_parser_accepts_all_mode() -> None:
    parser = create_parser()
    args = parser.parse_args(["benchmark", "--mode", "all"])

    assert args.mode == "all"


def test_verify_parser_exposes_shared_report_options() -> None:
    """Verify should expose the same report shape controls as scan-like commands."""
    parser = create_parser()
    args = parser.parse_args(
        ["contracts", "target.py", "-f", "func", "--format", "json", "-o", "report.json"]
    )

    assert args.format == "json"
    assert args.output == "report.json"
    assert args.function == "func"


def test_verify_parser_accepts_symbolic_args() -> None:
    """Verify should parse declared symbolic argument types."""
    parser = create_parser()
    args = parser.parse_args(
        ["contracts", "target.py", "-f", "target", "--args", "value:int", "flag:bool"]
    )

    assert args.args == ["value:int", "flag:bool"]


def test_verify_parser_allows_optional_function() -> None:
    """Verify parser should accept verify without a function target, defaulting to None."""
    parser = create_parser()
    args = parser.parse_args(["contracts", "target.py"])
    assert args.function is None

