"""Regression tests for CLI argument parsing and entrypoints."""

from __future__ import annotations

import pysymex.cli as cli
import pysymex.verify_cli as verify_cli
from pysymex.cli.parser import create_parser


class TestCLIParser:
    """Parser-level tests for command syntax."""

    def test_scan_subcommand_parses_with_path(self):
        parser = create_parser()
        args = parser.parse_args(["scan", "sample.py"])

        assert args.command == "scan"
        assert args.path == "sample.py"

    def test_analyze_subcommand_parses_with_function(self):
        parser = create_parser()
        args = parser.parse_args(["analyze", "sample.py", "-f", "target"])

        assert args.command == "analyze"
        assert args.file == "sample.py"
        assert args.function == "target"

    def test_verify_subcommand_parses_with_file(self):
        parser = create_parser()
        args = parser.parse_args(["verify", "sample.py"])

        assert args.command == "verify"
        assert args.file == "sample.py"

    def test_scan_trace_flags_parse(self):
        parser = create_parser()
        args = parser.parse_args(
            [
                "scan",
                "sample.py",
                "--trace",
                "--trace-output-dir",
                ".trace-out",
                "--trace-verbosity",
                "full",
            ]
        )

        assert args.command == "scan"
        assert args.trace is True
        assert args.trace_output_dir == ".trace-out"
        assert args.trace_verbosity == "full"


class TestCLIMain:
    """Dispatcher-level tests for CLI compatibility behavior."""

    def test_legacy_analyze_args_are_translated(self, monkeypatch):
        monkeypatch.setattr(cli, "ensure_z3_ready", lambda: None)
        captured: dict[str, str] = {}

        def fake_cmd_analyze(args):
            captured["command"] = args.command
            captured["file"] = args.file
            captured["function"] = args.function
            return 17

        monkeypatch.setattr("pysymex.cli.commands.cmd_analyze", fake_cmd_analyze)

        exit_code = cli.main(["target.py", "-f", "check_me"])

        assert exit_code == 17
        assert captured == {
            "command": "analyze",
            "file": "target.py",
            "function": "check_me",
        }

    def test_scan_subcommand_dispatches_normally(self, monkeypatch):
        monkeypatch.setattr(cli, "ensure_z3_ready", lambda: None)
        captured: dict[str, str] = {}

        def fake_cmd_scan(args):
            captured["command"] = args.command
            captured["path"] = args.path
            return 9

        monkeypatch.setattr("pysymex.cli.scan.cmd_scan", fake_cmd_scan)

        exit_code = cli.main(["scan", "project.py"])

        assert exit_code == 9
        assert captured == {
            "command": "scan",
            "path": "project.py",
        }


class TestVerifyEntrypoint:
    """Tests for the dedicated ``pysymex-verify`` console entrypoint."""

    def test_verify_entrypoint_prefixes_subcommand(self, monkeypatch):
        captured: dict[str, list[str] | None] = {}

        def fake_cli_main(argv=None):
            captured["argv"] = argv
            return 23

        monkeypatch.setattr(verify_cli, "_cli_main", fake_cli_main)

        exit_code = verify_cli.main(["module.py", "-f", "fn"])

        assert exit_code == 23
        assert captured["argv"] == ["verify", "module.py", "-f", "fn"]
