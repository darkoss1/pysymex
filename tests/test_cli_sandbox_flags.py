"""Focused tests for opt-in sandbox command routing."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from pysymex.cli import commands
from pysymex.cli.parser import create_parser


def _make_temp_python_file() -> Path:
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("def f(x):\n    return x\n")
        return Path(f.name)


def test_cmd_verify_routes_to_sandbox(monkeypatch):
    target = _make_temp_python_file()

    captured: dict[str, object] = {}

    def fake_runner(command: str, args: argparse.Namespace) -> int:
        captured["command"] = command
        captured["sandbox"] = getattr(args, "sandbox", False)
        return 7

    monkeypatch.setattr(commands, "_run_cli_command_sandboxed", fake_runner)

    try:
        args = argparse.Namespace(file=str(target), function=None, verbose=False, sandbox=True)
        exit_code = commands.cmd_verify(args)

        assert exit_code == 7
        assert captured == {"command": "verify", "sandbox": True}
    finally:
        target.unlink(missing_ok=True)


def test_cmd_concolic_routes_to_sandbox(monkeypatch):
    target = _make_temp_python_file()

    captured: dict[str, object] = {}

    def fake_runner(command: str, args: argparse.Namespace) -> int:
        captured["command"] = command
        captured["sandbox"] = getattr(args, "sandbox", False)
        return 9

    monkeypatch.setattr(commands, "_run_cli_command_sandboxed", fake_runner)

    try:
        args = argparse.Namespace(
            file=str(target),
            function="f",
            iterations=5,
            verbose=False,
            sandbox=True,
        )
        exit_code = commands.cmd_concolic(args)

        assert exit_code == 9
        assert captured == {"command": "concolic", "sandbox": True}
    finally:
        target.unlink(missing_ok=True)


def test_verify_parser_defaults_to_sandbox_enabled():
    parser = create_parser()
    args = parser.parse_args(["verify", "target.py"])
    assert args.sandbox is True


def test_verify_parser_no_sandbox_opt_out():
    parser = create_parser()
    args = parser.parse_args(["verify", "target.py", "--no-sandbox"])
    assert args.sandbox is False


def test_concolic_parser_defaults_to_sandbox_enabled():
    parser = create_parser()
    args = parser.parse_args(["concolic", "target.py", "-f", "f"])
    assert args.sandbox is True


def test_concolic_parser_no_sandbox_opt_out():
    parser = create_parser()
    args = parser.parse_args(["concolic", "target.py", "-f", "f", "--no-sandbox"])
    assert args.sandbox is False
