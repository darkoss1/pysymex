import argparse
import ast
from dataclasses import dataclass
from functools import cache
from importlib import import_module
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

from pysymex._internal.cli.commands.completion import generate_completion
from pysymex._internal.cli.commands.registry import (
    command_names,
    dispatch_command,
    iter_command_specs,
)
from pysymex._internal.cli.parser.builder import create_parser

_ENGINE_PACKAGES_WITHOUT_CLI = ("analysis", "execution", "core", "models", "scanner", "tracing")
_NON_CLI_IMPORT_ALLOWLIST = {
    Path("pysymex/__main__.py"),
    Path("pysymex/_internal/benchmarks/suite/workload/reporting.py"),
}
_CLI_IMPORT_PREFIXES = ("pysymex._internal.cli", "argparse", "click", "typer")
_CLI_PARSER_CALLS = ("ArgumentParser", "add_parser", "add_argument", "add_subparsers", "parse_args")


@dataclass(frozen=True)
class _CliSourceFacts:
    imports_cli_construct: bool = False
    imports_argparse: bool = False
    imports_webbrowser: bool = False
    calls_parser_construct: bool = False
    calls_engine_forbidden_construct: bool = False
    calls_print: bool = False
    uses_sys_cli_surface: bool = False


def test_parser_subcommands_match_command_registry() -> None:
    parser = create_parser()

    assert tuple(_subparser_choices(parser)) == command_names()


def test_command_parser_builders_use_command_specific_names() -> None:
    """Command registry targets command-specific parser builders."""
    for spec in iter_command_specs():
        module_name, separator, attr_name = spec.parser_builder.partition(":")
        assert separator == ":"
        assert attr_name != "add_parser"
        module = import_module(module_name)
        assert callable(getattr(module, attr_name))


def test_dispatch_command_uses_registered_handler() -> None:
    def handler(args: argparse.Namespace) -> int:
        assert args.command == "scan"
        return 17

    with patch("pysymex._internal.cli.commands.registry._load_attr", return_value=handler):
        result = dispatch_command(argparse.Namespace(command="scan"))

    assert result == 17


def test_dispatch_command_ignores_unknown_or_missing_command() -> None:
    assert dispatch_command(argparse.Namespace(command="missing")) is None
    assert dispatch_command(argparse.Namespace()) is None


def test_completion_scripts_use_registered_commands(capsys: pytest.CaptureFixture[str]) -> None:
    for shell in ("bash", "zsh", "fish"):
        assert generate_completion(shell) == 0
        output = capsys.readouterr().out
        for spec in iter_command_specs():
            assert spec.name in output
            if shell != "bash":
                assert spec.help in output


def test_entrypoint_has_no_command_name_dispatch_branches() -> None:
    source_path = _repo_root() / "pysymex" / "_internal" / "cli" / "entrypoint.py"
    tree = _ast_tree(source_path)
    registered_names = set(command_names())

    assert _imports_dispatch_command(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            compared_strings = {
                operand.value
                for operand in (node.left, *node.comparators)
                if isinstance(operand, ast.Constant) and isinstance(operand.value, str)
            }
            duplicate_names = registered_names.intersection(compared_strings)
            assert not duplicate_names


def test_legacy_parser_command_modules_are_removed() -> None:
    parser_dir = _repo_root() / "pysymex" / "_internal" / "cli" / "parser"

    assert not (parser_dir / "commands.py").exists()
    assert not (parser_dir / "scan.py").exists()


def test_engine_layers_do_not_own_cli_constructs() -> None:
    root = _repo_root()

    for package_name in _ENGINE_PACKAGES_WITHOUT_CLI:
        for source_path in _python_sources(root / "pysymex" / "_internal" / package_name):
            facts = _cli_source_facts(source_path)
            assert not facts.imports_cli_construct, source_path
            assert not facts.calls_engine_forbidden_construct, source_path
            assert not facts.uses_sys_cli_surface, source_path


def test_non_cli_source_has_no_unowned_cli_imports_or_parsers() -> None:
    root = _repo_root()
    cli_root = root / "pysymex" / "_internal" / "cli"
    allowed_paths = {root / path for path in _NON_CLI_IMPORT_ALLOWLIST}

    for source_path in _python_sources(root / "pysymex"):
        if source_path.is_relative_to(cli_root) or source_path in allowed_paths:
            continue
        facts = _cli_source_facts(source_path)
        assert not facts.imports_cli_construct, source_path
        assert not facts.calls_parser_construct, source_path


def test_cli_side_effects_stay_in_cli_owned_modules() -> None:
    root = _repo_root()
    no_print_modules = (
        "pysymex/_internal/benchmarks/suite/runner.py",
        "pysymex/_internal/benchmarks/suite/reporting.py",
        "pysymex/_internal/reporting/realtime/server.py",
        "pysymex/_internal/tracing/analyzer/stream/__init__.py",
    )
    for relative_path in no_print_modules:
        facts = _cli_source_facts(root / relative_path)
        assert not facts.calls_print, relative_path

    realtime_server = _cli_source_facts(root / "pysymex/_internal/reporting/realtime/server.py")
    assert not realtime_server.imports_webbrowser

    for source_path in (root / "pysymex/_internal/tracing/analyzer/pipeline").rglob("*.py"):
        facts = _cli_source_facts(source_path)
        assert not facts.imports_argparse, source_path

    for source_path in (root / "pysymex/_internal/tracing/analyzer").rglob("*.py"):
        facts = _cli_source_facts(source_path)
        assert not facts.uses_sys_cli_surface, source_path

    legacy_trace_cli = root / "pysymex/_internal/tracing/analyzer/cli"
    assert not any(legacy_trace_cli.glob("*.py"))


def _subparser_choices(parser: argparse.ArgumentParser) -> tuple[str, ...]:
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if getattr(action, "dest", None) == "command" and isinstance(choices, dict):
            typed_choices = cast("dict[object, object]", choices)
            return tuple(str(choice) for choice in typed_choices)
    raise AssertionError("parser has no command subparser action")


def _imports_dispatch_command(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == "pysymex._internal.cli.commands.registry"
        ):
            return any(alias.name == "dispatch_command" for alias in node.names)
    return False


def _matches_module_prefix(module_name: str, module_prefixes: tuple[str, ...]) -> bool:
    return any(
        module_name == module_prefix or module_name.startswith(f"{module_prefix}.")
        for module_prefix in module_prefixes
    )


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


@cache
def _python_sources(root: Path) -> tuple[Path, ...]:
    return tuple(sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts))


@cache
def _ast_tree(source_path: Path) -> ast.AST:
    return ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))


@cache
def _cli_source_facts(source_path: Path) -> _CliSourceFacts:
    imports_cli_construct = False
    imports_argparse = False
    imports_webbrowser = False
    calls_parser_construct = False
    calls_engine_forbidden_construct = False
    calls_print = False
    uses_sys_cli_surface = False
    parser_calls = set(_CLI_PARSER_CALLS)
    engine_forbidden_calls = {*parser_calls, "print", "CliOutput.safe_print"}

    for node in ast.walk(_ast_tree(source_path)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports_cli_construct |= _matches_module_prefix(alias.name, _CLI_IMPORT_PREFIXES)
                imports_argparse |= alias.name == "argparse"
                imports_webbrowser |= alias.name == "webbrowser"
            continue
        if isinstance(node, ast.ImportFrom):
            module_name = node.module
            if module_name is not None:
                imports_cli_construct |= _matches_module_prefix(module_name, _CLI_IMPORT_PREFIXES)
                imports_argparse |= module_name == "argparse"
                imports_webbrowser |= module_name == "webbrowser"
            continue
        if isinstance(node, ast.Call):
            qualified_name = _qualified_name(node.func)
            leaf_name = qualified_name.rsplit(".", maxsplit=1)[-1]
            calls_parser_construct |= qualified_name in parser_calls or leaf_name in parser_calls
            calls_engine_forbidden_construct |= (
                qualified_name in engine_forbidden_calls or leaf_name in engine_forbidden_calls
            )
            calls_print |= leaf_name == "print"
            continue
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in {"sys", "_sys"}:
                uses_sys_cli_surface |= node.attr in {"argv", "stdin", "stdout", "stderr"}

    return _CliSourceFacts(
        imports_cli_construct=imports_cli_construct,
        imports_argparse=imports_argparse,
        imports_webbrowser=imports_webbrowser,
        calls_parser_construct=calls_parser_construct,
        calls_engine_forbidden_construct=calls_engine_forbidden_construct,
        calls_print=calls_print,
        uses_sys_cli_surface=uses_sys_cli_surface,
    )


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]
