# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Single source of truth for first-class pysymex CLI commands."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Any, Protocol, cast

if TYPE_CHECKING:
    import argparse


class Subparsers(Protocol):
    """Subset of argparse subparser registration used by command modules."""

    def add_parser(self, name: str, **kwargs: Any) -> argparse.ArgumentParser:
        """Add a subparser and return the created parser."""
        ...


class CallableParserBuilder(Protocol):
    """Callable parser registration hook for a CLI command."""

    def __call__(self, subparsers: Subparsers) -> None: ...


class CallableCommandHandler(Protocol):
    """Callable runtime handler for a CLI command."""

    def __call__(self, args: argparse.Namespace) -> int: ...


@dataclass(frozen=True)
class CliCommandSpec:
    """Registered command metadata plus lazy parser and handler targets."""

    name: str
    help: str
    parser_builder: str
    handler: str


COMMAND_SPECS: tuple[CliCommandSpec, ...] = (
    CliCommandSpec(
        name="scan",
        help="Scan files for supported runtime issues",
        parser_builder="pysymex._internal.cli.commands.scan.command:add_scan_parser",
        handler="pysymex._internal.cli.commands.scan.command:run_scan_command",
    ),
    CliCommandSpec(
        name="contracts",
        help="Verify contract-decorated functions",
        parser_builder="pysymex._internal.cli.commands.verify:add_verify_parser",
        handler="pysymex._internal.cli.commands.verify:cmd_verify",
    ),
    CliCommandSpec(
        name="benchmark",
        help="Run built-in performance benchmarks",
        parser_builder="pysymex._internal.cli.commands.benchmark:add_benchmark_parser",
        handler="pysymex._internal.cli.commands.benchmark:cmd_benchmark",
    ),
    CliCommandSpec(
        name="trace-analyze",
        help="Filter and summarize JSONL execution traces",
        parser_builder="pysymex._internal.cli.commands.trace_analyze.command:add_trace_analyze_parser",
        handler="pysymex._internal.cli.commands.trace_analyze.command:run_trace_analyze_command",
    ),
)
_COMMAND_SPECS_BY_NAME = {spec.name: spec for spec in COMMAND_SPECS}


def _load_attr(target: str) -> object:
    module_name, separator, attr_name = target.partition(":")
    if not separator or not module_name or not attr_name:
        msg = f"Invalid CLI command registry target: {target}"
        raise RuntimeError(msg)
    module = import_module(module_name)
    return getattr(module, attr_name)


def iter_command_specs() -> tuple[CliCommandSpec, ...]:
    """Return registered command specifications in parser registration order."""
    return COMMAND_SPECS


def command_names() -> tuple[str, ...]:
    """Return registered command names in parser registration order."""
    return tuple(spec.name for spec in COMMAND_SPECS)


def get_command_spec(name: str) -> CliCommandSpec | None:
    """Return the command specification registered for *name*, if any."""
    return _COMMAND_SPECS_BY_NAME.get(name)


def add_command_parsers(subparsers: Subparsers) -> None:
    """Register every first-class command parser with argparse."""
    add_selected_command_parser(subparsers, selected_command=None)


def add_selected_command_parser(subparsers: Subparsers, selected_command: str | None) -> None:
    """Register one full command parser and placeholders for the rest."""
    for spec in COMMAND_SPECS:
        if selected_command is None or spec.name == selected_command:
            parser_builder = cast("CallableParserBuilder", _load_attr(spec.parser_builder))
            parser_builder(subparsers)
            continue
        subparsers.add_parser(spec.name, help=spec.help)


def add_command_placeholders(subparsers: Subparsers) -> None:
    """Register command names and help text without importing command handlers."""
    for spec in COMMAND_SPECS:
        subparsers.add_parser(spec.name, help=spec.help)


def dispatch_command(args: argparse.Namespace) -> int | None:
    """Dispatch parsed CLI arguments through the registered command handler."""
    command = getattr(args, "command", None)
    if not isinstance(command, str):
        return None
    spec = get_command_spec(command)
    if spec is None:
        return None
    handler = cast("CallableCommandHandler", _load_attr(spec.handler))
    return handler(args)
