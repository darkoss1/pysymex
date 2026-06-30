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

"""Argument parser creation for pysymex CLI."""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING, Any, NoReturn, cast

from pysymex._internal.cli.commands.registry import (
    add_command_parsers,
    add_command_placeholders,
    add_selected_command_parser,
)
from pysymex._internal.cli.commands.validation import non_negative_int

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


class PysymexHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Argparse formatter tuned for clean PySyMex terminal help."""

    def _format_action(self, action: argparse.Action) -> str:
        """Render subcommands as a command table without argparse's metavar row."""
        subactions = _get_subactions(action)
        if subactions is not None:
            format_action = super()._format_action
            return "".join(format_action(choice) for choice in subactions)
        return super()._format_action(action)


class PysymexArgumentParser(argparse.ArgumentParser):
    """Argument parser with consistent PySyMex terminal presentation."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Create a parser with polished section titles."""
        if kwargs.get("formatter_class") is argparse.RawDescriptionHelpFormatter:
            kwargs["formatter_class"] = PysymexHelpFormatter
        super().__init__(*args, **kwargs)
        self._positionals.title = "Arguments"
        self._optionals.title = "Options"

    def format_help(self) -> str:
        """Return full help text with a leading spacer and polished usage label."""
        return _format_terminal_parser_text(super().format_help())

    def format_usage(self) -> str:
        """Return usage text with a leading spacer and polished usage label."""
        rendered = _format_terminal_parser_text(super().format_usage())
        return f"{rendered.rstrip()}\n\n"

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        """Exit after optionally spacing successful one-line parser messages."""
        if status == 0 and message and not message.startswith("\n"):
            message = f"\n{message}"
        super().exit(status=status, message=message)


class PysymexVersionAction(argparse.Action):
    """Argparse version action with the same terminal spacer as help output."""

    def __init__(self, option_strings: list[str], version: str, **kwargs: Any) -> None:
        """Create a version action that prints one human-facing line."""
        super().__init__(option_strings=option_strings, nargs=0, **kwargs)
        self._version = version

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        """Print the version and exit successfully."""
        _ = namespace, values, option_string
        parser._print_message(f"\n{self._version}\n", sys.stdout)
        parser.exit()


def _format_terminal_parser_text(text: str) -> str:
    """Normalize parser output spacing for interactive terminals."""
    rendered = _format_usage_block(text)
    rendered = rendered.replace(
        "show this help message and exit",
        "Show this help message and exit",
    )
    return rendered if rendered.startswith("\n") else f"\n{rendered}"


def _get_subactions(action: argparse.Action) -> tuple[argparse.Action, ...] | None:
    """Return argparse subparser pseudo-actions when *action* owns a command table."""
    get_subactions = getattr(action, "_get_subactions", None)
    if not callable(get_subactions):
        return None
    subaction_provider = cast("Callable[[], Iterable[argparse.Action]]", get_subactions)
    subactions = tuple(subaction_provider())
    return subactions or None


def _format_usage_block(text: str) -> str:
    """Render argparse's single-line usage label as a terminal-friendly block."""
    prefix = "usage: "
    if not text.startswith(prefix):
        return text.replace("usage:", "Usage:", 1)

    usage_line, separator, rest = text.partition("\n")
    usage = usage_line.removeprefix(prefix).strip()
    return f"Usage:\n  {usage}{separator}{rest}"


def create_parser(
    *,
    include_command_options: bool = True,
    selected_command: str | None = None,
) -> argparse.ArgumentParser:
    """Create the argument parser with subcommands."""
    parser = PysymexArgumentParser(
        prog="pysymex",
        usage="pysymex [global-options] <command> [command-options]",
        description="PySyMex symbolic execution and verification CLI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  pysymex scan path/to/file.py\n"
            "  pysymex scan path/to/dir --format sarif -o report.sarif\n"
            "  pysymex contracts file.py\n"
            "  pysymex contracts file.py -f func_name --args x:int y:int\n"
            "  pysymex benchmark --list\n"
            "  pysymex trace-analyze trace.jsonl --format summary"
        ),
    )

    from pysymex._internal.config.defaults import VERSION

    __version__ = VERSION

    parser.add_argument(
        "-V",
        "--version",
        action=PysymexVersionAction,
        version=f"pysymex {__version__}",
        help="Show version and exit",
    )
    parser.add_argument(
        "--generate-completion",
        choices=["bash", "zsh", "fish"],
        metavar="SHELL",
        help="Generate shell completion script. Choices: bash, zsh, fish",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error diagnostics")
    parser.add_argument("--debug", action="store_true", help="Enable debug diagnostics")
    parser.add_argument("--diagnostic-trace", action="store_true", help="Enable trace diagnostics")
    parser.add_argument(
        "--log-category",
        action="append",
        default=None,
        help="Enable a diagnostic category; can be passed multiple times",
    )
    parser.add_argument("--log-jsonl", help="Write structured diagnostics to a JSONL file")
    parser.add_argument(
        "--log-history",
        type=non_negative_int,
        default=0,
        help="Retain a bounded in-memory diagnostic history for this run",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="<command>",
        title="Commands",
        description='Run "pysymex <command> --help" for command-specific options.',
        parser_class=PysymexArgumentParser,
    )
    if include_command_options and selected_command is not None:
        add_selected_command_parser(subparsers, selected_command)
    elif include_command_options:
        add_command_parsers(subparsers)
    else:
        add_command_placeholders(subparsers)
    return parser
