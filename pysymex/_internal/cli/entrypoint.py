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

"""Command-line interface for pysymex."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from pysymex._internal.cli.entry import normalize_argv
from pysymex._internal.config.defaults import VERSION

if TYPE_CHECKING:
    from types import ModuleType

__version__ = VERSION
_GLOBAL_OPTIONS_WITH_VALUE = frozenset(
    (
        "--generate-completion",
        "--log-category",
        "--log-history",
        "--log-jsonl",
    ),
)
_GLOBAL_FLAG_OPTIONS = frozenset(
    (
        "--debug",
        "--diagnostic-trace",
        "--quiet",
    ),
)


def ensure_z3_ready() -> ModuleType:
    """Validate Z3 lazily when a command needs symbolic execution support."""
    from pysymex._internal.deps import ensure_z3_ready as ensure_runtime_z3_ready

    return ensure_runtime_z3_ready()


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point.

    Requires explicit subcommands. Ensures Z3 is available, then dispatches to
    the sub-command handler.

    Args:
        argv: Command-line arguments.  Defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code (``0`` = success).

    """
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    normalized_argv = normalize_argv(raw_argv)

    if _is_root_help_request(normalized_argv):
        return _print_root_help()
    if _is_root_version_request(normalized_argv):
        sys.stdout.write(f"\npysymex {__version__}\n")
        sys.stdout.flush()
        return 0

    stdout_reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(stdout_reconfigure):
        try:
            stdout_reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            _log_stream_reconfigure_failure("stdout")
    stderr_reconfigure = getattr(sys.stderr, "reconfigure", None)
    if callable(stderr_reconfigure):
        try:
            stderr_reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            _log_stream_reconfigure_failure("stderr")

    from pysymex._internal.cli.parser.builder import create_parser

    parser = create_parser(selected_command=_selected_command_from_argv(normalized_argv))
    args = parser.parse_args(normalized_argv)

    if hasattr(args, "generate_completion") and args.generate_completion:
        from pysymex._internal.cli.commands.completion import generate_completion

        return generate_completion(args.generate_completion)

    if getattr(args, "command", None) is None:
        parser.error("a command is required; run 'pysymex --help' to list commands")

    try:
        ensure_z3_ready()
    except RuntimeError:
        return 2

    configure_cli_diagnostics(args)

    from pysymex._internal.cli.commands.registry import dispatch_command

    result = dispatch_command(args)
    if result is not None:
        return result

    parser.print_help()
    return 0


def configure_cli_diagnostics(args: object) -> None:
    """Configure pysymex diagnostics after parsing CLI flags."""
    from pathlib import Path
    from typing import cast

    from pysymex._internal.logging.bridge import setup_python_logging
    from pysymex._internal.logging.levels import LogLevel
    from pysymex._internal.logging.root import configure_logging

    level = LogLevel.NORMAL
    if bool(getattr(args, "quiet", False)):
        level = LogLevel.QUIET
    elif bool(getattr(args, "diagnostic_trace", False)):
        level = LogLevel.TRACE
    elif bool(getattr(args, "debug", False)):
        level = LogLevel.DEBUG
    elif bool(getattr(args, "verbose", False)):
        level = LogLevel.VERBOSE

    raw_categories: object = getattr(args, "log_category", None)
    categories: set[str] | None = None
    if isinstance(raw_categories, list):
        category_values: list[str] = []
        for raw_category in cast("list[object]", raw_categories):
            if isinstance(raw_category, str):
                category_values.append(raw_category)
        categories = set(category_values)
    jsonl_raw = getattr(args, "log_jsonl", None)
    jsonl_path = Path(jsonl_raw) if isinstance(jsonl_raw, str) else None
    raw_history = getattr(args, "log_history", 0)
    history_capacity = raw_history if isinstance(raw_history, int) and raw_history > 0 else 0
    output_format = getattr(args, "format", None)
    diagnostic_stream = (
        sys.stderr if output_format in {"json", "sarif", "html", "markdown"} else None
    )
    configure_logging(
        level=level,
        categories=categories,
        jsonl_path=jsonl_path,
        history_capacity=history_capacity,
        stream=diagnostic_stream,
    )
    setup_python_logging()


def _is_root_help_request(argv: list[str]) -> bool:
    """Return whether argv is an exact root help request."""
    return len(argv) == 1 and argv[0] in {"-h", "--help"}


def _is_root_version_request(argv: list[str]) -> bool:
    """Return whether argv is an exact root version request."""
    return len(argv) == 1 and argv[0] in {"-V", "--version"}


def _print_root_help() -> int:
    """Print root help without importing heavyweight command parser modules."""
    from pysymex._internal.cli.parser.builder import create_parser

    parser = create_parser(include_command_options=False)
    parser.print_help()
    return 0


def _selected_command_from_argv(argv: list[str]) -> str | None:
    """Return the requested command name before building command-specific parsers."""
    from pysymex._internal.cli.commands.registry import command_names

    commands = set(command_names())
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in commands:
            return token
        if token in _GLOBAL_FLAG_OPTIONS:
            index += 1
            continue
        if token in _GLOBAL_OPTIONS_WITH_VALUE:
            index += 2
            continue
        option_name, has_value, _option_value = token.partition("=")
        if has_value and option_name in _GLOBAL_OPTIONS_WITH_VALUE:
            index += 1
            continue
        if token.startswith("-"):
            return None
        return None
    return None


def _log_stream_reconfigure_failure(stream_name: str) -> None:
    """Log stream reconfiguration failures without importing diagnostics on the fast path."""
    from pysymex._internal.logging.root import get_logger

    logger = get_logger(__name__)
    logger.debug("Failed to reconfigure %s encoding", stream_name)


if __name__ == "__main__":
    sys.exit(main())
