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

import io
import sys
from pathlib import Path
from typing import cast

from pysymex.logger import LogLevel, configure_logging, get_logger, setup_python_logging
from pysymex.deps import ensure_z3_ready
from pysymex.lazy import lazy_dir, lazy_getattr
from pysymex.cli.entry_helpers import normalize_argv
from pysymex.config import VERSION

logger = get_logger(__name__)
__version__ = VERSION

_EXPORTS: dict[str, tuple[str, str]] = {
    "create_parser": ("pysymex.cli.parser", "create_parser"),
    "cmd_scan": ("pysymex.cli.scan", "cmd_scan"),
    "cmd_scan_async": ("pysymex.cli.scan", "cmd_scan_async"),
    "cmd_analyze": ("pysymex.cli.commands", "cmd_analyze"),
    "cmd_benchmark": ("pysymex.cli.commands", "cmd_benchmark"),
    "cmd_check": ("pysymex.cli.commands", "cmd_check"),
    "cmd_verify": ("pysymex.cli.commands", "cmd_verify"),
    "generate_completion": ("pysymex.cli.commands", "generate_completion"),
}


def __getattr__(name: str) -> object:
    """Getattr."""
    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    """Dir."""
    return lazy_dir(_EXPORTS, globals(), extra=("main", "__version__"))


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point.

    Requires explicit subcommands. Ensures Z3 is available, then dispatches to
    the sub-command handler.

    Args:
        argv: Command-line arguments.  Defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code (``0`` = success).
    """

    if hasattr(sys.stdout, "reconfigure"):
        try:
            cast("io.TextIOWrapper", sys.stdout).reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            logger.debug("Failed to reconfigure stdout encoding", exc_info=True)
    if hasattr(sys.stderr, "reconfigure"):
        try:
            cast("io.TextIOWrapper", sys.stderr).reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            logger.debug("Failed to reconfigure stderr encoding", exc_info=True)

    try:
        ensure_z3_ready()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    from pysymex.cli.parser import create_parser

    parser = create_parser()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(normalize_argv(raw_argv))
    configure_cli_diagnostics(args)

    if hasattr(args, "generate_completion") and args.generate_completion:
        from pysymex.cli.commands import generate_completion

        return generate_completion(args.generate_completion)

    elif args.command == "scan" and getattr(args, "use_async", False):
        import asyncio

        from pysymex.cli.scan import cmd_scan_async

        return asyncio.run(cmd_scan_async(args))
    elif args.command == "scan":
        from pysymex.cli.scan import cmd_scan

        return cmd_scan(args)
    elif args.command == "analyze":
        from pysymex.cli.commands import cmd_analyze

        return cmd_analyze(args)
    elif args.command == "verify":
        from pysymex.cli.commands import cmd_verify

        return cmd_verify(args)
    elif args.command == "benchmark":
        from pysymex.cli.commands import cmd_benchmark

        return cmd_benchmark(args)
    elif args.command == "check":
        from pysymex.cli.commands import cmd_check

        return cmd_check(args)

    parser.print_help()
    return 0


def configure_cli_diagnostics(args: object) -> None:
    """Configure pysymex diagnostics after parsing CLI flags."""
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


if __name__ == "__main__":
    sys.exit(main())
