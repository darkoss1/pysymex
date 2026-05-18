# pysymex: Python Symbolic Execution & Formal Verification
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

"""Command-line interface for pysymex.
Provides two modes:
1. Single function analysis: pysymex file.py -f function_name
2. Full file/directory scan: pysymex scan path/to/code
"""

from __future__ import annotations

import argparse
import io
import logging
import sys
from typing import Protocol, TypeGuard, cast, runtime_checkable

from pysymex._deps import ensure_z3_ready
from pysymex._lazy import lazy_dir, lazy_getattr

logger = logging.getLogger(__name__)

from pysymex.config import VERSION

__version__ = VERSION

_EXPORTS: dict[str, tuple[str, str]] = {
    "create_parser": ("pysymex.cli.parser", "create_parser"),
    "cmd_scan": ("pysymex.cli.scan", "cmd_scan"),
    "cmd_scan_async": ("pysymex.cli.scan", "cmd_scan_async"),
    "cmd_analyze": ("pysymex.cli.commands", "cmd_analyze"),
    "cmd_benchmark": ("pysymex.cli.commands", "cmd_benchmark"),
    "cmd_check": ("pysymex.cli.commands", "cmd_check"),
    "cmd_concolic": ("pysymex.cli.commands", "cmd_concolic"),
    "cmd_verify": ("pysymex.cli.commands", "cmd_verify"),
    "generate_completion": ("pysymex.cli.commands", "generate_completion"),
}


def __getattr__(name: str) -> object:
    """Getattr."""
    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    """Dir."""
    return lazy_dir(_EXPORTS, globals(), extra=("main", "__version__"))


_Namespace = argparse.Namespace


@runtime_checkable
class _IssueLike(Protocol):
    def to_dict(self) -> dict[str, object]: ...


@runtime_checkable
class _SymbolicResultLike(Protocol):
    issues: list[_IssueLike]

    def to_dict(self) -> dict[str, object]: ...


def _is_issue_like_list(value: object) -> TypeGuard[list[_IssueLike]]:
    """Return whether value is a list of issue-like objects."""
    if not isinstance(value, list):
        return False
    issue_items: list[object] = list(value)  # type: ignore[arg-type]  # value is list[Unknown] after isinstance check
    return all(isinstance(item, _IssueLike) for item in issue_items)


_SUBCOMMANDS = frozenset(
    {
        "scan",
        "analyze",
        "verify",
        "concolic",
        "benchmark",
        "check",
    }
)


def _normalize_argv(argv: list[str]) -> list[str]:
    """Translate legacy analyze syntax into modern subcommand form.

    Legacy form:
        pysymex file.py -f function_name

    Modern form:
        pysymex analyze file.py -f function_name
    """
    if not argv:
        return argv

    first = argv[0]
    if first.startswith("-") or first in _SUBCOMMANDS:
        return argv

    tail = argv[1:]
    if "-f" not in tail and "--function" not in tail:
        return argv

    return ["analyze", first, *tail]


IssueLike = _IssueLike
SymbolicResultLike = _SymbolicResultLike
is_issue_like_list = _is_issue_like_list
normalize_argv = _normalize_argv


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point.

    Normalises legacy ``pysymex file.py -f func`` invocations, ensures Z3
    is available, then dispatches to the appropriate sub-command handler.

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
    args = parser.parse_args(_normalize_argv(raw_argv))

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
    elif args.command == "concolic":
        from pysymex.cli.commands import cmd_concolic

        return cmd_concolic(args)
    elif args.command == "benchmark":
        from pysymex.cli.commands import cmd_benchmark

        return cmd_benchmark(args)
    elif args.command == "check":
        from pysymex.cli.commands import cmd_check

        return cmd_check(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
