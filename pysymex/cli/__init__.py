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

"""Command-line interface package exports for pysymex."""

from __future__ import annotations

from pysymex._lazy import lazy_dir, lazy_getattr
from pysymex.cli.entrypoint import (
    __version__,
    IssueLike as _IssueLike,
    SymbolicResultLike as _SymbolicResultLike,
    is_issue_like_list as _is_issue_like_list,
    main,
    normalize_argv as _normalize_argv,
)


_EXPORTS: dict[str, tuple[str, str]] = {
    "create_parser": ("pysymex.cli.parser", "create_parser"),
    "cmd_scan": ("pysymex.cli.scan", "cmd_scan"),
    "cmd_scan_async": ("pysymex.cli.scan", "cmd_scan_async"),
    "get_formatter": ("pysymex.cli.formatters", "get_formatter"),
    "cmd_analyze": ("pysymex.cli.commands", "cmd_analyze"),
    "cmd_benchmark": ("pysymex.cli.commands", "cmd_benchmark"),
    "cmd_check": ("pysymex.cli.commands", "cmd_check"),
    "cmd_concolic": ("pysymex.cli.commands", "cmd_concolic"),
    "cmd_verify": ("pysymex.cli.commands", "cmd_verify"),
    "generate_completion": ("pysymex.cli.commands", "generate_completion"),
}


def __getattr__(name: str) -> object:
    """Resolve lazily exported CLI helpers."""
    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    """Return package attributes including lazily exported CLI helpers."""
    return lazy_dir(
        _EXPORTS,
        globals(),
        extra=(
            "__version__",
            "_IssueLike",
            "_SymbolicResultLike",
            "_is_issue_like_list",
            "_normalize_argv",
            "main",
        ),
    )


__all__ = [
    "__version__",
    "_IssueLike",
    "_SymbolicResultLike",
    "_is_issue_like_list",
    "_normalize_argv",
    "main",
]
