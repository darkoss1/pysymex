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

"""Lightweight contextlib utility stubs."""

from __future__ import annotations

import builtins
import contextlib
from typing import TYPE_CHECKING, Self, cast

if TYPE_CHECKING:
    import types


class Suppress:
    """Stub context manager for suppress."""

    def __init__(self, *exceptions: type[BaseException]) -> None:
        """Store the exception classes this manager is allowed to suppress."""
        self._exceptions = exceptions

    def __enter__(self) -> Self:
        return self

    def suppresses(self, exc_type: object) -> bool:
        """Return whether ``contextlib.suppress`` would consume this exception."""
        if isinstance(exc_type, str):
            exc_type = getattr(builtins, exc_type, None)
        return (
            isinstance(exc_type, type)
            and issubclass(exc_type, BaseException)
            and issubclass(exc_type, self._exceptions)
        )

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> bool:
        return self.suppresses(exc_type)


def apply_supported_suppress_call(
    func_obj: object,
    args: list[object],
    kwargs: dict[str, object],
) -> object | None:
    """Apply trusted ``contextlib.suppress`` construction and exit calls."""
    receiver_offset = int(bool(args and getattr(args[0], "name", "") == "contextlib"))
    if (
        func_obj is contextlib.suppress
        and not kwargs
        and all(
            isinstance(arg, type) and issubclass(arg, BaseException)
            for arg in args[receiver_offset:]
        )
    ):
        exceptions = cast("list[type[BaseException]]", args[receiver_offset:])
        return Suppress(*exceptions)
    suppressor = getattr(func_obj, "__self__", None)
    if isinstance(suppressor, Suppress) and getattr(func_obj, "__name__", "") == "__exit__":
        return suppressor.suppresses(args[0] if args else None)
    return None
