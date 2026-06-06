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

"""Typed accessors for Windows ``ctypes`` last-error state.

This module owns the narrow compatibility boundary for ``ctypes.get_last_error``
and ``ctypes.set_last_error``. Those functions are Windows-only in typeshed, so
Linux-hosted type checking cannot see them directly even though the AppContainer
runtime only calls them behind Windows backend paths.
"""

from __future__ import annotations

from collections.abc import Callable
import ctypes
from typing import cast

_fallback_last_error = 0


def get_windows_last_error() -> int:
    """Return the Win32 last-error value tracked by ``ctypes``.

    On non-Windows hosts this returns the local fallback value so platform-
    independent unit tests can exercise fake Win32 calls without importing
    Windows-only ``ctypes`` members.
    """
    candidate = getattr(ctypes, "get_last_error", None)
    if callable(candidate):
        get_last_error = cast(Callable[[], int], candidate)
        return int(get_last_error())
    return _fallback_last_error


def set_windows_last_error(error: int) -> None:
    """Set the Win32 last-error value tracked by ``ctypes`` or the fallback."""
    candidate = getattr(ctypes, "set_last_error", None)
    if callable(candidate):
        set_last_error = cast(Callable[[int], None], candidate)
        set_last_error(error)
        return

    global _fallback_last_error
    _fallback_last_error = int(error)


__all__ = ["get_windows_last_error", "set_windows_last_error"]
