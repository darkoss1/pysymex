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

"""Typed access for Windows ``ctypes`` last-error state.

This module owns the narrow compatibility boundary for ``ctypes.get_last_error``
which is Windows-only in typeshed. Linux-hosted type checking cannot see it
directly even though the AppContainer runtime only calls it behind Windows
backend paths.
"""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable


def get_windows_last_error() -> int:
    """Return the Win32 last-error value tracked by ``ctypes``.

    On non-Windows hosts this returns ``0`` because no Win32 last-error value
    exists.
    """
    candidate = getattr(ctypes, "get_last_error", None)
    if callable(candidate):
        get_last_error = cast("Callable[[], int]", candidate)
        return int(get_last_error())
    return 0
