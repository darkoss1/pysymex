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

"""functools.cmp_to_key model."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


def _cmp_as_int(res: object) -> int:
    if isinstance(res, bool):
        return int(res)
    if isinstance(res, int):
        return res
    int_method = getattr(res, "__int__", None)
    if callable(int_method):
        try:
            int_value = int_method()
            if isinstance(int_value, int):
                return int_value
            return 0
        except (TypeError, ValueError):
            return 0
    return 0


def model_cmp_to_key(mycmp: Callable[[object, object], object]) -> type:
    """Model functools.cmp_to_key(mycmp)."""

    class K:
        """Key selector wrapper for comparison functions."""

        __slots__ = ["obj"]

        def __init__(self, obj: object) -> None:
            """Initialize a new K instance."""
            self.obj = obj

        def __lt__(self, other: K) -> bool:
            res = mycmp(self.obj, other.obj)
            return _cmp_as_int(res) < 0

        def __gt__(self, other: K) -> bool:
            res = mycmp(self.obj, other.obj)
            return _cmp_as_int(res) > 0

        def __eq__(self, other: object) -> bool:
            if not isinstance(other, K):
                return NotImplemented
            res = mycmp(self.obj, other.obj)
            return _cmp_as_int(res) == 0

        def __le__(self, other: K) -> bool:
            res = mycmp(self.obj, other.obj)
            return _cmp_as_int(res) <= 0

        def __ge__(self, other: K) -> bool:
            res = mycmp(self.obj, other.obj)
            return _cmp_as_int(res) >= 0

    return K
