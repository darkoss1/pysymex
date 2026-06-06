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

"""Compatibility exports for core cache helpers.

Code-object cache ownership lives in ``pysymex.core.cache.code_objects`` so this
package initializer does not own runtime imports or cache registration.
"""

from __future__ import annotations

CacheInfo: object
get_exception_entries: object
get_instructions: object

__all__ = ["CacheInfo", "get_exception_entries", "get_instructions"]

_EXPORTS = frozenset(__all__)


def __getattr__(name: str) -> object:
    """Load compatibility exports lazily from the implementation module."""
    if name not in _EXPORTS:
        raise AttributeError(name)
    module = __import__("pysymex.core.cache.code_objects", fromlist=[name])
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Return stable public names for interactive inspection."""
    return sorted([*globals(), *__all__])
