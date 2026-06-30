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

"""Dependency-free runtime shape guards shared across early-import modules."""

from __future__ import annotations

from typing import TypeGuard


def _list(value: object) -> TypeGuard[list[object]]:
    """Return whether *value* is a list of runtime objects."""
    return isinstance(value, list)


def _tuple(value: object) -> TypeGuard[tuple[object, ...]]:
    """Return whether *value* is a tuple of runtime objects."""
    return isinstance(value, tuple)


def _dict(value: object) -> TypeGuard[dict[object, object]]:
    """Return whether *value* is a dictionary of runtime objects."""
    return isinstance(value, dict)


def _set(value: object) -> TypeGuard[set[object]]:
    """Return whether *value* is a set of runtime objects."""
    return isinstance(value, set)


def _frozenset(value: object) -> TypeGuard[frozenset[object]]:
    """Return whether *value* is a frozenset of runtime objects."""
    return isinstance(value, frozenset)


class RuntimeObjectGuards:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    @staticmethod
    def list(value: object) -> TypeGuard[list[object]]:
        """Return whether *value* is a list of runtime objects."""
        return _list(value)

    @staticmethod
    def tuple(value: object) -> TypeGuard[tuple[object, ...]]:
        """Return whether *value* is a tuple of runtime objects."""
        return _tuple(value)

    @staticmethod
    def dict(value: object) -> TypeGuard[dict[object, object]]:
        """Return whether *value* is a dictionary of runtime objects."""
        return _dict(value)

    @staticmethod
    def set(value: object) -> TypeGuard[set[object]]:
        """Return whether *value* is a set of runtime objects."""
        return _set(value)

    @staticmethod
    def frozenset(value: object) -> TypeGuard[frozenset[object]]:
        """Return whether *value* is a frozenset of runtime objects."""
        return _frozenset(value)
