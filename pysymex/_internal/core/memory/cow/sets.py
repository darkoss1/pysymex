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

"""Persistent set wrapper used by forked symbolic execution state."""

from __future__ import annotations

from collections.abc import Hashable, Iterator
from dataclasses import dataclass
from typing import Any, Generic, TypeVar, cast

import immutables

from pysymex._internal.core.memory.cow.hashing import cow_set_item_hash

S = TypeVar("S", bound=Hashable)
_EMPTY_SET_MAP: immutables.Map[object, None] = immutables.Map()


@dataclass(init=False, repr=False, eq=False, slots=True)
class CowSet(Generic[S]):
    """Set-like copy-on-write wrapper backed by a persistent map.

    Forks initially share their immutable backing map. A mutation replaces
    only the mutating wrapper's map reference.
    """

    _data: immutables.Map[S, None]
    _hash: int | None

    def __init__(
        self,
        data: set[S] | frozenset[S] | immutables.Map[S, None] | CowSet[S] | None = None,
    ) -> None:
        """Create a wrapper around persistent set membership."""
        if isinstance(data, immutables.Map):
            base_data: immutables.Map[S, None] = data
        elif isinstance(data, CowSet):
            base_data = data._data
        elif data is not None:
            base_data = immutables.Map(dict.fromkeys(data))
        else:
            base_data = cast("immutables.Map[S, None]", _EMPTY_SET_MAP)
        self._data = base_data
        self._hash = None

    def add(self, item: S) -> None:
        """Add ``item`` and maintain an existing cached summary hash."""
        if self._hash is None:
            self._data = self._data.set(item, None)
            return
        if item not in self._data:
            self._hash ^= cow_set_item_hash(item)
            self._hash &= 0xFFFFFFFFFFFFFFFF
            self._data = self._data.set(item, None)

    def discard(self, item: S) -> None:
        """Remove ``item`` when present and maintain an existing cached summary hash."""
        if item in self._data:
            if self._hash is not None:
                self._hash ^= cow_set_item_hash(item)
                self._hash &= 0xFFFFFFFFFFFFFFFF
            self._data = self._data.delete(item)

    def __contains__(self, item: object) -> bool:
        """Return whether ``item`` is present in this set."""
        return item in self._data

    def __len__(self) -> int:
        """Return the number of set members."""
        return len(self._data)

    def __iter__(self) -> Iterator[S]:
        """Iterate set members."""
        return iter(self._data.keys())

    def hash_value(self) -> int:
        """Return a cached structural hash of current members.

        Notes:
            The value is a compact state summary and is not a proof that two
            sets are semantically equal.

        """
        if self._hash is not None:
            return self._hash ^ len(self._data)
        h = 0
        for item in self._data:
            h ^= cow_set_item_hash(item)
        self._hash = h & 0xFFFFFFFFFFFFFFFF
        return self._hash ^ len(self._data)

    def cow_fork(self) -> CowSet[S]:
        """Return a wrapper sharing the persistent map until either wrapper mutates."""
        new_copy = type(self).__new__(type(self))
        new_copy._data = self._data
        new_copy._hash = self._hash
        return new_copy

    def mutate(self) -> CowSetMutation[S]:
        """Return a mutation context for bulk set updates."""
        return CowSetMutation(self)

    def begin_mutation(self) -> Any:
        """Return a mutable builder over the current persistent set map."""
        return self._data.mutate()

    def finish_mutation(self, mutation: Any) -> None:
        """Install a finished mutable builder and reset derived caches."""
        self._data = cast("immutables.Map[S, None]", mutation.finish())
        self._hash = None


class CowSetMutation(Generic[S]):
    """Mutation context for CowSet allowing efficient bulk updates."""

    __slots__ = ("_cow_set", "_mutation")

    def __init__(self, cow_set: CowSet[S]) -> None:
        self._cow_set = cow_set
        self._mutation = cow_set.begin_mutation()

    def add(self, item: S) -> None:
        self._mutation[item] = None

    def discard(self, item: S) -> None:
        if item in self._mutation:
            del self._mutation[item]

    def __contains__(self, item: object) -> bool:
        return item in self._mutation

    def finish(self) -> None:
        """Apply all mutations to the parent CowSet and reset its cache."""
        self._cow_set.finish_mutation(self._mutation)

    def __enter__(self) -> CowSetMutation[S]:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if exc_type is None:
            self.finish()
