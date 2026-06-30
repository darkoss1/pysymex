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

"""Persistent dictionary wrapper used by forked symbolic execution state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Generic, TypeVar, cast

import immutables

from pysymex._internal.core.memory.cow.hashing import cow_pair_hash, deterministic_sort_key

if TYPE_CHECKING:
    from collections.abc import ItemsView, Iterator, KeysView, ValuesView

K = TypeVar("K")
V = TypeVar("V")
_EMPTY_MAP: immutables.Map[object, object] = immutables.Map()


@dataclass(init=False, repr=False, eq=False, slots=True)
class CowDict(Generic[K, V]):
    """Dictionary-like copy-on-write wrapper backed by ``immutables.Map``."""

    _data: immutables.Map[K, V]
    _hash: int | None
    _sorted_items: tuple[tuple[K, V], ...] | None
    _sorted_keys: tuple[K, ...] | None

    def __init__(
        self,
        data: immutables.Map[K, V] | dict[K, V] | CowDict[K, V] | None = None,
    ) -> None:
        """Create a wrapper around persistent map contents."""
        if isinstance(data, immutables.Map):
            base_data: immutables.Map[K, V] = data
        elif isinstance(data, CowDict):
            base_data = data._data
        elif isinstance(data, dict):
            base_data = immutables.Map(data)
        else:
            base_data = cast("immutables.Map[K, V]", _EMPTY_MAP)
        self._data = base_data
        self._hash = None
        self._sorted_items = None
        self._sorted_keys = None

    def __getitem__(self, key: K) -> V:
        """Return the item mapped to ``key``."""
        return self._data[key]

    def __contains__(self, key: object) -> bool:
        """Return whether ``key`` is present in this mapping."""
        return key in self._data

    def __len__(self) -> int:
        """Return the number of mapped items."""
        return len(self._data)

    def __iter__(self) -> Iterator[K]:
        """Iterate mapped keys."""
        return iter(self._data)

    def __repr__(self) -> str:
        """Return a diagnostic representation of current mapped items."""
        return f"CowDict({dict(self._data)!r})"

    def hash_value(self) -> int:
        """Return a cached order-independent structural hash of current items.

        Notes:
            The value is a compact state summary and is not a proof that two
            mappings are semantically equal.

        """
        if self._hash is not None:
            return self._hash
        h = 0
        for k, v in self._data.items():
            h ^= cow_pair_hash(k, v)
        self._hash = h & 0xFFFFFFFFFFFFFFFF
        return self._hash

    def __setitem__(self, key: K, value: V) -> None:
        """Store one item and maintain an existing cached summary hash."""
        if self._hash is None:
            self._data = self._data.set(key, value)
            self._sorted_items = None
            self._sorted_keys = None
            return
        try:
            old_value = self._data[key]
            self._hash ^= cow_pair_hash(key, old_value)
            self._hash ^= cow_pair_hash(key, value)
            self._hash &= 0xFFFFFFFFFFFFFFFF
        except KeyError:
            self._hash ^= cow_pair_hash(key, value)
            self._hash &= 0xFFFFFFFFFFFFFFFF
        self._data = self._data.set(key, value)
        self._sorted_items = None
        self._sorted_keys = None

    def __delitem__(self, key: K) -> None:
        """Remove one item and maintain an existing cached summary hash.

        Raises:
            KeyError: If ``key`` is absent.

        """
        try:
            old_value = self._data[key]
            if self._hash is not None:
                self._hash ^= cow_pair_hash(key, old_value)
                self._hash &= 0xFFFFFFFFFFFFFFFF
            self._data = self._data.delete(key)
            self._sorted_items = None
            self._sorted_keys = None
        except KeyError:
            raise KeyError(key)

    def get(self, key: K, default: V | None = None) -> V | None:
        """Return the mapped value for ``key`` or ``default``."""
        return self._data.get(key, default)

    def keys(self) -> KeysView[K]:
        """Return a view of mapped keys."""
        return self._data.keys()

    def values(self) -> ValuesView[V]:
        """Return a view of mapped values."""
        return self._data.values()

    def items(self) -> ItemsView[K, V]:
        """Return a view of mapped key-value pairs."""
        return self._data.items()

    def setdefault(self, key: K, default: V) -> V:
        """Return an existing item or store ``default`` in this wrapper."""
        if key not in self._data:
            if self._hash is not None:
                self._hash ^= cow_pair_hash(key, default)
                self._hash &= 0xFFFFFFFFFFFFFFFF
            self._data = self._data.set(key, default)
            self._sorted_items = None
            self._sorted_keys = None
            return default
        return self._data[key]

    def pop(self, key: K, *args: V) -> V:
        """Remove and return one item, or return the supplied default.

        Raises:
            KeyError: If ``key`` is absent and no default was supplied.

        """
        if key in self._data:
            val = self._data[key]
            if self._hash is not None:
                self._hash ^= cow_pair_hash(key, val)
                self._hash &= 0xFFFFFFFFFFFFFFFF
            self._data = self._data.delete(key)
            self._sorted_items = None
            self._sorted_keys = None
            return val
        if args:
            return args[0]
        raise KeyError(key)

    def cow_fork(self) -> CowDict[K, V]:
        """Return a wrapper sharing the persistent map until either wrapper mutates."""
        new_copy = type(self).__new__(type(self))
        new_copy._hash = self._hash
        new_copy._data = self._data
        new_copy._sorted_items = self._sorted_items
        new_copy._sorted_keys = self._sorted_keys
        return new_copy

    def copy(self) -> CowDict[K, V]:
        """Return a copy-on-write fork sharing the current persistent map."""
        return self.cow_fork()

    def to_dict(self) -> dict[K, V]:
        """Return a mutable built-in dictionary snapshot of current items."""
        return dict(self._data)

    def sorted_keys(self) -> tuple[K, ...]:
        """Return mapped keys in deterministic sorted order, cached until mutation."""
        if self._sorted_keys is None:
            self._sorted_keys = tuple(sorted(self._data.keys(), key=deterministic_sort_key))
        return self._sorted_keys

    def sorted_items(self) -> tuple[tuple[K, V], ...]:
        """Return mapped items in deterministic key order, cached until mutation."""
        if self._sorted_items is None:
            self._sorted_items = tuple((key, self._data[key]) for key in self.sorted_keys())
        return self._sorted_items

    def mutate(self) -> CowDictMutation[K, V]:
        """Return a mutation context for bulk updates."""
        return CowDictMutation(self)

    def begin_mutation(self) -> Any:
        """Return a mutable builder over the current persistent map."""
        return self._data.mutate()

    def finish_mutation(self, mutation: Any) -> None:
        """Install a finished mutable builder and reset derived caches."""
        self._data = cast("immutables.Map[K, V]", mutation.finish())
        self._hash = None
        self._sorted_items = None
        self._sorted_keys = None


class CowDictMutation(Generic[K, V]):
    """Mutation context for CowDict allowing efficient bulk updates."""

    __slots__ = ("_cow_dict", "_mutation")

    def __init__(self, cow_dict: CowDict[K, V]) -> None:
        self._cow_dict = cow_dict
        self._mutation = cow_dict.begin_mutation()

    def __setitem__(self, key: K, value: V) -> None:
        self._mutation[key] = value

    def __delitem__(self, key: K) -> None:
        try:
            del self._mutation[key]
        except KeyError:
            raise KeyError(key)

    def __getitem__(self, key: K) -> V:
        return self._mutation[key]

    def __contains__(self, key: object) -> bool:
        return key in self._mutation

    def get(self, key: K, default: V | None = None) -> V | None:
        return self._mutation.get(key, default)

    def finish(self) -> None:
        """Apply all mutations to the parent CowDict and reset its cache."""
        self._cow_dict.finish_mutation(self._mutation)

    def __enter__(self) -> CowDictMutation[K, V]:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if exc_type is None:
            self.finish()
