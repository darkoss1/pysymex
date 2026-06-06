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

"""Persistent collection wrappers used by forked symbolic execution state.

``CowDict`` and ``CowSet`` share immutable map backing across forks; mutation
replaces the receiving map and maintains a structural hash summary, not proof
of semantic path equivalence.
"""

from __future__ import annotations

from collections.abc import Hashable, ItemsView, Iterator, KeysView, ValuesView
from typing import Generic, TypeVar

import immutables

from pysymex.logger import get_logger

K = TypeVar("K")
V = TypeVar("V")
S = TypeVar("S", bound=Hashable)
logger = get_logger(__name__)


class CowDict(Generic[K, V]):
    """Dictionary-like copy-on-write wrapper backed by ``immutables.Map``."""

    __slots__ = ("_data", "_hash", "_sorted_items", "_sorted_keys")
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
            base_data = immutables.Map()
        self._data = base_data
        self._hash: int | None = None
        self._sorted_items: tuple[tuple[K, V], ...] | None = None
        self._sorted_keys: tuple[K, ...] | None = None

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

    def _safe_hash(self, obj: object) -> int:
        """Derive a hash summary from a value or its symbolic representation."""
        try:
            return hash(obj)
        except TypeError:
            if logger.state.debug_enabled:
                logger.debug("Hashing unhashable CowDict value structurally", exc_info=True)
            hash_value = getattr(obj, "hash_value", None)
            if callable(hash_value):
                hv = hash_value()
                if isinstance(hv, int):
                    return hv
                return hash(str(hv))
            to_z3 = getattr(obj, "to_z3", None)
            if callable(to_z3):
                z3_ast = to_z3()
                z3_hash = getattr(z3_ast, "hash", None)
                if callable(z3_hash):
                    zh = z3_hash()
                    if isinstance(zh, int):
                        return zh
                    return hash(str(zh))
                return hash(str(z3_ast))
            return hash(repr(obj))

    def _compute_pair_hash(self, k: object, v: object) -> int:
        """Return a mixed structural summary for one mapping item."""
        hk = self._safe_hash(k)
        hv = self._safe_hash(v)
        pair_h = (hk ^ (hv * 1000003)) & 0xFFFFFFFFFFFFFFFF
        pair_h = (pair_h ^ (pair_h >> 30)) * 0xBF58476D1CE4E5B9 & 0xFFFFFFFFFFFFFFFF
        pair_h = (pair_h ^ (pair_h >> 27)) * 0x94D049BB133111EB & 0xFFFFFFFFFFFFFFFF
        pair_h = pair_h ^ (pair_h >> 31)
        return pair_h

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
            h ^= self._compute_pair_hash(k, v)
        self._hash = h & 0xFFFFFFFFFFFFFFFF
        return self._hash

    def __setitem__(self, key: K, value: V) -> None:
        """Store one item and maintain an existing cached summary hash."""
        try:
            old_value = self._data[key]
            if self._hash is not None:
                self._hash ^= self._compute_pair_hash(key, old_value)
                self._hash ^= self._compute_pair_hash(key, value)
                self._hash &= 0xFFFFFFFFFFFFFFFF
        except KeyError:
            if self._hash is not None:
                self._hash ^= self._compute_pair_hash(key, value)
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
                self._hash ^= self._compute_pair_hash(key, old_value)
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
                self._hash ^= self._compute_pair_hash(key, default)
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
                self._hash ^= self._compute_pair_hash(key, val)
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
            self._sorted_keys = tuple(sorted(self._data.keys(), key=_deterministic_sort_key))
        return self._sorted_keys

    def sorted_items(self) -> tuple[tuple[K, V], ...]:
        """Return mapped items in deterministic key order, cached until mutation."""
        if self._sorted_items is None:
            self._sorted_items = tuple((key, self._data[key]) for key in self.sorted_keys())
        return self._sorted_items


class CowSet(Generic[S]):
    """Set-like copy-on-write wrapper backed by a persistent map.

    Forks initially share their immutable backing map. A mutation replaces
    only the mutating wrapper's map reference.
    """

    __slots__ = ("_data", "_hash")
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
            base_data = immutables.Map({k: None for k in data})
        else:
            base_data = immutables.Map()
        self._data = base_data
        self._hash: int | None = None

    def _compute_item_hash(self, item: S) -> int:
        """Return a mixed structural summary for one set member."""
        item_h = hash(item) & 0xFFFFFFFFFFFFFFFF
        item_h = (item_h ^ (item_h >> 30)) * 0xBF58476D1CE4E5B9 & 0xFFFFFFFFFFFFFFFF
        item_h = (item_h ^ (item_h >> 27)) * 0x94D049BB133111EB & 0xFFFFFFFFFFFFFFFF
        item_h = item_h ^ (item_h >> 31)
        return item_h

    def add(self, item: S) -> None:
        """Add ``item`` and maintain an existing cached summary hash."""
        if item not in self._data:
            if self._hash is not None:
                self._hash ^= self._compute_item_hash(item)
                self._hash &= 0xFFFFFFFFFFFFFFFF
            self._data = self._data.set(item, None)

    def discard(self, item: S) -> None:
        """Remove ``item`` when present and maintain an existing cached summary hash."""
        if item in self._data:
            if self._hash is not None:
                self._hash ^= self._compute_item_hash(item)
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
            h ^= self._compute_item_hash(item)
        self._hash = h & 0xFFFFFFFFFFFFFFFF
        return self._hash ^ len(self._data)

    def cow_fork(self) -> CowSet[S]:
        """Return a wrapper sharing the persistent map until either wrapper mutates."""
        new_copy = type(self).__new__(type(self))
        new_copy._data = self._data
        new_copy._hash = self._hash
        return new_copy


def _deterministic_sort_key(value: object) -> tuple[str, str, str]:
    """Return a stable cross-type sort key for diagnostic snapshots."""
    value_type = type(value)
    return (value_type.__module__, value_type.__qualname__, repr(value))
