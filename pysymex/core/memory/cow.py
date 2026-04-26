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

"""Copy-on-Write data structures for pysymex.

Provides efficient state forking via copy-on-write semantics:
- CowDict: Dictionary that shares backing store until mutation
- CowSet: Set that shares backing store until mutation
- ConstraintChain: Persistent linked list for O(1) constraint fork
"""

from __future__ import annotations

from collections.abc import ItemsView, Iterator, KeysView, ValuesView
from dataclasses import dataclass
from typing import Generic, TypeVar

import z3

K = TypeVar("K")
V = TypeVar("V")


import immutables


class CowDict(Generic[K, V]):
    """True Copy-on-Write dictionary utilizing a Hash Array Mapped Trie (HAMT).
    Guarantees O(log N) mutation overhead per write, eliminating the O(N)
    deferred copy trap of the previous implementation.
    """

    __slots__ = ("_data", "_hash")
    _data: immutables.Map[K, V]
    _hash: int | None

    def __init__(
        self,
        data: immutables.Map[K, V] | dict[K, V] | CowDict[K, V] | None = None,
        *,
        shared: bool = False,
    ) -> None:
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

    def __getitem__(self, key: K) -> V:
        return self._data[key]

    def __contains__(self, key: object) -> bool:
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self) -> Iterator[K]:
        return iter(self._data)

    def __repr__(self) -> str:
        return f"CowDict({dict(self._data)!r})"

    def _safe_hash(self, obj: object) -> int:
        try:
            return hash(obj)
        except TypeError:
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
            return 0

    def _compute_pair_hash(self, k: object, v: object) -> int:
        hk = self._safe_hash(k)
        hv = self._safe_hash(v)
        pair_h = (hk ^ (hv * 1000003)) & 0xFFFFFFFFFFFFFFFF
        pair_h = (pair_h ^ (pair_h >> 30)) * 0xBF58476D1CE4E5B9 & 0xFFFFFFFFFFFFFFFF
        pair_h = (pair_h ^ (pair_h >> 27)) * 0x94D049BB133111EB & 0xFFFFFFFFFFFFFFFF
        pair_h = pair_h ^ (pair_h >> 31)
        return pair_h

    def hash_value(self) -> int:
        if self._hash is not None:
            return self._hash
        h = 0
        for k, v in self._data.items():
            h ^= self._compute_pair_hash(k, v)
        self._hash = h & 0xFFFFFFFFFFFFFFFF
        return self._hash

    def __setitem__(self, key: K, value: V) -> None:
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

    def __delitem__(self, key: K) -> None:
        try:
            old_value = self._data[key]
            if self._hash is not None:
                self._hash ^= self._compute_pair_hash(key, old_value)
                self._hash &= 0xFFFFFFFFFFFFFFFF
            self._data = self._data.delete(key)
        except KeyError:
            raise KeyError(key)

    def get(self, key: K, default: V | None = None) -> V | None:
        return self._data.get(key, default)

    def keys(self) -> KeysView[K]:
        return self._data.keys()  # type: ignore[return-value]

    def values(self) -> ValuesView[V]:
        return self._data.values()  # type: ignore[return-value]

    def items(self) -> ItemsView[K, V]:
        return self._data.items()  # type: ignore[return-value]

    def setdefault(self, key: K, default: V) -> V:
        if key not in self._data:
            if self._hash is not None:
                self._hash ^= self._compute_pair_hash(key, default)
                self._hash &= 0xFFFFFFFFFFFFFFFF
            self._data = self._data.set(key, default)
            return default
        return self._data[key]

    def update(self, other: dict[K, V] | CowDict[K, V]) -> None:
        new_hash = self._hash
        with self._data.mutate() as mm:
            if isinstance(other, CowDict):
                for k, v in other._data.items():
                    if new_hash is not None:
                        if k in self._data:
                            new_hash ^= self._compute_pair_hash(k, self._data[k])
                        new_hash ^= self._compute_pair_hash(k, v)
                        new_hash &= 0xFFFFFFFFFFFFFFFF
                    mm.set(k, v)
            else:
                for k, v in other.items():
                    if new_hash is not None:
                        if k in self._data:
                            new_hash ^= self._compute_pair_hash(k, self._data[k])
                        new_hash ^= self._compute_pair_hash(k, v)
                        new_hash &= 0xFFFFFFFFFFFFFFFF
                    mm.set(k, v)
            self._data = mm.finish()
        self._hash = new_hash

    def pop(self, key: K, *args: V) -> V:
        if key in self._data:
            val = self._data[key]
            if self._hash is not None:
                self._hash ^= self._compute_pair_hash(key, val)
                self._hash &= 0xFFFFFFFFFFFFFFFF
            self._data = self._data.delete(key)
            return val
        if args:
            return args[0]
        raise KeyError(key)

    def cow_fork(self) -> "CowDict[K, V]":
        new_copy = CowDict(self._data)
        new_copy._hash = self._hash
        return new_copy

    def copy(self) -> "CowDict[K, V]":
        return self.cow_fork()

    def to_dict(self) -> dict[K, V]:
        return dict(self._data)


class CowSet:
    """Copy-on-Write set with caching hash using immutables.Map."""

    __slots__ = ("_data", "_hash")
    _data: immutables.Map[int, None]
    _hash: int | None

    def __init__(
        self,
        data: set[int] | frozenset[int] | immutables.Map[int, None] | CowSet | None = None,
        *,
        shared: bool = False,
    ) -> None:
        if isinstance(data, immutables.Map):
            base_data: immutables.Map[int, None] = data
        elif isinstance(data, CowSet):
            base_data = data._data
        elif data is not None:
            base_data = immutables.Map({k: None for k in data})
        else:
            base_data = immutables.Map()
        self._data = base_data
        self._hash: int | None = None

    def _compute_item_hash(self, item: int) -> int:
        item_h = (item + 0x9E3779B9) & 0xFFFFFFFFFFFFFFFF
        item_h = (item_h ^ (item_h >> 30)) * 0xBF58476D1CE4E5B9 & 0xFFFFFFFFFFFFFFFF
        item_h = (item_h ^ (item_h >> 27)) * 0x94D049BB133111EB & 0xFFFFFFFFFFFFFFFF
        item_h = item_h ^ (item_h >> 31)
        return item_h

    def add(self, item: int) -> None:
        if item not in self._data:
            if self._hash is not None:
                self._hash ^= self._compute_item_hash(item)
                self._hash &= 0xFFFFFFFFFFFFFFFF
            self._data = self._data.set(item, None)

    def discard(self, item: int) -> None:
        if item in self._data:
            if self._hash is not None:
                self._hash ^= self._compute_item_hash(item)
                self._hash &= 0xFFFFFFFFFFFFFFFF
            self._data = self._data.delete(item)

    def __contains__(self, item: object) -> bool:
        return item in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self) -> Iterator[int]:
        return iter(self._data.keys())

    def hash_value(self) -> int:
        if self._hash is not None:
            return self._hash ^ len(self._data)
        h = 0
        for item in self._data:
            h ^= self._compute_item_hash(item)
        self._hash = h & 0xFFFFFFFFFFFFFFFF
        return self._hash ^ len(self._data)

    def cow_fork(self) -> "CowSet":
        new_copy = CowSet(self._data)
        new_copy._hash = self._hash
        return new_copy

    def to_set(self) -> set[int]:
        return set(self._data.keys())


@dataclass(frozen=True, slots=True)
class BranchRecord:
    """Records a branch decision in an execution trace."""

    pc: int
    condition: z3.BoolRef
    taken: bool


class BranchChain:
    """Persistent linked list for branch decisions.

    Forking is O(1) — both parent and child share the same chain.
    """

    __slots__ = ("_length", "parent", "record")

    def __init__(
        self,
        record: BranchRecord | None = None,
        parent: BranchChain | None = None,
    ) -> None:
        self.record = record
        self.parent = parent
        if parent is None:
            self._length = 1 if record is not None else 0
        else:
            self._length = parent._length + (1 if record is not None else 0)

    def append(self, record: BranchRecord) -> BranchChain:
        """Append a branch record, returning a new chain head. O(1)."""
        return BranchChain(record, self)

    def to_list(self) -> list[BranchRecord]:
        """Materialize the chain as a Python list. O(n)."""
        result: list[BranchRecord] = []
        node: BranchChain | None = self
        while node is not None and node.record is not None:
            result.append(node.record)
            node = node.parent
        result.reverse()
        return result

    def __len__(self) -> int:
        """Return the depth (number of records) of the branch chain."""
        return self._length

    @staticmethod
    def empty() -> BranchChain:
        """Create an empty branch chain."""
        return BranchChain()


class ConstraintChain:
    """Persistent linked list for Z3 path constraints.

    Forking is O(1) — both parent and child share the same chain.
    New constraints are appended by creating a new head node.
    """

    __slots__ = ("_hash", "_incremental_hash", "_length", "_seen_hashes", "constraint", "parent")

    def __init__(
        self,
        constraint: z3.BoolRef | None = None,
        parent: ConstraintChain | None = None,
    ) -> None:
        self.constraint = constraint
        self.parent = parent

        if parent is None:
            self._length = 1 if constraint is not None else 0
            self._seen_hashes: frozenset[int] = (
                frozenset({constraint.hash()}) if constraint is not None else frozenset()
            )
            h = 0x3456789A
            if constraint is not None:
                ch = constraint.hash() & 0xFFFFFFFFFFFFFFFF
                h = ((h ^ ch) * 1000000007) & 0xFFFFFFFFFFFFFFFF
            self._incremental_hash = h
        else:
            self._length = parent._length + (1 if constraint is not None else 0)
            if constraint is not None:
                ch = constraint.hash() & 0xFFFFFFFFFFFFFFFF
                self._incremental_hash = (
                    (parent._incremental_hash ^ ch) * 1000000007
                ) & 0xFFFFFFFFFFFFFFFF

                self._seen_hashes = parent._seen_hashes | {constraint.hash()}
            else:
                self._incremental_hash = parent._incremental_hash
                self._seen_hashes = parent._seen_hashes

        self._hash = (self._incremental_hash ^ self._length) & 0xFFFFFFFFFFFFFFFF

    def append(self, constraint: z3.BoolRef) -> ConstraintChain:
        """Append a constraint, returning a new chain head. O(1).

        Always creates a new node. Each constraint on a path represents a
        distinct branch decision, even if structurally identical to an
        ancestor constraint.
        """
        return ConstraintChain(constraint, self)

    def to_list(self) -> list[z3.BoolRef]:
        """Materialize the chain as a Python list. O(n).

        Returns constraints in chronological order (oldest first).
        """
        result: list[z3.BoolRef] = []
        node: ConstraintChain | None = self
        while node is not None and node.constraint is not None:
            result.append(node.constraint)
            node = node.parent
        result.reverse()
        return result

    def __len__(self) -> int:
        """Return the number of constraints in the chain."""
        return self._length

    def __iter__(self) -> Iterator[z3.BoolRef]:
        """Iterate constraints in chronological order (oldest first)."""
        yield from self.to_list()

    def __reversed__(self) -> Iterator[z3.BoolRef]:
        """Iterate constraints in reverse chronological order (newest first)."""
        node: ConstraintChain | None = self
        while node is not None and node.constraint is not None:
            yield node.constraint
            node = node.parent

    def newest(self) -> z3.BoolRef | None:
        """Return the newest constraint in O(1), or None if empty."""
        return self.constraint

    def __getitem__(self, index: int | slice) -> z3.BoolRef | list[z3.BoolRef]:
        """Support subscripting and slicing."""
        constraints = self.to_list()
        return constraints[index]

    def __bool__(self) -> bool:
        """Return True if the chain is non-empty."""
        return self._length > 0

    def hash_value(self) -> int:
        """Return structural hash of the constraint chain. O(1)."""
        return self._hash

    @staticmethod
    def empty() -> ConstraintChain:
        """Create an empty constraint chain."""
        return ConstraintChain()

    @staticmethod
    def from_list(constraints: list[z3.BoolRef]) -> ConstraintChain:
        """Build a chain from a list of constraints."""
        chain = ConstraintChain()
        for c in constraints:
            chain = chain.append(c)
        return chain

    def __repr__(self) -> str:
        """Return a string representation of the constraint chain."""
        return f"ConstraintChain(length={self._length})"
