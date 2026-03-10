"""Copy-on-Write data structures for pysymex.

Provides efficient state forking via copy-on-write semantics:
- CowDict: Dictionary that shares backing store until mutation
- CowSet: Set that shares backing store until mutation
- ConstraintChain: Persistent linked list for O(1) constraint fork
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Generic, TypeVar

import z3

K = TypeVar("K")
V = TypeVar("V")


class CowDict(Generic[K, V]):
    """Copy-on-Write dictionary with incremental hashing.

    Shares the backing dict between forks until a mutation occurs.
    Maintains a rolling hash of its contents for O(1) deduplication.
    """

    __slots__ = ("_data", "_hash", "_shared")

    def __init__(self, data: dict[K, V] | None = None, *, shared: bool = False) -> None:
        self._data: dict[K, V] = data if data is not None else {}
        self._shared = shared
        self._hash: int | None = None

    def _ensure_writable(self) -> None:
        """Copy the backing dict if shared."""
        if self._shared:
            self._data = dict(self._data)
            self._shared = False

    def __getitem__(self, key: K) -> V:
        return self._data[key]

    def __contains__(self, key: object) -> bool:
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self) -> Iterator[K]:
        return iter(self._data)

    def __repr__(self) -> str:
        return f"CowDict({self._data!r}, shared={self._shared})"

    def _safe_hash(self, obj: object) -> int:
        """Compute a stable hash for a value, avoiding id() for symbolic types.

        This is critical for state deduplication. We prioritize deterministic
        hashing over object identity to allow merging of equivalent symbolic states.
        """
        try:
            return hash(obj)
        except TypeError:
            if hasattr(obj, "hash_value") and callable(obj.hash_value):
                return obj.hash_value()

            if hasattr(obj, "to_z3") and callable(obj.to_z3):
                z3_ast = obj.to_z3()
                if hasattr(z3_ast, "hash") and callable(z3_ast.hash):
                    return z3_ast.hash()
                return hash(str(z3_ast))

            return 0

    def hash_value(self) -> int:
        """Compute/return content-based hash. O(N) first time, then O(1).

        Uses an order-sensitive polynomial rolling hash (keys sorted by
        repr for determinism) to avoid XOR-commutativity collisions (BUG-001).
        Previously, {x:10, y:20} and {x:20, y:10} produced identical hashes.
        """
        if self._hash is not None:
            return self._hash
        h = 0x345678
        for k in sorted(self._data.keys(), key=repr):
            v = self._data[k]
            h = h * 1000003 ^ self._safe_hash(k)
            h = h * 1000003 ^ self._safe_hash(v)
        self._hash = h
        return h

    def __setitem__(self, key: K, value: V) -> None:
        self._ensure_writable()
        # Invalidate the cached hash on any mutation; recompute lazily on next
        # hash_value() call.  Incremental order-sensitive updates are complex
        # and error-prone, so we just invalidate.
        self._hash = None
        self._data[key] = value

    def __delitem__(self, key: K) -> None:
        if key in self._data:
            self._ensure_writable()
            self._hash = None
            del self._data[key]

    def get(self, key: K, default: V | None = None) -> V | None:
        """Get value by key with optional default."""
        return self._data.get(key, default)

    def keys(self):
        """Return dict keys."""
        return self._data.keys()

    def values(self):
        """Return dict values."""
        return self._data.values()

    def items(self):
        """Return dict items."""
        return self._data.items()

    def setdefault(self, key: K, default: V | None = None) -> V | None:
        """Set default value for key."""
        if key not in self._data and default is not None:
            self[key] = default
        return self._data.get(key)

    def update(self, other: dict[K, V] | CowDict[K, V]) -> None:
        """Update with another dict."""
        self._ensure_writable()
        if isinstance(other, CowDict):
            self._data.update(other._data)
        else:
            self._data.update(other)
        self._hash = None

    def pop(self, key: K, *args: V) -> V:
        """Remove and return value for key."""
        self._ensure_writable()
        self._hash = None
        return self._data.pop(key, *args)

    def cow_fork(self) -> CowDict[K, V]:
        """Create a copy-on-write fork. O(1) operation."""
        self._shared = True
        new_copy = CowDict(self._data, shared=True)
        new_copy._hash = self._hash
        return new_copy

    def copy(self) -> CowDict[K, V]:
        """Return a shallow copy (uses CoW under the hood)."""
        return self.cow_fork()

    def to_dict(self) -> dict[K, V]:
        """Return a plain dict copy of the data."""
        return dict(self._data)


class CowSet:
    """Copy-on-Write set with caching hash."""

    __slots__ = ("_data", "_hash", "_shared")

    def __init__(self, data: set[int] | None = None, *, shared: bool = False) -> None:
        self._data: set[int] = data if data is not None else set()
        self._shared = shared
        self._hash: int | None = None

    def _ensure_writable(self) -> None:
        if self._shared:
            self._data = set(self._data)
            self._shared = False

    def add(self, item: int) -> None:
        if item not in self._data:
            self._ensure_writable()
            if self._hash is not None:
                self._hash ^= hash(item + 1)  # BUG-002: use item+1 so hash(0) != 0
            self._data.add(item)

    def discard(self, item: int) -> None:
        if item in self._data:
            self._ensure_writable()
            if self._hash is not None:
                self._hash ^= hash(item + 1)  # BUG-002: keep consistent with add()
            self._data.discard(item)

    def __contains__(self, item: object) -> bool:
        return item in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self) -> Iterator[int]:
        return iter(self._data)

    def hash_value(self) -> int:
        """Content hash for the set.

        Uses hash(item + 1) instead of hash(item) to avoid the BUG-002
        problem where hash(0) == 0 makes PC=0 invisible to XOR accumulation.
        """
        if self._hash is not None:
            return self._hash
        h = 0
        for item in self._data:
            h ^= hash(item + 1)
        self._hash = h
        return h

    def cow_fork(self) -> CowSet:
        """Create a copy-on-write fork. O(1) operation."""
        self._shared = True
        new_copy = CowSet(self._data, shared=True)
        new_copy._hash = self._hash
        return new_copy

    def to_set(self) -> set[int]:
        """Return a plain set copy."""
        return set(self._data)


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
            h = 0x345678
            if constraint is not None:
                h = (h ^ constraint.hash()) * 1000003
            self._incremental_hash = h
        else:
            self._length = parent._length + (1 if constraint is not None else 0)
            if constraint is not None:
                mult = 1000003 + (self._length - 1) * 82520
                self._incremental_hash = (parent._incremental_hash ^ constraint.hash()) * mult
                # BUG-006 fix: track all constraint hashes, not just immediate parent
                self._seen_hashes = parent._seen_hashes | {constraint.hash()}
            else:
                self._incremental_hash = parent._incremental_hash
                self._seen_hashes = parent._seen_hashes

        self._hash = self._incremental_hash ^ self._length

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
        return self._length

    def __iter__(self) -> Iterator[z3.BoolRef]:
        """Iterate constraints in reverse chronological order (newest first)."""
        node: ConstraintChain | None = self
        while node is not None and node.constraint is not None:
            yield node.constraint
            node = node.parent

    def __getitem__(self, index: int | slice) -> z3.BoolRef | list[z3.BoolRef]:
        """Support subscripting and slicing."""
        constraints = self.to_list()
        return constraints[index]

    def __bool__(self) -> bool:
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
        return f"ConstraintChain(length={self._length})"
