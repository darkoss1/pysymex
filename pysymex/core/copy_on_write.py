"""Copy-on-Write data structures for pysymex.

Provides efficient state forking via copy-on-write semantics:
- CowDict: Dictionary that shares backing store until mutation
- CowSet: Set that shares backing store until mutation
- ConstraintChain: Persistent linked list for O(1) constraint fork
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
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
        """Retrieve the value associated with the given key from the dictionary."""
        return self._data[key]

    def __contains__(self, key: object) -> bool:
        """Check if the given key exists in the current dictionary view."""
        return key in self._data

    def __len__(self) -> int:
        """Return the number of key-value pairs in the dictionary."""
        return len(self._data)

    def __iter__(self) -> Iterator[K]:
        """Return an iterator over the dictionary's keys."""
        return iter(self._data)

    def __repr__(self) -> str:
        return f"CowDict({self._data!r}, shared={self._shared})"

    def _safe_hash(self, obj: object) -> int:
        """Compute a stable hash for a value, avoiding id() for symbolic types.

        This is critical for state deduplication. We prioritize deterministic
        hashing over object identity to allow merging of equivalent symbolic states.
        """
        from typing import Any as _Any

        try:
            return hash(obj)
        except TypeError:
            obj_any: _Any = obj
            if hasattr(obj_any, "hash_value") and callable(obj_any.hash_value):
                return int(obj_any.hash_value())

            if hasattr(obj_any, "to_z3") and callable(obj_any.to_z3):
                z3_ast: _Any = obj_any.to_z3()
                if hasattr(z3_ast, "hash") and callable(z3_ast.hash):
                    return int(z3_ast.hash())
                return hash(str(z3_ast))

            return 0

    def hash_value(self) -> int:
        """Compute/return content-based hash. O(N) first time, then O(1).

        Uses an order-independent XOR-sum over a strongly avalanched SplitMix64
        style payload for extreme collision resistance while maintaining a strict
        64-bit boundary. This prevents Python from arbitrarily scaling the integer,
        which previously destroyed CPU cache locality on deep Execution chains.
        """
        if self._hash is not None:
            return self._hash

        h = 0
        for k, v in self._data.items():
            hk = self._safe_hash(k)
            hv = self._safe_hash(v)
            
            # Combine the pair with a strong avalanche multiplier
            pair_h = (hk ^ (hv * 1000003)) & 0xFFFFFFFFFFFFFFFF
            pair_h = (pair_h ^ (pair_h >> 30)) * 0xbf58476d1ce4e5b9 & 0xFFFFFFFFFFFFFFFF
            pair_h = (pair_h ^ (pair_h >> 27)) * 0x94d049bb133111eb & 0xFFFFFFFFFFFFFFFF
            pair_h = pair_h ^ (pair_h >> 31)
            
            # XOR sum is perfectly commutative but the avalanche makes it collision-proof
            h ^= pair_h
            
        self._hash = h & 0xFFFFFFFFFFFFFFFF
        return self._hash

    def __setitem__(self, key: K, value: V) -> None:
        """Store a key-value pair, ensuring the internal data is writable first."""
        self._ensure_writable()
        # Invalidate the cached hash on any mutation; recompute lazily on next
        # hash_value() call.  Incremental order-sensitive updates are complex
        # and error-prone, so we just invalidate.
        self._hash = None
        self._data[key] = value

    def __delitem__(self, key: K) -> None:
        """Remove a key and its value, ensuring the internal data is writable first.

        Raises:
            KeyError: If the key is not present (matching dict semantics).
        """
        if key not in self._data:
            raise KeyError(key)
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
        """Set default value for key, matching dict.setdefault semantics exactly.

        Unlike the previous implementation, this always inserts *default*
        (even when it is ``None``) if *key* is absent — matching the contract
        of the built-in ``dict.setdefault``.
        """
        if key not in self._data:
            self[key] = default  # type: ignore[assignment]
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
        """Create a private copy of the backing set if it is currently marked as shared."""
        if self._shared:
            self._data = set(self._data)
            self._shared = False

    def add(self, item: int) -> None:
        """Add an element to the set, ensuring it is writable first."""
        if item not in self._data:
            self._ensure_writable()
            # Invalidate the cached hash; recomputed lazily in hash_value().
            # Incremental XOR updates were removed because the XOR-based running
            # total was not consistent with the polynomial hash used in hash_value().
            self._hash = None
            self._data.add(item)

    def discard(self, item: int) -> None:
        """Remove an element from the set if it is a member."""
        if item in self._data:
            self._ensure_writable()
            self._hash = None
            self._data.discard(item)

    def __contains__(self, item: object) -> bool:
        """Check if an element is present in the set."""
        return item in self._data

    def __len__(self) -> int:
        """Return the number of elements in the set."""
        return len(self._data)

    def __iter__(self) -> Iterator[int]:
        """Return an iterator over the elements in the set."""
        return iter(self._data)

    def hash_value(self) -> int:
        """Content hash for the set using a 64-bit bounded order-independent hash.

        Items are avalanched and summed via XOR to ensure order-independence
        without sorting, constrained to 64-bits for CPU cache optimization.
        """
        if self._hash is not None:
            return self._hash
            
        h = 0
        for item in self._data:
            item_h = (item + 0x9E3779B9) & 0xFFFFFFFFFFFFFFFF
            item_h = (item_h ^ (item_h >> 30)) * 0xbf58476d1ce4e5b9 & 0xFFFFFFFFFFFFFFFF
            item_h = (item_h ^ (item_h >> 27)) * 0x94d049bb133111eb & 0xFFFFFFFFFFFFFFFF
            item_h = item_h ^ (item_h >> 31)
            h ^= item_h
            
        h ^= len(self._data)
        self._hash = h & 0xFFFFFFFFFFFFFFFF
        return self._hash

    def cow_fork(self) -> CowSet:
        """Create a copy-on-write fork. O(1) operation."""
        self._shared = True
        new_copy = CowSet(self._data, shared=True)
        new_copy._hash = self._hash
        return new_copy

    def to_set(self) -> set[int]:
        """Return a plain set copy."""
        return set(self._data)


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
                # 64-bit bounded rolling hash using a strong prime
                ch = constraint.hash() & 0xFFFFFFFFFFFFFFFF
                self._incremental_hash = ((parent._incremental_hash ^ ch) * 1000000007) & 0xFFFFFFFFFFFFFFFF
                # BUG-006 fix: track all constraint hashes, not just immediate parent
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
