"""Copy-on-Write data structures for pysymex.

Provides efficient state forking via copy-on-write semantics:
- CowDict: Dictionary that shares backing store until mutation
- CowSet: Set that shares backing store until mutation
- ConstraintChain: Persistent linked list for O(1) constraint fork
"""

from __future__ import annotations


from collections.abc import Iterator

from typing import Any, TypeVar


import z3

K = TypeVar("K")

V = TypeVar("V")


class CowDict:
    """Copy-on-Write dictionary.

    Shares the backing dict between forks until a mutation occurs,
    at which point the mutating copy gets its own dict.
    """

    __slots__ = ("_data", "_shared")

    def __init__(self, data: dict[str, Any] | None = None, *, shared: bool = False) -> None:
        self._data: dict[str, Any] = data if data is not None else {}

        self._shared = shared

    def _ensure_writable(self) -> None:
        """Copy the backing dict if shared."""

        if self._shared:
            self._data = dict(self._data)

            self._shared = False

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._ensure_writable()

        self._data[key] = value

    def __delitem__(self, key: str) -> None:
        self._ensure_writable()

        del self._data[key]

    def __contains__(self, key: object) -> bool:
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __repr__(self) -> str:
        return f"CowDict({self._data!r}, shared={self._shared})"

    def get(self, key: str, default: Any = None) -> Any:
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

    def setdefault(self, key: str, default: Any = None) -> Any:
        """Set default value for key."""

        if key not in self._data:
            self._ensure_writable()

            self._data[key] = default

        return self._data[key]

    def update(self, other: dict[str, Any] | CowDict) -> None:
        """Update with another dict."""

        self._ensure_writable()

        if isinstance(other, CowDict):
            self._data.update(other._data)

        else:
            self._data.update(other)

    def pop(self, key: str, *args: Any) -> Any:
        """Remove and return value for key."""

        self._ensure_writable()

        return self._data.pop(key, *args)

    def cow_fork(self) -> CowDict:
        """Create a copy-on-write fork. O(1) operation.

        Both the original and the fork share the same backing dict.
        The first mutation on either side triggers a copy.
        """

        self._shared = True

        return CowDict(self._data, shared=True)

    def copy(self) -> CowDict:
        """Return a shallow copy (uses CoW under the hood)."""

        return self.cow_fork()

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict copy of the data."""

        return dict(self._data)


class CowSet:
    """Copy-on-Write set.

    Shares the backing set between forks until a mutation occurs.
    """

    __slots__ = ("_data", "_shared")

    def __init__(self, data: set[Any] | None = None, *, shared: bool = False) -> None:
        self._data: set[Any] = data if data is not None else set()

        self._shared = shared

    def _ensure_writable(self) -> None:
        if self._shared:
            self._data = set(self._data)

            self._shared = False

    def add(self, item: Any) -> None:
        self._ensure_writable()

        self._data.add(item)

    def discard(self, item: Any) -> None:
        self._ensure_writable()

        self._data.discard(item)

    def __contains__(self, item: object) -> bool:
        return item in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self) -> Iterator[Any]:
        return iter(self._data)

    def cow_fork(self) -> CowSet:
        """Create a copy-on-write fork. O(1) operation."""

        self._shared = True

        return CowSet(self._data, shared=True)

    def to_set(self) -> set[Any]:
        """Return a plain set copy."""

        return set(self._data)


class ConstraintChain:
    """Persistent linked list for Z3 path constraints.

    Forking is O(1) — both parent and child share the same chain.
    New constraints are appended by creating a new head node.
    """

    __slots__ = ("constraint", "parent", "_length", "_hash")

    def __init__(
        self,
        constraint: z3.BoolRef | None = None,
        parent: ConstraintChain | None = None,
    ) -> None:
        self.constraint = constraint

        self.parent = parent

        self._length = (parent._length + 1) if parent is not None and constraint is not None else 0

        self._hash: int | None = None

    def append(self, constraint: z3.BoolRef) -> ConstraintChain:
        """Append a constraint, returning a new chain head. O(1).

        The original chain is unmodified (persistent data structure).
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

    def __bool__(self) -> bool:
        return self._length > 0

    def hash_value(self) -> int:
        """Compute structural hash of the constraint chain.

        Cached after first computation.
        """

        if self._hash is not None:
            return self._hash

        from pysymex.core.constraint_hash import structural_hash

        self._hash = structural_hash(self.to_list())

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
