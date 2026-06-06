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

"""Persistent path-constraint chain for forked execution state."""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterator

import z3

from pysymex.core.solver.constraints.theory import is_bitvector_smt_theory


class ConstraintChain:
    """Persistent linked list for recorded Z3 path constraints.

    Forking is O(1) because parent and child may retain the same chain head.
    New constraints are appended by creating a new head node.

    Limitations:
        This structure stores expressions and compact hash metadata; it does
        not query satisfiability or prove path equivalence.
    """

    __slots__ = (
        "_hash",
        "_has_bitvector_smt_theory",
        "_incremental_hash",
        "_length",
        "_constraint_hash",
        "_sorted_constraint_hashes",
        "constraint",
        "parent",
    )

    def __init__(
        self,
        constraint: z3.BoolRef | None = None,
        parent: ConstraintChain | None = None,
    ) -> None:
        """Initialize a chain head and its cached structural summaries."""
        self.constraint = constraint
        self.parent = parent
        self._constraint_hash = (
            constraint.hash() & 0xFFFFFFFFFFFFFFFF if constraint is not None else None
        )
        self._sorted_constraint_hashes: tuple[int, ...] | None = None

        if parent is None:
            self._length = 1 if constraint is not None else 0
            self._has_bitvector_smt_theory = bool(
                constraint is not None and is_bitvector_smt_theory(constraint)
            )
            h = 0x3456789A
            if self._constraint_hash is not None:
                h = ((h ^ self._constraint_hash) * 1000000007) & 0xFFFFFFFFFFFFFFFF
            self._incremental_hash = h
        else:
            self._length = parent._length + (1 if constraint is not None else 0)
            if constraint is not None and self._constraint_hash is not None:
                self._incremental_hash = (
                    (parent._incremental_hash ^ self._constraint_hash) * 1000000007
                ) & 0xFFFFFFFFFFFFFFFF
                self._has_bitvector_smt_theory = (
                    parent._has_bitvector_smt_theory or is_bitvector_smt_theory(constraint)
                )
            else:
                self._incremental_hash = parent._incremental_hash
                self._has_bitvector_smt_theory = parent._has_bitvector_smt_theory

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

    def __getitem__(self, index: int | slice) -> z3.BoolRef | list[z3.BoolRef]:
        """Support subscripting and slicing."""
        constraints = self.to_list()
        return constraints[index]

    def __bool__(self) -> bool:
        """Return True if the chain is non-empty."""
        return self._length > 0

    def hash_value(self) -> int:
        """Return the cached Z3-hash-based chain summary in O(1)."""
        return self._hash

    def sorted_constraint_hashes(self) -> tuple[int, ...]:
        """Return sorted Z3 AST hashes for exact set-style frontier summaries."""
        if self._sorted_constraint_hashes is not None:
            return self._sorted_constraint_hashes
        if self.constraint is None:
            self._sorted_constraint_hashes = ()
            return self._sorted_constraint_hashes

        constraint_hash = self._constraint_hash
        if constraint_hash is None:
            self._sorted_constraint_hashes = ()
            return self._sorted_constraint_hashes
        if self.parent is None:
            self._sorted_constraint_hashes = (constraint_hash,)
            return self._sorted_constraint_hashes

        parent_hashes = self.parent.sorted_constraint_hashes()
        insert_at = bisect_right(parent_hashes, constraint_hash)
        self._sorted_constraint_hashes = (
            parent_hashes[:insert_at] + (constraint_hash,) + parent_hashes[insert_at:]
        )
        return self._sorted_constraint_hashes

    def has_bitvector_smt_theory(self) -> bool:
        """Return whether any recorded constraint contains bit-vector SMT terms."""
        return self._has_bitvector_smt_theory

    @staticmethod
    def empty() -> ConstraintChain:
        """Create an empty constraint chain."""
        return ConstraintChain()

    @staticmethod
    def from_list(constraints: list[z3.BoolRef]) -> ConstraintChain:
        """Build a chain from a list of constraints."""
        chain = ConstraintChain()
        for constraint in constraints:
            chain = chain.append(constraint)
        return chain

    def __repr__(self) -> str:
        """Return a string representation of the constraint chain."""
        return f"ConstraintChain(length={self._length})"
