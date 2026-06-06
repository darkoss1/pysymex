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

"""Shared disjoint-set implementation used by core graph consumers."""

from collections.abc import Hashable
from typing import Generic, TypeVar

T = TypeVar("T", bound=Hashable)


class UnionFind(Generic[T]):
    """Maintain disjoint groups with path compression and union by rank.

    Items must be registered with :meth:`make_set` before direct
    :meth:`find` calls; :meth:`union` registers either missing endpoint.
    """

    __slots__ = ("_parent", "_rank")

    def __init__(self) -> None:
        """Initialize an empty parent and rank mapping."""
        self._parent: dict[T, T] = {}
        self._rank: dict[T, int] = {}

    def make_set(self, x: T) -> None:
        """Register ``x`` as an isolated element when it is not already known."""
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0

    def find(self, x: T) -> T:
        """Return ``x``'s representative while compressing its parent path.

        Raises:
            KeyError: If ``x`` has not been registered.
        """
        # Find root
        root = x
        while self._parent[root] != root:
            root = self._parent[root]

        # Path compression
        curr = x
        while curr != root:
            nxt = self._parent[curr]
            self._parent[curr] = root
            curr = nxt

        return root

    def union(self, x: T, y: T) -> bool:
        """Join the groups containing ``x`` and ``y`` using rank.

        Returns:
            ``True`` if groups were joined, or ``False`` if already connected.

        Side Effects:
            Registers either missing endpoint before performing the union.
        """
        self.make_set(x)
        self.make_set(y)

        root_x = self.find(x)
        root_y = self.find(y)

        if root_x == root_y:
            return False

        if self._rank[root_x] < self._rank[root_y]:
            self._parent[root_x] = root_y
        elif self._rank[root_x] > self._rank[root_y]:
            self._parent[root_y] = root_x
        else:
            self._parent[root_y] = root_x
            self._rank[root_x] += 1

        return True

    def connected(self, x: T, y: T) -> bool:
        """Return whether two registered elements have the same representative.

        Raises:
            KeyError: If either element has not been registered.
        """
        return self.find(x) == self.find(y)

    def groups(self) -> dict[T, set[T]]:
        """Return disjoint sets keyed by representative, compressing paths."""
        groups: dict[T, set[T]] = {}
        for x in self._parent:
            root = self.find(x)
            groups.setdefault(root, set()).add(x)
        return groups

    def get_components(self) -> list[list[T]]:
        """Return disjoint groups as element lists, compressing paths."""
        components: dict[T, list[T]] = {}
        for x in self._parent:
            root = self.find(x)
            if root not in components:
                components[root] = []
            components[root].append(x)
        return list(components.values())

    def clear(self) -> None:
        """Remove all registered elements and rank metadata."""
        self._parent.clear()
        self._rank.clear()


__all__ = ["UnionFind"]
