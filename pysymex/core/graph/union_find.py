from typing import Dict, Generic, Hashable, List, TypeVar

T = TypeVar("T", bound=Hashable)

class UnionFind(Generic[T]):
    """
    Highly optimized Union-Find (Disjoint Set) data structure.
    Implements path compression and union by rank for amortized O(alpha(n)) time complexity.
    Designed for constraint independence optimization and dynamic clustering in PySyMex v2.
    """
    __slots__ = ("_parent", "_rank")

    def __init__(self) -> None:
        self._parent: Dict[T, T] = {}
        self._rank: Dict[T, int] = {}

    def make_set(self, x: T) -> None:
        """Initializes a new isolated set for element x."""
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0

    def find(self, x: T) -> T:
        """
        Finds the representative of the set containing x with path compression.
        Raises KeyError if x is not in any set.
        """
        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])
        return self._parent[x]

    def union(self, x: T, y: T) -> bool:
        """
        Unites the sets containing x and y using union by rank.
        Returns True if a new union was formed, False if they were already in the same set.
        Automatically creates sets for x or y if they don't exist.
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

    def get_components(self) -> List[List[T]]:
        """Returns a list of all disjoint sets (components)."""
        components: Dict[T, List[T]] = {}
        for x in self._parent:
            root = self.find(x)
            if root not in components:
                components[root] = []
            components[root].append(x)
        return list(components.values())

    def clear(self) -> None:
        """Clears all sets."""
        self._parent.clear()
        self._rank.clear()
