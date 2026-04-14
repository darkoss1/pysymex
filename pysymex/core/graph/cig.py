from typing import Dict, FrozenSet, Hashable, Set

class ConstraintInteractionGraph:
    """
    Constraint Interaction Graph (CIG) for PySyMex v2.
    Tracks variable-sharing between branch points.
    Vertices are branch PCs (Program Counters).
    Edges represent shared symbolic variables between the conditions at two PCs.
    """
    __slots__ = ("_adjacency", "_branch_vars", "_num_edges")

    def __init__(self) -> None:
        # Maps pc -> set of connected pcs
        self._adjacency: Dict[int, Set[int]] = {}
        # Maps pc -> set of normalized symbolic variables at this pc
        self._branch_vars: Dict[int, FrozenSet[Hashable]] = {}
        self._num_edges: int = 0

    def add_branch(self, pc: int, variables: FrozenSet[Hashable]) -> None:
        """
        Registers a new branch point and its associated symbolic variables.
        Incrementally builds edges to all existing branches that share at least one variable.
        O(V) worst-case insertion time, optimized via set intersection.
        """
        if pc in self._adjacency:
            return  # Branch already registered. In a real VM, we might update, but PCs are stable.
            
        self._adjacency[pc] = set()
        self._branch_vars[pc] = variables

        # Connect to existing branches if they share variables
        for other_pc, other_vars in self._branch_vars.items():
            if other_pc != pc and not variables.isdisjoint(other_vars):
                self._add_edge(pc, other_pc)

    def _add_edge(self, pc1: int, pc2: int) -> None:
        """Adds an undirected edge between two branch PCs."""
        self._adjacency[pc1].add(pc2)
        self._adjacency[pc2].add(pc1)
        self._num_edges += 1

    def get_degree(self, pc: int) -> int:
        """Returns the degree of the branch PC in the CIG."""
        return len(self._adjacency.get(pc, set()))

    def get_neighbors(self, pc: int) -> Set[int]:
        """Returns the neighbors of the branch PC."""
        return self._adjacency.get(pc, set())

    @property
    def num_vertices(self) -> int:
        return len(self._adjacency)

    @property
    def num_edges(self) -> int:
        return self._num_edges
        
    def clear(self) -> None:
        """Clears the graph."""
        self._adjacency.clear()
        self._branch_vars.clear()
        self._num_edges = 0
