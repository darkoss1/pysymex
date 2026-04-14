from typing import List, Set

class BitPackedCoreRegistry:
    """
    Registry for storing and checking bit-packed UNSAT cores.
    Allows O(1) (per core) path pruning via fast bitwise AND operations.
    """
    __slots__ = ("_cores",)

    def __init__(self) -> None:
        self._cores: Set[int] = set()

    def add_core(self, core_indices: List[int]) -> None:
        """
        Converts a list of branch constraint indices into a bitmask
        and registers it as a known Minimum Unsatisfiable Subset (MUS).
        """
        if not core_indices:
            return

        core_mask = 0
        for idx in core_indices:
            core_mask |= (1 << idx)
        self._cores.add(core_mask)

    def is_feasible(self, path_bitmask: int) -> bool:
        """
        Checks if the given path bitmask is feasible.
        A path is INFEASIBLE if it contains all constraint indices of ANY known UNSAT core.
        Mathematically: (path_bitmask & core_mask) == core_mask -> path is dead.
        Returns True if feasible, False if structurally pruned.
        """
        # Optimization: In a real system, we might organize masks by size or use bitwise tries, 
        # but Python's set iteration over integers combined with bitwise ops is very fast.
        for core_mask in self._cores:
            if (path_bitmask & core_mask) == core_mask:
                return False
        return True
        
    @property
    def num_cores(self) -> int:
        """Returns the number of learned UNSAT cores."""
        return len(self._cores)
        
    def clear(self) -> None:
        """Clears all learned cores."""
        self._cores.clear()
