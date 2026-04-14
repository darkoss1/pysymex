from typing import List, Optional

class BranchHistoryNode:
    """
    Flyweight persistent linked list for tracking execution paths.
    Provides O(1) memory growth per branch by only storing the delta.
    """
    __slots__ = ("pc", "branch_index", "is_true_branch", "parent", "_depth", "_bitmask")

    def __init__(self, pc: int, branch_index: int, is_true_branch: bool, parent: Optional['BranchHistoryNode'] = None):
        self.pc = pc
        self.branch_index = branch_index # Unique index representing this specific branch outcome (constraint)
        self.is_true_branch = is_true_branch
        self.parent = parent
        self._depth = 1 if parent is None else parent._depth + 1
        
        # Calculate bitmask for fast UNSAT core pruning.
        # This requires the branch_index to be uniquely assigned per outcome.
        self._bitmask = (1 << branch_index)
        if parent is not None:
            self._bitmask |= parent._bitmask

    @property
    def bitmask(self) -> int:
        """Returns the bit-packed signature of the current path."""
        return self._bitmask
        
    @property
    def depth(self) -> int:
        """Returns the length of the path from root to this node."""
        return self._depth

    def to_list(self) -> List[tuple[int, bool]]:
        """
        Returns the full path as a list of (pc, is_true_branch) tuples.
        Executes in O(D) time where D is the depth of the node.
        """
        path = []
        current: Optional['BranchHistoryNode'] = self
        while current is not None:
            path.append((current.pc, current.is_true_branch))
            current = current.parent
        path.reverse()
        return path
