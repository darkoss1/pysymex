import pytest

from pysymex.core.memory.branch_history import BranchHistoryNode

def test_branch_history_creation():
    node = BranchHistoryNode(pc=10, branch_index=0, is_true_branch=True)
    assert node.pc == 10
    assert node.branch_index == 0
    assert node.is_true_branch is True
    assert node.parent is None
    assert node.depth == 1
    assert node.bitmask == 1  # 1 << 0

def test_branch_history_chaining():
    root = BranchHistoryNode(pc=10, branch_index=0, is_true_branch=True)
    child = BranchHistoryNode(pc=20, branch_index=1, is_true_branch=False, parent=root)
    grandchild = BranchHistoryNode(pc=30, branch_index=5, is_true_branch=True, parent=child)
    
    assert grandchild.depth == 3
    assert grandchild.bitmask == (1 << 0) | (1 << 1) | (1 << 5)
    
    path = grandchild.to_list()
    assert path == [(10, True), (20, False), (30, True)]
