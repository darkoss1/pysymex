"""Tests for pysymex.core.memory.branch_history."""

from pysymex.core.memory.branch_history import BranchHistoryNode


class TestBranchHistoryNode:
    def test_init_without_parent_sets_depth_one(self) -> None:
        node = BranchHistoryNode(pc=10, branch_index=0, is_true_branch=True)
        assert node.depth == 1
        assert node.pc == 10
        assert node.branch_index == 0
        assert node.is_true_branch is True

    def test_init_with_parent_increments_depth(self) -> None:
        parent = BranchHistoryNode(pc=10, branch_index=0, is_true_branch=True)
        node = BranchHistoryNode(pc=20, branch_index=1, is_true_branch=False, parent=parent)
        assert node.depth == 2

    def test_to_list_without_parent(self) -> None:
        node = BranchHistoryNode(pc=10, branch_index=0, is_true_branch=True)
        path = node.to_list()
        assert path == [(10, True)]

    def test_to_list_with_parents_returns_ordered_path(self) -> None:
        node1 = BranchHistoryNode(pc=10, branch_index=0, is_true_branch=True)
        node2 = BranchHistoryNode(pc=20, branch_index=1, is_true_branch=False, parent=node1)
        node3 = BranchHistoryNode(pc=30, branch_index=2, is_true_branch=True, parent=node2)
        path = node3.to_list()
        assert path == [(10, True), (20, False), (30, True)]
