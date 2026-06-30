import z3

from pysymex._internal.core.state.branches import BranchChain, BranchRecord


class TestBranchRecord:
    """Test suite for BranchRecord."""

    def test_initialization(self) -> None:
        """Scenario: branch record stores pc/condition/decision fields."""
        rec = BranchRecord(1, z3.BoolVal(True), True)
        assert rec.pc == 1


class TestBranchChain:
    """Test suite for BranchChain."""

    def test_append(self) -> None:
        """Scenario: append one record to empty chain; expected length one."""
        chain = BranchChain.empty()
        chain = chain.append(BranchRecord(1, z3.BoolVal(True), True))
        assert len(chain) == 1

    def test_to_list(self) -> None:
        """Scenario: convert chain with one record; expected one-item list."""
        rec = BranchRecord(1, z3.BoolVal(True), True)
        chain = BranchChain.empty().append(rec)
        assert chain.to_list() == [rec]

    def test_empty(self) -> None:
        """Scenario: empty chain factory; expected zero length."""
        assert len(BranchChain.empty()) == 0
