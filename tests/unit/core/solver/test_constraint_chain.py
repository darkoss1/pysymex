import z3

from pysymex.core.solver.constraints.chain import ConstraintChain


class TestConstraintChain:
    """Test suite for ConstraintChain."""

    def test_append(self) -> None:
        """Scenario: append one constraint; expected chain length one."""
        chain = ConstraintChain.empty().append(z3.Bool("c"))
        assert len(chain) == 1

    def test_to_list(self) -> None:
        """Scenario: materialize chain list; expected original constraint order."""
        constraint = z3.Bool("c")
        chain = ConstraintChain.empty().append(constraint)
        assert chain.to_list() == [constraint]

    def test_hash_value(self) -> None:
        """Scenario: chain hash query; expected integer hash."""
        chain = ConstraintChain.empty().append(z3.Bool("c"))
        assert isinstance(chain.hash_value(), int)

    def test_empty(self) -> None:
        """Scenario: empty chain evaluates false; expected boolean false."""
        assert bool(ConstraintChain.empty()) is False

    def test_from_list(self) -> None:
        """Scenario: build chain from list; expected same number of constraints."""
        constraints = [z3.Bool("a"), z3.Bool("b")]
        chain = ConstraintChain.from_list(constraints)
        assert len(chain.to_list()) == 2

    def test_has_bitvector_smt_theory_tracks_appended_constraints(self) -> None:
        """Scenario: append BitVec-backed constraint; expected chain summary is set."""
        x = z3.Int("x")
        plain_chain = ConstraintChain.empty().append(x > 0)

        bv_constraint = z3.BV2Int(z3.Int2BV(x, 64)) == 1
        bitvector_chain = plain_chain.append(bv_constraint)

        assert plain_chain.has_bitvector_smt_theory() is False
        assert bitvector_chain.has_bitvector_smt_theory() is True

    def test_has_bitvector_smt_theory_from_list(self) -> None:
        """Scenario: build from list with BitVec term; expected cached summary is set."""
        x = z3.Int("x")
        chain = ConstraintChain.from_list([x > 0, z3.BV2Int(z3.Int2BV(x, 64)) >= 0])

        assert chain.has_bitvector_smt_theory() is True
