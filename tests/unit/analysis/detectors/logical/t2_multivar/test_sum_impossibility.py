"""Tests for pysymex/analysis/detectors/logical/t2_multivar/sum_impossibility.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t2_multivar.impossibility.sum import SumImpossibilityRule


def MockInstr(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    import dis

    def _dummy() -> None:
        pass

    template = next(dis.get_instructions(_dummy))
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


class TestSumImpossibilityRule:
    """Test suite for SumImpossibilityRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert SumImpossibilityRule is not None
        assert SumImpossibilityRule.__name__ == "SumImpossibilityRule"

    def test_matches_sum_below_known_lower_bound(self) -> None:
        """Classify explicit lower-bound sum contradictions."""
        x = z3.Int("x")
        y = z3.Int("y")
        core = [x >= 2, y >= 3, x + y < 5]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert SumImpossibilityRule().matches(ctx)

    def test_matches_sum_at_strict_lower_bound(self) -> None:
        """Classify sums equal to a strict lower bound as impossible."""
        x = z3.Int("x")
        y = z3.Int("y")
        core = [x > 2, y >= 3, x + y <= 5]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert SumImpossibilityRule().matches(ctx)

    def test_does_not_match_unrelated_sum_shape(self) -> None:
        """Do not classify satisfiable sum constraints by operator presence alone."""
        x = z3.Int("x")
        y = z3.Int("y")
        core = [x >= 2, y >= 3, x + y >= 5]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not SumImpossibilityRule().matches(ctx)
