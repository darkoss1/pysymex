"""Tests for pysymex/analysis/detectors/logical/t1_local/equality.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t1_local.equality import EqualityContradictionRule


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


class TestEqualityContradictionRule:
    """Test suite for EqualityContradictionRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert EqualityContradictionRule is not None
        assert EqualityContradictionRule.__name__ == "EqualityContradictionRule"

    def test_matches_conflicting_equalities(self) -> None:
        """Classify explicit same-variable equality conflicts."""
        x = z3.Int("x")
        core = [x == 1, x == 2]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert EqualityContradictionRule().matches(ctx)

    def test_does_not_match_repeated_same_equality(self) -> None:
        """Repeated identical equality facts are not contradictions."""
        x = z3.Int("x")
        core = [x == 1, x == 1]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not EqualityContradictionRule().matches(ctx)
