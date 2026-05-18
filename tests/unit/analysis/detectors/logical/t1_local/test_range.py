"""Tests for pysymex/analysis/detectors/logical/t1_local/range.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t1_local.range import RangeContradictionRule


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


class TestRangeContradictionRule:
    """Test suite for RangeContradictionRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert RangeContradictionRule is not None
        assert RangeContradictionRule.__name__ == "RangeContradictionRule"

    def test_matches_inconsistent_bounds(self) -> None:
        """Classify only impossible same-variable interval bounds."""
        x = z3.Int("x")
        core = [x > 5, x <= 5]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert RangeContradictionRule().matches(ctx)

    def test_does_not_match_satisfiable_bounds(self) -> None:
        """Do not classify ordinary lower and upper bounds as contradictions."""
        x = z3.Int("x")
        core = [x > 0, x < 10]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not RangeContradictionRule().matches(ctx)
