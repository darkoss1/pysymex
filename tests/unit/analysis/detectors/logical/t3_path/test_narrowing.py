"""Tests for pysymex/analysis/detectors/logical/t3_path/narrowing.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t3_path.narrowing import NarrowingContradictionRule


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


class TestNarrowingContradictionRule:
    """Test suite for NarrowingContradictionRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert NarrowingContradictionRule is not None
        assert NarrowingContradictionRule.__name__ == "NarrowingContradictionRule"

    def test_matches_inconsistent_narrowed_bounds(self) -> None:
        """Classify contradictions introduced by multiple narrowing facts."""
        x = z3.Int("x")
        core = [x >= 0, x <= 10, x > 10]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert NarrowingContradictionRule().matches(ctx)

    def test_does_not_match_consistent_narrowing(self) -> None:
        """Do not classify compatible narrowing facts."""
        x = z3.Int("x")
        core = [x >= 0, x <= 10, x > 3]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not NarrowingContradictionRule().matches(ctx)
