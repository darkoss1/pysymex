"""Tests for pysymex/analysis/detectors/logical/t2_multivar/antisymmetry.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t2_multivar.antisymmetry import AntisymmetryRule


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


class TestAntisymmetryRule:
    """Test suite for AntisymmetryRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert AntisymmetryRule is not None
        assert AntisymmetryRule.__name__ == "AntisymmetryRule"

    def test_matches_opposing_strict_order(self) -> None:
        """Classify opposing strict relations on the same variables."""
        x = z3.Int("x")
        y = z3.Int("y")
        core = [x > y, y >= x]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert AntisymmetryRule().matches(ctx)

    def test_does_not_match_consistent_order(self) -> None:
        """Do not classify consistent variable ordering relations."""
        x = z3.Int("x")
        y = z3.Int("y")
        core = [x > y, x >= y]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not AntisymmetryRule().matches(ctx)
