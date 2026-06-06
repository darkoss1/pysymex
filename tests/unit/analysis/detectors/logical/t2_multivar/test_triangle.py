"""Tests for pysymex/analysis/detectors/logical/t2_multivar/triangle.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t2_multivar.triangle import TriangleImpossibilityRule


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


class TestTriangleImpossibilityRule:
    """Test suite for TriangleImpossibilityRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert TriangleImpossibilityRule is not None
        assert TriangleImpossibilityRule.__name__ == "TriangleImpossibilityRule"

    def test_matches_three_variable_sum_below_known_lower_bound(self) -> None:
        """Classify only explicit three-variable bound contradictions."""
        x = z3.Int("x")
        y = z3.Int("y")
        z = z3.Int("z")
        core = [x >= 2, y >= 3, z >= 4, x + y + z < 9]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert TriangleImpossibilityRule().matches(ctx)

    def test_matches_three_variable_sum_at_strict_lower_bound(self) -> None:
        """Classify strict-bound three-variable sum contradictions."""
        x = z3.Int("x")
        y = z3.Int("y")
        z = z3.Int("z")
        core = [x > 2, y >= 3, z >= 4, x + y + z <= 9]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert TriangleImpossibilityRule().matches(ctx)

    def test_does_not_match_three_variable_sum_without_contradiction(self) -> None:
        """Do not classify a satisfiable triangle-shaped sum by arity alone."""
        x = z3.Int("x")
        y = z3.Int("y")
        z = z3.Int("z")
        core = [x >= 2, y >= 3, z >= 4, x + y + z >= 9]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not TriangleImpossibilityRule().matches(ctx)
