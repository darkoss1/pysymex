"""Tests for pysymex/analysis/detectors/logical/t1_local/arithmetic.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t1_local.arithmetic import ArithmeticImpossibilityRule


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


class TestArithmeticImpossibilityRule:
    """Test suite for ArithmeticImpossibilityRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert ArithmeticImpossibilityRule is not None
        assert ArithmeticImpossibilityRule.__name__ == "ArithmeticImpossibilityRule"

    def test_matches_integer_only_linear_impossibility(self) -> None:
        """Classify equations impossible over integers but satisfiable over reals."""
        x = z3.Int("x")
        core = [2 * x == 1]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=[])
        assert ArithmeticImpossibilityRule().matches(ctx)

    def test_does_not_match_satisfiable_arithmetic_equality(self) -> None:
        """Do not classify arithmetic equalities that have integer models."""
        x = z3.Int("x")
        core = [x + 1 == 2]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=[])
        assert not ArithmeticImpossibilityRule().matches(ctx)
