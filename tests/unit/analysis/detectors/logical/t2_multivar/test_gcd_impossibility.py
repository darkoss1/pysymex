"""Tests for pysymex/analysis/detectors/logical/t2_multivar/gcd_impossibility.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t2_multivar.gcd_impossibility import GcdImpossibilityRule


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


class TestGcdImpossibilityRule:
    """Test suite for GcdImpossibilityRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert GcdImpossibilityRule is not None
        assert GcdImpossibilityRule.__name__ == "GcdImpossibilityRule"

    def test_matches_conflicting_modulo_remainders(self) -> None:
        """Classify explicit same-modulus remainder conflicts."""
        x = z3.Int("x")
        core = [x % 4 == 1, x % 4 == 3]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert GcdImpossibilityRule().matches(ctx)

    def test_does_not_match_unrelated_modulo_expression(self) -> None:
        """Modulo presence alone is not enough for a GCD classification."""
        x = z3.Int("x")
        y = z3.Int("y")
        core = [x % 4 == 1, y % 4 == 3]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not GcdImpossibilityRule().matches(ctx)
