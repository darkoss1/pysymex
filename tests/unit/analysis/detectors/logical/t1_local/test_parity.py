"""Tests for pysymex/analysis/detectors/logical/t1_local/parity.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t1_local.parity import ParityContradictionRule


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


class TestParityContradictionRule:
    """Test suite for ParityContradictionRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert ParityContradictionRule is not None
        assert ParityContradictionRule.__name__ == "ParityContradictionRule"

    def test_matches_conflicting_even_odd_remainders(self) -> None:
        """Classify explicit parity conflicts for the same variable."""
        x = z3.Int("x")
        core = [x % 2 == 0, x % 2 == 1]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert ParityContradictionRule().matches(ctx)

    def test_does_not_match_single_parity_fact(self) -> None:
        """Modulo by two alone is not a contradiction."""
        x = z3.Int("x")
        core = [x % 2 == 0]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=[])
        assert not ParityContradictionRule().matches(ctx)
