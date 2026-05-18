"""Tests for pysymex/analysis/detectors/logical/t1_local/self_contradiction.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t1_local.self_contradiction import SelfContradictionRule


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


class TestSelfContradictionRule:
    """Test suite for SelfContradictionRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert SelfContradictionRule is not None
        assert SelfContradictionRule.__name__ == "SelfContradictionRule"

    def test_matches_explicit_self_disequality(self) -> None:
        """Classify only explicit self-disequality contradictions."""
        x = z3.Int("x")
        core = [z3.Not(x == x)]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=[])
        assert SelfContradictionRule().matches(ctx)

    def test_does_not_match_single_negated_bound(self) -> None:
        """A single negated non-self comparison is not a self-contradiction."""
        x = z3.Int("x")
        core = [z3.Not(x > 0)]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=[])
        assert not SelfContradictionRule().matches(ctx)
