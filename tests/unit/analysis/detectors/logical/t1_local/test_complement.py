"""Tests for pysymex/analysis/detectors/logical/t1_local/complement.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t1_local.complement import ComplementContradictionRule


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


class TestComplementContradictionRule:
    """Test suite for ComplementContradictionRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert ComplementContradictionRule is not None
        assert ComplementContradictionRule.__name__ == "ComplementContradictionRule"

    def test_matches_boolean_complement_conflict(self) -> None:
        """Classify explicit boolean complement conflicts."""
        flag = z3.Bool("flag")
        core = [flag, z3.Not(flag)]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert ComplementContradictionRule().matches(ctx)

    def test_does_not_match_single_negated_fact(self) -> None:
        """A single negated boolean fact is not a contradiction."""
        flag = z3.Bool("flag")
        core = [z3.Not(flag)]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=[])
        assert not ComplementContradictionRule().matches(ctx)
