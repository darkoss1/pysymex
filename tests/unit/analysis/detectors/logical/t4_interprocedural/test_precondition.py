"""Tests for pysymex/analysis/detectors/logical/t4_interprocedural/precondition.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t4_interprocedural.precondition import (
    PreconditionImpossibilityRule,
)


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


class TestPreconditionImpossibilityRule:
    """Test suite for PreconditionImpossibilityRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert PreconditionImpossibilityRule is not None
        assert PreconditionImpossibilityRule.__name__ == "PreconditionImpossibilityRule"

    def test_matches_argument_bound_contradiction(self) -> None:
        """Classify inconsistent precondition bounds on argument-like symbols."""
        user_arg = z3.Int("user_arg")
        core = [user_arg >= 10, user_arg < 10]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert PreconditionImpossibilityRule().matches(ctx)

    def test_does_not_match_unrelated_bounds(self) -> None:
        """Do not classify non-argument variable contradictions as precondition issues."""
        local_value = z3.Int("local_value")
        core = [local_value >= 10, local_value < 10]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not PreconditionImpossibilityRule().matches(ctx)
