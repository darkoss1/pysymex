"""Tests for pysymex/analysis/detectors/logical/t3_path/post_assignment.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t3_path.post_assignment import (
    PostAssignmentContradictionRule,
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


class TestPostAssignmentContradictionRule:
    """Test suite for PostAssignmentContradictionRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert PostAssignmentContradictionRule is not None
        assert PostAssignmentContradictionRule.__name__ == "PostAssignmentContradictionRule"

    def test_matches_assignment_outside_known_bounds(self) -> None:
        """Classify exact assignment facts that violate known bounds."""
        value = z3.Int("value")
        core = [value == 3, value > 3]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert PostAssignmentContradictionRule().matches(ctx)

    def test_does_not_match_assignment_inside_known_bounds(self) -> None:
        """Do not classify compatible post-assignment bounds."""
        value = z3.Int("value")
        core = [value == 3, value >= 0, value <= 10]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not PostAssignmentContradictionRule().matches(ctx)
