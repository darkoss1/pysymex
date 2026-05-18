"""Tests for pysymex/analysis/detectors/logical/t5_temporal/state_impossibility.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t5_temporal.state_impossibility import (
    StateImpossibilityRule,
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


class TestStateImpossibilityRule:
    """Test suite for StateImpossibilityRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert StateImpossibilityRule is not None
        assert StateImpossibilityRule.__name__ == "StateImpossibilityRule"

    def test_matches_same_state_boolean_conflict(self) -> None:
        """Classify conflicting facts for the same state-like boolean."""
        phase_active = z3.Bool("phase_active")
        core = [phase_active, z3.Not(phase_active)]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert StateImpossibilityRule().matches(ctx)

    def test_does_not_match_distinct_state_names(self) -> None:
        """Distinct state names are not contradictory without same-symbol proof."""
        state_open = z3.Bool("state_open")
        state_closed = z3.Bool("state_closed")
        core = [state_open, state_closed]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not StateImpossibilityRule().matches(ctx)
