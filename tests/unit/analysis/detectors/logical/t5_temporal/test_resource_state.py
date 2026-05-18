"""Tests for pysymex/analysis/detectors/logical/t5_temporal/resource_state.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t5_temporal.resource_state import (
    ResourceStateContradictionRule,
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


class TestResourceStateContradictionRule:
    """Test suite for ResourceStateContradictionRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert ResourceStateContradictionRule is not None
        assert ResourceStateContradictionRule.__name__ == "ResourceStateContradictionRule"

    def test_matches_same_resource_boolean_conflict(self) -> None:
        """Classify only same-resource incompatible boolean facts."""
        file_open = z3.Bool("file_open")
        core = [file_open, z3.Not(file_open)]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert ResourceStateContradictionRule().matches(ctx)

    def test_does_not_match_distinct_open_and_closed_names(self) -> None:
        """Distinct resource state names are not contradictory without equality/alias proof."""
        file_open = z3.Bool("file_open")
        file_closed = z3.Bool("file_closed")
        core = [file_open, file_closed]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not ResourceStateContradictionRule().matches(ctx)
