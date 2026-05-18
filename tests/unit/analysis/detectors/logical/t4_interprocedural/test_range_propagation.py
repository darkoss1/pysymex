"""Tests for pysymex/analysis/detectors/logical/t4_interprocedural/range_propagation.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t4_interprocedural.range_propagation import (
    NumericRangePropagationRule,
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


class TestNumericRangePropagationRule:
    """Test suite for NumericRangePropagationRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert NumericRangePropagationRule is not None
        assert NumericRangePropagationRule.__name__ == "NumericRangePropagationRule"

    def test_matches_interprocedural_relation_conflict(self) -> None:
        """Classify contradictory propagated ranges between interprocedural variables."""
        caller_arg = z3.Int("caller_arg")
        callee_result = z3.Int("callee_result")
        core = [caller_arg < callee_result, callee_result <= caller_arg]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert NumericRangePropagationRule().matches(ctx)

    def test_does_not_match_unrelated_relation_when_interproc_signal_exists(self) -> None:
        """Do not classify unrelated variable relations because another interproc marker exists."""
        caller_arg = z3.Int("caller_arg")
        x = z3.Int("x")
        y = z3.Int("y")
        core = [caller_arg >= 0, x < y, y <= x]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not NumericRangePropagationRule().matches(ctx)
