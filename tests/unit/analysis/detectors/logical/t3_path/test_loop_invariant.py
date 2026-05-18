"""Tests for pysymex/analysis/detectors/logical/t3_path/loop_invariant.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t3_path.loop_invariant import LoopInvariantViolationRule


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


class TestLoopInvariantViolationRule:
    """Test suite for LoopInvariantViolationRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert LoopInvariantViolationRule is not None
        assert LoopInvariantViolationRule.__name__ == "LoopInvariantViolationRule"

    def test_matches_unsat_self_referential_loop_equality(self) -> None:
        """Classify self-referential loop equalities only when unsatisfiable."""
        loop_i = z3.Int("loop_i")
        core = [loop_i == loop_i + 1]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=[])
        assert LoopInvariantViolationRule().matches(ctx)

    def test_does_not_match_satisfiable_self_referential_equality(self) -> None:
        """Do not classify satisfiable self-reference as a loop invariant violation."""
        loop_i = z3.Int("loop_i")
        core = [loop_i == 2 * loop_i]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=[])
        assert not LoopInvariantViolationRule().matches(ctx)
