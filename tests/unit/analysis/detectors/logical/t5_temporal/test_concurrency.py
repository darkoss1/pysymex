"""Tests for pysymex/analysis/detectors/logical/t5_temporal/concurrency.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t5_temporal.concurrency import ConcurrencyContradictionRule


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


class TestConcurrencyContradictionRule:
    """Test suite for ConcurrencyContradictionRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert ConcurrencyContradictionRule is not None
        assert ConcurrencyContradictionRule.__name__ == "ConcurrencyContradictionRule"

    def test_matches_same_lock_boolean_conflict(self) -> None:
        """Classify same-lock contradictory boolean facts."""
        lock_held = z3.Bool("lock_held")
        core = [lock_held, z3.Not(lock_held)]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert ConcurrencyContradictionRule().matches(ctx)

    def test_does_not_match_distinct_concurrency_markers(self) -> None:
        """Do not classify unrelated concurrency names as contradictory."""
        lock_a = z3.Bool("lock_a")
        mutex_b = z3.Bool("mutex_b")
        core = [lock_a, mutex_b]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not ConcurrencyContradictionRule().matches(ctx)
