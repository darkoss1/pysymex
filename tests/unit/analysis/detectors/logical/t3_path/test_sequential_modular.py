"""Tests for pysymex/analysis/detectors/logical/t3_path/sequential_modular.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t3_path.sequential_modular import SequentialModularRule


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


class TestSequentialModularRule:
    """Test suite for SequentialModularRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert SequentialModularRule is not None
        assert SequentialModularRule.__name__ == "SequentialModularRule"

    def test_matches_modulo_conflict_with_multiplicative_context(self) -> None:
        """Sequential modular classification requires conflict plus multiplication context."""
        x = z3.Int("x")
        y = z3.Int("y")
        core = [x % 5 == 1, x % 5 == 2, x * y == 10]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert SequentialModularRule().matches(ctx)

    def test_does_not_match_modulo_and_multiply_without_conflict(self) -> None:
        """Do not classify any modulo-plus-multiply expression as sequential contradiction."""
        x = z3.Int("x")
        y = z3.Int("y")
        core = [x % 5 == 1, x * y == 10]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not SequentialModularRule().matches(ctx)
