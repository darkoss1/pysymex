"""Tests for pysymex/analysis/detectors/logical/t1_local/modular.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t1_local.modular import ModularContradictionRule


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


class TestModularContradictionRule:
    """Test suite for ModularContradictionRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert ModularContradictionRule is not None
        assert ModularContradictionRule.__name__ == "ModularContradictionRule"

    def test_matches_conflicting_remainders_for_same_modulus(self) -> None:
        """Classify only explicit same-variable modulo remainder conflicts."""
        x = z3.Int("x")
        core = [x % 3 == 1, x % 3 == 2]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert ModularContradictionRule().matches(ctx)

    def test_does_not_match_single_modulo_fact(self) -> None:
        """A modulo operator alone is not a contradiction."""
        x = z3.Int("x")
        core = [x % 3 == 1]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=[])
        assert not ModularContradictionRule().matches(ctx)
