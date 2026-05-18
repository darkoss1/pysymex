"""Tests for pysymex/analysis/detectors/logical/t2_multivar/product_sign.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t2_multivar.product_sign import ProductSignContradictionRule


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


class TestProductSignContradictionRule:
    """Test suite for ProductSignContradictionRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert ProductSignContradictionRule is not None
        assert ProductSignContradictionRule.__name__ == "ProductSignContradictionRule"

    def test_matches_positive_product_declared_negative(self) -> None:
        """Classify only explicit product sign contradictions."""
        x = z3.Int("x")
        y = z3.Int("y")
        core = [x > 0, y > 0, x * y <= 0]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert ProductSignContradictionRule().matches(ctx)

    def test_does_not_match_unrelated_multiplication_constraints(self) -> None:
        """Do not classify arbitrary multiplication plus inequality as product-sign proof."""
        x = z3.Int("x")
        y = z3.Int("y")
        core = [x >= 0, y >= 0, x * y >= 0]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not ProductSignContradictionRule().matches(ctx)
