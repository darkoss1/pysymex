"""Tests for pysymex/analysis/detectors/logical/t3_path/return_type.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t3_path.return_type import ReturnTypeContradictionRule


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


class TestReturnTypeContradictionRule:
    """Test suite for ReturnTypeContradictionRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert ReturnTypeContradictionRule is not None
        assert ReturnTypeContradictionRule.__name__ == "ReturnTypeContradictionRule"

    def test_matches_same_result_conflicting_true_type_markers(self) -> None:
        """Classify return type markers only with an explicit exclusivity proof."""
        result_is_int = z3.Bool("result_is_int")
        result_is_str = z3.Bool("result_is_str")
        core = [result_is_int, result_is_str, z3.Not(z3.And(result_is_int, result_is_str))]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert ReturnTypeContradictionRule().matches(ctx)

    def test_does_not_match_type_markers_without_exclusivity_proof(self) -> None:
        """Do not classify multiple type markers unless the core proves exclusivity."""
        result_is_int = z3.Bool("result_is_int")
        result_is_str = z3.Bool("result_is_str")
        core = [result_is_int, result_is_str]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not ReturnTypeContradictionRule().matches(ctx)

    def test_does_not_match_unassigned_type_marker_names(self) -> None:
        """Do not classify type-looking names without contradictory marker values."""
        result_is_int = z3.Bool("result_is_int")
        result_is_str = z3.Bool("result_is_str")
        core = [result_is_int == result_is_str]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=[])
        assert not ReturnTypeContradictionRule().matches(ctx)
