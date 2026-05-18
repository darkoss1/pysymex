"""Tests for pysymex/analysis/detectors/logical/t4_interprocedural/api_contract.py."""

import dis
import z3
from pysymex.analysis.detectors.logical.base import ContradictionContext
from pysymex.analysis.detectors.logical.t4_interprocedural.api_contract import (
    ApiContractViolationRule,
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


class TestApiContractViolationRule:
    """Test suite for ApiContractViolationRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert ApiContractViolationRule is not None
        assert ApiContractViolationRule.__name__ == "ApiContractViolationRule"

    def test_matches_contract_relation_conflict(self) -> None:
        """Classify contradictory relations between contract-bearing variables."""
        api_arg = z3.Int("api_arg")
        api_result = z3.Int("api_result")
        core = [api_arg > api_result, api_result >= api_arg]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert ApiContractViolationRule().matches(ctx)

    def test_does_not_match_unrelated_relation_when_api_signal_exists(self) -> None:
        """Do not classify unrelated variable relations because another API marker exists."""
        api_contract_ok = z3.Bool("api_contract_ok")
        x = z3.Int("x")
        y = z3.Int("y")
        core = [api_contract_ok, x > y, y >= x]
        ctx = ContradictionContext(core=core, branch_cond=core[-1], path_constraints=core[:-1])
        assert not ApiContractViolationRule().matches(ctx)
