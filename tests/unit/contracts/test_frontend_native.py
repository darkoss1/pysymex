from __future__ import annotations

import z3

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.frontend.native import (
    NATIVE_FRONTEND,
    native_clause_ir_from_contract,
)
from pysymex._internal.contracts.ir.evidence import SolverStatus
from pysymex._internal.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex._internal.contracts.obligations.evidence import build_contract_evidence
from pysymex._internal.contracts.types import Contract, ContractSeverity
from pysymex.contracts import ContractKind


def test_native_frontend_lowers_explicit_contract_without_solver_work() -> None:
    def target(x: int) -> int:
        return x

    clause = Contract(
        kind=ContractKind.REQUIRES,
        predicate="x > 0",
        message="positive",
        severity=ContractSeverity.WARNING,
        line_number=7,
    )

    clause_ir = native_clause_ir_from_contract(clause, target)

    assert clause_ir.kind is ContractKind.REQUIRES
    assert clause_ir.predicate == "x > 0"
    assert clause_ir.severity is ContractSeverity.WARNING
    assert clause_ir.line_number == 7
    assert (
        clause_ir.target.qualname
        == "test_native_frontend_lowers_explicit_contract_without_solver_work.<locals>.target"
    )


def test_obligation_builder_uses_native_frontend_clause_ir() -> None:
    def target(x: int) -> int:
        return x

    clause = Contract(
        kind=ContractKind.REQUIRES,
        predicate="x > 0",
        message="requires x > 0",
    )
    clause_ir = native_clause_ir_from_contract(clause, target)
    condition = z3.Int("x") > 0
    evidence = build_contract_evidence(
        Contract(
            kind=ContractKind.REQUIRES,
            predicate=clause_ir.predicate,
            message=clause_ir.message,
            line_number=clause_ir.line_number,
        ),
        target,
        hook=ObligationHook.CALL_SITE,
        query_kind=QueryKind.CALL_PRECONDITION,
        pc=3,
        status=VerificationResult.VERIFIED,
        solver_status=SolverStatus.UNSAT,
        message="verified",
        formula=condition,
    )

    assert evidence.obligation.clause.frontend == NATIVE_FRONTEND
