from __future__ import annotations

import z3

from pysymex.contracts import assigns, assumes, ensures, pure, requires
from pysymex.contracts.frontend.native import (
    NATIVE_FRONTEND,
    native_clause_ir_from_contract,
    native_function_clause_irs,
)
from pysymex.contracts.ir.evidence import SolverStatus
from pysymex.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex.contracts.obligations import build_contract_evidence
from pysymex.contracts.types import Contract, ContractKind, Severity, VerificationResult


def test_native_frontend_lowers_registered_clauses_to_clause_ir() -> None:
    @assumes("x < 10")
    @ensures("result() >= x")
    @requires("x >= 0")
    def target(x: int) -> int:
        return x

    clauses = native_function_clause_irs(target)

    assert [(clause.kind, clause.condition, clause.frontend) for clause in clauses] == [
        (ContractKind.REQUIRES, "x >= 0", NATIVE_FRONTEND),
        (ContractKind.ASSUMES, "x < 10", NATIVE_FRONTEND),
        (ContractKind.ENSURES, "result() >= x", NATIVE_FRONTEND),
    ]
    assert all(clause.target.name == "target" for clause in clauses)
    assert all(clause.clause_id[-1] == NATIVE_FRONTEND for clause in clauses)


def test_native_frontend_lowers_effect_declarations_to_clause_ir() -> None:
    @assigns("self.y", "self.x")
    def mutates(self: object) -> None:
        _ = self

    @pure
    def query() -> int:
        return 1

    assigns_clause = native_function_clause_irs(mutates)[0]
    pure_clause = native_function_clause_irs(query)[0]

    assert assigns_clause.kind is ContractKind.ASSIGNS
    assert assigns_clause.condition == "assigns(self.x, self.y)"
    assert pure_clause.kind is ContractKind.PURE
    assert pure_clause.condition == "pure"


def test_native_frontend_lowers_explicit_contract_without_solver_work() -> None:
    def target(x: int) -> int:
        return x

    clause = Contract(
        kind=ContractKind.REQUIRES,
        predicate="x > 0",
        message="positive",
        severity=Severity.WARNING,
        line_number=7,
    )

    clause_ir = native_clause_ir_from_contract(clause, target)

    assert clause_ir.kind is ContractKind.REQUIRES
    assert clause_ir.predicate == "x > 0"
    assert clause_ir.severity is Severity.WARNING
    assert clause_ir.line_number == 7
    assert (
        clause_ir.target.qualname
        == "test_native_frontend_lowers_explicit_contract_without_solver_work.<locals>.target"
    )


def test_obligation_builder_uses_native_frontend_clause_ir() -> None:
    @requires("x > 0")
    def target(x: int) -> int:
        return x

    clause = native_function_clause_irs(target)[0]
    condition = z3.Int("x") > 0
    evidence = build_contract_evidence(
        Contract(
            kind=ContractKind.REQUIRES,
            predicate=clause.predicate,
            message=clause.message,
            line_number=clause.line_number,
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
