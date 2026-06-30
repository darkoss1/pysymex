from __future__ import annotations

from collections.abc import Iterable
from typing import cast

import z3

from pysymex._internal.contracts.ir.evidence import TheoryFeature
from pysymex._internal.contracts.ir.obligations import QueryKind
from pysymex._internal.contracts.solver.query import ContractQuery, check_contract_query
from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.core.solver.engine.results import SolverResult


class _UnknownSolver:
    """Solver test double that preserves UNKNOWN results."""

    calls: int

    def __init__(self) -> None:
        self.calls = 0

    def check_sat_result(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        self.calls += 1
        return SolverResult.unknown()

    def check_sat_cached(
        self,
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        _ = constraints
        _ = known_sat_prefix_len
        return SolverResult.unknown()

    def check(
        self,
        *assumptions: z3.BoolRef,
        need_model: bool = True,
    ) -> SolverResult:
        return SolverResult.unknown()

    def push(self) -> None:
        return None

    def pop(self) -> None:
        return None

    def add(self, *constraints: z3.BoolRef) -> None:
        return None

    def reset(self) -> None:
        return None

    def path_may_be_feasible(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        return True

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        return None

    def get_stats(self) -> dict[str, object]:
        return {}

    def constraint_optimizer(self) -> object:
        return object()

    def set_deadline(self, deadline_time: float | None) -> None:
        return None


def test_contract_query_materializes_constraints() -> None:
    constraint = z3.BoolVal(True)

    query = ContractQuery.from_constraints(
        [constraint],
        query_kind=QueryKind.ASSERTION,
        known_sat_prefix_len=1,
    )

    assert query.constraints == (constraint,)
    assert query.known_sat_prefix_len == 1
    assert query.query_kind is QueryKind.ASSERTION
    assert query.use_cache is False


def test_contract_query_uses_solver_result_semantics() -> None:
    x = z3.Int("x")
    query = ContractQuery.from_constraints(
        [x > 0, x <= 0],
        query_kind=QueryKind.POSTCONDITION,
        need_model=True,
    )

    result = check_contract_query(query)

    assert result.is_unsat is True
    assert result.is_sat is False
    assert result.is_unknown is False
    assert query.need_model is True
    assert TheoryFeature.INTEGER in query.theory_profile
    assert TheoryFeature.BOOL in query.theory_profile


def test_contract_query_extracts_model_only_when_requested() -> None:
    x = z3.Int("model_x")

    without_model = check_contract_query(
        ContractQuery.from_constraints(
            [x > 0],
            query_kind=QueryKind.POSTCONDITION,
            need_model=False,
        )
    )
    with_model = check_contract_query(
        ContractQuery.from_constraints(
            [x > 0],
            query_kind=QueryKind.POSTCONDITION,
            need_model=True,
        )
    )

    assert without_model.is_sat is True
    assert without_model.model is None
    assert with_model.is_sat is True
    assert with_model.model is not None


def test_contract_query_profiles_quantifiers_without_ast_application_crash() -> None:
    x = z3.Int("x")
    quantified = cast("z3.BoolRef", z3.ForAll([x], x >= 0))

    query = ContractQuery.from_constraints(
        [z3.Not(quantified)],
        query_kind=QueryKind.POSTCONDITION,
    )

    assert TheoryFeature.QUANTIFIER in query.theory_profile
    assert TheoryFeature.INTEGER in query.theory_profile


def test_contract_query_preserves_solver_unknown() -> None:
    fake_solver = _UnknownSolver()
    token = SolverContext.active.set(fake_solver)
    try:
        query = ContractQuery.from_constraints(
            [z3.Bool("flag")],
            query_kind=QueryKind.ASSERTION,
        )
        result = check_contract_query(query)
    finally:
        SolverContext.active.reset(token)

    assert fake_solver.calls == 1
    assert result.is_unknown is True
    assert result.is_sat is False
    assert result.is_unsat is False
