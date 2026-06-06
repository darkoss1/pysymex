from __future__ import annotations

import pytest

from pysymex.contracts.contract_enums import ContractKind
from pysymex.contracts.frontend.common import UnsupportedFrontendSyntax
from pysymex.contracts.frontend.deal import DEAL_FRONTEND, deal_clause_irs_from_source


def test_deal_frontend_lowers_pre_and_post_lambdas() -> None:
    source = """
import deal

@deal.post(lambda result: result >= 0, message="non-negative")
@deal.pre(lambda x: x > 0)
def target(x):
    return x
"""

    clauses = deal_clause_irs_from_source(source, module="sample")

    assert [(clause.kind, clause.condition, clause.frontend) for clause in clauses] == [
        (ContractKind.ENSURES, "result >= 0", DEAL_FRONTEND),
        (ContractKind.REQUIRES, "x > 0", DEAL_FRONTEND),
    ]
    assert clauses[0].message == "non-negative"
    assert all(clause.target.qualname == "target" for clause in clauses)


def test_deal_frontend_lowers_class_invariant_lambda() -> None:
    source = """
import deal

@deal.inv(lambda self: self.balance >= 0)
class Account:
    pass
"""

    clause = deal_clause_irs_from_source(source, module="sample")[0]

    assert clause.kind is ContractKind.INVARIANT
    assert clause.condition == "self.balance >= 0"
    assert clause.target.name == "Account"
    assert clause.target.qualname == "Account"


def test_deal_frontend_rejects_helper_function_conditions() -> None:
    source = """
import deal

def positive(x):
    return x > 0

@deal.pre(positive)
def target(x):
    return x
"""

    with pytest.raises(UnsupportedFrontendSyntax, match="inline lambda") as exc_info:
        deal_clause_irs_from_source(source)

    assert exc_info.value.frontend == DEAL_FRONTEND


def test_deal_frontend_rejects_unsupported_decorator_sections() -> None:
    source = """
import deal

@deal.raises(ValueError)
def target(x):
    return x
"""

    with pytest.raises(UnsupportedFrontendSyntax, match="deal.raises") as exc_info:
        deal_clause_irs_from_source(source)

    assert exc_info.value.frontend == DEAL_FRONTEND


def test_deal_frontend_rejects_extra_positional_arguments() -> None:
    source = """
import deal

@deal.pre(lambda x: x > 0, "positive", "unexpected")
def target(x):
    return x
"""

    with pytest.raises(UnsupportedFrontendSyntax, match="only a lambda") as exc_info:
        deal_clause_irs_from_source(source)

    assert exc_info.value.frontend == DEAL_FRONTEND


def test_deal_frontend_rejects_wrong_decorator_target() -> None:
    source = """
import deal

@deal.pre(lambda self: True)
class Account:
    pass
"""

    with pytest.raises(UnsupportedFrontendSyntax, match="functions only"):
        deal_clause_irs_from_source(source)


def test_deal_frontend_rejects_invalid_source() -> None:
    with pytest.raises(UnsupportedFrontendSyntax, match="could not be parsed") as exc_info:
        deal_clause_irs_from_source("def broken(:")

    assert exc_info.value.frontend == DEAL_FRONTEND
