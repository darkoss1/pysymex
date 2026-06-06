from __future__ import annotations

import pytest

from pysymex.contracts.contract_enums import ContractKind
from pysymex.contracts.frontend.common import UnsupportedFrontendSyntax
from pysymex.contracts.frontend.icontract import (
    ICONTRACT_FRONTEND,
    icontract_clause_irs_from_source,
)


def test_icontract_frontend_lowers_require_and_ensure_lambdas() -> None:
    source = """
import icontract

@icontract.ensure(lambda result, x: result >= x, description="keeps value")
@icontract.require(lambda x: x > 0)
def target(x):
    return x
"""

    clauses = icontract_clause_irs_from_source(source, module="sample")

    assert [(clause.kind, clause.condition, clause.frontend) for clause in clauses] == [
        (ContractKind.ENSURES, "result >= x", ICONTRACT_FRONTEND),
        (ContractKind.REQUIRES, "x > 0", ICONTRACT_FRONTEND),
    ]
    assert clauses[0].message == "keeps value"
    assert all(clause.target.qualname == "target" for clause in clauses)


def test_icontract_frontend_lowers_class_invariant_lambda() -> None:
    source = """
import icontract

@icontract.invariant(lambda self: self.balance >= 0)
class Account:
    pass
"""

    clause = icontract_clause_irs_from_source(source, module="sample")[0]

    assert clause.kind is ContractKind.INVARIANT
    assert clause.condition == "self.balance >= 0"
    assert clause.target.name == "Account"
    assert clause.target.qualname == "Account"


def test_icontract_frontend_tracks_nested_class_qualnames() -> None:
    source = """
import icontract

class Outer:
    @icontract.invariant(lambda self: self.balance >= 0)
    class Account:
        pass
"""

    clause = icontract_clause_irs_from_source(source, module="sample")[0]

    assert clause.target.name == "Account"
    assert clause.target.qualname == "Outer.Account"


def test_icontract_frontend_rejects_helper_function_conditions() -> None:
    source = """
import icontract

def positive(x):
    return x > 0

@icontract.require(positive)
def target(x):
    return x
"""

    with pytest.raises(UnsupportedFrontendSyntax, match="inline lambda") as exc_info:
        icontract_clause_irs_from_source(source)

    assert exc_info.value.frontend == ICONTRACT_FRONTEND


def test_icontract_frontend_rejects_unsupported_keywords() -> None:
    source = """
import icontract

@icontract.require(lambda x: x > 0, enabled=True)
def target(x):
    return x
"""

    with pytest.raises(UnsupportedFrontendSyntax, match="enabled") as exc_info:
        icontract_clause_irs_from_source(source)

    assert exc_info.value.frontend == ICONTRACT_FRONTEND


def test_icontract_frontend_rejects_wrong_decorator_target() -> None:
    source = """
import icontract

@icontract.require(lambda self: True)
class Account:
    pass
"""

    with pytest.raises(UnsupportedFrontendSyntax, match="functions only"):
        icontract_clause_irs_from_source(source)


def test_icontract_frontend_rejects_invalid_source() -> None:
    with pytest.raises(UnsupportedFrontendSyntax, match="could not be parsed") as exc_info:
        icontract_clause_irs_from_source("def broken(:")

    assert exc_info.value.frontend == ICONTRACT_FRONTEND
