from __future__ import annotations

import pytest

from pysymex.contracts.contract_enums import ContractKind
from pysymex.contracts.frontend.common import UnsupportedFrontendSyntax
from pysymex.contracts.frontend.pep316 import (
    PEP316_FRONTEND,
    pep316_clause_irs_from_source,
)


def test_pep316_frontend_lowers_function_pre_and_post_docstrings() -> None:
    source = '''
def target(x):
    """
    pre: x > 0
    post: result() >= x
    """
    return x
'''

    clauses = pep316_clause_irs_from_source(source, module="sample")

    assert [(clause.kind, clause.condition, clause.frontend) for clause in clauses] == [
        (ContractKind.REQUIRES, "x > 0", PEP316_FRONTEND),
        (ContractKind.ENSURES, "result() >= x", PEP316_FRONTEND),
    ]
    assert all(clause.target.qualname == "target" for clause in clauses)
    assert all(clause.target.module == "sample" for clause in clauses)


def test_pep316_frontend_lowers_class_invariant_docstring() -> None:
    source = '''
class Account:
    """
    inv: self.balance >= 0
    """

    def __init__(self, balance):
        self.balance = balance
'''

    clause = pep316_clause_irs_from_source(source, module="sample")[0]

    assert clause.kind is ContractKind.INVARIANT
    assert clause.condition == "self.balance >= 0"
    assert clause.target.name == "Account"
    assert clause.target.qualname == "Account"


def test_pep316_frontend_tracks_nested_method_docstring_targets() -> None:
    source = '''
class Account:
    def withdraw(self, amount):
        """
        pre: amount >= 0
        """
        return amount
'''

    clause = pep316_clause_irs_from_source(source, module="sample")[0]

    assert clause.kind is ContractKind.REQUIRES
    assert clause.target.name == "withdraw"
    assert clause.target.qualname == "Account.withdraw"


def test_pep316_frontend_rejects_unsupported_sections() -> None:
    source = '''
def target(x):
    """
    raises: ValueError
    """
    return x
'''

    with pytest.raises(UnsupportedFrontendSyntax, match="raises") as exc_info:
        pep316_clause_irs_from_source(source)

    assert exc_info.value.frontend == PEP316_FRONTEND
    assert exc_info.value.line_number == 4


def test_pep316_frontend_rejects_empty_clause_condition() -> None:
    source = '''
def target(x):
    """
    pre:
    """
    return x
'''

    with pytest.raises(UnsupportedFrontendSyntax, match="requires a condition"):
        pep316_clause_irs_from_source(source)


def test_pep316_frontend_rejects_invalid_source() -> None:
    with pytest.raises(UnsupportedFrontendSyntax, match="could not be parsed") as exc_info:
        pep316_clause_irs_from_source("def broken(:")

    assert exc_info.value.frontend == PEP316_FRONTEND
