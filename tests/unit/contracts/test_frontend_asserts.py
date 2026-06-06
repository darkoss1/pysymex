from __future__ import annotations

import pytest

from pysymex.contracts.contract_enums import ContractKind
from pysymex.contracts.frontend.asserts import (
    ASSERT_FRONTEND,
    assertion_clause_irs_from_source,
)
from pysymex.contracts.frontend.common import UnsupportedFrontendSyntax


def test_assert_frontend_lowers_function_asserts_to_clause_ir() -> None:
    source = """
def target(x):
    assert x > 0, "positive"
    return x
"""

    clauses = assertion_clause_irs_from_source(source, module="sample")

    assert len(clauses) == 1
    clause = clauses[0]
    assert clause.kind is ContractKind.ASSERT
    assert clause.condition == "x > 0"
    assert clause.message == "positive"
    assert clause.frontend == ASSERT_FRONTEND
    assert clause.line_number == 3
    assert clause.target.name == "target"
    assert clause.target.qualname == "target"
    assert clause.target.module == "sample"


def test_assert_frontend_tracks_nested_source_qualnames() -> None:
    source = """
class Box:
    def check(self, x):
        assert x >= 0
"""

    clause = assertion_clause_irs_from_source(source, module="sample")[0]

    assert clause.target.name == "check"
    assert clause.target.qualname == "Box.check"
    assert clause.message == "Assertion: x >= 0"


def test_assert_frontend_source_targets_are_deterministic() -> None:
    source = """
def target(x):
    assert x
"""

    first = assertion_clause_irs_from_source(source, module="sample")[0]
    second = assertion_clause_irs_from_source(source, module="sample")[0]

    assert first.target.identity == second.target.identity
    assert first.clause_id == second.clause_id


def test_assert_frontend_rejects_non_literal_messages() -> None:
    source = """
def target(x):
    assert x > 0, f"{x}"
"""

    with pytest.raises(UnsupportedFrontendSyntax, match="string literals") as exc_info:
        assertion_clause_irs_from_source(source)

    assert exc_info.value.frontend == ASSERT_FRONTEND
    assert exc_info.value.line_number == 3


def test_assert_frontend_rejects_invalid_source() -> None:
    with pytest.raises(UnsupportedFrontendSyntax, match="could not be parsed") as exc_info:
        assertion_clause_irs_from_source("def broken(:")

    assert exc_info.value.frontend == ASSERT_FRONTEND
