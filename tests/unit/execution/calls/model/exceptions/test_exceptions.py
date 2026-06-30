"""Tests for execution-owned model exception branch routing."""

from __future__ import annotations

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.calls.model.exceptions.potential import (
    branch_on_caught_potential_exception,
)
from pysymex._internal.execution.calls.model.exceptions.raised import (
    branch_on_caught_raised_exception,
)
from pysymex._internal.models.contracts.results import ModelResult


def test_raised_exception_branch_requires_dispatch_context() -> None:
    result = ModelResult(
        value=0,
        side_effects={
            "raised_exception": {
                "issue_kind": "TYPE_ERROR",
                "exception_type": "TypeError",
                "message": "bad call",
                "source": "test",
            }
        },
    )

    assert branch_on_caught_raised_exception(VMState(), None, None, result) is None


def test_potential_exception_branch_requires_dispatch_context() -> None:
    result = ModelResult(
        value=0,
        side_effects={
            "potential_exception": {
                "type": "ValueError",
                "message": "bad value",
                "condition": z3.BoolVal(True),
            }
        },
    )

    assert (
        branch_on_caught_potential_exception(
            VMState(),
            None,
            None,
            result,
            lambda _constraints: True,
        )
        is None
    )
