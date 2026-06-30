from __future__ import annotations

from pathlib import Path

import z3

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.exceptions.policy import (
    canonical_exception_type,
    issue_kind_for_exception,
    issue_kind_for_explicit_raise,
    modeled_exception,
    runtime_exception,
    type_error,
)
from pysymex._internal.core.outcome import IssueKind


def test_policy_canonicalizes_builtin_exception_names() -> None:
    assert canonical_exception_type("TypeError") is TypeError
    assert canonical_exception_type("CustomFailure") == "CustomFailure"


def test_policy_constructs_unconditional_concrete_exception() -> None:
    exc = type_error("bad operand")

    assert isinstance(exc, SymbolicException)
    assert exc.exc_type is TypeError
    assert exc.message == "bad operand"
    assert exc.args == ("bad operand",)
    assert exc.is_unconditional()


def test_policy_constructs_conditional_runtime_exception() -> None:
    condition = z3.Bool("raises")
    exc = runtime_exception("ValueError", "bad value", condition=condition, raised_at=42)

    assert exc.exc_type is ValueError
    assert exc.message == "bad value"
    assert exc.condition is condition
    assert exc.raised_at == 42


def test_policy_constructs_modeled_exception_with_confidence() -> None:
    exc = modeled_exception(
        "ZeroDivisionError",
        message="division by zero",
        raised_at=7,
        confidence=0.5,
        likelihood=0.25,
    )

    assert exc.exc_type is ZeroDivisionError
    assert exc.name == "ZeroDivisionError"
    assert exc.confidence == 0.5
    assert exc.likelihood == 0.25
    assert exc.raised_at == 7


def test_policy_owns_runtime_issue_mapping() -> None:
    assert issue_kind_for_exception(TypeError) is IssueKind.TYPE_ERROR
    assert issue_kind_for_exception("KeyError") is IssueKind.KEY_ERROR
    assert issue_kind_for_exception(ZeroDivisionError, "modulo by zero") is IssueKind.MODULO_BY_ZERO
    assert issue_kind_for_exception("CustomFailure") is IssueKind.UNHANDLED_EXCEPTION


def test_policy_separates_explicit_raise_from_operation_errors() -> None:
    assert issue_kind_for_explicit_raise(TypeError) is IssueKind.TYPE_ERROR
    assert issue_kind_for_explicit_raise(ZeroDivisionError) is IssueKind.UNHANDLED_EXCEPTION


def test_runtime_exception_construction_is_centralized() -> None:
    root = Path(__file__).resolve().parents[4]
    owners = {
        root / "pysymex" / "_internal" / "core" / "exceptions" / "objects.py",
        root / "pysymex" / "_internal" / "core" / "exceptions" / "policy.py",
    }
    offenders: list[str] = []
    for path in (root / "pysymex").rglob("*.py"):
        if path in owners:
            continue
        text = path.read_text(encoding="utf-8")
        if "SymbolicException.concrete(" in text or "SymbolicException(" in text:
            offenders.append(str(path.relative_to(root)))

    assert offenders == []
