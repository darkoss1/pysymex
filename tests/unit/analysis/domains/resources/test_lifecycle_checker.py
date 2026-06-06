"""Tests for the generic resource lifecycle checker."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

from pytest import MonkeyPatch
import z3

from pysymex.analysis.domains.resources.lifecycle.checker import ResourceLifecycleChecker
from pysymex.analysis.domains.resources.types import (
    ResourceIssueKind,
    ResourceKind,
    ResourceSafetyProofReason,
    ResourceSafetyProofStatus,
)


class TestResourceLifecycleChecker:
    """Test suite for pysymex.analysis.domains.resources.lifecycle.ResourceLifecycleChecker."""

    def test_create_resource(self) -> None:
        checker = ResourceLifecycleChecker()
        resource = checker.create_resource("f", ResourceKind.FILE)
        assert resource.name == "f"

    def test_check_action(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("f", ResourceKind.FILE)
        assert checker.check_action("f", "read") is not None
        assert checker.check_action("f", "open_read") is None

    def test_check_leaks(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("f", ResourceKind.FILE)
        assert checker.check_action("f", "open_read") is None
        assert len(checker.check_leaks()) == 1
        assert checker.check_action("f", "close") is None
        assert len(checker.check_leaks()) == 0

    def test_check_leaks_prunes_definitely_infeasible_path(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("f", ResourceKind.FILE)
        assert checker.check_action("f", "open_read") is None
        x = z3.Int("resource_infeasible_path")

        assert checker.check_leaks([x > 0, x < 0]) == []

    def test_check_leaks_preserves_solver_unknown_as_possible_path(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("f", ResourceKind.FILE)
        assert checker.check_action("f", "open_read") is None
        checker.solver.set_deadline(time.perf_counter() - 1.0)
        x = z3.Int("resource_unknown_path")

        issues = checker.check_leaks([x > 0])

        assert len(issues) == 1
        assert issues[0].resource_name == "f"
        assert issues[0].severity == "warning"

    def test_check_action_marks_solver_unknown_path_issue_as_warning(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.solver.set_deadline(time.perf_counter() - 1.0)
        x = z3.Int("resource_action_unknown_path")

        issue = checker.check_action("missing", "read", path_constraints=[x > 0])

        assert issue is not None
        assert issue.kind is ResourceIssueKind.MISSING_INITIALIZATION
        assert issue.severity == "warning"

    def test_check_action_marks_solver_query_failure_path_issue_as_warning(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        checker = ResourceLifecycleChecker()

        def raising_check(*constraints: z3.BoolRef, need_model: bool = False) -> object:
            _ = constraints
            _ = need_model
            raise z3.Z3Exception("forced resource path query failure")

        monkeypatch.setattr(checker.solver, "check", raising_check)

        issue = checker.check_action(
            "missing",
            "read",
            path_constraints=[z3.Bool("resource_add_failure_path")],
        )

        assert issue is not None
        assert issue.kind is ResourceIssueKind.MISSING_INITIALIZATION
        assert issue.severity == "warning"
        assert getattr(checker.solver, "_scope_depth") == 0

    def test_check_use_after(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("f", ResourceKind.FILE)
        assert checker.check_action("f", "open_read") is None
        assert checker.check_action("f", "close") is None
        assert checker.check_use_after("f", "read") is not None

    def test_check_double_operation(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("f", ResourceKind.FILE)
        assert checker.check_action("f", "open_read") is None
        assert checker.check_action("f", "close") is None
        assert checker.check_double_operation("f", "close") is not None

    def test_disconnected_resource_uses_disconnect_issue_kinds(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("db", ResourceKind.DATABASE_CONNECTION)
        assert checker.check_action("db", "connect_start") is None
        assert checker.check_action("db", "connect_complete") is None
        assert checker.check_action("db", "disconnect") is None

        use_issue = checker.check_use_after("db", "execute")
        double_issue = checker.check_double_operation("db", "disconnect")

        assert use_issue is not None
        assert use_issue.kind is ResourceIssueKind.USE_AFTER_DISCONNECT
        assert double_issue is not None
        assert double_issue.kind is ResourceIssueKind.DOUBLE_DISCONNECT

    def test_check_lock_ordering(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("L1", ResourceKind.LOCK)
        checker.create_resource("L2", ResourceKind.LOCK)
        assert checker.check_action("L2", "acquire") is None
        assert checker.check_action("L1", "acquire") is None
        assert checker.check_lock_ordering(["L2", "L1"], ["L1", "L2"]) is not None

    def test_check_transaction_state(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("t", ResourceKind.DATABASE_TRANSACTION)
        assert checker.check_action("t", "begin") is None
        assert checker.check_transaction_state("t") is not None

    @patch(
        "pysymex.analysis.domains.resources.lifecycle.checker.z3.Solver.check",
        return_value=z3.unsat,
    )
    def test_prove_resource_safety(self, mock_check: MagicMock) -> None:
        _ = mock_check
        checker = ResourceLifecycleChecker()
        checker.create_resource("f", ResourceKind.FILE)
        proof = checker.prove_resource_safety_result("f")
        safe, reason = checker.prove_resource_safety("f")
        assert proof.status is ResourceSafetyProofStatus.PROVEN_SAFE
        assert proof.reason is None
        assert proof.is_safe
        assert safe is True
        assert reason is None

    def test_prove_resource_safety_result_reports_untracked_resource(self) -> None:
        checker = ResourceLifecycleChecker()

        proof = checker.prove_resource_safety_result("missing")

        assert proof.status is ResourceSafetyProofStatus.NOT_TRACKED
        assert proof.reason is ResourceSafetyProofReason.RESOURCE_NOT_TRACKED
        assert proof.message == "Resource not tracked"

    def test_prove_resource_safety_result_reports_unsafe_resource(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("f", ResourceKind.FILE)
        assert checker.check_action("f", "open_read") is None

        proof = checker.prove_resource_safety_result("f")

        assert proof.status is ResourceSafetyProofStatus.UNSAFE
        assert proof.reason is ResourceSafetyProofReason.UNSAFE_FINAL_STATE_REACHABLE
        assert proof.is_unsafe
        assert proof.message == "Resource may not be properly closed/released"

    def test_prove_resource_safety_reports_solver_unknown(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("f", ResourceKind.FILE)
        checker.solver.set_deadline(time.perf_counter() - 1.0)

        proof = checker.prove_resource_safety_result("f")
        safe, reason = checker.prove_resource_safety("f")

        assert proof.status is ResourceSafetyProofStatus.INCONCLUSIVE
        assert proof.reason is ResourceSafetyProofReason.SOLVER_UNKNOWN
        assert proof.is_inconclusive
        assert safe is False
        assert reason is not None
        assert "unknown" in reason

    def test_prove_resource_safety_restores_solver_scope_on_query_failure(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("f", ResourceKind.FILE)

        def raising_check(*constraints: z3.BoolRef, need_model: bool = False) -> object:
            _ = constraints
            _ = need_model
            raise z3.Z3Exception("forced resource proof query failure")

        monkeypatch.setattr(checker.solver, "check", raising_check)

        proof = checker.prove_resource_safety_result("f", [z3.Bool("resource_scope_failure")])
        safe, reason = proof.as_legacy_tuple()

        assert proof.status is ResourceSafetyProofStatus.INCONCLUSIVE
        assert proof.reason is ResourceSafetyProofReason.SOLVER_UNKNOWN
        assert safe is False
        assert reason is not None
        assert "inconclusive" in reason
        assert getattr(checker.solver, "_scope_depth") == 0

    def test_get_all_issues(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("f", ResourceKind.FILE)
        assert checker.check_action("f", "open_read") is None
        assert len(checker.get_all_issues()) > 0

    def test_get_resource_summary(self) -> None:
        checker = ResourceLifecycleChecker()
        checker.create_resource("f", ResourceKind.FILE)
        assert "f" in checker.get_resource_summary()
