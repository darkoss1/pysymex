from __future__ import annotations

from unittest.mock import patch

import z3


from pysymex.contracts.ir.obligations import QueryKind
from pysymex.core.solver.engine.results import SolverResult
from pysymex.contracts.types import Contract, ContractKind, Severity, VerificationResult
from pysymex.contracts.verifier import ContractVerifier, VerificationReport


class TestContractVerifier:
    """Test suite for ContractVerifier in contracts/verifier.py."""

    def test_verify_precondition_sat(self) -> None:
        """Verify precondition returning VERIFIED for SAT."""
        verifier = ContractVerifier()
        contract = Contract(kind=ContractKind.REQUIRES, predicate="x == 1")
        symbols = {"x": z3.Int("x")}
        result, _ = verifier.verify_precondition(contract, [], symbols)
        assert result == VerificationResult.VERIFIED

    def test_verify_precondition_unsat(self) -> None:
        """Verify precondition returning UNREACHABLE for UNSAT path."""
        verifier = ContractVerifier()
        contract = Contract(kind=ContractKind.REQUIRES, predicate="x == 1")
        x = z3.Int("x")
        symbols = {"x": x}
        path_constraints = [x == 2]
        result, _ = verifier.verify_precondition(contract, path_constraints, symbols)
        assert result == VerificationResult.UNREACHABLE

    def test_verify_postcondition_valid(self) -> None:
        """Verify postcondition returning VERIFIED (no counterexample)."""
        verifier = ContractVerifier()
        contract = Contract(kind=ContractKind.ENSURES, predicate="y == 1")
        y = z3.Int("y")
        symbols = {"y": y}
        path_constraints = [y == 1]
        result, _ = verifier.verify_postcondition(contract, [], path_constraints, symbols)
        assert result == VerificationResult.VERIFIED

    def test_verify_postcondition_violated(self) -> None:
        """Verify postcondition returning VIOLATED when counterexample exists."""
        verifier = ContractVerifier()
        contract = Contract(kind=ContractKind.ENSURES, predicate="y == 1")
        y = z3.Int("y")
        symbols = {"y": y}
        path_constraints = [y == 2]
        result, counter = verifier.verify_postcondition(contract, [], path_constraints, symbols)
        assert result == VerificationResult.VIOLATED
        assert counter is not None

    def test_verify_postcondition_compile_failure_is_unsupported(self) -> None:
        """Unsupported predicates must not be treated as verified."""
        verifier = ContractVerifier()

        def bad_predicate(y: z3.ArithRef) -> object:
            _ = y
            return object()

        contract = Contract(
            kind=ContractKind.ENSURES,
            predicate=bad_predicate,  # type: ignore[arg-type]  # invalid predicate exercises UNKNOWN path
        )
        y = z3.Int("y")
        result, counter = verifier.verify_postcondition(contract, [], [y == 1], {"y": y})
        assert result == VerificationResult.UNSUPPORTED
        assert counter is None

    def test_real_sorted_string_postcondition_is_unsupported_without_ieee_model(self) -> None:
        """Mathematical Reals cannot prove general Python float postconditions."""
        verifier = ContractVerifier()
        contract = Contract(kind=ContractKind.ENSURES, predicate="x + 1 > x")
        x = z3.Real("x")

        result, counter = verifier.verify_postcondition(contract, [], [], {"x": x})

        assert not (float("inf") + 1 > float("inf"))
        assert result is VerificationResult.UNSUPPORTED
        assert counter is None

    def test_verify_loop_invariant_base_violated(self) -> None:
        """Verify loop invariant returns VIOLATED on base case."""
        verifier = ContractVerifier()
        contract = Contract(kind=ContractKind.LOOP_INVARIANT, predicate="i > 0")
        i = z3.Int("i")
        symbols = {"i": i}
        result, _ = verifier.verify_loop_invariant(
            contract, z3.BoolVal(True), [], [i == 0], symbols, symbols
        )
        assert result == VerificationResult.VIOLATED

    def test_verify_loop_invariant_inductive_violated(self) -> None:
        """Verify loop invariant returns VIOLATED on inductive step."""
        verifier = ContractVerifier()
        contract = Contract(kind=ContractKind.LOOP_INVARIANT, predicate="i > 0")
        i = z3.Int("i")
        symbols = {"i": i}
        i_after = z3.Int("i_after")
        symbols_after = {"i": i_after}
        result, _ = verifier.verify_loop_invariant(
            contract, z3.BoolVal(True), [i_after == 0], [i == 1], symbols, symbols_after
        )
        assert result == VerificationResult.VIOLATED

    def test_verify_loop_invariant_verified(self) -> None:
        """Verify loop invariant returns VERIFIED when both steps pass."""
        verifier = ContractVerifier()
        contract = Contract(kind=ContractKind.LOOP_INVARIANT, predicate="i >= 0")
        i = z3.Int("i")
        symbols = {"i": i}
        i_after = z3.Int("i_after")
        symbols_after = {"i": i_after}
        result, _ = verifier.verify_loop_invariant(
            contract, z3.BoolVal(True), [i_after == i + 1], [i == 0], symbols, symbols_after
        )
        assert result == VerificationResult.VERIFIED

    def test_verify_assertion_verified(self) -> None:
        """Verify assertion returns VERIFIED when valid."""
        verifier = ContractVerifier()
        x = z3.Int("x")
        result, _ = verifier.verify_assertion(x == 1, [x == 1], {"x": x})
        assert result == VerificationResult.VERIFIED

    def test_verify_assertion_violated(self) -> None:
        """Verify assertion returns VIOLATED when invalid."""
        verifier = ContractVerifier()
        x = z3.Int("x")
        result, _ = verifier.verify_assertion(x == 1, [x == 2], {"x": x})
        assert result == VerificationResult.VIOLATED

    def test_solver_failures_are_unknown_for_all_obligation_queries(self) -> None:
        """Operational solver failures never imply support or verification."""
        verifier = ContractVerifier()
        x = z3.Int("x")
        requires = Contract(kind=ContractKind.REQUIRES, predicate="x > 0")
        ensures = Contract(kind=ContractKind.ENSURES, predicate="x > 0")
        invariant = Contract(kind=ContractKind.LOOP_INVARIANT, predicate="x >= 0")

        with patch.object(verifier.solver, "check", side_effect=RuntimeError("solver failed")):
            results = [
                verifier.verify_precondition(requires, [], {"x": x})[0],
                verifier.verify_postcondition(ensures, [], [], {"x": x})[0],
                verifier.verify_loop_invariant(
                    invariant, z3.BoolVal(True), [], [], {"x": x}, {"x": x}
                )[0],
                verifier.verify_assertion(x > 0, [], {"x": x})[0],
            ]

        assert results == [VerificationResult.UNKNOWN] * 4

    def test_verifier_routes_assertion_through_contract_query_owner(self) -> None:
        verifier = ContractVerifier()
        x = z3.Int("x")

        with patch(
            "pysymex.contracts.verifier.check_contract_query",
            return_value=SolverResult.unsat(),
        ) as check_query:
            result, counter = verifier.verify_assertion(x > 0, [], {"x": x})

        query = check_query.call_args.args[0]
        assert result is VerificationResult.VERIFIED
        assert counter is None
        assert query.query_kind is QueryKind.ASSERTION
        assert query.need_model is True

    def test_extract_counterexample(self) -> None:
        """Verify model extraction handles ints, reals, and bools."""
        verifier = ContractVerifier()
        solver = z3.Solver()
        x = z3.Int("x")
        y = z3.Real("y")
        b = z3.Bool("b")
        solver.add(x == 42, y == 3.14, b)
        solver.check()
        model = solver.model()
        counter = verifier.extract_counterexample(model, {"x": x, "y": y, "b": b})
        assert counter["x"] == 42
        assert isinstance(counter["y"], float)
        assert counter["b"] is True


class TestVerificationReport:
    """Test suite for VerificationReport in contracts/verifier.py."""

    def test_add_result(self) -> None:
        """Verify recording of all non-error contract outcome categories."""
        report = VerificationReport(function_name="foo")
        c1 = Contract(kind=ContractKind.REQUIRES, predicate="x")
        report.add_result(c1, VerificationResult.VERIFIED)
        report.add_result(c1, VerificationResult.VIOLATED)
        report.add_result(c1, VerificationResult.UNKNOWN)
        report.add_result(c1, VerificationResult.UNSUPPORTED)
        report.add_result(c1, VerificationResult.UNREACHABLE)
        assert report.total_contracts == 5
        assert report.verified == 1
        assert report.violated == 1
        assert report.unknown == 1
        assert report.unsupported == 1
        assert report.unreachable == 1
        assert len(report.violations) == 1

    def test_format_clean_verified(self) -> None:
        """Verify formatting cleanly for VERIFIED report."""
        report = VerificationReport(function_name="foo")
        c1 = Contract(kind=ContractKind.REQUIRES, predicate="x")
        report.add_result(c1, VerificationResult.VERIFIED)
        fmt = report.format()
        assert "All contracts verified!" in fmt

    def test_format_violated(self) -> None:
        """Verify formatting for VIOLATED report."""
        report = VerificationReport(function_name="foo")
        c1 = Contract(kind=ContractKind.REQUIRES, predicate="x")
        report.add_result(c1, VerificationResult.VIOLATED)
        fmt = report.format()
        assert "Contract violations found" in fmt

    def test_violation_report_preserves_warning_severity(self) -> None:
        report = VerificationReport(function_name="foo")
        contract = Contract(
            kind=ContractKind.ENSURES,
            predicate="x > 0",
            severity=Severity.WARNING,
        )

        report.add_result(contract, VerificationResult.VIOLATED)

        assert report.violations[0].severity is Severity.WARNING
        assert "[WARNING]" in report.violations[0].format()
