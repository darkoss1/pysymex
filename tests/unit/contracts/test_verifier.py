from __future__ import annotations

import z3

import pytest

from pysymex.contracts.types import Contract, ContractKind, VerificationResult
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

    def test_extract_counterexample(self) -> None:
        """Verify model extraction handles ints, reals, and bools."""
        verifier = ContractVerifier()
        solver = z3.Solver()
        x = z3.Int("x")
        y = z3.Real("y")
        b = z3.Bool("b")
        solver.add(x == 42, y == 3.14, b == True)
        solver.check()
        model = solver.model()
        counter = verifier._extract_counterexample(model, {"x": x, "y": y, "b": b})
        assert counter["x"] == 42
        assert isinstance(counter["y"], float)
        assert counter["b"] is True


class TestVerificationReport:
    """Test suite for VerificationReport in contracts/verifier.py."""

    def test_add_result(self) -> None:
        """Verify recording of VERIFIED, VIOLATED, and UNKNOWN results."""
        report = VerificationReport(function_name="foo")
        c1 = Contract(kind=ContractKind.REQUIRES, predicate="x")
        report.add_result(c1, VerificationResult.VERIFIED)
        report.add_result(c1, VerificationResult.VIOLATED)
        report.add_result(c1, VerificationResult.UNKNOWN)
        assert report.total_contracts == 3
        assert report.verified == 1
        assert report.violated == 1
        assert report.unknown == 1
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
