"""Tests for contract-based verification."""

import pytest

import z3


from pysymex.analysis.contracts import (
    ContractKind,
    VerificationResult,
    ContractViolation,
    Contract,
    FunctionContract,
    ContractCompiler,
    ContractVerifier,
    requires,
    ensures,
    invariant,
    loop_invariant,
    get_function_contract,
    VerificationReport,
    ContractAnalyzer,
)


class TestContractKind:
    """Tests for ContractKind enum."""

    def test_requires_kind(self):
        assert ContractKind.REQUIRES.name == "REQUIRES"

    def test_ensures_kind(self):
        assert ContractKind.ENSURES.name == "ENSURES"

    def test_invariant_kind(self):
        assert ContractKind.INVARIANT.name == "INVARIANT"

    def test_loop_invariant_kind(self):
        assert ContractKind.LOOP_INVARIANT.name == "LOOP_INVARIANT"


class TestVerificationResult:
    """Tests for VerificationResult enum."""

    def test_verified_result(self):
        assert VerificationResult.VERIFIED.name == "VERIFIED"

    def test_violated_result(self):
        assert VerificationResult.VIOLATED.name == "VIOLATED"

    def test_unknown_result(self):
        assert VerificationResult.UNKNOWN.name == "UNKNOWN"


class TestContractViolation:
    """Tests for ContractViolation dataclass."""

    def test_create_violation(self):
        v = ContractViolation(
            kind=ContractKind.REQUIRES,
            condition="x > 0",
            message="x must be positive",
        )

        assert v.kind == ContractKind.REQUIRES

        assert v.condition == "x > 0"

        assert v.message == "x must be positive"

    def test_violation_with_counterexample(self):
        v = ContractViolation(
            kind=ContractKind.ENSURES,
            condition="result() > 0",
            message="Result must be positive",
            counterexample={"x": -5},
        )

        assert v.counterexample == {"x": -5}

    def test_format_violation(self):
        v = ContractViolation(
            kind=ContractKind.REQUIRES,
            condition="x > 0",
            message="x must be positive",
            line_number=10,
            function_name="foo",
            counterexample={"x": -1},
        )

        formatted = v.format()

        assert "REQUIRES" in formatted

        assert "foo" in formatted

        assert "line 10" in formatted

        assert "x > 0" in formatted

        assert "x = -1" in formatted


class TestContract:
    """Tests for Contract dataclass."""

    def test_create_contract(self):
        c = Contract(
            kind=ContractKind.REQUIRES,
            condition="x > 0",
        )

        assert c.kind == ContractKind.REQUIRES

        assert c.condition == "x > 0"

    def test_compile_simple_condition(self):
        c = Contract(
            kind=ContractKind.REQUIRES,
            condition="x > 0",
        )

        symbols = {"x": z3.Int("x")}

        expr = c.compile(symbols)

        assert isinstance(expr, z3.BoolRef)


class TestFunctionContract:
    """Tests for FunctionContract dataclass."""

    def test_create_function_contract(self):
        fc = FunctionContract(function_name="divide")

        assert fc.function_name == "divide"

        assert fc.preconditions == []

        assert fc.postconditions == []

    def test_add_precondition(self):
        fc = FunctionContract(function_name="divide")

        fc.add_precondition("y != 0", "Divisor must be non-zero")

        assert len(fc.preconditions) == 1

        assert fc.preconditions[0].condition == "y != 0"

    def test_add_postcondition(self):
        fc = FunctionContract(function_name="abs_val")

        fc.add_postcondition("result() >= 0", "Result must be non-negative")

        assert len(fc.postconditions) == 1

    def test_add_loop_invariant(self):
        fc = FunctionContract(function_name="sum_loop")

        fc.add_loop_invariant(10, "i >= 0", "Index non-negative")

        assert 10 in fc.loop_invariants

        assert len(fc.loop_invariants[10]) == 1


class TestContractCompiler:
    """Tests for ContractCompiler."""

    def test_compile_comparison_lt(self):
        symbols = {"x": z3.Int("x")}

        expr = ContractCompiler.compile_expression("x < 5", symbols)

        solver = z3.Solver()

        solver.add(expr)

        solver.add(symbols["x"] == 3)

        assert solver.check() == z3.sat

    def test_compile_comparison_gt(self):
        symbols = {"x": z3.Int("x")}

        expr = ContractCompiler.compile_expression("x > 0", symbols)

        solver = z3.Solver()

        solver.add(expr)

        solver.add(symbols["x"] == 5)

        assert solver.check() == z3.sat

    def test_compile_comparison_eq(self):
        symbols = {"x": z3.Int("x"), "y": z3.Int("y")}

        expr = ContractCompiler.compile_expression("x == y", symbols)

        solver = z3.Solver()

        solver.add(expr)

        solver.add(symbols["x"] == 10)

        solver.add(symbols["y"] == 10)

        assert solver.check() == z3.sat

    def test_compile_and_expression(self):
        symbols = {"x": z3.Int("x")}

        expr = ContractCompiler.compile_expression("x > 0 and x < 10", symbols)

        solver = z3.Solver()

        solver.add(expr)

        solver.add(symbols["x"] == 5)

        assert solver.check() == z3.sat

    def test_compile_or_expression(self):
        symbols = {"x": z3.Int("x")}

        expr = ContractCompiler.compile_expression("x < 0 or x > 100", symbols)

        solver = z3.Solver()

        solver.add(expr)

        solver.add(symbols["x"] == -5)

        assert solver.check() == z3.sat

    def test_compile_not_expression(self):
        symbols = {"x": z3.Int("x")}

        expr = ContractCompiler.compile_expression("not x == 0", symbols)

        solver = z3.Solver()

        solver.add(expr)

        solver.add(symbols["x"] == 5)

        assert solver.check() == z3.sat

    def test_compile_arithmetic_add(self):
        symbols = {"x": z3.Int("x"), "y": z3.Int("y")}

        expr = ContractCompiler.compile_expression("x + y > 0", symbols)

        solver = z3.Solver()

        solver.add(expr)

        solver.add(symbols["x"] == 3)

        solver.add(symbols["y"] == 5)

        assert solver.check() == z3.sat

    def test_compile_arithmetic_sub(self):
        symbols = {"x": z3.Int("x"), "y": z3.Int("y")}

        expr = ContractCompiler.compile_expression("x - y == 2", symbols)

        solver = z3.Solver()

        solver.add(expr)

        solver.add(symbols["x"] == 5)

        solver.add(symbols["y"] == 3)

        assert solver.check() == z3.sat

    def test_compile_arithmetic_mult(self):
        symbols = {"x": z3.Int("x")}

        expr = ContractCompiler.compile_expression("x * 2 == 10", symbols)

        solver = z3.Solver()

        solver.add(expr)

        solver.add(symbols["x"] == 5)

        assert solver.check() == z3.sat

    def test_compile_abs_function(self):
        symbols = {"x": z3.Int("x")}

        expr = ContractCompiler.compile_expression("abs(x) >= 0", symbols)

        solver = z3.Solver()

        solver.add(z3.Not(expr))

        assert solver.check() == z3.unsat

    def test_compile_min_function(self):
        symbols = {"x": z3.Int("x"), "y": z3.Int("y")}

        expr = ContractCompiler.compile_expression("min(x, y) <= x", symbols)

        solver = z3.Solver()

        solver.add(z3.Not(expr))

        assert solver.check() == z3.unsat

    def test_compile_max_function(self):
        symbols = {"x": z3.Int("x"), "y": z3.Int("y")}

        expr = ContractCompiler.compile_expression("max(x, y) >= x", symbols)

        solver = z3.Solver()

        solver.add(z3.Not(expr))

        assert solver.check() == z3.unsat

    def test_compile_old_reference(self):
        symbols = {"x": z3.Int("x"), "old_x": z3.Int("old_x")}

        expr = ContractCompiler.compile_expression("old(x) < x", symbols)

        solver = z3.Solver()

        solver.add(expr)

        solver.add(symbols["old_x"] == 5)

        solver.add(symbols["x"] == 10)

        assert solver.check() == z3.sat

    def test_compile_result_reference(self):
        symbols = {"__result__": z3.Int("__result__")}

        expr = ContractCompiler.compile_expression("result() > 0", symbols)

        solver = z3.Solver()

        solver.add(expr)

        solver.add(symbols["__result__"] == 42)

        assert solver.check() == z3.sat

    def test_compile_ternary(self):
        symbols = {"x": z3.Int("x")}

        expr = ContractCompiler.compile_expression("x if x > 0 else -x", symbols)

        assert expr is not None


class TestContractVerifier:
    """Tests for ContractVerifier."""

    def test_verify_satisfiable_precondition(self):
        verifier = ContractVerifier()

        contract = Contract(
            kind=ContractKind.REQUIRES,
            condition="x > 0",
        )

        symbols = {"x": z3.Int("x")}

        result, _ = verifier.verify_precondition(contract, [], symbols)

        assert result == VerificationResult.VERIFIED

    def test_verify_unsatisfiable_precondition(self):
        verifier = ContractVerifier()

        contract = Contract(
            kind=ContractKind.REQUIRES,
            condition="x > 0 and x < 0",
        )

        symbols = {"x": z3.Int("x")}

        result, _ = verifier.verify_precondition(contract, [], symbols)

        assert result == VerificationResult.UNREACHABLE

    def test_verify_postcondition_holds(self):
        verifier = ContractVerifier()

        pre = Contract(kind=ContractKind.REQUIRES, condition="x >= 0")

        post = Contract(kind=ContractKind.ENSURES, condition="x >= 0")

        symbols = {"x": z3.Int("x")}

        result, _ = verifier.verify_postcondition(post, [pre], [], symbols)

        assert result == VerificationResult.VERIFIED

    def test_verify_postcondition_violated(self):
        verifier = ContractVerifier()

        pre = Contract(kind=ContractKind.REQUIRES, condition="x > 0")

        post = Contract(kind=ContractKind.ENSURES, condition="x < 0")

        symbols = {"x": z3.Int("x")}

        result, counter = verifier.verify_postcondition(post, [pre], [], symbols)

        assert result == VerificationResult.VIOLATED

        assert counter is not None

    def test_verify_assertion_holds(self):
        verifier = ContractVerifier()

        x = z3.Int("x")

        symbols = {"x": x}

        path_constraints = [x > 0]

        condition = x >= 0

        result, _ = verifier.verify_assertion(condition, path_constraints, symbols)

        assert result == VerificationResult.VERIFIED

    def test_verify_assertion_can_fail(self):
        verifier = ContractVerifier()

        x = z3.Int("x")

        symbols = {"x": x}

        result, counter = verifier.verify_assertion(x > 0, [], symbols)

        assert result == VerificationResult.VIOLATED

        assert counter is not None


class TestDecorators:
    """Tests for contract decorators."""

    def test_requires_decorator(self):
        @requires("x > 0", "x must be positive")
        def positive_func(x):
            return x + 1

        contract = get_function_contract(positive_func)

        assert contract is not None

        assert len(contract.preconditions) == 1

        assert contract.preconditions[0].condition == "x > 0"

    def test_ensures_decorator(self):
        @ensures("result() >= 0", "result must be non-negative")
        def abs_func(x):
            return abs(x)

        contract = get_function_contract(abs_func)

        assert contract is not None

        assert len(contract.postconditions) == 1

    def test_multiple_contracts(self):
        @requires("x > 0")
        @requires("y > 0")
        @ensures("result() > 0")
        def multiply(x, y):
            return x * y

        contract = get_function_contract(multiply)

        assert contract is not None

        assert len(contract.preconditions) == 2

        assert len(contract.postconditions) == 1

    def test_invariant_decorator(self):
        @invariant("self.value >= 0")
        class Counter:
            def __init__(self):
                self.value = 0

        assert hasattr(Counter, "__invariants__")

        assert len(Counter.__invariants__) == 1


class TestVerificationReport:
    """Tests for VerificationReport."""

    def test_create_empty_report(self):
        report = VerificationReport(function_name="foo")

        assert report.function_name == "foo"

        assert report.total_contracts == 0

        assert report.is_verified

    def test_add_verified_result(self):
        report = VerificationReport(function_name="foo")

        contract = Contract(kind=ContractKind.REQUIRES, condition="x > 0")

        report.add_result(contract, VerificationResult.VERIFIED)

        assert report.total_contracts == 1

        assert report.verified == 1

        assert report.is_verified

    def test_add_violated_result(self):
        report = VerificationReport(function_name="foo")

        contract = Contract(kind=ContractKind.REQUIRES, condition="x > 0")

        report.add_result(
            contract,
            VerificationResult.VIOLATED,
            counterexample={"x": -1},
            function_name="foo",
        )

        assert report.total_contracts == 1

        assert report.violated == 1

        assert report.has_violations

        assert not report.is_verified

        assert len(report.violations) == 1

    def test_format_report(self):
        report = VerificationReport(function_name="test_func")

        contract = Contract(kind=ContractKind.REQUIRES, condition="x > 0")

        report.add_result(contract, VerificationResult.VERIFIED)

        formatted = report.format()

        assert "test_func" in formatted

        assert "Verified: 1" in formatted


class TestContractAnalyzer:
    """Tests for ContractAnalyzer."""

    def test_analyze_function_without_contracts(self):
        analyzer = ContractAnalyzer()

        def simple_func(x):
            return x + 1

        report = analyzer.analyze_function(simple_func)

        assert report.total_contracts == 0

    def test_analyze_function_with_precondition(self):
        analyzer = ContractAnalyzer()

        @requires("x > 0")
        def positive_func(x):
            return x * 2

        report = analyzer.analyze_function(positive_func, {"x": "int"})

        assert report.total_contracts >= 1

    def test_get_all_reports(self):
        analyzer = ContractAnalyzer()

        @requires("x > 0")
        def func1(x):
            return x

        analyzer.analyze_function(func1)

        reports = analyzer.get_all_reports()

        assert len(reports) >= 1
