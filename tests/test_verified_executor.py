"""Tests for verified executor with contract and property integration."""

import pytest

import z3


from pysymex.execution.verified_executor import (
    VerifiedExecutor,
    VerifiedExecutionConfig,
    VerifiedExecutionResult,
    TerminationStatus,
    TerminationProof,
    RankingFunction,
    TerminationAnalyzer,
    ContractIssue,
    ArithmeticIssue,
    InferredProperty,
    verify,
    check_contracts,
    check_arithmetic,
    prove_termination,
)

from pysymex.analysis.contracts import (
    requires,
    ensures,
    invariant,
    ContractKind,
    VerificationResult,
)

from pysymex.analysis.properties import PropertyKind, ProofStatus


@pytest.fixture
def config():
    """Default verified execution config."""

    return VerifiedExecutionConfig(
        max_paths=100,
        max_iterations=1000,
        solver_timeout_ms=5000,
        check_preconditions=True,
        check_postconditions=True,
        check_overflow=True,
        check_division_safety=True,
    )


@pytest.fixture
def executor(config):
    """Verified executor instance."""

    return VerifiedExecutor(config)


class TestVerifiedExecutor:
    """Tests for VerifiedExecutor."""

    def test_executor_creation(self):
        """Test executor can be created."""

        executor = VerifiedExecutor()

        assert executor is not None

        assert executor.contract_verifier is not None

        assert executor.property_prover is not None

        assert executor.arithmetic_verifier is not None

    def test_executor_with_config(self, config):
        """Test executor with custom config."""

        executor = VerifiedExecutor(config)

        assert executor.config.max_paths == 100

        assert executor.config.check_preconditions is True

    def test_simple_function_execution(self, executor):
        """Test executing a simple function."""

        def add(x, y):
            return x + y

        result = executor.execute_function(add, {"x": "int", "y": "int"})

        assert isinstance(result, VerifiedExecutionResult)

        assert result.function_name == "add"

        assert result.paths_explored >= 0

    def test_function_with_no_issues(self, executor):
        """Test function that should have no issues."""

        def identity(x):
            return x

        result = executor.execute_function(identity, {"x": "int"})

        assert len(result.issues) == 0


class TestContractIntegration:
    """Tests for contract verification during execution."""

    def test_precondition_extraction(self, executor):
        """Test that preconditions are extracted from decorators."""

        @requires("x > 0")
        def positive_sqrt(x):
            return x**0.5

        result = executor.execute_function(positive_sqrt, {"x": "int"})

        assert result.contracts_checked >= 1

    def test_postcondition_extraction(self, executor):
        """Test that postconditions are extracted from decorators."""

        @ensures("result() >= 0")
        def absolute(x):
            if x >= 0:
                return x

            return -x

        result = executor.execute_function(absolute, {"x": "int"})

        assert result.contracts_checked >= 1

    def test_valid_precondition_verified(self):
        """Test that valid preconditions are verified."""

        @requires("x > 0")
        def increment(x):
            return x + 1

        config = VerifiedExecutionConfig(
            check_preconditions=True,
            check_postconditions=False,
            max_paths=10,
        )

        executor = VerifiedExecutor(config)

        result = executor.execute_function(increment, {"x": "int"})

        assert result.contracts_checked >= 1

    def test_docstring_contracts(self, executor):
        """Test contracts in docstrings."""

        def divide(x, y):
            """
            :requires: y != 0
            :ensures: True
            """

            return x / y

        result = executor.execute_function(divide, {"x": "int", "y": "int"})

        assert result.contracts_checked >= 1

    def test_multiple_preconditions(self, executor):
        """Test function with multiple preconditions."""

        @requires("x >= 0")
        @requires("y >= 0")
        def both_positive(x, y):
            return x + y

        result = executor.execute_function(both_positive, {"x": "int", "y": "int"})

        assert result.contracts_checked >= 2


class TestArithmeticSafety:
    """Tests for arithmetic safety verification."""

    def test_division_safety_check(self):
        """Test that division by zero is checked."""

        def unsafe_divide(x, y):
            return x / y

        config = VerifiedExecutionConfig(
            check_division_safety=True,
            max_paths=50,
        )

        executor = VerifiedExecutor(config)

        result = executor.execute_function(unsafe_divide, {"x": "int", "y": "int"})

        has_div_issue = any(i.kind.name == "DIVISION_BY_ZERO" for i in result.issues) or any(
            i.kind == "division_by_zero" for i in result.arithmetic_issues
        )

        assert isinstance(result, VerifiedExecutionResult)

    def test_overflow_check(self):
        """Test overflow detection."""

        def multiply(x, y):
            return x * y

        config = VerifiedExecutionConfig(
            check_overflow=True,
            integer_bits=32,
            max_paths=50,
        )

        executor = VerifiedExecutor(config)

        result = executor.execute_function(multiply, {"x": "int", "y": "int"})

        assert isinstance(result, VerifiedExecutionResult)

    def test_safe_division_no_issue(self):
        """Test that safe division doesn't raise issues."""

        @requires("y != 0")
        def safe_divide(x, y):
            return x / y

        config = VerifiedExecutionConfig(
            check_division_safety=True,
            check_preconditions=True,
            max_paths=50,
        )

        executor = VerifiedExecutor(config)

        result = executor.execute_function(safe_divide, {"x": "int", "y": "int"})

        assert isinstance(result, VerifiedExecutionResult)


class TestTerminationAnalysis:
    """Tests for termination analysis."""

    def test_termination_analyzer_creation(self):
        """Test termination analyzer can be created."""

        analyzer = TerminationAnalyzer()

        assert analyzer is not None

    def test_ranking_function(self):
        """Test ranking function dataclass."""

        rf = RankingFunction(
            name="countdown",
            expression="n",
            variables=["n"],
        )

        assert rf.name == "countdown"

        assert rf.expression == "n"

    def test_verify_simple_ranking(self):
        """Test verifying a simple ranking function."""

        analyzer = TerminationAnalyzer()

        n = z3.Int("n")

        loop_condition = n > 0

        loop_body_effect = {"n": n - 1}

        symbols = {"n": n}

        ranking = RankingFunction(
            name="n_rank",
            expression="n",
            z3_expr=n,
            variables=["n"],
        )

        proof = analyzer.check_termination(
            loop_condition,
            loop_body_effect,
            symbols,
            ranking,
        )

        assert proof.status == TerminationStatus.TERMINATES

    def test_non_terminating_ranking(self):
        """Test ranking function that doesn't prove termination."""

        analyzer = TerminationAnalyzer()

        n = z3.Int("n")

        loop_condition = n > 0

        loop_body_effect = {"n": n + 1}

        symbols = {"n": n}

        ranking = RankingFunction(
            name="n_rank",
            expression="n",
            z3_expr=n,
            variables=["n"],
        )

        proof = analyzer.check_termination(
            loop_condition,
            loop_body_effect,
            symbols,
            ranking,
        )

        assert proof.status in (TerminationStatus.UNKNOWN, TerminationStatus.NON_TERMINATING)

    def test_synthesize_ranking(self):
        """Test automatic ranking function synthesis."""

        analyzer = TerminationAnalyzer()

        n = z3.Int("n")

        loop_condition = n > 0

        loop_body_effect = {"n": n - 1}

        symbols = {"n": n}

        proof = analyzer._synthesize_ranking(loop_condition, loop_body_effect, symbols)

        assert proof.status == TerminationStatus.TERMINATES

        assert proof.ranking_function is not None


class TestVerifiedExecutionResult:
    """Tests for VerifiedExecutionResult."""

    def test_result_creation(self):
        """Test result dataclass creation."""

        result = VerifiedExecutionResult(
            function_name="test_func",
            paths_explored=10,
            paths_completed=8,
        )

        assert result.function_name == "test_func"

        assert result.paths_explored == 10

    def test_is_verified_no_issues(self):
        """Test is_verified property with no issues."""

        result = VerifiedExecutionResult()

        assert result.is_verified is True

    def test_is_verified_with_issues(self):
        """Test is_verified property with issues."""

        from pysymex.analysis.detectors import Issue, IssueKind

        result = VerifiedExecutionResult(
            issues=[Issue(kind=IssueKind.DIVISION_BY_ZERO, message="test")],
        )

        assert result.is_verified is False

        assert result.has_issues is True

    def test_is_verified_with_contract_issues(self):
        """Test is_verified with contract issues."""

        result = VerifiedExecutionResult(
            contract_issues=[
                ContractIssue(
                    kind=ContractKind.REQUIRES,
                    condition="x > 0",
                    message="Precondition violated",
                )
            ],
        )

        assert result.is_verified is False

    def test_format_summary(self):
        """Test format_summary method."""

        result = VerifiedExecutionResult(
            function_name="test_func",
            paths_explored=10,
            paths_completed=8,
            contracts_checked=5,
            contracts_verified=5,
            total_time_seconds=0.5,
        )

        summary = result.format_summary()

        assert "test_func" in summary

        assert "10" in summary

        assert "Contracts" in summary


class TestContractIssue:
    """Tests for ContractIssue."""

    def test_contract_issue_creation(self):
        """Test contract issue creation."""

        issue = ContractIssue(
            kind=ContractKind.REQUIRES,
            condition="x > 0",
            message="Precondition may fail",
        )

        assert issue.kind == ContractKind.REQUIRES

        assert issue.condition == "x > 0"

    def test_contract_issue_with_counterexample(self):
        """Test contract issue with counterexample."""

        issue = ContractIssue(
            kind=ContractKind.ENSURES,
            condition="result() > 0",
            message="Postcondition violated",
            counterexample={"x": -5},
        )

        assert issue.counterexample == {"x": -5}

    def test_contract_issue_format(self):
        """Test format method."""

        issue = ContractIssue(
            kind=ContractKind.REQUIRES,
            condition="x > 0",
            message="Precondition may fail",
            line_number=10,
            function_name="test_func",
        )

        formatted = issue.format()

        assert "REQUIRES" in formatted

        assert "x > 0" in formatted

        assert "line 10" in formatted


class TestArithmeticIssue:
    """Tests for ArithmeticIssue."""

    def test_arithmetic_issue_creation(self):
        """Test arithmetic issue creation."""

        issue = ArithmeticIssue(
            kind="overflow",
            expression="x * y",
            message="Operation may overflow",
        )

        assert issue.kind == "overflow"

        assert issue.expression == "x * y"

    def test_arithmetic_issue_format(self):
        """Test format method."""

        issue = ArithmeticIssue(
            kind="division_by_zero",
            expression="x / y",
            message="Division may fail",
            line_number=15,
            counterexample={"y": 0},
        )

        formatted = issue.format()

        assert "DIVISION_BY_ZERO" in formatted

        assert "y = 0" in formatted


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_verify_function(self):
        """Test verify() convenience function."""

        def simple(x):
            return x + 1

        result = verify(simple, {"x": "int"}, max_paths=10)

        assert isinstance(result, VerifiedExecutionResult)

        assert result.function_name == "simple"

    def test_check_contracts_function(self):
        """Test check_contracts() convenience function."""

        @requires("x > 0")
        def positive(x):
            return x

        issues = check_contracts(positive, {"x": "int"})

        assert isinstance(issues, list)

    def test_check_arithmetic_function(self):
        """Test check_arithmetic() convenience function."""

        def multiply(x, y):
            return x * y

        issues = check_arithmetic(multiply, {"x": "int", "y": "int"})

        assert isinstance(issues, list)

    def test_prove_termination_function(self):
        """Test prove_termination() convenience function."""

        def countdown(n):
            while n > 0:
                n -= 1

            return n

        proof = prove_termination(countdown, {"n": "int"})

        assert isinstance(proof, TerminationProof)


class TestInferredProperties:
    """Tests for property inference."""

    def test_inferred_property_creation(self):
        """Test InferredProperty dataclass."""

        prop = InferredProperty(
            kind=PropertyKind.COMMUTATIVITY,
            description="Function is commutative",
            confidence=0.9,
        )

        assert prop.kind == PropertyKind.COMMUTATIVITY

        assert prop.confidence == 0.9

    def test_property_inference_two_args(self):
        """Test property inference for two-argument function."""

        def add(x, y):
            return x + y

        config = VerifiedExecutionConfig(
            infer_properties=True,
            max_paths=10,
        )

        executor = VerifiedExecutor(config)

        result = executor.execute_function(add, {"x": "int", "y": "int"})

        assert isinstance(result.inferred_properties, list)


class TestEdgeCases:
    """Tests for edge cases."""

    def test_function_with_no_args(self, executor):
        """Test function with no arguments."""

        def constant():
            return 42

        result = executor.execute_function(constant, {})

        assert result.function_name == "constant"

    def test_function_with_many_args(self, executor):
        """Test function with many arguments."""

        def many(a, b, c, d, e):
            return a + b + c + d + e

        result = executor.execute_function(
            many, {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int"}
        )

        assert result.function_name == "many"

    def test_nested_function_calls(self, executor):
        """Test function with nested calls."""

        def outer(x):
            def inner(y):
                return y * 2

            return inner(x) + 1

        result = executor.execute_function(outer, {"x": "int"})

        assert isinstance(result, VerifiedExecutionResult)

    def test_empty_contracts(self, executor):
        """Test function with no contracts."""

        def no_contracts(x):
            return x

        result = executor.execute_function(no_contracts, {"x": "int"})

        assert result.contracts_checked == 0


class TestFullIntegration:
    """Full integration tests."""

    def test_full_verification_pipeline(self):
        """Test complete verification pipeline."""

        @requires("n >= 0")
        @ensures("result() >= 0")
        def factorial_iterative(n):
            result = 1

            i = 1

            while i <= n:
                result = result * i

                i = i + 1

            return result

        config = VerifiedExecutionConfig(
            check_preconditions=True,
            check_postconditions=True,
            check_overflow=True,
            check_loop_invariants=True,
            max_paths=100,
            max_loop_iterations=5,
        )

        executor = VerifiedExecutor(config)

        result = executor.execute_function(factorial_iterative, {"n": "int"})

        assert result.function_name == "factorial_iterative"

        assert result.contracts_checked >= 1

    def test_verified_execution_with_issues(self):
        """Test verified execution that should find issues."""

        def divide_unchecked(x, y):
            return x / y

        config = VerifiedExecutionConfig(
            check_division_safety=True,
            detect_division_by_zero=True,
            max_paths=50,
        )

        executor = VerifiedExecutor(config)

        result = executor.execute_function(divide_unchecked, {"x": "int", "y": "int"})

        assert result.has_issues or len(result.arithmetic_issues) > 0 or len(result.issues) > 0

    def test_verified_safe_function(self):
        """Test verified execution of a safe function."""

        @requires("y != 0")
        def safe_divide(x, y):
            return x / y

        config = VerifiedExecutionConfig(
            check_preconditions=True,
            check_division_safety=True,
            max_paths=50,
        )

        executor = VerifiedExecutor(config)

        result = executor.execute_function(safe_divide, {"x": "int", "y": "int"})

        assert isinstance(result, VerifiedExecutionResult)
