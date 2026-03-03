"""Pytest configuration and fixtures for pysymex tests."""

import pytest

import sys

from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def simple_int_params():
    """Simple integer parameter specification."""

    return {"x": "int"}


@pytest.fixture
def two_int_params():
    """Two integer parameters."""

    return {"x": "int", "y": "int"}


@pytest.fixture
def three_int_params():
    """Three integer parameters."""

    return {"x": "int", "y": "int", "z": "int"}


@pytest.fixture
def mixed_params():
    """Mixed parameter types."""

    return {"x": "int", "s": "str", "b": "bool"}


@pytest.fixture
def unsafe_division():
    """A function with unsafe division."""

    def divide(x, y):
        return x / y

    return divide


@pytest.fixture
def safe_division():
    """A function with safe (guarded) division."""

    def divide(x, y):
        if y != 0:
            return x / y

        return 0

    return divide


@pytest.fixture
def failing_assertion():
    """A function with a potentially failing assertion."""

    def check(x):
        assert x > 0

        return x * 2

    return check


@pytest.fixture
def complex_branching():
    """A function with complex branching logic."""

    def branch(x, y, z):
        result = 0

        if x > 0:
            result += 1

        if y > 0:
            result += 2

        if z > 0:
            result += 4

        return result

    return branch


class AnalysisHelper:
    """Helper class for common analysis operations."""

    @staticmethod
    def count_issues_by_kind(result, kind):
        """Count issues of a specific kind."""

        return len([i for i in result.issues if i.kind == kind])

    @staticmethod
    def get_all_counterexamples(result):
        """Get all counterexamples from issues."""

        return [i.get_counterexample() for i in result.issues]

    @staticmethod
    def has_issue_for_var(result, var_name, value):
        """Check if any issue has a counterexample with given variable value."""

        for issue in result.issues:
            ce = issue.get_counterexample()

            if ce.get(var_name) == value:
                return True

        return False


@pytest.fixture
def analysis_helper():
    """Provide analysis helper instance."""

    return AnalysisHelper()


def pytest_configure(config):
    """Configure pytest markers."""

    config.addinivalue_line("markers", "slow: marks tests as slow")

    config.addinivalue_line("markers", "integration: marks integration tests")

    config.addinivalue_line("markers", "unit: marks unit tests")
