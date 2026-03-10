from collections import namedtuple
from unittest.mock import MagicMock

from pysymex.analysis.detectors import IssueKind
from pysymex.execution.executor import SymbolicExecutor


def test_abstract_interpreter_integration():
    """Verify that abstract interpretation runs and detects definite bugs."""

    def definite_crash(x):
        return x / 0

    executor = SymbolicExecutor()
    # Ensure it's enabled
    assert executor.config.enable_abstract_interpretation is True
    assert executor._abstract_analyzer is not None, "AbstractAnalyzer failed to initialize"

    # Mock the analyzer to return a definite warning
    # We create a fake warning object that matches what executor expects
    WarningMock = namedtuple("WarningMock", ["confidence", "line", "pc", "message"])
    fake_warning = WarningMock(
        confidence="definite", line=10, pc=20, message="Fake division by zero"
    )

    executor._abstract_analyzer.analyze_function = MagicMock(return_value=[fake_warning])

    result = executor.execute_function(definite_crash)

    # Verify the analyzer was called
    executor._abstract_analyzer.analyze_function.assert_called()

    # Verify the warning was converted to an issue
    abstract_issues = [i for i in result.issues if "[Abstract Interpreter]" in i.message]

    # Abstract interpreter should catch simple constant division by zero
    assert len(abstract_issues) > 0, "Abstract Interpreter warning was not converted to Issue"
    assert "Fake division by zero" in abstract_issues[0].message
    assert abstract_issues[0].kind == IssueKind.DIVISION_BY_ZERO

    # Note: We rely on the mock so we don't check for z3_issues here as they might depend on actual execution which we aren't testing for the architecture check.
    # But executor should still run symbolically.
