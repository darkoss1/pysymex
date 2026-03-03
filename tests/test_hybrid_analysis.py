import pytest

from pysymex.execution.executor import SymbolicExecutor

from pysymex.analysis.detectors import IssueKind

from unittest.mock import MagicMock

from collections import namedtuple


def test_abstract_interpreter_integration():
    """Verify that abstract interpretation runs and detects definite bugs."""

    def definite_crash(x):
        return x / 0

    executor = SymbolicExecutor()

    assert executor.config.enable_abstract_interpretation is True

    assert executor._abstract_analyzer is not None, "AbstractAnalyzer failed to initialize"

    WarningMock = namedtuple("WarningMock", ["confidence", "line", "pc", "message"])

    fake_warning = WarningMock(
        confidence="definite", line=10, pc=20, message="Fake division by zero"
    )

    executor._abstract_analyzer.analyze_function = MagicMock(return_value=[fake_warning])

    result = executor.execute_function(definite_crash)

    executor._abstract_analyzer.analyze_function.assert_called()

    abstract_issues = [i for i in result.issues if "[Abstract Interpreter]" in i.message]

    assert len(abstract_issues) > 0, "Abstract Interpreter warning was not converted to Issue"

    assert "Fake division by zero" in abstract_issues[0].message

    assert abstract_issues[0].kind == IssueKind.DIVISION_BY_ZERO
