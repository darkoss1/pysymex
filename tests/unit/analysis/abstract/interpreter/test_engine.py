from types import FunctionType

from pysymex.analysis.abstract.interpreter.engine import AbstractInterpreter
from pysymex.analysis.abstract.interpreter.state import DivisionByZeroWarning


def _division_warnings_for(function: FunctionType) -> list[DivisionByZeroWarning]:
    interpreter = AbstractInterpreter()
    warnings = interpreter.analyze(function.__code__, "abstract_branch_refinement.py")
    return [warning for warning in warnings if isinstance(warning, DivisionByZeroWarning)]


def test_branch_refinement_prunes_infeasible_negative_floor_division_zero() -> None:
    def target(x: int) -> int:
        if x < 0 and x > -4:
            q = x // 2
            if q == 0:
                return 1 // 0
        return 0

    assert _division_warnings_for(target) == []


def test_branch_refinement_keeps_feasible_floor_division_zero_warning() -> None:
    def target(x: int) -> int:
        if x > -2 and x < 2:
            q = x // 2
            if q == 0:
                return 1 // 0
        return 0

    warnings = _division_warnings_for(target)

    assert len(warnings) == 1
    assert warnings[0].confidence == "definite"
