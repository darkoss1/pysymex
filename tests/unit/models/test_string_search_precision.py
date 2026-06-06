from __future__ import annotations

import z3

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel


def _endswith_model() -> FunctionModel:
    from pysymex.models.containers.strings.search.affixes import StrEndswithModel

    return StrEndswithModel()


def _rfind_model() -> FunctionModel:
    from pysymex.models.containers.strings.search.indexing import StrRfindModel

    return StrRfindModel()


def test_symbolic_rfind_missing_is_infeasible_when_string_has_suffix() -> None:
    text, text_constraint = SymbolicString.symbolic("text")

    endswith = _endswith_model().apply([text, "a"], {}, VMState(pc=10))
    assert isinstance(endswith.value, SymbolicValue)
    rfind = _rfind_model().apply([text, "a"], {}, VMState(pc=20))
    assert isinstance(rfind.value, SymbolicValue)

    solver = z3.Solver()
    solver.add(text_constraint, *endswith.constraints, *rfind.constraints)
    solver.add(endswith.value.z3_bool, rfind.value.z3_int == -1)

    assert solver.check() == z3.unsat


def test_symbolic_rfind_missing_remains_feasible_without_substring() -> None:
    text, text_constraint = SymbolicString.symbolic("text")

    rfind = _rfind_model().apply([text, "a"], {}, VMState(pc=20))
    assert isinstance(rfind.value, SymbolicValue)

    solver = z3.Solver()
    solver.add(text_constraint, *rfind.constraints)
    solver.add(text.z3_str == z3.StringVal("bbb"), rfind.value.z3_int == -1)

    assert solver.check() == z3.sat


def test_symbolic_rfind_empty_substring_returns_length() -> None:
    text, text_constraint = SymbolicString.symbolic("text")

    rfind = _rfind_model().apply([text, ""], {}, VMState(pc=20))
    assert isinstance(rfind.value, SymbolicValue)

    solver = z3.Solver()
    solver.add(text_constraint, *rfind.constraints)
    solver.add(rfind.value.z3_int != text.z3_len)

    assert solver.check() == z3.unsat
