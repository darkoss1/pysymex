from __future__ import annotations

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.stdlib.regex.compiler import PatternCompiler, compile_pattern
from pysymex._internal.models.stdlib.regex.matching import (
    ReFullmatchModel,
    ReMatchModel,
    ReSearchModel,
)
from pysymex._internal.models.stdlib.regex.registry import ReCompileModel, ReEscapeModel
from pysymex._internal.models.stdlib.regex.sequences import ReFindallModel, ReSplitModel, ReSubModel


def _state() -> VMState:
    return VMState(pc=0)


def _assert_result(fn: object) -> None:
    assert callable(fn)
    result = fn()
    assert hasattr(result, "value")


class TestPatternCompiler:
    """Test suite for pysymex._internal.models.stdlib.regex.PatternCompiler."""

    def test_faithfulness(self) -> None:
        compiler = PatternCompiler()
        pattern = compiler.compile(r"ab+c")
        assert isinstance(pattern, z3.ReRef)

    def test_error_path(self) -> None:
        compiler = PatternCompiler()
        pattern = compiler.compile("")
        assert isinstance(pattern, z3.ReRef)


def test_compile_pattern() -> None:
    """Test compile_pattern behavior."""
    pattern = compile_pattern(r"a|b")
    assert isinstance(pattern, z3.ReRef)


class TestReMatchModel:
    """Test suite for pysymex._internal.models.stdlib.regex.ReMatchModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("abc")
        _assert_result(lambda: ReMatchModel().apply(["a", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: ReMatchModel().apply([], {}, _state()))

    def test_matching_result_is_truthy(self) -> None:
        result = ReMatchModel().apply(
            [SymbolicString.from_const("0+"), SymbolicString.from_const("00")], {}, _state()
        )
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(*result.constraints, z3.Not(result.value.could_be_truthy()))
        assert solver.check() == z3.unsat

    def test_nonmatching_result_is_falsy(self) -> None:
        result = ReMatchModel().apply(
            [SymbolicString.from_const("0+"), SymbolicString.from_const("10")], {}, _state()
        )
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(*result.constraints, result.value.could_be_truthy())
        assert solver.check() == z3.unsat


class TestReSearchModel:
    """Test suite for pysymex._internal.models.stdlib.regex.ReSearchModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("abc")
        _assert_result(lambda: ReSearchModel().apply(["b", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: ReSearchModel().apply([], {}, _state()))

    def test_matching_result_is_truthy(self) -> None:
        result = ReSearchModel().apply(
            [SymbolicString.from_const("0+"), SymbolicString.from_const("a0")], {}, _state()
        )
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(*result.constraints, z3.Not(result.value.could_be_truthy()))
        assert solver.check() == z3.unsat

    def test_nonmatching_result_is_falsy(self) -> None:
        result = ReSearchModel().apply(
            [SymbolicString.from_const("0+"), SymbolicString.from_const("abc")], {}, _state()
        )
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(*result.constraints, result.value.could_be_truthy())
        assert solver.check() == z3.unsat


class TestReFullmatchModel:
    """Test suite for pysymex._internal.models.stdlib.regex.ReFullmatchModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("abc")
        _assert_result(lambda: ReFullmatchModel().apply(["abc", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: ReFullmatchModel().apply([], {}, _state()))

    def test_matching_result_is_truthy(self) -> None:
        result = ReFullmatchModel().apply(
            [SymbolicString.from_const("abc"), SymbolicString.from_const("abc")], {}, _state()
        )
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(*result.constraints, z3.Not(result.value.could_be_truthy()))
        assert solver.check() == z3.unsat

    def test_nonmatching_result_is_falsy(self) -> None:
        result = ReFullmatchModel().apply(
            [SymbolicString.from_const("abc"), SymbolicString.from_const("xyz")], {}, _state()
        )
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(*result.constraints, result.value.could_be_truthy())
        assert solver.check() == z3.unsat


class TestReFindallModel:
    """Test suite for pysymex._internal.models.stdlib.regex.ReFindallModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("abca")
        _assert_result(lambda: ReFindallModel().apply(["a", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: ReFindallModel().apply([], {}, _state()))


class TestReSubModel:
    """Test suite for pysymex._internal.models.stdlib.regex.ReSubModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("abc")
        _assert_result(lambda: ReSubModel().apply(["a", "x", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: ReSubModel().apply([], {}, _state()))


class TestReSplitModel:
    """Test suite for pysymex._internal.models.stdlib.regex.ReSplitModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("a,b,c")
        _assert_result(lambda: ReSplitModel().apply([",", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: ReSplitModel().apply([], {}, _state()))


class TestReCompileModel:
    """Test suite for pysymex._internal.models.stdlib.regex.ReCompileModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: ReCompileModel().apply(["abc"], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: ReCompileModel().apply([], {}, _state()))


class TestReEscapeModel:
    """Test suite for pysymex._internal.models.stdlib.regex.ReEscapeModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("a+b")
        _assert_result(lambda: ReEscapeModel().apply([s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: ReEscapeModel().apply([], {}, _state()))
