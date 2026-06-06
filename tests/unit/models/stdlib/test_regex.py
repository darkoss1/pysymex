from __future__ import annotations


import z3

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.scalars.strings import SymbolicString

from pysymex.models.stdlib import regex as regex_models


def _state() -> VMState:
    return VMState(pc=0)


def _assert_result(fn: object) -> None:
    assert callable(fn)
    result = fn()
    assert hasattr(result, "value")


class TestPatternCompiler:
    """Test suite for pysymex.models.stdlib.regex.PatternCompiler."""

    def test_faithfulness(self) -> None:
        compiler = regex_models.PatternCompiler()
        pattern = compiler.compile(r"ab+c")
        assert isinstance(pattern, z3.ReRef)

    def test_error_path(self) -> None:
        compiler = regex_models.PatternCompiler()
        pattern = compiler.compile("")
        assert isinstance(pattern, z3.ReRef)


def test_compile_pattern() -> None:
    """Test compile_pattern behavior."""
    pattern = regex_models.compile_pattern(r"a|b")
    assert isinstance(pattern, z3.ReRef)


class TestReMatchModel:
    """Test suite for pysymex.models.stdlib.regex.ReMatchModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("abc")
        _assert_result(lambda: regex_models.ReMatchModel().apply(["a", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: regex_models.ReMatchModel().apply([], {}, _state()))

    def test_matching_result_is_truthy(self) -> None:
        result = regex_models.ReMatchModel().apply(
            [SymbolicString.from_const("0+"), SymbolicString.from_const("00")], {}, _state()
        )
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(*result.constraints, z3.Not(result.value.could_be_truthy()))
        assert solver.check() == z3.unsat

    def test_nonmatching_result_is_falsy(self) -> None:
        result = regex_models.ReMatchModel().apply(
            [SymbolicString.from_const("0+"), SymbolicString.from_const("10")], {}, _state()
        )
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(*result.constraints, result.value.could_be_truthy())
        assert solver.check() == z3.unsat


class TestReSearchModel:
    """Test suite for pysymex.models.stdlib.regex.ReSearchModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("abc")
        _assert_result(lambda: regex_models.ReSearchModel().apply(["b", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: regex_models.ReSearchModel().apply([], {}, _state()))

    def test_matching_result_is_truthy(self) -> None:
        result = regex_models.ReSearchModel().apply(
            [SymbolicString.from_const("0+"), SymbolicString.from_const("a0")], {}, _state()
        )
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(*result.constraints, z3.Not(result.value.could_be_truthy()))
        assert solver.check() == z3.unsat

    def test_nonmatching_result_is_falsy(self) -> None:
        result = regex_models.ReSearchModel().apply(
            [SymbolicString.from_const("0+"), SymbolicString.from_const("abc")], {}, _state()
        )
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(*result.constraints, result.value.could_be_truthy())
        assert solver.check() == z3.unsat


class TestReFullmatchModel:
    """Test suite for pysymex.models.stdlib.regex.ReFullmatchModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("abc")
        _assert_result(lambda: regex_models.ReFullmatchModel().apply(["abc", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: regex_models.ReFullmatchModel().apply([], {}, _state()))

    def test_matching_result_is_truthy(self) -> None:
        result = regex_models.ReFullmatchModel().apply(
            [SymbolicString.from_const("abc"), SymbolicString.from_const("abc")], {}, _state()
        )
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(*result.constraints, z3.Not(result.value.could_be_truthy()))
        assert solver.check() == z3.unsat

    def test_nonmatching_result_is_falsy(self) -> None:
        result = regex_models.ReFullmatchModel().apply(
            [SymbolicString.from_const("abc"), SymbolicString.from_const("xyz")], {}, _state()
        )
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(*result.constraints, result.value.could_be_truthy())
        assert solver.check() == z3.unsat


class TestReFindallModel:
    """Test suite for pysymex.models.stdlib.regex.ReFindallModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("abca")
        _assert_result(lambda: regex_models.ReFindallModel().apply(["a", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: regex_models.ReFindallModel().apply([], {}, _state()))


class TestReSubModel:
    """Test suite for pysymex.models.stdlib.regex.ReSubModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("abc")
        _assert_result(lambda: regex_models.ReSubModel().apply(["a", "x", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: regex_models.ReSubModel().apply([], {}, _state()))


class TestReSplitModel:
    """Test suite for pysymex.models.stdlib.regex.ReSplitModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("a,b,c")
        _assert_result(lambda: regex_models.ReSplitModel().apply([",", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: regex_models.ReSplitModel().apply([], {}, _state()))


class TestReCompileModel:
    """Test suite for pysymex.models.stdlib.regex.ReCompileModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: regex_models.ReCompileModel().apply(["abc"], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: regex_models.ReCompileModel().apply([], {}, _state()))


class TestReEscapeModel:
    """Test suite for pysymex.models.stdlib.regex.ReEscapeModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("a+b")
        _assert_result(lambda: regex_models.ReEscapeModel().apply([s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: regex_models.ReEscapeModel().apply([], {}, _state()))
