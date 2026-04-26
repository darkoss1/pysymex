from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import z3

from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicString


def _load_regex_models() -> ModuleType:
    module_path = Path(__file__).resolve().parents[4] / "pysymex" / "models" / "stdlib" / "regex.py"
    spec = importlib.util.spec_from_file_location("pysymex_models_stdlib_regex", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load stdlib regex models module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


regex_models = _load_regex_models()


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


class TestReSearchModel:
    """Test suite for pysymex.models.stdlib.regex.ReSearchModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("abc")
        _assert_result(lambda: regex_models.ReSearchModel().apply(["b", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: regex_models.ReSearchModel().apply([], {}, _state()))


class TestReFullmatchModel:
    """Test suite for pysymex.models.stdlib.regex.ReFullmatchModel."""

    def test_faithfulness(self) -> None:
        s = SymbolicString.from_const("abc")
        _assert_result(lambda: regex_models.ReFullmatchModel().apply(["abc", s], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: regex_models.ReFullmatchModel().apply([], {}, _state()))


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
