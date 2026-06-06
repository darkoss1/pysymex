import dis
import os
import tempfile
from types import CodeType
from typing import Protocol, cast

from pysymex.analysis.domains.exceptions.analyzer.ast import ExceptionASTAnalyzer
from pysymex.analysis.domains.exceptions.analyzer.bytecode import (
    ExceptionBytecodeAnalyzer,
    catches_name,
    infer_caught_at,
    infer_with_manager_call_at,
)
from pysymex.analysis.domains.exceptions.analyzer.chain import ExceptionChainAnalyzer
from pysymex.analysis.domains.exceptions.analyzer.core import ExceptionAnalyzer
from pysymex.analysis.domains.exceptions.analyzer.uncaught import UncaughtExceptionAnalyzer
from pysymex.analysis.domains.exceptions.types import ExceptionWarningKind


class _ExceptionEntry(Protocol):
    start: int
    end: int
    target: int


def make_dummy_code() -> CodeType:
    def f() -> None:
        try:
            _x = 1 / 0
        except ZeroDivisionError:
            pass

    return f.__code__


class TestExceptionASTAnalyzer:
    """Test suite for ExceptionASTAnalyzer."""

    def test_visit_FunctionDef(self) -> None:
        """Test visit_FunctionDef behavior."""
        analyzer = ExceptionASTAnalyzer("test.py")
        source = "def foo():\n    raise ValueError"
        analyzer.analyze(source)
        assert "ValueError" in analyzer.function_raises["foo"]

    def test_visit_AsyncFunctionDef(self) -> None:
        """Test visit_AsyncFunctionDef behavior."""
        analyzer = ExceptionASTAnalyzer("test.py")
        source = "async def foo():\n    raise TypeError"
        analyzer.analyze(source)
        assert "TypeError" in analyzer.function_raises["foo"]

    def test_visit_Try(self) -> None:
        """Test visit_Try behavior."""
        analyzer = ExceptionASTAnalyzer("test.py")
        source = """
try:
    raise ValueError
except:
    pass
finally:
    return 1
        """
        warnings = analyzer.analyze(source)
        kinds = [w.kind for w in warnings]
        assert ExceptionWarningKind.BARE_EXCEPT in kinds
        assert ExceptionWarningKind.FINALLY_RETURN in kinds
        assert ExceptionWarningKind.EXCEPTION_SWALLOWED in kinds

    def test_visit_Raise(self) -> None:
        """Test visit_Raise behavior."""
        analyzer = ExceptionASTAnalyzer("test.py")
        source = "def f():\n    raise Exception('foo')"
        analyzer.analyze(source)
        assert "Exception" in analyzer.function_raises["f"]

    def test_analyze(self) -> None:
        """Test analyze behavior."""
        analyzer = ExceptionASTAnalyzer("test.py")
        warnings = analyzer.analyze("try:\n    pass\nexcept BaseException:\n    pass")
        assert len(warnings) > 0
        assert any(w.kind == ExceptionWarningKind.TOO_BROAD_EXCEPT for w in warnings)

    def test_analyze_reports_duplicate_named_except_handler(self) -> None:
        analyzer = ExceptionASTAnalyzer("test.py")
        warnings = analyzer.analyze(
            "try:\n"
            "    int('x')\n"
            "except ValueError:\n"
            "    print('first')\n"
            "except ValueError:\n"
            "    print('second')\n"
        )

        assert any(w.kind == ExceptionWarningKind.DUPLICATE_EXCEPT for w in warnings)

    def test_analyze_reports_unreachable_specific_after_broad_handler(self) -> None:
        analyzer = ExceptionASTAnalyzer("test.py")
        warnings = analyzer.analyze(
            "try:\n"
            "    int('x')\n"
            "except Exception:\n"
            "    print('broad')\n"
            "except ValueError:\n"
            "    print('specific')\n"
        )

        assert any(w.kind == ExceptionWarningKind.UNREACHABLE_EXCEPT for w in warnings)


class TestExceptionBytecodeAnalyzer:
    """Test suite for ExceptionBytecodeAnalyzer."""

    def test_analyze(self) -> None:
        """Test analyze behavior."""
        analyzer = ExceptionBytecodeAnalyzer()
        code = make_dummy_code()
        warnings = analyzer.analyze(code)
        assert isinstance(warnings, list)
        assert len(warnings) == 0

    def test_infer_caught_at_handles_tuple_exceptions(self) -> None:
        """Tuple except clauses should be inferred as multiple caught types."""

        def target(x: int) -> int:
            try:
                return 10 // x
            except (ZeroDivisionError, ValueError):
                return 0

        instructions = list(dis.get_instructions(target))
        entries = cast(
            list[_ExceptionEntry],
            list(getattr(dis.Bytecode(target), "exception_entries", ())),
        )
        assert entries
        caught = infer_caught_at(instructions, entries[0].target)
        assert "ZeroDivisionError" in caught
        assert "ValueError" in caught

    def test_infer_caught_at_does_not_treat_finally_cleanup_as_catch(self) -> None:
        """A try/finally cleanup target runs for exceptions but does not catch them."""

        def target(x: int) -> int:
            value = 0
            try:
                value = 10 // x
            finally:
                value += 1
            return value

        instructions = list(dis.get_instructions(target))
        entries = cast(
            list[_ExceptionEntry],
            list(getattr(dis.Bytecode(target), "exception_entries", ())),
        )
        assert entries
        caught = infer_caught_at(instructions, entries[0].target)
        assert caught == set()

    def test_infer_caught_at_treats_bare_except_as_catch_all(self) -> None:
        """Bare except handlers have no CHECK_EXC_MATCH but do catch exceptions."""

        def target(x: int) -> int:
            try:
                return 10 // x
            except:  # noqa: E722 - this fixture intentionally exercises bare-except bytecode.
                return 0

        instructions = list(dis.get_instructions(target))
        entries = cast(
            list[_ExceptionEntry],
            list(getattr(dis.Bytecode(target), "exception_entries", ())),
        )
        assert entries
        caught = infer_caught_at(instructions, entries[0].target)
        assert caught == {"BaseException"}

    def test_infer_caught_at_does_not_treat_except_cleanup_as_catch(self) -> None:
        """An exception raised inside an except body escapes its cleanup epilogue."""

        def target(x: int) -> int:
            try:
                raise ValueError("body")
            except ValueError:
                return 10 // x

        instructions = list(dis.get_instructions(target))
        division = next(instr for instr in instructions if instr.opname == "BINARY_OP")
        entries = cast(
            list[_ExceptionEntry],
            list(getattr(dis.Bytecode(target), "exception_entries", ())),
        )
        cleanup_entry = next(
            entry for entry in entries if entry.start <= division.offset < entry.end
        )

        assert infer_caught_at(instructions, cleanup_entry.target) == set()

    def test_catches_name_uses_builtin_exception_subclass_relationships(self) -> None:
        assert catches_name("KeyError", {"LookupError"}) is True
        assert catches_name("FileNotFoundError", {"OSError"}) is True
        assert catches_name("NotImplementedError", {"RuntimeError"}) is True
        assert catches_name("ValueError", {"LookupError"}) is False

    def test_infer_with_manager_call_at_handles_local_manager_call_layout(self) -> None:
        def target() -> int:
            class SuppressZero:
                def __enter__(self) -> object:
                    return self

                def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
                    _ = exc, tb
                    return exc_type is ZeroDivisionError

            with SuppressZero():
                _ = 1 / 0
            return 5

        instructions = list(dis.get_instructions(target))
        division = next(instr for instr in instructions if instr.opname == "BINARY_OP")
        entries = cast(
            list[_ExceptionEntry],
            list(getattr(dis.Bytecode(target), "exception_entries", ())),
        )
        entry = next(entry for entry in entries if entry.start <= division.offset < entry.end)

        assert infer_with_manager_call_at(instructions, entry.start, entry.target) == (
            "SuppressZero",
            (),
        )


class TestUncaughtExceptionAnalyzer:
    """Test suite for UncaughtExceptionAnalyzer."""

    @staticmethod
    def _single_function_code(source: str) -> CodeType:
        module_code = compile(source, "<uncaught-exception-test>", "exec")
        code_objects = [const for const in module_code.co_consts if isinstance(const, CodeType)]
        assert len(code_objects) == 1
        return code_objects[0]

    def test_analyze(self) -> None:
        """Test analyze behavior."""
        analyzer = UncaughtExceptionAnalyzer()
        module_code = compile(
            "def f(obj):\n    x = obj.missing_attr\n",
            "<exception-test>",
            "exec",
        )
        code_objects = [const for const in module_code.co_consts if isinstance(const, CodeType)]
        assert len(code_objects) == 1
        code = code_objects[0]
        potential = analyzer.analyze(code)
        assert len(potential) > 0
        has_attr = any("AttributeError" in errs for errs in potential.values())
        assert has_attr is True
        assert isinstance(potential, dict)

    def test_analyze_detects_current_binary_op_zero_division(self) -> None:
        analyzer = UncaughtExceptionAnalyzer()
        expressions = ["1 / x", "1 // x", "1 % x"]

        for expression in expressions:
            code = self._single_function_code(f"def f(x):\n    return {expression}\n")
            potential = analyzer.analyze(code)

            assert any("ZeroDivisionError" in errors for errors in potential.values())

    def test_analyze_suppresses_caught_current_binary_op_zero_division(self) -> None:
        analyzer = UncaughtExceptionAnalyzer()
        code = self._single_function_code(
            "def f(x):\n"
            "    try:\n"
            "        return 1 / x\n"
            "    except ZeroDivisionError:\n"
            "        return 0\n"
        )

        potential = analyzer.analyze(code)

        assert not any("ZeroDivisionError" in errors for errors in potential.values())

    def test_analyze_reports_binary_op_zero_division_caught_by_unrelated_exception(self) -> None:
        analyzer = UncaughtExceptionAnalyzer()
        code = self._single_function_code(
            "def f(x):\n    try:\n        return 1 / x\n    except ValueError:\n        return 0\n"
        )

        potential = analyzer.analyze(code)

        assert any("ZeroDivisionError" in errors for errors in potential.values())


class TestExceptionChainAnalyzer:
    """Test suite for ExceptionChainAnalyzer."""

    def test_analyze_source(self) -> None:
        """Test analyze_source behavior."""
        analyzer = ExceptionChainAnalyzer()
        warnings = analyzer.analyze_source("raise ValueError from e")
        assert isinstance(warnings, list)
        assert len(warnings) == 0

    def test_analyze_source_warns_on_different_exception_without_explicit_chain(self) -> None:
        analyzer = ExceptionChainAnalyzer()
        warnings = analyzer.analyze_source(
            "try:\n    int('x')\nexcept ValueError as exc:\n    raise RuntimeError('wrapped')\n",
            "sample.py",
        )

        assert len(warnings) == 1
        warning = warnings[0]
        assert warning.kind == ExceptionWarningKind.RERAISE_DIFFERENT_TYPE
        assert warning.file == "sample.py"
        assert warning.line == 4
        assert warning.exception_type == "RuntimeError"

    def test_analyze_source_accepts_explicit_chain(self) -> None:
        analyzer = ExceptionChainAnalyzer()
        warnings = analyzer.analyze_source(
            "try:\n"
            "    int('x')\n"
            "except ValueError as exc:\n"
            "    raise RuntimeError('wrapped') from exc\n"
        )

        assert warnings == []

    def test_analyze_source_accepts_bare_reraise(self) -> None:
        analyzer = ExceptionChainAnalyzer()
        warnings = analyzer.analyze_source("try:\n    int('x')\nexcept ValueError:\n    raise\n")

        assert warnings == []


class TestExceptionAnalyzer:
    """Test suite for ExceptionAnalyzer."""

    def test_analyze_source(self) -> None:
        """Test analyze_source behavior."""
        analyzer = ExceptionAnalyzer()
        warnings = analyzer.analyze_source("try:\n    pass\nexcept:\n    pass")
        assert len(warnings) > 0
        assert any(w.kind == ExceptionWarningKind.BARE_EXCEPT for w in warnings)

    def test_analyze_function(self) -> None:
        """Test analyze_function behavior."""
        analyzer = ExceptionAnalyzer()
        code = make_dummy_code()
        warnings = analyzer.analyze_function(code)
        assert isinstance(warnings, list)

    def test_analyze_file(self) -> None:
        """Test analyze_file behavior."""
        analyzer = ExceptionAnalyzer()
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".py") as f:
            f.write("try:\n    pass\nexcept:\n    pass")
            name = f.name

        try:
            warnings = analyzer.analyze_file(name)
            assert len(warnings) > 0
            assert any(w.kind == ExceptionWarningKind.BARE_EXCEPT for w in warnings)
        finally:
            os.remove(name)

    def test_get_potential_exceptions(self) -> None:
        """Test get_potential_exceptions behavior."""
        analyzer = ExceptionAnalyzer()
        code = make_dummy_code()
        pot = analyzer.get_potential_exceptions(code)
        assert isinstance(pot, dict)
