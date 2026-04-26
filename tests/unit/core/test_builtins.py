"""Tests for pysymex.core.builtins."""

import builtins

from pysymex.core.builtins import get_all_builtins, get_safe_builtins_for_symbolic_exec
from pysymex.core.exceptions.analyzer import BUILTIN_EXCEPTIONS


class TestGetAllBuiltins:
    def test_get_all_builtins_includes_standard_names(self) -> None:
        result = get_all_builtins()
        assert "len" in result
        assert result["len"] is builtins.len

    def test_get_all_builtins_excludes_private_names(self) -> None:
        result = get_all_builtins()
        assert "__name__" not in result

    def test_get_all_builtins_includes_exceptions(self) -> None:
        result = get_all_builtins()
        for exc_type in BUILTIN_EXCEPTIONS:
            assert exc_type.__name__ in result
            assert result[exc_type.__name__] is exc_type

    def test_get_all_builtins_includes_special_constants(self) -> None:
        result = get_all_builtins()
        assert result["True"] is True
        assert result["False"] is False
        assert result["None"] is None
        assert result["Ellipsis"] is Ellipsis
        assert result["__debug__"] is __debug__
        assert result["__build_class__"] is builtins.__build_class__
        assert result["__import__"] is builtins.__import__


class TestGetSafeBuiltinsForSymbolicExec:
    def test_get_safe_builtins_returns_all_builtins(self) -> None:
        safe_builtins = get_safe_builtins_for_symbolic_exec()
        all_builtins = get_all_builtins()
        assert safe_builtins == all_builtins
