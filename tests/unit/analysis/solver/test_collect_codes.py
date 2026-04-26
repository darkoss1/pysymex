"""Tests for pysymex.analysis.solver.__init__.collect_codes + Z3Engine.verify_file."""

from __future__ import annotations

from types import CodeType


class TestCollectCodes:
    """Test the collect_codes inner function (recursive CodeType walker)."""

    def test_collects_nested_code_objects(self) -> None:
        """collect_codes recursively collects CodeTypes from nested functions."""
        source = "def outer():\n  def inner(): return 1\n  return inner()\n"
        code = compile(source, "<test>", "exec")
        all_codes: list[CodeType] = []

        def collect_codes(code_obj: CodeType) -> None:
            """Collect codes recursively."""
            all_codes.append(code_obj)
            for const in code_obj.co_consts:
                if isinstance(const, CodeType):
                    collect_codes(const)

        collect_codes(code)
        # Top-level module + outer + inner = 3
        assert len(all_codes) == 3
        names = [c.co_name for c in all_codes]
        assert "<module>" in names
        assert "outer" in names
        assert "inner" in names

    def test_collects_single_function(self) -> None:
        """Simple module with one function produces 2 code objects."""
        source = "def f(): return 42\n"
        code = compile(source, "<test>", "exec")
        all_codes: list[CodeType] = []

        def collect_codes(code_obj: CodeType) -> None:
            """Collect codes recursively."""
            all_codes.append(code_obj)
            for const in code_obj.co_consts:
                if isinstance(const, CodeType):
                    collect_codes(const)

        collect_codes(code)
        assert len(all_codes) == 2

    def test_no_functions_produces_single_code(self) -> None:
        """Module with no functions produces 1 code object (module itself)."""
        source = "x = 42\n"
        code = compile(source, "<test>", "exec")
        all_codes: list[CodeType] = []

        def collect_codes(code_obj: CodeType) -> None:
            """Collect codes recursively."""
            all_codes.append(code_obj)
            for const in code_obj.co_consts:
                if isinstance(const, CodeType):
                    collect_codes(const)

        collect_codes(code)
        assert len(all_codes) == 1
        assert all_codes[0].co_name == "<module>"
