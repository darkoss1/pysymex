"""Tests for pysymex._compat — cross-version compatibility helpers."""

from __future__ import annotations

import dis
import sys

from pysymex._compat import batched, get_starts_line


class TestBatched:
    """Tests for the batched() polyfill."""

    def test_exact_division(self) -> None:
        """Batching 6 items into groups of 3 yields two full tuples."""
        result = list(batched([1, 2, 3, 4, 5, 6], 3))
        assert result == [(1, 2, 3), (4, 5, 6)]

    def test_remainder_batch(self) -> None:
        """When items don't divide evenly, the last batch is shorter."""
        result = list(batched([1, 2, 3, 4, 5], 2))
        assert result == [(1, 2), (3, 4), (5,)]

    def test_single_element_batches(self) -> None:
        """Batch size of 1 yields one-element tuples."""
        result = list(batched("abc", 1))
        assert result == [("a",), ("b",), ("c",)]

    def test_empty_iterable(self) -> None:
        """Batching an empty iterable yields nothing."""
        result = list(batched([], 3))
        assert result == []

    def test_batch_size_larger_than_input(self) -> None:
        """When batch size exceeds input length, one batch with all items."""
        result = list(batched([1, 2], 10))
        assert result == [(1, 2)]

    def test_invalid_batch_size_zero(self) -> None:
        """Batch size of 0 raises ValueError."""
        import pytest

        with pytest.raises(ValueError, match="at least one"):
            list(batched([1, 2], 0))

    def test_invalid_batch_size_negative(self) -> None:
        """Batch size of -1 raises ValueError."""
        import pytest

        with pytest.raises(ValueError, match="at least one"):
            list(batched([1, 2], -1))

    def test_generator_input(self) -> None:
        """Batching a generator works correctly."""
        gen = (x for x in range(5))
        result = list(batched(gen, 2))
        assert result == [(0, 1), (2, 3), (4,)]


class TestGetStartsLine:
    """Tests for get_starts_line() normalisation wrapper."""

    def test_returns_int_or_none(self) -> None:
        """get_starts_line always returns int or None regardless of Python version."""
        code = compile("x = 1", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        for instr in instructions:
            result = get_starts_line(instr)
            assert result is None or isinstance(result, int)

    def test_multiline_code_has_line_info(self) -> None:
        """Multi-line code has at least one instruction with line info on Python <=3.12.

        On Python 3.13+, starts_line is a bool, so get_starts_line returns
        None for all instructions (the line info is accessed via .line_number).
        """
        code = compile("x = 1\ny = 2\nz = x + y", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        results = [get_starts_line(instr) for instr in instructions]

        if sys.version_info >= (3, 13):
            # On 3.13+, starts_line is bool → get_starts_line returns None
            assert all(r is None for r in results)
        else:
            # On <=3.12, starts_line is int | None
            int_results = [r for r in results if isinstance(r, int)]
            assert len(int_results) >= 1

    def test_never_returns_bool(self) -> None:
        """get_starts_line never returns a bool, even on 3.13+."""
        code = compile("x = 1", "<test>", "exec")
        for instr in dis.get_instructions(code):
            result = get_starts_line(instr)
            if result is not None:
                assert not isinstance(result, bool)
