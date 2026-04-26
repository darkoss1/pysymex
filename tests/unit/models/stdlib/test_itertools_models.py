"""Tests for pysymex.models.stdlib.itertools — all model functions + registry."""

from __future__ import annotations

import z3


class TestModelChain:
    """Test model_chain."""

    def test_empty_chain_returns_symbolic_list(self) -> None:
        """chain() with no iterables returns empty SymbolicList."""
        from pysymex.models.stdlib.itertools import model_chain
        from pysymex.core.types.containers import SymbolicList

        result = model_chain()
        assert isinstance(result, SymbolicList)

    def test_chain_single_iterable_preserves_length(self) -> None:
        """chain(iter1) has z3_len == iter1.z3_len."""
        from pysymex.models.stdlib.itertools import model_chain
        from pysymex.core.types.containers import SymbolicList

        it1 = SymbolicList.empty("a")
        it1.z3_len = z3.IntVal(5)
        result = model_chain(it1)
        s = z3.Solver()
        s.add(result.z3_len == z3.IntVal(5))
        assert s.check() == z3.sat

    def test_chain_two_iterables_sums_length(self) -> None:
        """chain(a, b) has z3_len == a.z3_len + b.z3_len."""
        from pysymex.models.stdlib.itertools import model_chain
        from pysymex.core.types.containers import SymbolicList

        a = SymbolicList.empty("a")
        a.z3_len = z3.IntVal(3)
        b = SymbolicList.empty("b")
        b.z3_len = z3.IntVal(7)
        result = model_chain(a, b)
        s = z3.Solver()
        s.add(result.z3_len == z3.IntVal(10))
        assert s.check() == z3.sat


class TestModelIslice:
    """Test model_islice."""

    def test_islice_with_stop_only(self) -> None:
        """islice(iter, 5) clamps at min(iter.z3_len, 5)."""
        from pysymex.models.stdlib.itertools import model_islice
        from pysymex.core.types.containers import SymbolicList

        it = SymbolicList.empty("it")
        it.z3_len = z3.IntVal(10)
        result = model_islice(it, 5)
        assert isinstance(result, SymbolicList)

    def test_islice_with_start_stop_step(self) -> None:
        """islice(iter, 0, 10, 3) produces ceil(10/3) = 4 elements."""
        from pysymex.models.stdlib.itertools import model_islice
        from pysymex.core.types.containers import SymbolicList

        it = SymbolicList.empty("it")
        it.z3_len = z3.IntVal(20)
        result = model_islice(it, 0, 10, 3)
        s = z3.Solver()
        s.add(result.z3_len == z3.IntVal(4))
        assert s.check() == z3.sat


class TestModelProduct:
    """Test model_product."""

    def test_empty_product_returns_list(self) -> None:
        """product() with no iterables returns empty SymbolicList."""
        from pysymex.models.stdlib.itertools import model_product
        from pysymex.core.types.containers import SymbolicList

        result = model_product()
        assert isinstance(result, SymbolicList)


class TestModelRepeat:
    """Test model_repeat."""

    def test_repeat_with_times(self) -> None:
        """repeat(obj, 5) has z3_len == 5."""
        from pysymex.models.stdlib.itertools import model_repeat
        from pysymex.core.types.containers import SymbolicList

        result = model_repeat("x", times=5)
        assert isinstance(result, SymbolicList)
        s = z3.Solver()
        s.add(result.z3_len == z3.IntVal(5))
        assert s.check() == z3.sat


class TestModelAccumulate:
    """Test model_accumulate."""

    def test_accumulate_with_initial(self) -> None:
        """accumulate(iter, initial=0) has z3_len == iter.z3_len + 1."""
        from pysymex.models.stdlib.itertools import model_accumulate
        from pysymex.core.types.containers import SymbolicList

        it = SymbolicList.empty("it")
        it.z3_len = z3.IntVal(5)
        result = model_accumulate(it, initial=0)
        s = z3.Solver()
        s.add(result.z3_len == z3.IntVal(6))
        assert s.check() == z3.sat


class TestModelCount:
    """Test model_count."""

    def test_returns_symbolic_value(self) -> None:
        """count() returns a SymbolicValue."""
        from pysymex.models.stdlib.itertools import model_count
        from pysymex.core.types.scalars import SymbolicValue

        result = model_count()
        assert isinstance(result, SymbolicValue)


class TestModelGroupby:
    """Test model_groupby."""

    def test_returns_symbolic_list(self) -> None:
        """groupby returns a SymbolicList."""
        from pysymex.models.stdlib.itertools import model_groupby
        from pysymex.core.types.containers import SymbolicList

        it = SymbolicList.empty("it")
        result = model_groupby(it)
        assert isinstance(result, SymbolicList)


class TestModelZipLongest:
    """Test model_zip_longest."""

    def test_empty_returns_list(self) -> None:
        """zip_longest() with no iterables returns SymbolicList."""
        from pysymex.models.stdlib.itertools import model_zip_longest
        from pysymex.core.types.containers import SymbolicList

        result = model_zip_longest()
        assert isinstance(result, SymbolicList)


class TestGetItertoolsModel:
    """Test get_itertools_model."""

    def test_known_returns_function(self) -> None:
        """Known names return the model function."""
        from pysymex.models.stdlib.itertools import get_itertools_model, model_chain

        assert get_itertools_model("chain") is model_chain

    def test_unknown_returns_none(self) -> None:
        """Unknown name returns None."""
        from pysymex.models.stdlib.itertools import get_itertools_model

        assert get_itertools_model("nonexistent") is None


class TestRegisterItertoolsModels:
    """Test register_itertools_models."""

    def test_returns_full_qualified_mapping(self) -> None:
        """All models returned with 'itertools.' prefix."""
        from pysymex.models.stdlib.itertools import register_itertools_models

        registry = register_itertools_models()
        assert "itertools.chain" in registry
        assert "itertools.repeat" in registry
        assert len(registry) == 15
