from __future__ import annotations

import pysymex.models.builtins.functions as functions
from pysymex.analysis.type_inference import PyType, TypeKind


def _sample_raises() -> None:
    raise RuntimeError("boom")


class TestParameterInfo:
    """Test suite for pysymex.models.builtins.functions.ParameterInfo."""

    def test_faithfulness(self) -> None:
        """Initialization stores field values as provided."""
        info = functions.ParameterInfo(name="x", position=1, declared_type=PyType.int_type())
        assert info.name == "x"
        assert info.position == 1
        assert info.declared_type is not None
        assert info.declared_type.kind is TypeKind.INT

    def test_error_path(self) -> None:
        """Default factory fields are independent per instance."""
        first = functions.ParameterInfo(name="a", position=0)
        second = functions.ParameterInfo(name="b", position=1)
        first.inferred_types.add(PyType.int_type())
        assert len(first.inferred_types) == 1
        assert len(second.inferred_types) == 0


class TestFunctionSummary:
    """Test suite for pysymex.models.builtins.functions.FunctionSummary."""

    def test_faithfulness(self) -> None:
        """Parameter lookups return expected objects and declared types."""
        param = functions.ParameterInfo(name="x", position=0, declared_type=PyType.int_type())
        summary = functions.FunctionSummary(name="f", parameters=[param])
        assert summary.get_parameter("x") is param
        typ = summary.get_parameter_type("x")
        assert typ is not None
        assert typ.kind is TypeKind.INT

    def test_error_path(self) -> None:
        """Unknown parameter lookups return None."""
        summary = functions.FunctionSummary(name="f")
        assert summary.get_parameter("missing") is None
        assert summary.get_parameter_type("missing") is None


class TestFunctionSummarizer:
    """Test suite for pysymex.models.builtins.functions.FunctionSummarizer."""

    def test_faithfulness(self) -> None:
        """Summarize code captures args, varargs, kwargs, and raises side-effect flags."""
        summarizer = functions.FunctionSummarizer()
        summary = summarizer.summarize_code(_sample_raises.__code__, "sample")
        assert summary.name == "sample"
        assert summary.is_analyzed is True
        assert "Exception" in summary.may_raise

    def test_error_path(self) -> None:
        """Unknown summary names resolve to None."""
        summarizer = functions.FunctionSummarizer()
        assert summarizer.get_summary("definitely_missing") is None
