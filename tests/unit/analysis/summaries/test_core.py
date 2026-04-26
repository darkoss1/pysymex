import z3
from pysymex.analysis.summaries.core import (
    SummaryBuilder,
    SummaryRegistry,
    get_summary,
    register_summary,
    compose_summaries,
    instantiate_summary,
    create_builtin_summaries,
    register_builtin_summaries,
    SummaryAnalyzer,
)
from pysymex.analysis.summaries.types import CallSite, FunctionSummary


class TestSummaryBuilder:
    """Test suite for pysymex.analysis.summaries.core.SummaryBuilder."""

    def test_initial_args(self) -> None:
        """Test initial_args behavior."""
        b = SummaryBuilder("f")
        assert b.initial_args == []

    def test_set_initial_args(self) -> None:
        """Test set_initial_args behavior."""
        b = SummaryBuilder("f").set_initial_args([1])
        assert b.initial_args == [1]

    def test_set_qualname(self) -> None:
        """Test set_qualname behavior."""
        b = SummaryBuilder("f").set_qualname("mod.f")
        assert b.build().qualname == "mod.f"

    def test_set_module(self) -> None:
        """Test set_module behavior."""
        b = SummaryBuilder("f").set_module("mod")
        assert b.build().module == "mod"

    def test_add_parameter(self) -> None:
        """Test add_parameter behavior."""
        b = SummaryBuilder("f").add_parameter("x", "int", 0)
        assert len(b.build().parameters) == 1

    def test_set_return_type(self) -> None:
        """Test set_return_type behavior."""
        b = SummaryBuilder("f").set_return_type("int")
        assert b.build().return_type == "int"

    def test_require(self) -> None:
        """Test require behavior."""
        b = SummaryBuilder("f").require(z3.BoolVal(True))
        assert len(b.build().preconditions) == 1

    def test_ensure(self) -> None:
        """Test ensure behavior."""
        b = SummaryBuilder("f").ensure(z3.BoolVal(False))
        assert len(b.build().postconditions) == 1

    def test_modifies(self) -> None:
        """Test modifies behavior."""
        b = SummaryBuilder("f").modifies("x")
        assert len(b.build().modified) == 1

    def test_reads_var(self) -> None:
        """Test reads_var behavior."""
        b = SummaryBuilder("f").reads_var("x")
        assert len(b.build().reads) == 1

    def test_calls_function(self) -> None:
        """Test calls_function behavior."""
        b = SummaryBuilder("f").calls_function("g")
        assert len(b.build().calls) == 1

    def test_may_raise_exception(self) -> None:
        """Test may_raise_exception behavior."""
        b = SummaryBuilder("f").may_raise_exception("ValueError")
        assert len(b.build().may_raise) == 1

    def test_mark_pure(self) -> None:
        """Test mark_pure behavior."""
        b = SummaryBuilder("f").mark_pure()
        assert b.build().is_pure is True

    def test_mark_recursive(self) -> None:
        """Test mark_recursive behavior."""
        b = SummaryBuilder("f").mark_recursive()
        assert b.build().is_recursive is True

    def test_set_complexity(self) -> None:
        """Test set_complexity behavior."""
        b = SummaryBuilder("f").set_complexity("O(n)")
        assert b.build().complexity == "O(n)"

    def test_set_return_constraint(self) -> None:
        """Test set_return_constraint behavior."""
        b = SummaryBuilder("f").set_return_constraint(z3.BoolVal(True))
        assert b.build().return_constraint is not None

    def test_build(self) -> None:
        """Test build behavior."""
        b = SummaryBuilder("f")
        s = b.build()
        assert s.name == "f"


class TestSummaryRegistry:
    """Test suite for pysymex.analysis.summaries.core.SummaryRegistry."""

    def test_register(self) -> None:
        """Test register behavior."""
        r = SummaryRegistry()
        s = FunctionSummary("f", module="mod")
        r.register(s)
        assert r.has("f")

    def test_get(self) -> None:
        """Test get behavior."""
        r = SummaryRegistry()
        s = FunctionSummary("f")
        r.register(s)
        assert r.get("f") is s
        assert r.get("x") is None

    def test_get_for_module(self) -> None:
        """Test get_for_module behavior."""
        r = SummaryRegistry()
        r.register(FunctionSummary("f", module="mod1"))
        assert len(r.get_for_module("mod1")) == 1

    def test_has(self) -> None:
        """Test has behavior."""
        r = SummaryRegistry()
        assert not r.has("f")
        r.register(FunctionSummary("f"))
        assert r.has("f")

    def test_all_summaries(self) -> None:
        """Test all_summaries behavior."""
        r = SummaryRegistry()
        r.register(FunctionSummary("f"))
        assert len(r.all_summaries()) == 1

    def test_clear(self) -> None:
        """Test clear behavior."""
        r = SummaryRegistry()
        r.register(FunctionSummary("f"))
        r.clear()
        assert not r.has("f")


def test_get_summary() -> None:
    """Test get_summary behavior."""
    assert get_summary("missing_f") is None


def test_register_summary() -> None:
    """Test register_summary behavior."""
    register_summary(FunctionSummary("f_global"))
    assert get_summary("f_global") is not None


def test_compose_summaries() -> None:
    """Test compose_summaries behavior."""
    outer = FunctionSummary("outer")
    inner = SummaryBuilder("inner").may_raise_exception("ValueError").build()
    call = CallSite("inner")
    comp = compose_summaries(outer, call, inner)
    assert len(comp.may_raise) == 1


def test_instantiate_summary() -> None:
    """Test instantiate_summary behavior."""
    s = SummaryBuilder("f").add_parameter("x", "int").build()
    _pre, _post, ret = instantiate_summary(s, [z3.IntVal(1)], {})
    assert ret is not None


def test_create_builtin_summaries() -> None:
    """Test create_builtin_summaries behavior."""
    summaries = create_builtin_summaries()
    assert len(summaries) > 0


def test_register_builtin_summaries() -> None:
    """Test register_builtin_summaries behavior."""
    register_builtin_summaries()
    assert get_summary("builtins.len") is not None


class TestSummaryAnalyzer:
    """Test suite for pysymex.analysis.summaries.core.SummaryAnalyzer."""

    def test_is_pure(self) -> None:
        """Test is_pure behavior."""
        register_builtin_summaries()
        a = SummaryAnalyzer()
        assert a.is_pure("builtins.len") is True

    def test_may_modify_globals(self) -> None:
        """Test may_modify_globals behavior."""
        register_builtin_summaries()
        a = SummaryAnalyzer()
        assert a.may_modify_globals("builtins.print") is True

    def test_get_called_functions(self) -> None:
        """Test get_called_functions behavior."""
        a = SummaryAnalyzer()
        assert isinstance(a.get_called_functions("f"), set)

    def test_get_transitive_calls(self) -> None:
        """Test get_transitive_calls behavior."""
        a = SummaryAnalyzer()
        assert isinstance(a.get_transitive_calls("f"), set)

    def test_check_preconditions(self) -> None:
        """Test check_preconditions behavior."""
        a = SummaryAnalyzer()
        ok, ce = a.check_preconditions("missing", [], [])
        assert ok is True
        assert ce is None
