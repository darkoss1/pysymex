import z3

from pysymex.analysis.runtime.summaries.builder import SummaryBuilder
from pysymex.analysis.runtime.summaries.builtins import (
    create_builtin_summaries,
    register_builtin_summaries,
)
from pysymex.analysis.runtime.summaries.composition import compose_summaries
from pysymex.analysis.runtime.summaries.instantiation import instantiate_summary
from pysymex.analysis.runtime.summaries.registry import (
    SummaryRegistry,
    get_summary,
    register_summary,
)
from pysymex.analysis.runtime.summaries.types import CallSite, FunctionSummary


class TestSummaryBuilder:
    """Test suite for pysymex.analysis.runtime.summaries.builder.SummaryBuilder."""

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

    def test_clone_copies_mutable_builder_state(self) -> None:
        original = (
            SummaryBuilder("f")
            .set_initial_args([{"x": 1}])
            .add_parameter("x", "int")
            .require(z3.BoolVal(True))
        )

        clone = original.clone()
        clone.add_parameter("y", "int").ensure(z3.BoolVal(False))
        clone.initial_args.append({"y": 2})

        assert clone is not original
        assert clone.build() is not original.build()
        assert [param.name for param in original.build().parameters] == ["x"]
        assert [param.name for param in clone.build().parameters] == ["x", "y"]
        assert len(original.build().postconditions) == 0
        assert len(clone.build().postconditions) == 1
        assert original.initial_args == [{"x": 1}]


class TestSummaryRegistry:
    """Test suite for pysymex.analysis.runtime.summaries.registry.SummaryRegistry."""

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

    def test_register_reindexes_summary_when_module_changes(self) -> None:
        """Scenario: same key moves module; expected old module index is not stale."""
        r = SummaryRegistry()
        first = FunctionSummary("f", module="mod1")
        second = FunctionSummary("f", module="mod2")

        r.register(first)
        r.register(second)

        assert r.get("f") is second
        assert r.get_for_module("mod1") == []
        assert r.get_for_module("mod2") == [second]

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


def test_compose_summaries_uses_stable_unknown_argument_names() -> None:
    """Unknown call placeholders must be deterministic for reproducible diagnostics."""
    outer = FunctionSummary("outer")
    inner = SummaryBuilder("inner").add_parameter("x", "int").require(z3.Int("x") > 0).build()
    call = CallSite("inner", args=[object()], pc=42)

    first = compose_summaries(outer, call, inner)
    second = compose_summaries(outer, call, inner)

    assert len(first.preconditions) == 1
    assert len(second.preconditions) == 1
    assert first.preconditions[0].sexpr() == second.preconditions[0].sexpr()
    assert "outer_inner_42_unknown_arg_0" in first.preconditions[0].sexpr()


def test_compose_summaries_uses_stable_return_names() -> None:
    """Composed return constraints should not contain random summary instantiation names."""
    outer = FunctionSummary("outer")
    inner = SummaryBuilder("inner").add_parameter("x", "int").build()
    assert inner.return_var is not None
    inner.return_constraint = inner.return_var > z3.Int("x")
    call = CallSite("inner", args=[z3.Int("arg")], pc=42)

    first = compose_summaries(outer, call, inner)
    second = compose_summaries(outer, call, inner)

    assert len(first.postconditions) == 1
    assert len(second.postconditions) == 1
    assert first.postconditions[0].sexpr() == second.postconditions[0].sexpr()
    assert "inner_ret_outer_inner_42_ret" in first.postconditions[0].sexpr()


def test_instantiate_summary() -> None:
    """Test instantiate_summary behavior."""
    s = SummaryBuilder("f").add_parameter("x", "int").build()
    _pre, _post, ret = instantiate_summary(s, [z3.IntVal(1)], {})
    assert ret is not None


def test_instantiate_summary_default_return_names_are_deterministic_and_fresh() -> None:
    """Default return names use the shared monotonic fresh-name counter."""
    s = SummaryBuilder("f").add_parameter("x", "int").build()
    _pre, _post, first = instantiate_summary(s, [z3.IntVal(1)], {})
    _pre, _post, second = instantiate_summary(s, [z3.IntVal(2)], {})

    assert first is not None
    assert second is not None
    assert first.decl().name().startswith("f_ret_")
    assert second.decl().name().startswith("f_ret_")
    assert second.decl().name() != first.decl().name()


def test_create_builtin_summaries() -> None:
    """Test create_builtin_summaries behavior."""
    summaries = create_builtin_summaries()
    assert len(summaries) > 0


def test_register_builtin_summaries() -> None:
    """Test register_builtin_summaries behavior."""
    register_builtin_summaries()
    assert get_summary("builtins.len") is not None
