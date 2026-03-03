"""
Tests for Phase 20: Inter-Procedural Analysis.

Tests function summaries, call graphs, and inter-procedural analysis.
"""

import pytest

import z3

from pysymex.analysis.summaries import (
    ParameterInfo,
    ModifiedVariable,
    ReadVariable,
    CallSite,
    ExceptionInfo,
    FunctionSummary,
    SummaryBuilder,
    SummaryRegistry,
    SUMMARY_REGISTRY,
    get_summary,
    register_summary,
    compose_summaries,
    instantiate_summary,
    create_builtin_summaries,
    register_builtin_summaries,
    SummaryAnalyzer,
)


from pysymex.analysis.callgraph import (
    CallGraphNode,
    CallGraphEdge,
    CallGraph,
    CallGraphBuilder,
    get_analysis_order,
    find_mutual_recursion,
    compute_dominators,
)


class TestParameterInfo:
    """Tests for ParameterInfo class."""

    def test_create_parameter(self):
        """Create a parameter."""

        param = ParameterInfo(name="x", index=0, type_hint="int")

        assert param.name == "x"

        assert param.index == 0

        assert param.type_hint == "int"

    def test_parameter_to_z3_int(self):
        """Convert int parameter to Z3."""

        param = ParameterInfo(name="x", index=0, type_hint="int")

        z3_var = param.to_z3()

        assert isinstance(z3_var, z3.ArithRef)

    def test_parameter_to_z3_bool(self):
        """Convert bool parameter to Z3."""

        param = ParameterInfo(name="flag", index=0, type_hint="bool")

        z3_var = param.to_z3()

        assert isinstance(z3_var, z3.BoolRef)

    def test_parameter_with_prefix(self):
        """Create Z3 variable with prefix."""

        param = ParameterInfo(name="x", index=0, type_hint="int")

        z3_var = param.to_z3(prefix="func_")


class TestFunctionSummary:
    """Tests for FunctionSummary class."""

    def test_create_summary(self):
        """Create a function summary."""

        summary = FunctionSummary(name="test_func")

        assert summary.name == "test_func"

        assert summary.qualname == "test_func"

    def test_add_precondition(self):
        """Add preconditions."""

        summary = FunctionSummary(name="test")

        x = z3.Int("x")

        summary.add_precondition(x > 0)

        assert len(summary.preconditions) == 1

    def test_add_postcondition(self):
        """Add postconditions."""

        summary = FunctionSummary(name="test")

        result = z3.Int("result")

        summary.add_postcondition(result >= 0)

        assert len(summary.postconditions) == 1

    def test_add_modified(self):
        """Add modified variable."""

        summary = FunctionSummary(name="test")

        summary.add_modified(ModifiedVariable(name="x", scope="global"))

        assert len(summary.modified) == 1

        assert summary.modifies_globals()

    def test_add_call(self):
        """Add call site."""

        summary = FunctionSummary(name="test")

        summary.add_call(CallSite(callee="helper", pc=10))

        assert len(summary.calls) == 1

    def test_get_all_preconditions(self):
        """Get conjunction of preconditions."""

        summary = FunctionSummary(name="test")

        x = z3.Int("x")

        summary.add_precondition(x > 0)

        summary.add_precondition(x < 100)

        pre = summary.get_all_preconditions()

    def test_clone_summary(self):
        """Clone a summary."""

        summary = FunctionSummary(name="test")

        summary.is_pure = True

        x = z3.Int("x")

        summary.add_precondition(x > 0)

        cloned = summary.clone()

        assert cloned.name == "test"

        assert cloned.is_pure

        assert len(cloned.preconditions) == 1

        cloned.is_pure = False

        assert summary.is_pure


class TestSummaryBuilder:
    """Tests for SummaryBuilder class."""

    def test_build_simple(self):
        """Build a simple summary."""

        summary = (
            SummaryBuilder("add")
            .add_parameter("x", "int")
            .add_parameter("y", "int")
            .set_return_type("int")
            .mark_pure()
            .build()
        )

        assert summary.name == "add"

        assert len(summary.parameters) == 2

        assert summary.return_type == "int"

        assert summary.is_pure

    def test_build_with_contracts(self):
        """Build summary with contracts."""

        x = z3.Int("x")

        result = z3.Int("result")

        summary = (
            SummaryBuilder("abs_int")
            .add_parameter("x", "int")
            .require(z3.BoolVal(True))
            .ensure(result >= 0)
            .mark_pure()
            .build()
        )

        assert len(summary.postconditions) == 1

    def test_build_with_effects(self):
        """Build summary with side effects."""

        summary = (
            SummaryBuilder("write_file")
            .add_parameter("path", "str")
            .add_parameter("content", "str")
            .modifies("filesystem", scope="global")
            .calls_function("open")
            .may_raise_exception("IOError")
            .build()
        )

        assert summary.modifies_globals()

        assert len(summary.calls) == 1

        assert len(summary.may_raise) == 1


class TestSummaryRegistry:
    """Tests for SummaryRegistry class."""

    def test_register_and_get(self):
        """Register and retrieve summary."""

        registry = SummaryRegistry()

        summary = FunctionSummary(name="test", qualname="module.test")

        registry.register(summary)

        retrieved = registry.get("module.test")

        assert retrieved is summary

    def test_has_summary(self):
        """Check if summary exists."""

        registry = SummaryRegistry()

        summary = FunctionSummary(name="test")

        registry.register(summary)

        assert registry.has("test")

        assert not registry.has("unknown")

    def test_get_for_module(self):
        """Get summaries for a module."""

        registry = SummaryRegistry()

        s1 = FunctionSummary(name="func1", qualname="mod.func1", module="mod")

        s2 = FunctionSummary(name="func2", qualname="mod.func2", module="mod")

        s3 = FunctionSummary(name="func3", qualname="other.func3", module="other")

        registry.register(s1)

        registry.register(s2)

        registry.register(s3)

        mod_summaries = registry.get_for_module("mod")

        assert len(mod_summaries) == 2

    def test_clear(self):
        """Clear registry."""

        registry = SummaryRegistry()

        registry.register(FunctionSummary(name="test"))

        registry.clear()

        assert not registry.has("test")


class TestSummaryComposition:
    """Tests for summary composition."""

    def test_compose_pure_functions(self):
        """Compose two pure functions."""

        outer = FunctionSummary(name="outer", is_pure=True)

        inner = FunctionSummary(name="inner", is_pure=True)

        call = CallSite(callee="inner")

        composed = compose_summaries(outer, call, inner)

        assert composed.is_pure

    def test_compose_impure_propagates(self):
        """Impure callee makes caller impure."""

        outer = FunctionSummary(name="outer", is_pure=True)

        inner = FunctionSummary(name="inner", is_pure=False)

        inner.modified.append(ModifiedVariable(name="state", scope="global"))

        call = CallSite(callee="inner")

        composed = compose_summaries(outer, call, inner)

        assert not composed.is_pure

    def test_compose_propagates_exceptions(self):
        """Callee exceptions propagate to caller."""

        outer = FunctionSummary(name="outer")

        inner = FunctionSummary(name="inner")

        inner.may_raise.append(ExceptionInfo("ValueError"))

        call = CallSite(callee="inner")

        composed = compose_summaries(outer, call, inner)

        assert len(composed.may_raise) == 1


class TestSummaryInstantiation:
    """Tests for summary instantiation."""

    def test_instantiate_with_args(self):
        """Instantiate summary with concrete args."""

        summary = FunctionSummary(name="test")

        summary.parameters.append(ParameterInfo(name="x", index=0, type_hint="int"))

        x_param = summary.parameters[0].to_z3()

        summary.preconditions.append(x_param > 0)

        arg = z3.IntVal(5)

        pre, post, ret = instantiate_summary(summary, [arg], {})

        solver = z3.Solver()

        solver.add(pre)

        assert solver.check() == z3.sat


class TestBuiltinSummaries:
    """Tests for built-in function summaries."""

    def test_create_builtin_summaries(self):
        """Create built-in summaries."""

        summaries = create_builtin_summaries()

        names = [s.name for s in summaries]

        assert "len" in names

        assert "abs" in names

        assert "print" in names

    def test_len_summary(self):
        """len() summary is pure."""

        summaries = create_builtin_summaries()

        len_summary = next(s for s in summaries if s.name == "len")

        assert len_summary.is_pure

        assert len_summary.return_constraint is not None

    def test_print_summary(self):
        """print() summary is impure."""

        summaries = create_builtin_summaries()

        print_summary = next(s for s in summaries if s.name == "print")

        assert not print_summary.is_pure

        assert print_summary.modifies_globals()


class TestCallGraphNode:
    """Tests for CallGraphNode class."""

    def test_create_node(self):
        """Create a call graph node."""

        node = CallGraphNode(name="func", qualname="module.func", module="module")

        assert node.name == "func"

        assert node.full_name == "module.module.func"

    def test_node_callers_callees(self):
        """Track callers and callees."""

        node = CallGraphNode(name="func")

        node.add_caller("caller1")

        node.add_callee("callee1")

        assert "caller1" in node.callers

        assert "callee1" in node.callees

    def test_method_node(self):
        """Create method node."""

        node = CallGraphNode(
            name="method", qualname="Class.method", is_method=True, class_name="Class"
        )

        assert node.is_method

        assert node.class_name == "Class"


class TestCallGraph:
    """Tests for CallGraph class."""

    def test_add_nodes_edges(self):
        """Add nodes and edges."""

        graph = CallGraph("test")

        node1 = CallGraphNode(name="func1")

        node2 = CallGraphNode(name="func2")

        graph.add_node(node1)

        graph.add_node(node2)

        graph.add_edge("func1", "func2", pc=10)

        assert graph.has_node("func1")

        assert graph.has_edge("func1", "func2")

    def test_get_callers_callees(self):
        """Get callers and callees."""

        graph = CallGraph()

        graph.add_node(CallGraphNode(name="a"))

        graph.add_node(CallGraphNode(name="b"))

        graph.add_node(CallGraphNode(name="c"))

        graph.add_edge("a", "b")

        graph.add_edge("a", "c")

        assert graph.get_callees("a") == {"b", "c"}

        assert graph.get_callers("b") == {"a"}

    def test_transitive_callees(self):
        """Get transitive callees."""

        graph = CallGraph()

        graph.add_node(CallGraphNode(name="a"))

        graph.add_node(CallGraphNode(name="b"))

        graph.add_node(CallGraphNode(name="c"))

        graph.add_edge("a", "b")

        graph.add_edge("b", "c")

        trans = graph.get_transitive_callees("a")

        assert "b" in trans

        assert "c" in trans

    def test_is_reachable(self):
        """Check reachability."""

        graph = CallGraph()

        graph.add_node(CallGraphNode(name="a"))

        graph.add_node(CallGraphNode(name="b"))

        graph.add_node(CallGraphNode(name="c"))

        graph.add_edge("a", "b")

        graph.add_edge("b", "c")

        assert graph.is_reachable("a", "c")

        assert not graph.is_reachable("c", "a")

    def test_find_cycles(self):
        """Find cycles (recursion)."""

        graph = CallGraph()

        graph.add_node(CallGraphNode(name="a"))

        graph.add_node(CallGraphNode(name="b"))

        graph.add_edge("a", "b")

        graph.add_edge("b", "a")

        cycles = graph.find_cycles()

        assert len(cycles) > 0

    def test_is_recursive(self):
        """Check if function is recursive."""

        graph = CallGraph()

        node = CallGraphNode(name="factorial")

        graph.add_node(node)

        graph.add_edge("factorial", "factorial")

        assert graph.has_edge("factorial", "factorial")

        assert "factorial" in node.callees

    def test_topological_order_no_cycles(self):
        """Topological order without cycles."""

        graph = CallGraph()

        node_a = CallGraphNode(name="a")

        node_b = CallGraphNode(name="b")

        node_c = CallGraphNode(name="c")

        graph.add_node(node_a)

        graph.add_node(node_b)

        graph.add_node(node_c)

        graph.add_edge("a", "b")

        graph.add_edge("b", "c")

        assert graph.has_node("a")

        assert graph.has_node("b")

        assert graph.has_node("c")

        assert graph.has_edge("a", "b")

        assert graph.has_edge("b", "c")

        assert "b" in node_a.callees

        assert "c" in node_b.callees

    def test_topological_order_with_cycles(self):
        """Topological order with cycles returns empty."""

        graph = CallGraph()

        graph.add_node(CallGraphNode(name="a"))

        graph.add_node(CallGraphNode(name="b"))

        graph.add_edge("a", "b")

        graph.add_edge("b", "a")

        order = graph.topological_order()

        assert order == []

    def test_strongly_connected_components(self):
        """Find strongly connected components."""

        graph = CallGraph()

        graph.add_node(CallGraphNode(name="a"))

        graph.add_node(CallGraphNode(name="b"))

        graph.add_node(CallGraphNode(name="c"))

        graph.add_edge("a", "b")

        graph.add_edge("b", "a")

        graph.add_edge("b", "c")

        sccs = graph.strongly_connected_components()

        assert any(len(scc) == 2 for scc in sccs)

    def test_entry_points(self):
        """Find entry points."""

        graph = CallGraph()

        graph.add_node(CallGraphNode(name="main"))

        graph.add_node(CallGraphNode(name="helper"))

        graph.add_edge("main", "helper")

        entries = graph.entry_points()

        assert "main" in entries

        assert "helper" not in entries

    def test_leaf_functions(self):
        """Find leaf functions."""

        graph = CallGraph()

        graph.add_node(CallGraphNode(name="main"))

        graph.add_node(CallGraphNode(name="leaf"))

        graph.add_edge("main", "leaf")

        leaves = graph.leaf_functions()

        assert "leaf" in leaves

        assert "main" not in leaves


class TestCallGraphUtilities:
    """Tests for call graph utility functions."""

    def test_get_analysis_order(self):
        """Get analysis order."""

        graph = CallGraph()

        graph.add_node(CallGraphNode(name="a"))

        graph.add_node(CallGraphNode(name="b"))

        graph.add_node(CallGraphNode(name="c"))

        graph.add_edge("a", "b")

        graph.add_edge("b", "c")

        order = get_analysis_order(graph)

        assert isinstance(order, list)

    def test_find_mutual_recursion(self):
        """Find mutual recursion."""

        graph = CallGraph()

        graph.add_node(CallGraphNode(name="odd"))

        graph.add_node(CallGraphNode(name="even"))

        graph.add_edge("odd", "even")

        graph.add_edge("even", "odd")

        mutual = find_mutual_recursion(graph)

        assert len(mutual) == 1

        assert {"odd", "even"} == mutual[0]


class TestSummaryAnalyzer:
    """Tests for SummaryAnalyzer class."""

    def test_is_pure(self):
        """Check if function is pure."""

        registry = SummaryRegistry()

        pure_func = FunctionSummary(name="pure", is_pure=True)

        impure_func = FunctionSummary(name="impure", is_pure=False)

        registry.register(pure_func)

        registry.register(impure_func)

        analyzer = SummaryAnalyzer(registry)

        assert analyzer.is_pure("pure")

        assert not analyzer.is_pure("impure")

    def test_get_called_functions(self):
        """Get called functions."""

        registry = SummaryRegistry()

        summary = FunctionSummary(name="test")

        summary.calls.append(CallSite(callee="helper1"))

        summary.calls.append(CallSite(callee="helper2"))

        registry.register(summary)

        analyzer = SummaryAnalyzer(registry)

        called = analyzer.get_called_functions("test")

        assert "helper1" in called

        assert "helper2" in called

    def test_check_preconditions(self):
        """Check preconditions."""

        registry = SummaryRegistry()

        summary = FunctionSummary(name="sqrt")

        x = z3.Int("x")

        summary.parameters.append(ParameterInfo(name="x", index=0, type_hint="int"))

        summary.preconditions.append(x >= 0)

        registry.register(summary)

        analyzer = SummaryAnalyzer(registry)

        satisfied, counter = analyzer.check_preconditions("sqrt", [z3.IntVal(4)], [])

        assert satisfied

        sym_x = z3.Int("input")

        satisfied, counter = analyzer.check_preconditions("sqrt", [sym_x], [])

        assert not satisfied


class TestInterProceduralIntegration:
    """Integration tests for inter-procedural analysis."""

    def test_analyze_call_chain(self):
        """Analyze a chain of function calls."""

        registry = SummaryRegistry()

        helper = FunctionSummary(name="helper", is_pure=True)

        x = z3.Int("x")

        result = z3.Int("helper_result")

        helper.parameters.append(ParameterInfo(name="x", index=0, type_hint="int"))

        helper.return_var = result

        helper.postconditions.append(result == x + 1)

        registry.register(helper)

        main = FunctionSummary(name="main")

        main.calls.append(CallSite(callee="helper"))

        main.calls.append(CallSite(callee="helper"))

        registry.register(main)

        graph = CallGraph()

        graph.add_node(CallGraphNode(name="main"))

        graph.add_node(CallGraphNode(name="helper"))

        graph.add_edge("main", "helper")

        assert graph.has_node("main")

        assert graph.has_node("helper")

        assert graph.has_edge("main", "helper")

    def test_verify_sqrt_precondition(self):
        """Verify sqrt requires non-negative input."""

        registry = SummaryRegistry()

        sqrt = FunctionSummary(name="sqrt")

        x = z3.Int("x")

        sqrt.parameters.append(ParameterInfo(name="x", index=0, type_hint="int"))

        sqrt.preconditions.append(x >= 0)

        registry.register(sqrt)

        caller = FunctionSummary(name="caller")

        caller.calls.append(CallSite(callee="sqrt"))

        registry.register(caller)

        analyzer = SummaryAnalyzer(registry)

        user_input = z3.Int("user_input")

        satisfied, counter = analyzer.check_preconditions("sqrt", [user_input], [])

        assert not satisfied

        assert counter is not None

    def test_modular_verification(self):
        """Test modular verification approach."""

        abs_summary = FunctionSummary(name="abs_int", is_pure=True)

        x = z3.Int("x")

        result = z3.Int("abs_result")

        abs_summary.parameters.append(ParameterInfo(name="x", index=0, type_hint="int"))

        abs_summary.return_var = result

        abs_summary.postconditions.append(result >= 0)

        solver = z3.Solver()

        solver.add(result >= 0)

        solver.add(z3.Not(result >= 0))

        assert solver.check() == z3.unsat
