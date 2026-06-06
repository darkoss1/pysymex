import z3
from types import CodeType
from pysymex.analysis.static.cross_function import return_types
from pysymex.analysis.static.cross_function.analyzer import CrossFunctionAnalyzer
from pysymex.analysis.static.cross_function.call_graph import CallGraph
from pysymex.analysis.static.cross_function.call_graph.builder import CallGraphBuilder
from pysymex.analysis.static.cross_function.context import ContextSensitiveAnalyzer
from pysymex.analysis.static.cross_function.effects import EffectAnalyzer
from pysymex.analysis.static.cross_function.summary_cache import FunctionSummaryCache
from pysymex.analysis.static.cross_function.types import CallContext, Effect
from pysymex.core.types.scalars.values import SymbolicValue


def make_dummy_code() -> CodeType:
    def my_func() -> None:
        print("hello")

    return my_func.__code__


def test_return_type_exports_are_unique() -> None:
    assert len(return_types.__all__) == len(set(return_types.__all__))


class TestFunctionSummaryCache:
    """Test suite for pysymex.analysis.static.cross_function.summary_cache.FunctionSummaryCache."""

    def test_get(self) -> None:
        """Test get behavior."""
        cache = FunctionSummaryCache()
        assert cache.get("f", [], []) is None
        assert cache.misses == 1

    def test_put(self) -> None:
        """Test put behavior."""
        cache = FunctionSummaryCache()
        sym = z3.Int("x")
        cache.put("f", [1], [sym > 0], "summary1")
        res = cache.get("f", [1], [sym > 0])
        assert res == "summary1"
        assert cache.hits == 1

    def test_zero_size_cache_does_not_store_summary(self) -> None:
        """Zero-size summary caches are valid but never retain entries."""
        cache = FunctionSummaryCache(max_size=0)

        cache.put("f", [1], [], "summary1")

        assert cache.get("f", [1], []) is None
        assert len(cache.cache) == 0

    def test_summary_cache_eviction_is_lru(self) -> None:
        """Bounded summaries evict the least recently used entry."""
        cache = FunctionSummaryCache(max_size=2)

        cache.put("f1", [1], [], "summary1")
        cache.put("f2", [2], [], "summary2")
        assert cache.get("f1", [1], []) == "summary1"
        cache.put("f3", [3], [], "summary3")

        assert cache.get("f1", [1], []) == "summary1"
        assert cache.get("f2", [2], []) is None
        assert cache.get("f3", [3], []) == "summary3"

    def test_compute_key_canonicalizes_symbolic_argument_names(self) -> None:
        """Symbolic argument names should not affect summary key canonicalization."""
        cache = FunctionSummaryCache()
        x1, _ = SymbolicValue.symbolic_int("x")
        y1, _ = SymbolicValue.symbolic_int("y")
        key1 = cache.compute_key("f", [x1, y1], [x1.z3_int > y1.z3_int])

        x2, _ = SymbolicValue.symbolic_int("left")
        y2, _ = SymbolicValue.symbolic_int("right")
        key2 = cache.compute_key("f", [x2, y2], [x2.z3_int > y2.z3_int])

        assert key1 == key2

    def test_compute_key_distinguishes_concrete_symbolic_values(self) -> None:
        """Concrete SymbolicValue payloads must not collide when unconstrained."""
        cache = FunctionSummaryCache()
        one = SymbolicValue.from_const(1)
        two = SymbolicValue.from_const(2)

        key1 = cache.compute_key("f", [one], [])
        key2 = cache.compute_key("f", [two], [])

        assert key1 != key2

    def test_compute_key_distinguishes_none_symbolic_value_from_unknown_symbolic_value(
        self,
    ) -> None:
        """None carries no _constant_value payload, so it needs explicit key coverage."""
        cache = FunctionSummaryCache()
        none_value = SymbolicValue.from_const(None)
        unknown, _ = SymbolicValue.symbolic("maybe_none")

        key1 = cache.compute_key("f", [none_value], [])
        key2 = cache.compute_key("f", [unknown], [])

        assert key1 != key2

    def test_compute_key_ignores_constraints_when_arguments_are_concrete(self) -> None:
        """Concrete-only calls keep current behavior and hash constraints as zero."""
        cache = FunctionSummaryCache()
        x = z3.Int("x")
        key1 = cache.compute_key("f", [1, "a"], [x > 0])
        key2 = cache.compute_key("f", [1, "a"], [x < 0, x != 3])

        assert key1 == key2


class TestCallGraph:
    """Test suite for pysymex.analysis.static.cross_function.call_graph.CallGraph."""

    def test_add_function(self) -> None:
        """Test add_function behavior."""
        cg = CallGraph()
        node = cg.add_function("f1", "mod.f1")
        assert node.name == "f1"
        assert "f1" in cg.nodes

    def test_add_call(self) -> None:
        """Test add_call behavior."""
        cg = CallGraph()
        cg.add_call("f1", "f2", 10, 20)
        assert len(cg.nodes["f1"].callees) == 1
        assert cg.nodes["f1"].callees[0].callee == "f2"
        assert "f1" in cg.nodes["f2"].callers

    def test_get_callees(self) -> None:
        """Test get_callees behavior."""
        cg = CallGraph()
        cg.add_call("f1", "f2", 10, 20)
        assert cg.get_callees("f1") == ["f2"]
        assert cg.get_callees("unknown") == []

    def test_get_callers(self) -> None:
        """Test get_callers behavior."""
        cg = CallGraph()
        cg.add_call("f1", "f2", 10, 20)
        assert "f1" in cg.get_callers("f2")
        assert len(cg.get_callers("unknown")) == 0

    def test_find_recursive(self) -> None:
        """Test find_recursive behavior."""
        cg = CallGraph()
        cg.add_call("f1", "f2", 1, 1)
        cg.add_call("f2", "f1", 2, 2)
        rec = cg.find_recursive()
        assert "f1" in rec and "f2" in rec

    def test_topological_order(self) -> None:
        """Test topological_order behavior."""
        cg = CallGraph()
        cg.add_call("f1", "f2", 1, 1)
        cg.add_call("f2", "f3", 2, 2)
        order = cg.topological_order()
        assert order == ["f3", "f2", "f1"]

    def test_get_reachable(self) -> None:
        """Test get_reachable behavior."""
        cg = CallGraph()
        cg.add_call("f1", "f2", 1, 1)
        cg.add_call("f2", "f3", 2, 2)
        r = cg.get_reachable("f1")
        assert "f1" in r and "f2" in r and "f3" in r

    def test_get_reachable_unknown_function_is_empty(self) -> None:
        """Unknown start functions are not synthesized as reachable nodes."""
        cg = CallGraph()

        assert cg.get_reachable("missing") == set()


class TestCallGraphBuilder:
    """Test suite for pysymex.analysis.static.cross_function.call_graph.builder.CallGraphBuilder."""

    def test_build_from_module(self) -> None:
        """Test build_from_module behavior."""
        cgb = CallGraphBuilder()
        code = make_dummy_code()
        cg = cgb.build_from_module(code)
        assert isinstance(cg, CallGraph)
        assert "<module>" in cg.nodes

    def test_build_from_module_records_call_kw_callee(self) -> None:
        """CALL_KW keyword-name tuples are not callees."""
        module_code = compile(
            "def callee(*, x):\n    return x\ndef caller():\n    return callee(x=1)\n",
            "<call-kw>",
            "exec",
        )
        cgb = CallGraphBuilder()
        cg = cgb.build_from_module(module_code)

        callees = cg.get_callees("caller")

        assert "callee" in callees
        assert "const:('x',)" not in callees
        call_site = next(site for site in cg.nodes["caller"].callees if site.callee == "callee")
        assert call_site.has_kwargs is True
        assert call_site.arg_count == 1

    def test_build_from_module_records_call_function_ex_callee(self) -> None:
        """CALL_FUNCTION_EX argument payloads are not callees."""
        module_code = compile(
            "def callee(*args, **kwargs):\n"
            "    return args, kwargs\n"
            "def caller(args, kwargs):\n"
            "    return callee(*args, **kwargs)\n",
            "<call-function-ex>",
            "exec",
        )
        cgb = CallGraphBuilder()
        cg = cgb.build_from_module(module_code)

        callees = cg.get_callees("caller")

        assert "callee" in callees
        assert "args" not in callees
        assert "kwargs" not in callees
        call_site = next(site for site in cg.nodes["caller"].callees if site.callee == "callee")
        assert call_site.has_varargs is True
        assert call_site.has_kwargs is True


class TestEffectAnalyzer:
    """Test suite for pysymex.analysis.static.cross_function.effects.EffectAnalyzer."""

    def test_analyze_function(self) -> None:
        """Test analyze_function behavior."""
        ea = EffectAnalyzer()
        code = make_dummy_code()
        summary = ea.analyze_function(code, "my_func")
        assert summary.effects.value >= 0

    def test_analyze_function_default_name_does_not_reuse_other_code_summary(self) -> None:
        """Scenario: unnamed code objects; expected effect cache key includes code fingerprint."""
        ea = EffectAnalyzer()

        def pure_func() -> int:
            return 1

        def io_func() -> None:
            print("hello")

        pure_summary = ea.analyze_function(pure_func.__code__)
        io_summary = ea.analyze_function(io_func.__code__)

        assert pure_summary.is_pure is True
        assert "print" in io_summary.reads_globals

    def test_analyze_function_default_name_uses_stable_code_key(self) -> None:
        """Scenario: equivalent unnamed code objects; expected deterministic cache key reuse."""
        ea = EffectAnalyzer()
        first = compile("def f():\n    return 1\n", "<effects>", "exec")
        second = compile("def f():\n    return 1\n", "<effects>", "exec")
        first_code = next(c for c in first.co_consts if isinstance(c, CodeType))
        second_code = next(c for c in second.co_consts if isinstance(c, CodeType))

        first_summary = ea.analyze_function(first_code)
        second_summary = ea.analyze_function(second_code)

        assert first_summary is second_summary
        assert len(ea.cache) == 1
        assert next(iter(ea.cache)).startswith("<code:")

    def test_analyze_function_same_name_recomputes_for_different_code_object(self) -> None:
        """Scenario: reused function name with new code; expected stale summary is not reused."""
        ea = EffectAnalyzer()

        def pure_func() -> int:
            return 1

        def io_func() -> None:
            print("hello")

        pure_summary = ea.analyze_function(pure_func.__code__, "same_name")
        io_summary = ea.analyze_function(io_func.__code__, "same_name")

        assert pure_summary.is_pure is True
        assert "print" in io_summary.reads_globals

    def test_analyze_function_marks_keyword_call_as_local_read(self) -> None:
        """CALL_KW has the same local-read effect as positional calls."""
        ea = EffectAnalyzer()

        def callee(*, value: int) -> int:
            return value

        def caller() -> int:
            return callee(value=1)

        _ = callee
        summary = ea.analyze_function(caller.__code__, "caller")

        assert summary.effects & Effect.READ_LOCAL

    def test_analyze_function_marks_splat_call_as_local_read(self) -> None:
        """CALL_FUNCTION_EX has the same local-read effect as positional calls."""
        ea = EffectAnalyzer()

        def callee(*args: object, **kwargs: object) -> tuple[tuple[object, ...], dict[str, object]]:
            return args, kwargs

        def caller(args: tuple[object, ...], kwargs: dict[str, object]) -> object:
            return callee(*args, **kwargs)

        _ = callee
        summary = ea.analyze_function(caller.__code__, "caller")

        assert summary.effects & Effect.READ_LOCAL

    def test_analyze_with_call_graph(self) -> None:
        """Test analyze_with_call_graph behavior."""
        ea = EffectAnalyzer()
        cg = CallGraph()
        code = make_dummy_code()
        cg.add_call("f1", "f2", 1, 1)
        summaries = ea.analyze_with_call_graph(cg, {"f1": code, "f2": code})
        assert "f1" in summaries


class TestContextSensitiveAnalyzer:
    """Test suite for pysymex.analysis.static.cross_function.context.ContextSensitiveAnalyzer."""

    def test_analyze(self) -> None:
        """Test analyze behavior."""
        csa = ContextSensitiveAnalyzer()
        cg = CallGraph()
        cg.add_function("entry_func")
        cg.entry_points.add("entry_func")
        code = make_dummy_code()
        summaries = csa.analyze(cg, {"entry_func": code})
        key = ("entry_func", CallContext())
        assert key in summaries
        assert summaries[key].function == "entry_func"


class TestCrossFunctionAnalyzer:
    """Test suite for pysymex.analysis.static.cross_function.analyzer.CrossFunctionAnalyzer."""

    def test_analyze_module(self) -> None:
        """Test analyze_module behavior."""
        cfa = CrossFunctionAnalyzer()
        code = make_dummy_code()
        res = cfa.analyze_module(code)
        assert "call_graph" in res
        assert "effects" in res
        assert "escape" in res
        assert "context_sensitive" in res
