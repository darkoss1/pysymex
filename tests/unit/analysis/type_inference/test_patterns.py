from pysymex.analysis.type_inference.engine import TypeInferenceEngine
from pysymex.analysis.type_inference.env import TypeEnvironment
from pysymex.analysis.type_inference.kinds import PyType, TypeKind
from pysymex.analysis.type_inference.patterns import PatternRecognizer, TypeState, TypeStateMachine


class TestPatternRecognizer:
    """Test suite for pysymex.analysis.type_inference.patterns.PatternRecognizer."""

    def test_is_dict_get_pattern(self) -> None:
        """Test is_dict_get_pattern behavior."""
        engine = TypeInferenceEngine()
        pr = PatternRecognizer(engine)
        d = PyType.dict_(PyType.str_(), PyType.int_())

        res1 = pr.is_dict_get_pattern(d, "get", [PyType.str_()])
        assert res1 is not None and res1.is_optional() is True

        res2 = pr.is_dict_get_pattern(d, "get", [PyType.str_(), PyType.float_()])
        assert res2 is not None and res2.kind == TypeKind.FLOAT

    def test_is_defaultdict_pattern(self) -> None:
        """Test is_defaultdict_pattern behavior."""
        engine = TypeInferenceEngine()
        pr = PatternRecognizer(engine)
        assert pr.is_defaultdict_pattern(PyType.defaultdict_()) is True
        assert pr.is_defaultdict_pattern(PyType.dict_()) is False

    def test_is_safe_dict_access(self) -> None:
        """Test is_safe_dict_access behavior."""
        engine = TypeInferenceEngine()
        pr = PatternRecognizer(engine)
        assert pr.is_safe_dict_access(PyType.defaultdict_(), "__getitem__") is True
        assert pr.is_safe_dict_access(PyType.dict_(), "get") is True
        assert pr.is_safe_dict_access(PyType.dict_(), "__getitem__") is False

    def test_is_membership_guard(self) -> None:
        """Test is_membership_guard behavior."""
        engine = TypeInferenceEngine()
        pr = PatternRecognizer(engine)
        assert pr.is_membership_guard("x", "x", "d") is True
        assert pr.is_membership_guard("x", "y", "d") is False

    def test_recognize_iteration_pattern(self) -> None:
        """Test recognize_iteration_pattern behavior."""
        engine = TypeInferenceEngine()
        pr = PatternRecognizer(engine)
        lst = PyType.list_(PyType.int_())
        res = pr.recognize_iteration_pattern(lst)
        assert res is not None and res.kind == TypeKind.INT

    def test_recognize_dict_items_pattern(self) -> None:
        """Test recognize_dict_items_pattern behavior."""
        engine = TypeInferenceEngine()
        pr = PatternRecognizer(engine)
        d = PyType.dict_(PyType.str_(), PyType.int_())
        res = pr.recognize_dict_items_pattern(d, "items")
        assert res is not None and res[0].kind == TypeKind.STR and res[1].kind == TypeKind.INT

    def test_is_string_operation_safe(self) -> None:
        """Test is_string_operation_safe behavior."""
        engine = TypeInferenceEngine()
        pr = PatternRecognizer(engine)
        s = PyType.str_()
        i = PyType.int_()
        assert pr.is_string_operation_safe(s, s, "+") is True
        assert pr.is_string_operation_safe(s, i, "*") is True
        assert pr.is_string_operation_safe(s, i, "+") is False


class TestTypeState:
    """Test suite for pysymex.analysis.type_inference.patterns.TypeState."""

    def test_copy(self) -> None:
        """Test copy behavior."""
        env = TypeEnvironment()
        ts = TypeState(env, pc=10, loop_depth=1)
        copied = ts.copy()
        assert copied.pc == 10
        assert copied.loop_depth == 1
        assert copied is not ts

    def test_join(self) -> None:
        """Test join behavior."""
        env1 = TypeEnvironment()
        ts1 = TypeState(env1, pc=10, in_try_block=True)
        env2 = TypeEnvironment()
        ts2 = TypeState(env2, pc=20, in_try_block=False)
        joined = ts1.join(ts2)
        assert joined.pc == 20
        assert joined.in_try_block is True


class TestTypeStateMachine:
    """Test suite for pysymex.analysis.type_inference.patterns.TypeStateMachine."""

    def test_get_state(self) -> None:
        """Test get_state behavior."""
        engine = TypeInferenceEngine()
        tsm = TypeStateMachine(engine, PatternRecognizer(engine))
        ts = TypeState(TypeEnvironment(), pc=10)
        tsm.set_state(10, ts)
        assert tsm.get_state(10) is ts
        assert tsm.get_state(20) is None

    def test_set_state(self) -> None:
        """Test set_state behavior."""
        engine = TypeInferenceEngine()
        tsm = TypeStateMachine(engine, PatternRecognizer(engine))
        ts = TypeState(TypeEnvironment(), pc=10)
        tsm.set_state(10, ts)
        assert tsm.states[10] is ts

    def test_enter_branch(self) -> None:
        """Test enter_branch behavior."""
        engine = TypeInferenceEngine()
        tsm = TypeStateMachine(engine, PatternRecognizer(engine))
        ts = TypeState(TypeEnvironment())
        ts.env.set_type("x", PyType.union_(PyType.int_(), PyType.str_()))

        pos = tsm.enter_branch(ts, "x", PyType.int_(), True)
        assert pos.env.get_type("x").kind == TypeKind.INT
        assert pos.positive_branch is True

    def test_enter_none_branch(self) -> None:
        """Test enter_none_branch behavior."""
        engine = TypeInferenceEngine()
        tsm = TypeStateMachine(engine, PatternRecognizer(engine))
        ts = TypeState(TypeEnvironment())
        ts.env.set_type("x", PyType.optional_(PyType.int_()))

        res = tsm.enter_none_branch(ts, "x", True)
        assert res.env.get_type("x").kind == TypeKind.NONE

    def test_enter_truthiness_branch(self) -> None:
        """Test enter_truthiness_branch behavior."""
        engine = TypeInferenceEngine()
        tsm = TypeStateMachine(engine, PatternRecognizer(engine))
        ts = TypeState(TypeEnvironment())
        ts.env.set_type("x", PyType.optional_(PyType.int_()))

        res = tsm.enter_truthiness_branch(ts, "x", True)
        assert res.env.get_type("x").kind == TypeKind.INT

    def test_merge_branches(self) -> None:
        """Test merge_branches behavior."""
        engine = TypeInferenceEngine()
        tsm = TypeStateMachine(engine, PatternRecognizer(engine))
        ts1 = TypeState(TypeEnvironment())
        ts1.env.set_type("x", PyType.int_())
        ts2 = TypeState(TypeEnvironment())
        ts2.env.set_type("x", PyType.str_())

        merged = tsm.merge_branches([ts1, ts2])
        assert merged.env.get_type("x").kind == TypeKind.UNION

    def test_enter_loop(self) -> None:
        """Test enter_loop behavior."""
        engine = TypeInferenceEngine()
        tsm = TypeStateMachine(engine, PatternRecognizer(engine))
        ts = TypeState(TypeEnvironment())
        new_ts = tsm.enter_loop(ts)
        assert new_ts.loop_depth == 1
        assert new_ts.in_loop_body is True

    def test_exit_loop(self) -> None:
        """Test exit_loop behavior."""
        engine = TypeInferenceEngine()
        tsm = TypeStateMachine(engine, PatternRecognizer(engine))
        ts = TypeState(TypeEnvironment(), loop_depth=1, in_loop_body=True)
        new_ts = tsm.exit_loop(ts)
        assert new_ts.loop_depth == 0
        assert new_ts.in_loop_body is False

    def test_widen_loop_state(self) -> None:
        """Test widen_loop_state behavior."""
        engine = TypeInferenceEngine()
        tsm = TypeStateMachine(engine, PatternRecognizer(engine))
        ts1 = TypeState(TypeEnvironment())
        ts1.env.set_type("x", PyType.int_())
        ts2 = TypeState(TypeEnvironment())
        ts2.env.set_type("x", PyType.float_())

        widened = tsm.widen_loop_state(ts1, ts2)
        assert widened.env.get_type("x").kind == TypeKind.FLOAT

    def test_enter_try_block(self) -> None:
        """Test enter_try_block behavior."""
        engine = TypeInferenceEngine()
        tsm = TypeStateMachine(engine, PatternRecognizer(engine))
        ts = TypeState(TypeEnvironment())
        new_ts = tsm.enter_try_block(ts)
        assert new_ts.in_try_block is True

    def test_enter_except_block(self) -> None:
        """Test enter_except_block behavior."""
        engine = TypeInferenceEngine()
        tsm = TypeStateMachine(engine, PatternRecognizer(engine))
        ts = TypeState(TypeEnvironment(), in_try_block=True)
        new_ts = tsm.enter_except_block(ts, "e", PyType.instance("Exception"))
        assert new_ts.in_try_block is False
        assert new_ts.in_except_block is True
        assert new_ts.env.get_type("e").class_name == "Exception"

    def test_enter_finally_block(self) -> None:
        """Test enter_finally_block behavior."""
        engine = TypeInferenceEngine()
        tsm = TypeStateMachine(engine, PatternRecognizer(engine))
        ts = TypeState(TypeEnvironment(), in_try_block=True)
        new_ts = tsm.enter_finally_block(ts)
        assert new_ts.in_try_block is False
        assert new_ts.in_finally_block is True

    def test_exit_exception_handling(self) -> None:
        """Test exit_exception_handling behavior."""
        engine = TypeInferenceEngine()
        tsm = TypeStateMachine(engine, PatternRecognizer(engine))
        ts = TypeState(TypeEnvironment(), in_finally_block=True)
        new_ts = tsm.exit_exception_handling(ts)
        assert new_ts.in_try_block is False
        assert new_ts.in_except_block is False
        assert new_ts.in_finally_block is False
