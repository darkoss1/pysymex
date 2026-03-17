"""Tests for contextlib_models.py and dataclasses_models.py.

Phase 2 Part C -- Function Models (contextlib + dataclasses).
"""

from __future__ import annotations

import pytest

from pysymex.models.contextlib_models import (
    CONTEXTLIB_MODELS,
    AsyncContextManagerModel,
    AsyncExitStackModel,
    ContextDecoratorModel,
    ContextManagerModel,
    ExitStackModel,
    _stub_closing,
    _stub_aclosing,
    _stub_redirect_stdout,
    _stub_redirect_stderr,
    get_contextlib_model,
)
from pysymex.models.dataclasses_models import (
    DATACLASSES_MODELS,
    FieldInfo,
    asdict_model,
    astuple_model,
    dataclass_model,
    field_model,
    fields_model,
    get_dataclasses_model,
    is_dataclass_model,
    make_dataclass_model,
    replace_model,
)


# ===================================================================
# contextlib -- ContextManagerModel
# ===================================================================

class TestContextManagerModel:
    def test_callable_returns_context_manager(self):
        cm_factory = ContextManagerModel()
        def gen():
            yield 42
        cm = cm_factory(gen)
        assert hasattr(cm, "__enter__")
        assert hasattr(cm, "__exit__")

    def test_enter_yields_value(self):
        cm_factory = ContextManagerModel()
        def gen():
            yield 99
        cm = cm_factory(gen)
        val = cm.__enter__()
        assert val == 99

    def test_exit_normal(self):
        cm_factory = ContextManagerModel()
        def gen():
            yield "hello"
        cm = cm_factory(gen)
        cm.__enter__()
        result = cm.__exit__(None, None, None)
        assert result is None

    def test_exit_with_exception_suppresses(self):
        cm_factory = ContextManagerModel()
        def gen():
            try:
                yield "val"
            except ValueError:
                pass
        cm = cm_factory(gen)
        cm.__enter__()
        result = cm.__exit__(ValueError, ValueError("test"), None)
        assert result is True

    def test_generator_didnt_yield_raises(self):
        cm_factory = ContextManagerModel()
        def gen():
            return
            yield  # noqa: unreachable -- make it a generator
        cm = cm_factory(gen)
        with pytest.raises(RuntimeError, match="Generator didn't yield"):
            cm.__enter__()

    def test_generator_didnt_stop_raises(self):
        cm_factory = ContextManagerModel()
        def gen():
            yield 1
            yield 2
        cm = cm_factory(gen)
        cm.__enter__()
        with pytest.raises(RuntimeError, match="Generator didn't stop"):
            cm.__exit__(None, None, None)


# ===================================================================
# contextlib -- AsyncContextManagerModel
# ===================================================================

class TestAsyncContextManagerModel:
    def test_callable_returns_async_cm(self):
        acm_factory = AsyncContextManagerModel()
        async def gen():
            yield 42
        acm = acm_factory(gen)
        assert hasattr(acm, "__aenter__")
        assert hasattr(acm, "__aexit__")


# ===================================================================
# contextlib -- ContextDecoratorModel
# ===================================================================

class TestContextDecoratorModel:
    def test_enter_returns_self(self):
        cd = ContextDecoratorModel()
        assert cd.__enter__() is cd

    def test_exit_returns_none(self):
        cd = ContextDecoratorModel()
        cd.__enter__()
        assert cd.__exit__(None, None, None) is None

    def test_call_decorates_function(self):
        cd = ContextDecoratorModel()
        @cd
        def my_func():
            return 42
        assert my_func() == 42


# ===================================================================
# contextlib -- ExitStackModel
# ===================================================================

class TestExitStackModel:
    def test_enter_returns_self(self):
        es = ExitStackModel()
        assert es.__enter__() is es

    def test_exit_no_callbacks(self):
        es = ExitStackModel()
        es.__enter__()
        result = es.__exit__(None, None, None)
        assert result is False

    def test_callback_registered_and_called(self):
        es = ExitStackModel()
        es.__enter__()
        called = []
        es.callback(lambda: called.append(True))
        es.__exit__(None, None, None)
        assert called == [True]

    def test_pop_all_transfers_callbacks(self):
        es = ExitStackModel()
        es.__enter__()
        es.callback(lambda: None)
        new_es = es.pop_all()
        assert len(es._exit_callbacks) == 0
        assert len(new_es._exit_callbacks) == 1

    def test_push_with_exit(self):
        class FakeCM:
            def __enter__(self):
                return "entered"
            def __exit__(self, *args):
                return False
        es = ExitStackModel()
        es.__enter__()
        result = es.push(FakeCM())
        assert result == "entered"


# ===================================================================
# contextlib -- AsyncExitStackModel
# ===================================================================

class TestAsyncExitStackModel:
    def test_init(self):
        aes = AsyncExitStackModel()
        assert len(aes._exit_callbacks) == 0

    def test_push_async_exit(self):
        aes = AsyncExitStackModel()
        async def exit_fn(*args):
            pass
        aes.push_async_exit(exit_fn)
        assert len(aes._exit_callbacks) == 1

    def test_push_async_callback(self):
        aes = AsyncExitStackModel()
        async def cb():
            pass
        returned = aes.push_async_callback(cb)
        assert returned is cb
        assert len(aes._exit_callbacks) == 1


# ===================================================================
# contextlib -- stub helpers
# ===================================================================

class TestContextlibStubs:
    def test_closing(self):
        obj = object()
        assert _stub_closing(obj) is obj

    def test_aclosing(self):
        obj = object()
        assert _stub_aclosing(obj) is obj

    def test_redirect_stdout(self):
        result = _stub_redirect_stdout(None)
        assert hasattr(result, "__enter__")
        assert hasattr(result, "__exit__")

    def test_redirect_stderr(self):
        result = _stub_redirect_stderr(None)
        assert hasattr(result, "__enter__")
        assert hasattr(result, "__exit__")

    def test_suppress_model(self):
        sup = CONTEXTLIB_MODELS["suppress"]
        inst = sup()
        assert inst.__enter__() is inst
        assert inst.__exit__(None, None, None) is True


# ===================================================================
# contextlib -- registry
# ===================================================================

class TestContextlibRegistry:
    def test_all_expected_models(self):
        expected = [
            "contextmanager", "asynccontextmanager", "ContextDecorator",
            "ExitStack", "AsyncExitStack", "closing", "aclosing",
            "suppress", "redirect_stdout", "redirect_stderr",
        ]
        for name in expected:
            assert name in CONTEXTLIB_MODELS, f"Missing model: {name}"

    def test_get_contextlib_model(self):
        assert get_contextlib_model("ExitStack") is ExitStackModel

    def test_get_unknown_returns_none(self):
        assert get_contextlib_model("nonexistent") is None

    def test_model_count(self):
        assert len(CONTEXTLIB_MODELS) == 10


# ===================================================================
# dataclasses -- dataclass_model
# ===================================================================

class TestDataclassModel:
    def test_decorate_class_directly(self):
        @dataclass_model
        class Point:
            x: int = 0
            y: int = 0
        assert hasattr(Point, "__dataclass_fields__")
        assert hasattr(Point, "__dataclass_params__")

    def test_decorate_with_params(self):
        @dataclass_model(frozen=True, eq=True)
        class FrozenPoint:
            x: int = 0
        assert hasattr(FrozenPoint, "__dataclass_fields__")
        assert FrozenPoint.__dataclass_params__.frozen is True

    def test_auto_init(self):
        @dataclass_model
        class Obj:
            pass
        obj = Obj(a=1, b=2)
        assert obj.a == 1
        assert obj.b == 2

    def test_auto_repr(self):
        @dataclass_model
        class Obj:
            pass
        obj = Obj()
        assert "Obj" in repr(obj)

    def test_auto_eq(self):
        @dataclass_model
        class Obj:
            pass
        a = Obj()
        b = Obj()
        assert a == b

    def test_unsafe_hash(self):
        @dataclass_model(unsafe_hash=True)
        class Hashable:
            pass
        h = Hashable()
        assert hash(h) == 0


# ===================================================================
# dataclasses -- field_model
# ===================================================================

class TestFieldModel:
    def test_default_field(self):
        f = field_model()
        assert isinstance(f, FieldInfo)
        assert f.init is True
        assert f.repr is True
        assert f.compare is True

    def test_field_with_default(self):
        f = field_model(default=42)
        assert f.default == 42

    def test_field_with_factory(self):
        f = field_model(default_factory=list)
        assert f.default_factory is list

    def test_field_kw_only(self):
        f = field_model(kw_only=True)
        assert f.kw_only is True


# ===================================================================
# dataclasses -- asdict_model / astuple_model
# ===================================================================

class TestAsdictModel:
    def test_with_dataclass_fields(self):
        @dataclass_model
        class DC:
            pass
        obj = DC(x=1, y=2)
        result = asdict_model(obj)
        assert isinstance(result, dict)

    def test_without_dataclass_fields(self):
        class Plain:
            def __init__(self):
                self.a = 10
        result = asdict_model(Plain())
        assert isinstance(result, dict)


class TestAstupleModel:
    def test_with_dataclass_fields(self):
        @dataclass_model
        class DC:
            pass
        obj = DC(x=1, y=2)
        result = astuple_model(obj)
        assert isinstance(result, tuple)

    def test_without_dataclass_fields(self):
        class Plain:
            pass
        result = astuple_model(Plain())
        assert isinstance(result, tuple)


# ===================================================================
# dataclasses -- make_dataclass_model
# ===================================================================

class TestMakeDataclassModel:
    def test_simple_fields(self):
        DC = make_dataclass_model("Point", ["x", "y"])
        assert hasattr(DC, "__dataclass_fields__")
        obj = DC(x=1, y=2)
        assert obj.x == 1

    def test_typed_fields(self):
        DC = make_dataclass_model("TypedPoint", [("x", int), ("y", int)])
        assert hasattr(DC, "__dataclass_fields__")

    def test_fields_with_defaults(self):
        DC = make_dataclass_model("DefPoint", [("x", int, 0), ("y", int, 0)])
        assert hasattr(DC, "__dataclass_fields__")


# ===================================================================
# dataclasses -- replace_model
# ===================================================================

class TestReplaceModel:
    def test_replace_changes_field(self):
        @dataclass_model
        class DC:
            pass
        obj = DC(x=1, y=2)
        new_obj = replace_model(obj, x=10)
        assert new_obj.x == 10
        assert new_obj.y == 2

    def test_replace_preserves_type(self):
        @dataclass_model
        class DC:
            pass
        obj = DC(a="hello")
        new_obj = replace_model(obj, a="world")
        assert type(new_obj) is DC


# ===================================================================
# dataclasses -- is_dataclass_model / fields_model
# ===================================================================

class TestIsDataclassModel:
    def test_true_for_dataclass(self):
        @dataclass_model
        class DC:
            pass
        assert is_dataclass_model(DC) is True
        assert is_dataclass_model(DC()) is True

    def test_false_for_plain(self):
        class Plain:
            pass
        assert is_dataclass_model(Plain) is False


class TestFieldsModel:
    def test_raises_for_non_dataclass(self):
        with pytest.raises(TypeError, match="must be called with a dataclass"):
            fields_model(object())

    def test_returns_tuple_of_fieldinfo(self):
        @dataclass_model
        class DC:
            pass
        DC.__dataclass_fields__["x"] = FieldInfo(name="x", type=int)
        result = fields_model(DC)
        assert isinstance(result, tuple)
        assert all(isinstance(f, FieldInfo) for f in result)


# ===================================================================
# dataclasses -- registry
# ===================================================================

class TestDataclassesRegistry:
    def test_all_expected_models(self):
        expected = [
            "dataclass", "field", "Field", "asdict", "astuple",
            "make_dataclass", "replace", "is_dataclass", "fields",
            "MISSING", "KW_ONLY",
        ]
        for name in expected:
            assert name in DATACLASSES_MODELS, f"Missing model: {name}"

    def test_get_dataclasses_model(self):
        assert get_dataclasses_model("dataclass") is dataclass_model

    def test_get_unknown_returns_none(self):
        assert get_dataclasses_model("nonexistent") is None

    def test_missing_repr(self):
        missing = DATACLASSES_MODELS["MISSING"]
        assert repr(missing) == "MISSING"

    def test_kw_only_repr(self):
        kw = DATACLASSES_MODELS["KW_ONLY"]
        assert repr(kw) == "KW_ONLY"

    def test_model_count(self):
        assert len(DATACLASSES_MODELS) == 11
