from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def _load_dataclasses_models() -> ModuleType:
    module_path = (
        Path(__file__).resolve().parents[4] / "pysymex" / "models" / "stdlib" / "dataclasses.py"
    )
    spec = importlib.util.spec_from_file_location("pysymex_models_stdlib_dataclasses", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load stdlib dataclasses models module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


dc_models = _load_dataclasses_models()


class TestFieldInfo:
    """Test suite for pysymex.models.stdlib.dataclasses.FieldInfo."""

    def test_faithfulness(self) -> None:
        info = dc_models.FieldInfo(name="x", type=int, default=1)
        assert info.name == "x"

    def test_error_path(self) -> None:
        info = dc_models.FieldInfo(name="x", type=int)
        assert info.default is None


def test_dataclass_model() -> None:
    @dc_models.dataclass_model
    class X:
        pass

    assert hasattr(X, "__dataclass_fields__")


def test_field_model() -> None:
    fld = dc_models.field_model(default=3)
    assert isinstance(fld, dc_models.FieldInfo)


def test_asdict_model() -> None:
    class X:
        __dataclass_fields__ = {"a": object()}
        a = 4

    assert dc_models.asdict_model(X()) == {"a": 4}


def test_astuple_model() -> None:
    class X:
        __dataclass_fields__ = {"a": object()}
        a = 4

    assert dc_models.astuple_model(X()) == (4,)


def test_make_dataclass_model() -> None:
    cls = dc_models.make_dataclass_model("Y", ["a"])
    assert cls.__name__ == "Y"


def test_replace_model() -> None:
    class X:
        def __init__(self) -> None:
            self.a = 1

    replaced = dc_models.replace_model(X(), a=2)
    assert getattr(replaced, "a") == 2


def test_is_dataclass_model() -> None:
    class X:
        __dataclass_fields__ = {}

    assert dc_models.is_dataclass_model(X)


def test_fields_model() -> None:
    class X:
        __dataclass_fields__ = {"a": dc_models.FieldInfo(name="a", type=int)}

    fields = dc_models.fields_model(X)
    assert len(fields) == 1


def test_dataclass_fields_model() -> None:
    class X:
        __dataclass_fields__ = {"a": 1}

    assert dc_models.dataclass_fields_model(X) == {"a": 1}


def test_get_dataclasses_model() -> None:
    assert dc_models.get_dataclasses_model("dataclass") is not None
    assert dc_models.get_dataclasses_model("missing") is None


class TestDataclassModelHash:
    """Test suite for dataclass_model __hash__ method."""

    def test_hash_returns_zero_when_unsafe_hash(self) -> None:
        """Test that __hash__ returns 0 when unsafe_hash=True is used."""

        @dc_models.dataclass_model(unsafe_hash=True)
        class HashableClass:
            pass

        instance = HashableClass()
        assert hash(instance) == 0
