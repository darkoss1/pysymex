from __future__ import annotations

import pysymex._internal.models.stdlib.dataclasses.runtime as dc_models


class TestFieldInfo:
    """Test suite for pysymex._internal.models.stdlib.dataclasses.FieldInfo."""

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


def test_symbolic_function_models_share_the_dataclasses_family() -> None:
    assert (
        dc_models.DataclassModel.__module__ == "pysymex._internal.models.stdlib.dataclasses.models"
    )
    assert all(model.qualname.startswith("dataclasses.") for model in dc_models.dataclasses_models)


class TestDataclassModelHash:
    """Test suite for dataclass_model __hash__ method."""

    def test_hash_returns_zero_when_unsafe_hash(self) -> None:
        """Test that __hash__ returns 0 when unsafe_hash=True is used."""

        @dc_models.dataclass_model(unsafe_hash=True)
        class HashableClass:
            pass

        instance = HashableClass()
        assert hash(instance) == 0
