"""Models for the dataclasses module.

This module provides models for Python's dataclasses standard library,
including dataclass decorators and utility functions.
"""

from __future__ import annotations
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

T = TypeVar("T")


@dataclass
class FieldInfo:
    """Model representing a dataclass field."""

    name: str
    type: type | Any
    default: Any = field(default=None)
    default_factory: Callable[[], Any] | None = None
    init: bool = True
    repr: bool = True
    compare: bool = True
    hash: bool | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    kw_only: bool = False


def dataclass_model(
    cls: type | None = None,
    *,
    init: bool = True,
    repr: bool = True,
    eq: bool = True,
    order: bool = False,
    unsafe_hash: bool = False,
    frozen: bool = False,
    match_args: bool = True,
    kw_only: bool = False,
    slots: bool = False,
    weakref_slot: bool = False,
) -> type | Callable[[type], type]:
    """Model for the dataclass decorator.

    This is a simplified model that returns the class mostly unchanged
    but marks it as a dataclass for type inference purposes.
    """

    def wrap(cls: type) -> type:
        setattr(cls, "__dataclass_fields__", {})
        setattr(
            cls,
            "__dataclass_params__",
            type(
                "Params",
                (),
                {
                    "init": init,
                    "repr": repr,
                    "eq": eq,
                    "order": order,
                    "unsafe_hash": unsafe_hash,
                    "frozen": frozen,
                    "match_args": match_args,
                    "kw_only": kw_only,
                    "slots": slots,
                    "weakref_slot": weakref_slot,
                },
            )(),
        )

        if init and "__init__" not in cls.__dict__:

            def __init__(self, *args, **kwargs):  # type: ignore
                for k, v in kwargs.items():
                    setattr(self, k, v)

            cls.__init__ = __init__  # type: ignore

        if repr and "__repr__" not in cls.__dict__:

            def __repr__(self):  # type: ignore
                return f"{cls.__name__}(...)"

            cls.__repr__ = __repr__  # type: ignore

        if eq and "__eq__" not in cls.__dict__:

            def __eq__(self, other):  # type: ignore
                if not isinstance(other, cls):
                    return NotImplemented
                return True

            cls.__eq__ = __eq__  # type: ignore

        if unsafe_hash and "__hash__" not in cls.__dict__:

            def __hash__(self):  # type: ignore
                return 0

            cls.__hash__ = __hash__  # type: ignore

        return cls

    if cls is None:
        return wrap
    return wrap(cls)


def field_model(
    *,
    default: Any = None,
    default_factory: Callable[[], Any] | None = None,
    init: bool = True,
    repr: bool = True,
    compare: bool = True,
    hash: bool | None = None,
    metadata: dict[str, Any] | None = None,
    kw_only: bool = False,
) -> Any:
    """Model for the dataclasses.field() function.

    Returns a FieldInfo object that represents a dataclass field
    with special properties.
    """
    return FieldInfo(
        name="",
        type=Any,
        default=default,
        default_factory=default_factory,
        init=init,
        repr=repr,
        compare=compare,
        hash=hash,
        metadata=metadata or {},
        kw_only=kw_only,
    )


def asdict_model(obj: Any, *, dict_factory: type = dict) -> dict[str, Any]:
    """Model for dataclasses.asdict() - convert dataclass to dict."""
    result = dict_factory()
    if hasattr(obj, "__dataclass_fields__"):
        for name in obj.__dataclass_fields__:
            value = getattr(obj, name, None)
            result[name] = value
    else:
        for name in dir(obj):
            if not name.startswith("_"):
                try:
                    result[name] = getattr(obj, name)
                except:
                    pass
    return result


def astuple_model(obj: Any, *, tuple_factory: type = tuple) -> tuple[Any, ...]:
    """Model for dataclasses.astuple() - convert dataclass to tuple."""
    if hasattr(obj, "__dataclass_fields__"):
        values = []
        for name in obj.__dataclass_fields__:
            values.append(getattr(obj, name, None))
        return tuple_factory(values)
    else:
        return tuple_factory(getattr(obj, attr) for attr in dir(obj) if not attr.startswith("_"))


def make_dataclass_model(
    cls_name: str,
    fields: list[str | tuple[str, type] | tuple[str, type, Any]],
    *,
    bases: tuple[type, ...] = (),
    namespace: dict[str, Any] | None = None,
    init: bool = True,
    repr: bool = True,
    eq: bool = True,
    order: bool = False,
    unsafe_hash: bool = False,
    frozen: bool = False,
    match_args: bool = True,
    kw_only: bool = False,
    slots: bool = False,
    weakref_slot: bool = False,
    module: str | None = None,
) -> type:
    """Model for dataclasses.make_dataclass() - dynamically create a dataclass."""
    ns = namespace or {}
    annotations = {}

    for field_spec in fields:
        if isinstance(field_spec, str):
            name = field_spec
            annotations[name] = Any
        elif len(field_spec) == 2:
            name, typ = field_spec
            annotations[name] = typ
        elif len(field_spec) == 3:
            name, typ, default = field_spec
            annotations[name] = typ
            ns[name] = default

    ns["__annotations__"] = annotations

    cls = type(cls_name, bases, ns)

    return dataclass_model(
        cls,
        init=init,
        repr=repr,
        eq=eq,
        order=order,
        unsafe_hash=unsafe_hash,
        frozen=frozen,
        match_args=match_args,
        kw_only=kw_only,
        slots=slots,
        weakref_slot=weakref_slot,
    )


def replace_model(obj: Any, /, **changes: Any) -> Any:
    """Model for dataclasses.replace() - create a copy with changes."""
    new_obj = type(obj).__new__(type(obj))
    new_obj.__dict__.update(obj.__dict__)

    for key, value in changes.items():
        setattr(new_obj, key, value)

    return new_obj


def is_dataclass_model(obj: Any) -> bool:
    """Model for dataclasses.is_dataclass() - check if object is a dataclass."""
    return hasattr(obj, "__dataclass_fields__") or (
        isinstance(obj, type) and hasattr(obj, "__dataclass_fields__")
    )


def fields_model(obj: Any) -> tuple[FieldInfo, ...]:
    """Model for dataclasses.fields() - return tuple of FieldInfo objects."""
    if not is_dataclass_model(obj):
        raise TypeError("must be called with a dataclass type or instance")

    cls = obj if isinstance(obj, type) else type(obj)
    field_dict = getattr(cls, "__dataclass_fields__", {})

    result = []
    for name, info in field_dict.items():
        if isinstance(info, FieldInfo):
            result.append(info)
        else:
            result.append(FieldInfo(name=name, type=Any))

    return tuple(result)


def dataclass_fields_model(obj: Any) -> dict[str, Any]:
    """Model to get the fields dictionary from a dataclass."""
    return getattr(obj, "__dataclass_fields__", {})


DATACLASSES_MODELS = {
    "dataclass": dataclass_model,
    "field": field_model,
    "Field": FieldInfo,
    "asdict": asdict_model,
    "astuple": astuple_model,
    "make_dataclass": make_dataclass_model,
    "replace": replace_model,
    "is_dataclass": is_dataclass_model,
    "fields": fields_model,
    "MISSING": type("MISSING", (), {"__repr__": lambda self: "MISSING"})(),
    "KW_ONLY": type("KW_ONLY", (), {"__repr__": lambda self: "KW_ONLY"})(),
}


def get_dataclasses_model(name: str) -> Any | None:
    """Get a dataclasses model by name."""
    return DATACLASSES_MODELS.get(name)


__all__ = [
    "FieldInfo",
    "dataclass_model",
    "field_model",
    "asdict_model",
    "astuple_model",
    "make_dataclass_model",
    "replace_model",
    "is_dataclass_model",
    "fields_model",
    "DATACLASSES_MODELS",
    "get_dataclasses_model",
]
