"""Models for the dataclasses module.

This module provides models for Python's dataclasses standard library,
including dataclass decorators and utility functions.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar, cast

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class FieldInfo:
    """Model representing a dataclass field."""

    name: str
    type: type | Any
    default: object = field(default=None)
    default_factory: Callable[[], Any] | None = None
    init: bool = True
    repr: bool = True
    compare: bool = True
    hash: bool | None = None
    metadata: dict[str, object] = field(default_factory=dict[str, object])
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
        """Wrap."""
        cls.__dataclass_fields__ = {}
        cls.__dataclass_params__ = type(
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
        )()

        if init and "__init__" not in cls.__dict__:

            def __init__(self: object, *args: object, **kwargs: object) -> None:
                for k, v in kwargs.items():
                    setattr(self, k, v)

            cls.__init__ = __init__

        if repr and "__repr__" not in cls.__dict__:

            def __repr__(self):
                return f"{cls .__name__ }(...)"

            cls.__repr__ = __repr__

        if eq and "__eq__" not in cls.__dict__:

            def __eq__(self, other):
                if not isinstance(other, cls):
                    return NotImplemented
                return True

            cls.__eq__ = __eq__

        if unsafe_hash and "__hash__" not in cls.__dict__:

            def __hash__(self):
                """Hash."""
                return 0

            cls.__hash__ = __hash__

        return cls

    if cls is None:
        return wrap
    return wrap(cls)


def field_model(
    *,
    default: object = None,
    default_factory: Callable[[], Any] | None = None,
    init: bool = True,
    repr: bool = True,
    compare: bool = True,
    hash: bool | None = None,
    metadata: dict[str, object] | None = None,
    kw_only: bool = False,
) -> object:
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


def asdict_model(obj: object, *, dict_factory: type = dict) -> dict[str, object]:
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
                except AttributeError:
                    logger.debug("Failed to get attribute %s in asdict", name, exc_info=True)
    return result


def astuple_model(obj: object, *, tuple_factory: type = tuple) -> tuple[object, ...]:
    """Model for dataclasses.astuple() - convert dataclass to tuple."""
    if hasattr(obj, "__dataclass_fields__"):
        values: list[object] = []
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
    namespace: dict[str, object] | None = None,
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


def replace_model(obj: object, /, **changes: object) -> object:
    """Model for dataclasses.replace() - create a copy with changes."""
    new_obj: object = type(obj).__new__(type(obj))
    if hasattr(obj, "__dict__"):
        getattr(new_obj, "__dict__").update(getattr(obj, "__dict__"))

    for key, value in changes.items():
        setattr(new_obj, key, value)

    return cast("Any", new_obj)


def is_dataclass_model(obj: object) -> bool:
    """Model for dataclasses.is_dataclass() - check if object is a dataclass."""
    return hasattr(obj, "__dataclass_fields__") or (
        isinstance(obj, type) and hasattr(obj, "__dataclass_fields__")
    )


def fields_model(obj: object) -> tuple[FieldInfo, ...]:
    """Model for dataclasses.fields() - return tuple of FieldInfo objects."""
    if not is_dataclass_model(obj):
        raise TypeError("must be called with a dataclass type or instance")

    cls = obj if isinstance(obj, type) else type(obj)
    field_dict = getattr(cls, "__dataclass_fields__", {})

    result: list[FieldInfo] = []
    for name, info in field_dict.items():
        if isinstance(info, FieldInfo):
            result.append(info)
        else:
            result.append(FieldInfo(name=name, type=Any))

    return tuple(result)


def dataclass_fields_model(obj: object) -> dict[str, object]:
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


def get_dataclasses_model(name: str) -> object | None:
    """Get a dataclasses model by name."""
    return DATACLASSES_MODELS.get(name)


__all__ = [
    "DATACLASSES_MODELS",
    "FieldInfo",
    "asdict_model",
    "astuple_model",
    "dataclass_model",
    "field_model",
    "fields_model",
    "get_dataclasses_model",
    "is_dataclass_model",
    "make_dataclass_model",
    "replace_model",
]
