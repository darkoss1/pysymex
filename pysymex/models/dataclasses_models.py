# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Models for the dataclasses module.

This module provides models for Python's dataclasses standard library,
including dataclass decorators and utility functions.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class FieldInfo:
    """Model representing a dataclass field."""

    name: str
    type: type | object
    default: object = field(default=None)
    default_factory: Callable[[], object] | None = None
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

            def __init__(self: object, *args: object, **kwargs: object) -> None:
                for k, v in kwargs.items():
                    setattr(self, k, v)

            setattr(cls, "__init__", __init__)

        if repr and "__repr__" not in cls.__dict__:

            def __repr__(self: object) -> str:
                return f"{cls.__name__}(...)"

            setattr(cls, "__repr__", __repr__)

        if eq and "__eq__" not in cls.__dict__:

            def __eq__(self: object, other: object) -> bool:
                if not isinstance(other, cls):
                    return False
                return True

            setattr(cls, "__eq__", __eq__)

        if unsafe_hash and "__hash__" not in cls.__dict__:

            def __hash__(self: object) -> int:
                """Hash."""
                return 0

            setattr(cls, "__hash__", __hash__)

        return cls

    if cls is None:
        return wrap
    return wrap(cls)


def field_model(
    *,
    default: object = None,
    default_factory: Callable[[], object] | None = None,
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
        type=object,
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
    dataclass_fields = getattr(obj, "__dataclass_fields__", None)
    if isinstance(dataclass_fields, dict):
        for name in dataclass_fields:
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
    dataclass_fields = getattr(obj, "__dataclass_fields__", None)
    if isinstance(dataclass_fields, dict):
        values: list[object] = []
        for name in dataclass_fields:
            values.append(getattr(obj, name, None))
        return tuple_factory(values)
    else:
        return tuple_factory(getattr(obj, attr) for attr in dir(obj) if not attr.startswith("_"))


def make_dataclass_model(
    cls_name: str,
    fields: list[str | tuple[str, type] | tuple[str, type, object]],
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
            annotations[name] = object
        elif len(field_spec) == 2:
            name, typ = field_spec
            annotations[name] = typ
        elif len(field_spec) == 3:
            name, typ, default = field_spec
            annotations[name] = typ
            ns[name] = default

    ns["__annotations__"] = annotations

    cls = type(cls_name, bases, ns)

    decorated = dataclass_model(
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
    if isinstance(decorated, type):
        return decorated
    return cls


def replace_model(obj: object, /, **changes: object) -> object:
    """Model for dataclasses.replace() - create a copy with changes."""
    new_obj: object = type(obj).__new__(type(obj))
    if hasattr(obj, "__dict__"):
        new_obj.__dict__.update(obj.__dict__)

    for key, value in changes.items():
        setattr(new_obj, key, value)

    return new_obj


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
            result.append(FieldInfo(name=name, type=object))

    return tuple(result)


def dataclass_fields_model(obj: object) -> dict[str, object]:
    """Model to get the fields dictionary from a dataclass."""
    return getattr(obj, "__dataclass_fields__", {})


class _MissingSentinel:
    def __repr__(self) -> str:
        return "MISSING"


class _KWOnlySentinel:
    def __repr__(self) -> str:
        return "KW_ONLY"


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
    "MISSING": _MissingSentinel(),
    "KW_ONLY": _KWOnlySentinel(),
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
