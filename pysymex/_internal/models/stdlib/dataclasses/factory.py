# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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

"""Dataclass decorator and factory models."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


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

            type.__setattr__(cls, "__init__", __init__)

        if repr and "__repr__" not in cls.__dict__:

            def __repr__(self: object) -> str:
                return f"{cls.__name__}(...)"

            type.__setattr__(cls, "__repr__", __repr__)

        if eq and "__eq__" not in cls.__dict__:

            def __eq__(self: object, other: object) -> bool:
                return isinstance(other, cls)

            type.__setattr__(cls, "__eq__", __eq__)

        if unsafe_hash and "__hash__" not in cls.__dict__:

            def __hash__(self: object) -> int:
                """Hash."""
                return 0

            type.__setattr__(cls, "__hash__", __hash__)

        return cls

    if cls is None:
        return wrap
    return wrap(cls)


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
