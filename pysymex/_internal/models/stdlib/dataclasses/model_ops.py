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

"""Dataclass model operations and field metadata types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

logger = get_logger(__name__)


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


class MissingSentinel:
    def __repr__(self) -> str:
        return "MISSING"


class KWOnlySentinel:
    def __repr__(self) -> str:
        return "KW_ONLY"


class DataclassModelOps:
    """Domain owner for stdlib dataclass helper models."""

    @staticmethod
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
        """Model for the dataclasses.field() function."""
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

    @staticmethod
    def asdict_model(obj: object, *, dict_factory: type = dict) -> dict[str, object]:
        """Model for dataclasses.asdict() - convert dataclass to dict."""
        result = dict_factory()
        dataclass_fields = getattr(obj, "__dataclass_fields__", None)
        if isinstance(dataclass_fields, dict):
            for name in cast("dict[str, object]", dataclass_fields):
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

    @staticmethod
    def astuple_model(obj: object, *, tuple_factory: type = tuple) -> tuple[object, ...]:
        """Model for dataclasses.astuple() - convert dataclass to tuple."""
        dataclass_fields = getattr(obj, "__dataclass_fields__", None)
        if isinstance(dataclass_fields, dict):
            values: list[object] = []
            for name in cast("dict[str, object]", dataclass_fields):
                values.append(getattr(obj, name, None))
            return tuple_factory(values)
        return tuple_factory(getattr(obj, attr) for attr in dir(obj) if not attr.startswith("_"))

    @staticmethod
    def replace_model(obj: object, /, **changes: object) -> object:
        """Model for dataclasses.replace() - create a copy with changes."""
        new_obj: object = type(obj).__new__(type(obj))
        if hasattr(obj, "__dict__"):
            new_obj.__dict__.update(obj.__dict__)

        for key, value in changes.items():
            setattr(new_obj, key, value)

        return new_obj

    @staticmethod
    def is_dataclass_model(obj: object) -> bool:
        """Model for dataclasses.is_dataclass() - check if object is a dataclass."""
        return hasattr(obj, "__dataclass_fields__") or (
            isinstance(obj, type) and hasattr(obj, "__dataclass_fields__")
        )

    @staticmethod
    def fields_model(obj: object) -> tuple[FieldInfo, ...]:
        """Model for dataclasses.fields() - return tuple of FieldInfo objects."""
        if not DataclassModelOps.is_dataclass_model(obj):
            msg = "must be called with a dataclass type or instance"
            raise TypeError(msg)

        cls = obj if isinstance(obj, type) else type(obj)
        field_dict = getattr(cls, "__dataclass_fields__", {})

        result: list[FieldInfo] = []
        for name, info in field_dict.items():
            if isinstance(info, FieldInfo):
                result.append(info)
            else:
                result.append(FieldInfo(name=name, type=object))

        return tuple(result)

    @staticmethod
    def dataclass_fields_model(obj: object) -> dict[str, object]:
        """Model to get the fields dictionary from a dataclass."""
        return getattr(obj, "__dataclass_fields__", {})
