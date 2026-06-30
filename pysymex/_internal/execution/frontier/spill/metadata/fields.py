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

"""Shared scalar field decoders for spill execution metadata."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, TypeVar, cast

from .types import SpillMetadataDecodeError

if TYPE_CHECKING:
    from collections.abc import Mapping

EnumT = TypeVar("EnumT", bound=Enum)


def pair_payload(raw_payload: object) -> tuple[object, object] | None:
    """Return a two-item JSON list as a typed pair."""
    if not isinstance(raw_payload, list):
        return None
    items = cast("list[object]", raw_payload)
    if len(items) != 2:
        return None
    return (items[0], items[1])


def required_str(payload: Mapping[str, object], key: str) -> str:
    """Return a required string metadata field."""
    raw_value = payload.get(key)
    if isinstance(raw_value, str):
        return raw_value
    msg = f"metadata field {key!r} must be a string"
    raise SpillMetadataDecodeError(msg)


def required_int(payload: Mapping[str, object], key: str) -> int:
    """Return a required integer metadata field, excluding ``bool``."""
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        msg = f"metadata field {key!r} must be an integer"
        raise SpillMetadataDecodeError(msg)
    if isinstance(raw_value, int):
        return raw_value
    msg = f"metadata field {key!r} must be an integer"
    raise SpillMetadataDecodeError(msg)


def raw_int(raw_value: object) -> int:
    """Return a raw integer metadata value, excluding ``bool``."""
    if isinstance(raw_value, bool):
        msg = "metadata integer is malformed"
        raise SpillMetadataDecodeError(msg)
    if isinstance(raw_value, int):
        return raw_value
    msg = "metadata integer is malformed"
    raise SpillMetadataDecodeError(msg)


def optional_int(payload: Mapping[str, object], key: str) -> int | None:
    """Return an optional integer metadata field, excluding ``bool``."""
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    if isinstance(raw_value, bool):
        msg = f"metadata field {key!r} must be an integer"
        raise SpillMetadataDecodeError(msg)
    if isinstance(raw_value, int):
        return raw_value
    msg = f"metadata field {key!r} must be an integer or null"
    raise SpillMetadataDecodeError(msg)


def required_bool(payload: Mapping[str, object], key: str) -> bool:
    """Return a required boolean metadata field."""
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        return raw_value
    msg = f"metadata field {key!r} must be a bool"
    raise SpillMetadataDecodeError(msg)


def enum_member(enum_type: type[EnumT], name: str) -> EnumT:
    """Return an enum member by name or raise a metadata decode error."""
    try:
        return enum_type[name]
    except KeyError as exc:
        msg = "metadata enum value is unsupported"
        raise SpillMetadataDecodeError(msg) from exc
