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

"""Cache key types and stable content hash helpers.

Provides ``CacheKey`` (an immutable key with type, identifier, and version),
string hashing functions for bytecode, functions, files, and dicts, and a
code-object fingerprinting routine that normalises nested constants.
"""

from __future__ import annotations

from collections.abc import Mapping as _Mapping

import json
import types
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import cast

from pysymex.utils.hashing import stable_digest_hex


def cache_hit_rate(hits: int, misses: int) -> float:
    """Return hits / (hits + misses), or 0.0 when no lookups have occurred."""
    total = hits + misses
    return hits / total if total > 0 else 0.0


class CacheKeyType(Enum):
    """Discriminator for the kind of object a ``CacheKey`` identifies."""

    FUNCTION = auto()
    BYTECODE = auto()
    MODULE = auto()
    SUMMARY = auto()
    VERIFICATION = auto()
    CUSTOM = auto()


@dataclass(frozen=True)
class CacheKey:
    """Immutable, hashable cache key combining type, identifier, and version.

    Serialises to / parses from ``TYPE_NAME:identifier:version`` strings.
    """

    key_type: CacheKeyType
    identifier: str
    version: str = "1.0"

    def __hash__(self) -> int:
        """Return the hash value of the object."""
        return hash((self.key_type, self.identifier, self.version))

    def to_string(self) -> str:
        """Serialise to ``TYPE_NAME:identifier:version``."""
        return f"{self.key_type.name}:{self.identifier}:{self.version}"

    @classmethod
    def from_string(cls, s: str) -> CacheKey:
        """Parse a key from its ``TYPE_NAME:identifier[:version]`` string form.

        Raises:
            ValueError: If the string has no ``:`` separator.
            KeyError: If the type name is not a valid ``CacheKeyType``.
        """
        parts = s.split(":", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid cache key string: {s}")

        right_parts = parts[1].rsplit(":", 1)
        if len(right_parts) == 2:
            identifier, version = right_parts
        else:
            identifier = parts[1]
            version = "1.0"

        return cls(key_type=CacheKeyType[parts[0]], identifier=identifier, version=version)


def hash_bytecode(code: bytes) -> str:
    """Return the stable hex digest of raw bytecode bytes."""
    return stable_digest_hex(code)


def _normalise_code_constant(value: object) -> object:
    """Recursively normalizes a code constant to a serializable dictionary.

    Args:
        value (object): The constant object.

    Returns:
        object: The normalized serializable object representation.
    """
    if isinstance(value, types.CodeType):
        return {"kind": "code", "value": _code_fingerprint_payload(value)}
    if isinstance(value, bytes):
        return {"kind": "bytes", "value": value.hex()}
    if isinstance(value, tuple):
        tuple_items = cast("tuple[object, ...]", value)
        return {"kind": "tuple", "items": [_normalise_code_constant(item) for item in tuple_items]}
    if isinstance(value, frozenset):
        frozen_items = cast("frozenset[object]", value)
        items = [_normalise_code_constant(item) for item in frozen_items]
        return {"kind": "frozenset", "items": sorted(items, key=repr)}
    if isinstance(value, complex):
        return {"kind": "complex", "real": value.real, "imag": value.imag}
    if value is Ellipsis:
        return {"kind": "ellipsis"}
    if value is None or isinstance(value, bool | int | float | str):
        return {"kind": type(value).__qualname__, "value": value}
    return {"kind": type(value).__qualname__, "repr": repr(value)}


def _code_fingerprint_payload(code: types.CodeType) -> dict[str, object]:
    """Build a dictionary of relevant attributes from a CodeType object to compute fingerprint.

    Args:
        code (CodeType): The code object.

    Returns:
        dict[str, object]: Dictionary representation of code attributes.
    """
    return {
        "co_argcount": code.co_argcount,
        "co_cellvars": list(code.co_cellvars),
        "co_code": code.co_code.hex(),
        "co_consts": [_normalise_code_constant(value) for value in code.co_consts],
        "co_exceptiontable": getattr(code, "co_exceptiontable", b"").hex(),
        "co_flags": code.co_flags,
        "co_freevars": list(code.co_freevars),
        "co_kwonlyargcount": code.co_kwonlyargcount,
        "co_names": list(code.co_names),
        "co_nlocals": code.co_nlocals,
        "co_posonlyargcount": getattr(code, "co_posonlyargcount", 0),
        "co_stacksize": code.co_stacksize,
        "co_varnames": list(code.co_varnames),
    }


def hash_function(func_name: str, code: types.CodeType | bytes, signature: str = "") -> str:
    """Return a stable hex digest identifying a function by name, code, and optional signature.

    When *code* is a ``CodeType``, a stable JSON fingerprint of its
    bytecode attributes is computed (including nested code objects
    and constants).  When *code* is raw bytes, it is concatenated
    with name and signature directly.
    """
    if isinstance(code, bytes):
        content = f"{func_name}:{signature}:".encode() + code
    else:
        payload = {
            "function": func_name,
            "signature": signature,
            "code": _code_fingerprint_payload(code),
        }
        content = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return stable_digest_hex(content)


def hash_file(path: Path) -> str:
    """Return the stable hex digest of the file at *path*."""
    content = path.read_bytes()
    return stable_digest_hex(content)


def hash_dict(d: _Mapping[str, object]) -> str:
    """Return the stable hex digest of a JSON-serialised dict (sorted keys, ``str`` default)."""
    content = json.dumps(d, sort_keys=True, default=str)
    return stable_digest_hex(content.encode())


__all__ = [
    "CacheKey",
    "CacheKeyType",
    "cache_hit_rate",
    "hash_bytecode",
    "hash_dict",
    "hash_file",
    "hash_function",
]
