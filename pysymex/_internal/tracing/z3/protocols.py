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

"""Shared Z3 tracing protocols and constants."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Iterable

_z3_avail: bool = False
try:
    import z3

    _Z3_MODULE = z3
    _z3_avail = True
except ImportError:
    z3 = None

Z3_AVAILABLE: Final[bool] = _z3_avail

ABSTRACT_VAR_RE = re.compile(r"\bk!(\d+)\b|\b!(\d+)\b")

MAX_EXPR_CHARS = 16384

UNSERIALIZABLE = "<unserializable>"


@runtime_checkable
class ModelDeclLike(Protocol):
    """Minimal declaration protocol used for model serialization."""

    def name(self) -> str:
        """Return the declaration name."""
        ...


@runtime_checkable
class ModelLike(Protocol):
    """Minimal model protocol for indexed declaration lookup."""

    def decls(self) -> list[ModelDeclLike]:
        """Return model declarations."""
        ...

    def __getitem__(self, key: ModelDeclLike) -> object:
        """Return the assignment associated with a declaration."""
        ...


@runtime_checkable
class NamespaceLike(Protocol):
    """Dictionary-like namespace protocol for state serialization."""

    def items(self) -> Iterable[tuple[object, object]]:
        """Iterate namespace key/value pairs."""
        ...
