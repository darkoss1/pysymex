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

"""Concrete attribute safety guards for execution call and attribute handling."""

from __future__ import annotations

from pysymex._internal.sandbox.errors import SecurityViolationError

_BLOCKED_CONCRETE_ATTR_NAMES: frozenset[str] = frozenset(
    (
        "__subclasses__",
        "__bases__",
        "__mro__",
        "__globals__",
        "__builtins__",
        "__loader__",
        "__spec__",
        "__code__",
        "__closure__",
        "__func__",
        "__self__",
        "__wrapped__",
        "__getattribute__",
        "__reduce__",
        "__reduce_ex__",
        "__traceback__",
        "tb_frame",
        "f_globals",
        "f_locals",
        "f_code",
        "f_builtins",
        "f_back",
        "gi_frame",
        "gi_code",
        "cr_frame",
        "cr_code",
        "ag_frame",
        "ag_code",
    ),
)


def validate_concrete_attribute_access(attr_name: str) -> None:
    """Reject introspection attribute names on concrete VM objects."""
    if attr_name in _BLOCKED_CONCRETE_ATTR_NAMES:
        msg = "attribute access"
        raise SecurityViolationError(
            msg,
            f"attribute '{attr_name}' is blocked for concrete objects",
        )
