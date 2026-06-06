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

"""Structural protocols for control-flow bytecode metadata."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable


class ExceptionEntryProtocol(Protocol):
    """Protocol for exception table entries (Python 3.11+)."""

    @property
    def target(self) -> int:
        """The target byte-offset of the exception handler block."""
        ...

    @property
    def start(self) -> int:
        """The start byte-offset of the guarded block."""
        ...

    @property
    def end(self) -> int:
        """The end byte-offset of the guarded block."""
        ...


@runtime_checkable
class BytecodeWithExceptionEntries(Protocol):
    """Protocol for bytecode objects exposing parsed exception entries."""

    exception_entries: Sequence[ExceptionEntryProtocol]


__all__ = ["BytecodeWithExceptionEntries", "ExceptionEntryProtocol"]
