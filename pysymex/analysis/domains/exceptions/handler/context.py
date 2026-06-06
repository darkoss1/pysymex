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

"""Context types carried through exception handler analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


class ExceptionHandlerType(Enum):
    """Types of exception handlers."""

    EXCEPT = auto()
    EXCEPT_TYPE = auto()
    EXCEPT_AS = auto()
    FINALLY = auto()
    ELSE = auto()


@dataclass
class ExceptionHandlerInfo:
    """Information about an exception handler block."""

    handler_type: ExceptionHandlerType
    start_pc: int
    end_pc: int
    exception_types: list[str] = field(default_factory=list[str])
    exception_var: str | None = None
    nesting_depth: int = 0


@dataclass
class ExceptionHandlerState:
    """Tracks discovered exception handler spans."""

    all_handlers: list[ExceptionHandlerInfo] = field(default_factory=list[ExceptionHandlerInfo])
