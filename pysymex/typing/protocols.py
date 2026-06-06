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

"""Protocol definitions that do not depend on StackValue."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class SummaryProtocol(Protocol):
    """Protocol for function summaries being built."""

    parameters: list[object]
    preconditions: list[object]
    postconditions: list[object]
    modified: list[object]
    reads: list[object]
    calls: list[object]
    may_raise: list[object]


@runtime_checkable
class SummaryBuilderProtocol(Protocol):
    """Protocol for summary builders in state management."""

    summary: SummaryProtocol
    _initial_args: list[object]


@runtime_checkable
class VerificationResultProtocol(Protocol):
    """Protocol for verification results."""

    can_crash: bool
    proven_safe: bool
    z3_status: str
    verification_time_ms: float
    crash: object | None
