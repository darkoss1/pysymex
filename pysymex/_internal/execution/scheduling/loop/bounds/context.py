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

"""Shared loop-bound policy context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.execution.session.state.core import ExecutionSession


@dataclass(frozen=True, slots=True)
class LoopBoundContext:
    """Mutable execution owners and policy values needed for loop-bound handling."""

    session: ExecutionSession
    max_loop_iterations: int | None
    verbose: bool
    record_path_explored_event: Callable[[], None]
    continue_unsupported_with_host_guard: bool = False
