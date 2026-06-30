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

"""Callback contract for opcode-result processing."""

from __future__ import annotations

import dis
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.execution.results.routing.types import (
        HookMap,
        PathCompleteCallback,
        PathResourceTracker,
        RecordPathExplored,
    )
    from pysymex._internal.execution.session.state.core import ExecutionSession

ActiveInstructionLineResolver = Callable[[int, list[dis.Instruction]], int | None]


@dataclass(frozen=True, slots=True)
class ProcessingContext:
    """Mutable owners and callbacks needed to route one opcode result."""

    session: ExecutionSession
    hook_owner: object
    hooks: HookMap
    resource_tracker: PathResourceTracker | None
    resolve_line_number: ActiveInstructionLineResolver
    on_path_complete: PathCompleteCallback
    record_path_explored: RecordPathExplored
