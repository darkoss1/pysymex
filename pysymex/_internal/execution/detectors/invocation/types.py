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

"""Shared detector invocation types."""

from __future__ import annotations

import dis
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.contract import Detector
    from pysymex._internal.execution.detectors.publication.types import HookMap
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.typing.protocols import SolverProtocol

ResolveLineNumber = Callable[[int, list[dis.Instruction]], int | None]


@dataclass(frozen=True, slots=True)
class DetectorRunContext:
    """Runtime owners needed to run detectors for one instruction."""

    session: ExecutionSession
    solver: SolverProtocol
    dispatcher: OpcodeDispatcher
    hook_owner: object
    hooks: HookMap
    detector_dispatch: dict[str, list[Detector]]
    universal_detectors: list[Detector]
    resolve_line_number: ResolveLineNumber
