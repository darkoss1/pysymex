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

"""Detector SAT-query trace context construction."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.telemetry import DetectorQueryContext

if TYPE_CHECKING:
    import dis

    from pysymex._internal.analysis.detectors.detector.contract import Detector
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.detectors.invocation.types import DetectorRunContext


def build_detector_query_context(
    *,
    context: DetectorRunContext,
    detector: Detector,
    state: VMState,
    instr: dis.Instruction,
    active_instructions: list[dis.Instruction],
) -> DetectorQueryContext:
    """Build bounded detector-query context for trace observers."""
    return DetectorQueryContext(
        detector_name=detector.name,
        issue_kind=detector.issue_kind.name,
        path_id=state.path_id,
        pc=state.pc,
        line_number=context.resolve_line_number(state.pc, active_instructions),
        opcode=instr.opname,
        state_constraints_count=len(state.path_constraints),
        pending_constraint_count=state.pending_constraint_count,
        last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
    )
