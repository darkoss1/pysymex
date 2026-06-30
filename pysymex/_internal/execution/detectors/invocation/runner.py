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

"""Per-instruction detector execution orchestration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.state.record import StateConstraints, VMState
from pysymex._internal.execution.detectors.invocation.issues import record_detector_issue
from pysymex._internal.execution.detectors.invocation.query.context import (
    build_detector_query_context,
)
from pysymex._internal.execution.detectors.query.cache.policy import detector_query_is_sat
from pysymex._internal.execution.detectors.query.constraints import (
    canonicalize_detector_query_constraints,
    matching_known_sat_path_prefix_len,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import dis

    import z3

    from pysymex._internal.analysis.detectors.detector.contract import Detector
    from pysymex._internal.execution.detectors.invocation.types import DetectorRunContext
    from pysymex._internal.execution.detectors.telemetry import DetectorQueryContext

logger = get_logger(__name__)


def run_detectors(
    context: DetectorRunContext,
    state: VMState,
    instr: dis.Instruction,
    active_instructions: list[dis.Instruction],
) -> None:
    """Run enabled detectors for the current instruction and publish reportable issues."""
    context.session.deferred_detector_issues = []
    opname = instr.opname
    specific_detectors = context.detector_dispatch.get(opname)
    if not context.universal_detectors and not specific_detectors:
        return

    instruction_stream_id = id(active_instructions)
    for detector in context.universal_detectors:
        _run_detector(
            context=context,
            detector=detector,
            instruction_stream_id=instruction_stream_id,
            state=state,
            instr=instr,
            active_instructions=active_instructions,
        )

    if specific_detectors:
        for detector in specific_detectors:
            _run_detector(
                context=context,
                detector=detector,
                instruction_stream_id=instruction_stream_id,
                state=state,
                instr=instr,
                active_instructions=active_instructions,
            )


def _run_detector(
    *,
    context: DetectorRunContext,
    detector: Detector,
    instruction_stream_id: int,
    state: VMState,
    instr: dis.Instruction,
    active_instructions: list[dis.Instruction],
) -> None:
    """Run one detector unless this site was already reported."""
    site_key = (instruction_stream_id, state.pc, detector.issue_kind)
    if site_key in context.session.reported_detector_sites:
        return
    if logger.state.trace_enabled:
        logger.trace(
            "detector check name=%s path_id=%d pc=%d opname=%s",
            detector.name,
            state.path_id,
            state.pc,
            instr.opname,
        )

    query_oracle = _DetectorQueryOracle(
        context=context,
        detector=detector,
        state=state,
        instr=instr,
        active_instructions=active_instructions,
    )
    issue = detector.check(state, instr, query_oracle)
    if issue is not None:
        record_detector_issue(
            context=context,
            detector=detector,
            issue=issue,
            site_key=site_key,
            state=state,
            instr=instr,
            active_instructions=active_instructions,
        )


class _DetectorQueryOracle:
    """Detector SAT callback that also owns matching model extraction."""

    def __init__(
        self,
        *,
        context: DetectorRunContext,
        detector: Detector,
        state: VMState,
        instr: dis.Instruction,
        active_instructions: list[dis.Instruction],
    ) -> None:
        self._context = context
        self._detector = detector
        self._state = state
        self._instr = instr
        self._active_instructions = active_instructions

    def __call__(self, constraints: list[z3.BoolRef]) -> bool:
        """Return whether detector constraints are established SAT."""
        return detector_query_is_sat(
            session=self._context.session,
            solver=self._context.solver,
            constraints=constraints,
            inconclusive_path_prefix=self._inconclusive_path_prefix(),
            known_sat_path_prefix=self._known_sat_path_prefix(),
            query_context=self._query_context(),
        )

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        """Return model evidence using the same known-prefix gate as SAT queries."""
        known_sat_prefix_len = self._known_sat_prefix_len_for_query(constraints)
        result = self._context.solver.check_sat_cached(
            constraints,
            known_sat_prefix_len=known_sat_prefix_len,
        )
        if result.is_sat and result.model is not None:
            return result.model
        return None

    def _known_sat_path_prefix(self) -> tuple[z3.BoolRef, ...] | None:
        """Return the state path prefix already proved SAT by execution."""
        known_prefix_len = StateConstraints.known_sat_prefix_len(self._state)
        if known_prefix_len <= 0:
            return None
        return tuple(self._state.path_constraints)[:known_prefix_len]

    def _known_sat_prefix_len_for_query(self, constraints: list[z3.BoolRef]) -> int | None:
        """Return a verified known-SAT prefix length for this detector query."""
        normalized_constraints = canonicalize_detector_query_constraints(constraints)
        if isinstance(normalized_constraints, bool):
            return None
        return matching_known_sat_path_prefix_len(
            normalized_constraints,
            self._known_sat_path_prefix(),
        )

    def _inconclusive_path_prefix(self) -> tuple[z3.BoolRef, ...] | None:
        """Return the path prefix known only inconclusively, if the whole path matches."""
        if self._state.last_inconclusive_feasibility_len != len(self._state.path_constraints):
            return None
        return tuple(self._state.path_constraints)

    def _query_context(self) -> DetectorQueryContext | None:
        """Return detector-query telemetry context when observers are installed."""
        if not self._context.session.detector_query_event_observers:
            return None
        return build_detector_query_context(
            context=self._context,
            detector=self._detector,
            state=self._state,
            instr=self._instr,
            active_instructions=self._active_instructions,
        )
