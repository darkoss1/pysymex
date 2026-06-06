"""Tests for execution-owned detector invocation."""

from __future__ import annotations

import dis

import z3

from pysymex.analysis.detectors import Detector, IsSatFn, Issue, IssueKind
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.state.record import VMState
from pysymex.execution.detectors import DetectorQueryEvent
from pysymex.execution.detectors.invocation import DetectorRunContext, run_detectors
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.session.state import ExecutionSession


def _sample() -> int:
    return 1


def _first_instruction() -> dis.Instruction:
    return next(iter(dis.get_instructions(_sample)))


class UniversalIssueDetector(Detector):
    """Detector that reports once for any opcode."""

    name = "unit-universal-runtime"
    description = "reports at every opcode"
    issue_kind = IssueKind.UNKNOWN
    relevant_opcodes: frozenset[str] = frozenset()

    def __init__(self) -> None:
        self.calls = 0

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        _ = instruction
        self.calls += 1
        return Issue(kind=self.issue_kind, message="runtime issue", pc=state.pc, line_number=99)


class QueryingDetector(Detector):
    """Detector that performs one feasibility query without reporting an issue."""

    name = "unit-querying-runtime"
    description = "queries detector feasibility"
    issue_kind = IssueKind.TYPE_ERROR
    relevant_opcodes: frozenset[str] = frozenset()

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        solver_check: IsSatFn,
    ) -> Issue | None:
        _ = state
        _ = instruction
        assert solver_check([z3.BoolVal(True)]) is True
        return None


def test_run_detectors_publishes_issue_with_engine_resolved_line_number() -> None:
    session = ExecutionSession()
    instr = _first_instruction()
    active_instructions = [instr]
    detector = UniversalIssueDetector()
    seen_issues: list[Issue] = []

    def record_issue(_owner: object, _state: VMState, issue: Issue) -> None:
        seen_issues.append(issue)

    context = DetectorRunContext(
        session=session,
        solver=IncrementalSolver(),
        dispatcher=OpcodeDispatcher(),
        hook_owner=object(),
        hooks={"on_issue": [record_issue]},
        detector_dispatch={},
        universal_detectors=[detector],
        resolve_line_number=lambda _pc, _instructions: 7,
    )

    run_detectors(context, VMState(pc=0), instr, active_instructions)

    assert detector.calls == 1
    assert len(session.issues) == 1
    assert session.issues[0].line_number == 7
    assert seen_issues == session.issues


def test_run_detectors_skips_already_reported_site() -> None:
    session = ExecutionSession()
    instr = _first_instruction()
    active_instructions = [instr]
    detector = UniversalIssueDetector()
    session.reported_detector_sites.add((id(active_instructions), 0, detector.issue_kind))
    context = DetectorRunContext(
        session=session,
        solver=IncrementalSolver(),
        dispatcher=OpcodeDispatcher(),
        hook_owner=object(),
        hooks={},
        detector_dispatch={},
        universal_detectors=[detector],
        resolve_line_number=lambda _pc, _instructions: 7,
    )

    run_detectors(context, VMState(pc=0), instr, active_instructions)

    assert detector.calls == 0
    assert session.issues == []


def test_run_detectors_attaches_detector_query_trace_context() -> None:
    session = ExecutionSession()
    observed: list[DetectorQueryEvent] = []
    session.add_detector_query_event_observer(observed.append)
    instr = _first_instruction()
    active_instructions = [instr]
    detector = QueryingDetector()
    context = DetectorRunContext(
        session=session,
        solver=IncrementalSolver(),
        dispatcher=OpcodeDispatcher(),
        hook_owner=object(),
        hooks={},
        detector_dispatch={},
        universal_detectors=[detector],
        resolve_line_number=lambda _pc, _instructions: 12,
    )

    run_detectors(
        context,
        VMState(pc=0, path_id=9, pending_constraint_count=2),
        instr,
        active_instructions,
    )

    assert len(observed) == 1
    assert observed[0].detector_name == "unit-querying-runtime"
    assert observed[0].issue_kind == "TYPE_ERROR"
    assert observed[0].path_id == 9
    assert observed[0].pc == 0
    assert observed[0].line_number == 12
    assert observed[0].opcode == instr.opname
    assert observed[0].pending_constraint_count == 2
    assert observed[0].result is True
    assert observed[0].result_source == "literal_true"
