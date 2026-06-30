"""Tests for one-instruction step pipeline orchestration."""

from __future__ import annotations

import dis
from collections.abc import Callable

from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.state.types import VMStateError
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.session.state.core import ExecutionSession
from pysymex._internal.execution.step.context import StepExecutionContext
from pysymex._internal.execution.step.pipeline import execute_one_step


def _instructions(source: str) -> list[dis.Instruction]:
    code = compile(source, "<step-pipeline-test>", "exec")
    return list(dis.get_instructions(code))


def _context(
    *,
    session: ExecutionSession,
    dispatcher: OpcodeDispatcher,
    instructions: list[dis.Instruction],
    events: list[str] | None = None,
    process_result: Callable[[OpcodeResult, VMState, list[dis.Instruction]], None] | None = None,
) -> StepExecutionContext:
    event_log = events if events is not None else []

    def check_resource_limits(_state: VMState) -> bool:
        event_log.append("resource")
        return True

    def merge_state(state: VMState) -> VMState | None:
        event_log.append("merge")
        return state

    def handle_loop_logic(_state: VMState, _active: list[dis.Instruction]) -> bool:
        event_log.append("loop")
        return True

    def check_path_feasibility(_state: VMState) -> bool:
        event_log.append("feasible")
        return True

    def before_dispatch(
        _instr: dis.Instruction, _state: VMState, _active: list[dis.Instruction]
    ) -> None:
        event_log.append("before")

    def run_detectors(
        _state: VMState, _instr: dis.Instruction, _active: list[dis.Instruction]
    ) -> None:
        event_log.append("detectors")

    def default_process_result(
        _result: OpcodeResult, _state: VMState, _active: list[dis.Instruction]
    ) -> None:
        event_log.append("process")

    def on_path_complete(_state: VMState) -> None:
        event_log.append("complete")

    def get_line_number(_pc: int, _active: list[dis.Instruction]) -> int | None:
        return 42

    return StepExecutionContext(
        session=session,
        dispatcher=dispatcher,
        hook_owner=object(),
        hooks={"pre_step": [lambda *_args: event_log.append("pre")]},
        root_instructions=instructions,
        lazy_eval_threshold=100,
        check_resource_limits=check_resource_limits,
        merge_state=merge_state,
        handle_loop_logic=handle_loop_logic,
        check_path_feasibility=check_path_feasibility,
        before_dispatch=before_dispatch,
        has_detectors=lambda _opname: True,
        run_detectors=run_detectors,
        process_execution_result=process_result or default_process_result,
        on_path_complete=on_path_complete,
        get_line_number=get_line_number,
    )


def test_execute_one_step_records_completed_path() -> None:
    session = ExecutionSession()
    instructions = _instructions("x = 1")
    events: list[str] = []

    execute_one_step(
        _context(
            session=session,
            dispatcher=OpcodeDispatcher(),
            instructions=instructions,
            events=events,
        ),
        VMState(pc=len(instructions)),
    )

    assert session.paths_completed == 1
    assert events == ["pre", "complete"]


def test_execute_one_step_runs_gates_dispatch_and_result_routing_in_order() -> None:
    session = ExecutionSession()
    dispatcher = OpcodeDispatcher()
    instructions = _instructions("x = 1")
    instr = instructions[0]
    events: list[str] = []
    routed: list[OpcodeResult] = []

    def handler(
        _instr: dis.Instruction,
        state: VMState,
        _dispatcher: OpcodeDispatcher,
    ) -> OpcodeResult:
        events.append("dispatch")
        return OpcodeResult.continue_with(state.advance_pc())

    def process_result(
        result: OpcodeResult, _state: VMState, _active: list[dis.Instruction]
    ) -> None:
        events.append("process")
        routed.append(result)

    dispatcher.register_handler(instr.opname, handler)
    state = VMState(pc=0)

    execute_one_step(
        _context(
            session=session,
            dispatcher=dispatcher,
            instructions=instructions,
            events=events,
            process_result=process_result,
        ),
        state,
    )

    assert events == [
        "pre",
        "resource",
        "merge",
        "loop",
        "before",
        "detectors",
        "dispatch",
        "process",
    ]
    assert session.coverage == {0}
    assert state.current_instructions == instructions
    assert routed[0].new_states[0].pc == 1


def test_execute_one_step_skips_detector_callback_when_opcode_has_no_detectors() -> None:
    session = ExecutionSession()
    dispatcher = OpcodeDispatcher()
    instructions = _instructions("x = 1")
    instr = instructions[0]
    events: list[str] = []

    def handler(
        _instr: dis.Instruction,
        state: VMState,
        _dispatcher: OpcodeDispatcher,
    ) -> OpcodeResult:
        events.append("dispatch")
        return OpcodeResult.continue_with(state.advance_pc())

    dispatcher.register_handler(instr.opname, handler)
    context = _context(
        session=session,
        dispatcher=dispatcher,
        instructions=instructions,
        events=events,
    )
    context = StepExecutionContext(
        session=context.session,
        dispatcher=context.dispatcher,
        hook_owner=context.hook_owner,
        hooks=context.hooks,
        root_instructions=context.root_instructions,
        lazy_eval_threshold=context.lazy_eval_threshold,
        check_resource_limits=context.check_resource_limits,
        merge_state=context.merge_state,
        handle_loop_logic=context.handle_loop_logic,
        check_path_feasibility=context.check_path_feasibility,
        before_dispatch=context.before_dispatch,
        has_detectors=lambda _opname: False,
        run_detectors=context.run_detectors,
        process_execution_result=context.process_execution_result,
        on_path_complete=context.on_path_complete,
        get_line_number=context.get_line_number,
    )

    execute_one_step(context, VMState(pc=0))

    assert "detectors" not in events
    assert "dispatch" in events


def test_execute_one_step_preserves_pending_constraints_after_inconclusive_check() -> None:
    """The feasibility owner decides whether pending constraints are proven."""
    session = ExecutionSession()
    dispatcher = OpcodeDispatcher()
    instructions = _instructions("x = 1")
    instr = instructions[0]
    events: list[str] = []

    def handler(
        _instr: dis.Instruction,
        state: VMState,
        _dispatcher: OpcodeDispatcher,
    ) -> OpcodeResult:
        events.append("dispatch")
        return OpcodeResult.continue_with(state.advance_pc())

    def inconclusive_feasibility(state: VMState) -> bool:
        events.append("feasible")
        assert state.pending_constraint_count == 1
        return True

    dispatcher.register_handler(instr.opname, handler)
    base_context = _context(
        session=session,
        dispatcher=dispatcher,
        instructions=instructions,
        events=events,
    )
    context = StepExecutionContext(
        session=base_context.session,
        dispatcher=base_context.dispatcher,
        hook_owner=base_context.hook_owner,
        hooks=base_context.hooks,
        root_instructions=base_context.root_instructions,
        lazy_eval_threshold=1,
        check_resource_limits=base_context.check_resource_limits,
        merge_state=base_context.merge_state,
        handle_loop_logic=base_context.handle_loop_logic,
        check_path_feasibility=inconclusive_feasibility,
        before_dispatch=base_context.before_dispatch,
        has_detectors=lambda _opname: False,
        run_detectors=base_context.run_detectors,
        process_execution_result=base_context.process_execution_result,
        on_path_complete=base_context.on_path_complete,
        get_line_number=base_context.get_line_number,
    )
    state = VMState(pc=0, pending_constraint_count=1)

    execute_one_step(context, state)

    assert state.pending_constraint_count == 1
    assert events == [
        "pre",
        "resource",
        "merge",
        "loop",
        "feasible",
        "before",
        "dispatch",
        "process",
    ]


def test_execute_one_step_records_vm_state_error_as_unknown_issue() -> None:
    session = ExecutionSession()
    dispatcher = OpcodeDispatcher()
    instructions = _instructions("x = 1")
    instr = instructions[0]

    def handler(
        _instr: dis.Instruction,
        _state: VMState,
        _dispatcher: OpcodeDispatcher,
    ) -> OpcodeResult:
        raise VMStateError("unit step failure")

    dispatcher.register_handler(instr.opname, handler)

    execute_one_step(
        _context(session=session, dispatcher=dispatcher, instructions=instructions),
        VMState(pc=0),
    )

    assert session.paths_pruned == 1
    assert session.issues[-1].kind is IssueKind.UNKNOWN
    assert session.issues[-1].line_number == 42
    assert "unit step failure" in session.issues[-1].message
