"""Tests for scheduling-owned loop-bound and widening handoff policy."""

from __future__ import annotations

from types import CodeType
import dis

import z3

from pysymex.analysis.static.loops.detector import LoopDetector
from pysymex.analysis.static.loops.types import LoopInfo
from pysymex.core.bytecode import instruction_stream_key
from pysymex.analysis.static.loops.widening import LoopWidening
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.scheduling import create_path_manager
from pysymex.execution.scheduling.loop_bounds import LoopBoundContext, apply_loop_bound_policy
from pysymex.execution.session.state import ExecutionSession


def _loop_fixture() -> tuple[list[dis.Instruction], LoopDetector, LoopInfo, int]:
    module_code = compile(
        "def f(x):\n    while x > 0:\n        x -= 1\n    return x\n",
        "<loop-bound-policy-test>",
        "exec",
    )
    function_code = next(value for value in module_code.co_consts if isinstance(value, CodeType))
    instructions = list(dis.get_instructions(function_code))
    detector = LoopDetector()
    loop = detector.analyze_cfg(instructions)[0]
    header_idx = next(
        idx for idx, instruction in enumerate(instructions) if instruction.offset == loop.header_pc
    )
    return instructions, detector, loop, header_idx


def _for_loop_fixture() -> tuple[list[dis.Instruction], LoopDetector, LoopInfo, int]:
    module_code = compile(
        "def f(items):\n    for item in items:\n        pass\n    return 0\n",
        "<for-loop-bound-policy-test>",
        "exec",
    )
    function_code = next(value for value in module_code.co_consts if isinstance(value, CodeType))
    instructions = list(dis.get_instructions(function_code))
    detector = LoopDetector()
    loop = detector.analyze_cfg(instructions)[0]
    header_idx = next(
        idx for idx, instruction in enumerate(instructions) if instruction.offset == loop.header_pc
    )
    return instructions, detector, loop, header_idx


def _non_loop_collision_fixture(offset: int) -> tuple[list[dis.Instruction], int]:
    module_code = compile(
        "def g():\n    x = 1\n    return x\n",
        "<loop-offset-collision-test>",
        "exec",
    )
    function_code = next(value for value in module_code.co_consts if isinstance(value, CodeType))
    instructions = list(dis.get_instructions(function_code))
    instruction_idx = next(
        idx for idx, instruction in enumerate(instructions) if instruction.offset == offset
    )
    return instructions, instruction_idx


def _loop_key(instructions: list[dis.Instruction], loop: LoopInfo) -> tuple[int, ...]:
    return (*instruction_stream_key(instructions), loop.header_pc)


def _context(
    session: ExecutionSession,
    *,
    max_loop_iterations: int,
    events: list[str] | None = None,
) -> LoopBoundContext:
    event_log = events if events is not None else []
    return LoopBoundContext(
        session=session,
        max_loop_iterations=max_loop_iterations,
        verbose=False,
        record_path_explored_event=lambda: event_log.append("path_explored"),
    )


def test_apply_loop_bound_policy_saves_header_snapshot_within_bound() -> None:
    instructions, detector, loop, header_idx = _loop_fixture()
    session = ExecutionSession()
    session.loop_detector = detector
    session.loop_detectors[instruction_stream_key(instructions)] = detector
    state = VMState(pc=header_idx)

    result = apply_loop_bound_policy(
        _context(session, max_loop_iterations=2),
        state,
        instructions,
    )

    assert result is True
    loop_key = _loop_key(instructions, loop)
    assert state.loop_iterations[loop_key] == 1
    assert loop_key in state.prev_loop_states
    assert session.paths_pruned == 0


def test_apply_loop_bound_policy_prunes_when_bound_exceeded_without_widening() -> None:
    instructions, detector, _loop, header_idx = _loop_fixture()
    session = ExecutionSession()
    session.loop_detector = detector
    session.loop_detectors[instruction_stream_key(instructions)] = detector
    state = VMState(pc=header_idx)

    result = apply_loop_bound_policy(
        _context(session, max_loop_iterations=0),
        state,
        instructions,
    )

    assert result is False
    assert session.paths_pruned == 1
    assert session.paths_explored == 0


def test_apply_loop_bound_policy_extends_for_finite_symbolic_string_iterator() -> None:
    instructions, detector, loop, header_idx = _for_loop_fixture()
    session = ExecutionSession()
    session.loop_detector = detector
    session.loop_detectors[instruction_stream_key(instructions)] = detector
    symbolic_string, type_constraint = SymbolicString.symbolic("key")
    length_slot = z3.Int("len_key_int")
    loop_key = _loop_key(instructions, loop)
    state = VMState(
        stack=[SymbolicIterator("string_iter", symbolic_string)],
        path_constraints=[
            type_constraint,
            length_slot == symbolic_string.z3_len,
            z3.Not(16 != length_slot),
        ],
        pc=header_idx,
    )
    state.loop_iterations[loop_key] = 16

    result = apply_loop_bound_policy(
        _context(session, max_loop_iterations=10),
        state,
        instructions,
    )

    assert result is True
    assert state.loop_iterations[loop_key] == 17
    assert session.paths_pruned == 0


def test_apply_loop_bound_policy_extends_for_concrete_backed_symbolic_list_iterator() -> None:
    instructions, detector, loop, header_idx = _for_loop_fixture()
    session = ExecutionSession()
    session.loop_detector = detector
    session.loop_detectors[instruction_stream_key(instructions)] = detector
    loop_key = _loop_key(instructions, loop)
    state = VMState(
        stack=[SymbolicIterator("range_iter", SymbolicList.from_const(list(range(15))))],
        pc=header_idx,
    )
    state.loop_iterations[loop_key] = 15

    result = apply_loop_bound_policy(
        _context(session, max_loop_iterations=10),
        state,
        instructions,
    )

    assert result is True
    assert state.loop_iterations[loop_key] == 16
    assert session.paths_pruned == 0


def test_apply_loop_bound_policy_ignores_non_loop_offset_collision_in_nested_stream() -> None:
    root_instructions, detector, loop, _header_idx = _for_loop_fixture()
    nested_instructions, nested_idx = _non_loop_collision_fixture(loop.header_pc)
    session = ExecutionSession()
    session.instructions = root_instructions
    session.loop_detector = detector
    session.loop_detectors[instruction_stream_key(root_instructions)] = detector
    state = VMState(pc=nested_idx)

    result = apply_loop_bound_policy(
        _context(session, max_loop_iterations=0),
        state,
        nested_instructions,
    )

    assert result is True
    assert not state.loop_iterations
    assert session.paths_pruned == 0


def test_apply_loop_bound_policy_scopes_counts_by_instruction_stream() -> None:
    first_instructions, first_detector, _first_loop, first_header_idx = _for_loop_fixture()
    second_instructions, _second_detector, _second_loop, second_header_idx = _for_loop_fixture()
    session = ExecutionSession()
    session.instructions = first_instructions
    session.loop_detector = first_detector
    session.loop_detectors[instruction_stream_key(first_instructions)] = first_detector
    state = VMState(pc=first_header_idx)

    first_result = apply_loop_bound_policy(
        _context(session, max_loop_iterations=1),
        state,
        first_instructions,
    )
    state.set_pc(second_header_idx)
    second_result = apply_loop_bound_policy(
        _context(session, max_loop_iterations=1),
        state,
        second_instructions,
    )

    assert first_result is True
    assert second_result is True
    assert sorted(state.loop_iterations.values()) == [1, 1]
    assert session.paths_pruned == 0


def test_apply_loop_bound_policy_enqueues_widened_exit_state() -> None:
    instructions, detector, loop, header_idx = _loop_fixture()
    config = ExecutionConfig(deterministic_mode=True)
    session = ExecutionSession()
    session.loop_detector = detector
    session.loop_detectors[instruction_stream_key(instructions)] = detector
    session.loop_widening = LoopWidening(widening_threshold=1)
    worklist = create_path_manager(
        config.strategy,
        deterministic=config.deterministic_mode,
        random_seed=config.random_seed,
    )
    session.worklist = worklist
    state = VMState(pc=header_idx)
    state.prev_loop_states[_loop_key(instructions, loop)] = state.fork()
    events: list[str] = []

    result = apply_loop_bound_policy(
        _context(session, max_loop_iterations=0, events=events),
        state,
        instructions,
    )

    widened = worklist.get_next_state()
    exit_idx = next(
        idx
        for idx, instruction in enumerate(instructions)
        if instruction.offset > max(loop.body_pcs)
    )

    assert result is False
    assert widened is not None
    assert widened.pc == exit_idx
    assert session.paths_pruned == 1
    assert session.paths_explored == 1
    assert events == ["path_explored"]
