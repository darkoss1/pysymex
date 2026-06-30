"""Tests for scheduling-owned loop-bound and widening handoff policy."""

from __future__ import annotations

import dis
import sys
from types import CodeType

import z3

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.core.bytecode import instruction_stream_key
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.generators import ModeledGenerator
from pysymex._internal.core.types.containers.iterator_sources import EnumerateIteratorSource
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.scheduling.factory import create_path_manager
from pysymex._internal.execution.scheduling.loop.bounds.context import LoopBoundContext
from pysymex._internal.execution.scheduling.loop.bounds.context import (
    LoopBoundContext as LoopBoundContextOwner,
)
from pysymex._internal.execution.scheduling.loop.bounds.finite import (
    exact_int_value,
    finite_countdown_remaining_steps,
    finite_iterator_upper_bound,
)
from pysymex._internal.execution.scheduling.loop.bounds.generators import (
    generator_remaining_steps,
)
from pysymex._internal.execution.scheduling.loop.bounds.policy import (
    LOOP_WIDENING_DEGRADED_PASS,
    apply_loop_bound_policy,
)
from pysymex._internal.execution.scheduling.loop.bounds.policy import (
    apply_loop_bound_policy as apply_loop_bound_policy_owner,
)
from pysymex._internal.execution.scheduling.loop.bounds.ranking import (
    finite_container_descent_remaining_steps,
    guarded_affine_remaining_steps,
)
from pysymex._internal.execution.scheduling.loops.detector import LoopDetector
from pysymex._internal.execution.scheduling.loops.types import LoopInfo
from pysymex._internal.execution.scheduling.loops.widening import LoopWidening
from pysymex._internal.execution.session.state.core import ExecutionSession


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


def _no_exit_loop_fixture() -> tuple[list[dis.Instruction], LoopDetector, LoopInfo, int]:
    module_code = compile(
        "def f():\n    while True:\n        pass\n",
        "<no-exit-loop-bound-policy-test>",
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


def _increasing_loop_fixture() -> tuple[list[dis.Instruction], LoopDetector, LoopInfo, int]:
    module_code = compile(
        "def f():\n    step = 0\n    while step < 3:\n        step += 1\n    return step\n",
        "<increasing-loop-bound-policy-test>",
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
    max_loop_iterations: int | None,
    events: list[str] | None = None,
) -> LoopBoundContext:
    event_log = events if events is not None else []
    return LoopBoundContext(
        session=session,
        max_loop_iterations=max_loop_iterations,
        verbose=False,
        record_path_explored_event=lambda: event_log.append("path_explored"),
    )


def test_loop_bound_public_exports_point_to_direct_owners() -> None:
    assert LoopBoundContext is LoopBoundContextOwner
    assert apply_loop_bound_policy is apply_loop_bound_policy_owner


def test_exact_int_value_follows_alias_constraints() -> None:
    x = z3.Int("x")
    y = z3.Int("y")

    assert exact_int_value(x, [y == 3, x == y]) == 3


def test_finite_countdown_remaining_steps_proves_bounded_affine_recurrence() -> None:
    value, _ = SymbolicValue.symbolic_int("n")
    previous = VMState(local_vars={"k": value})
    current = VMState(
        local_vars={"k": value - SymbolicValue.from_const(1)},
        path_constraints=[value.z3_int >= 0, z3.IntVal(4) >= value.z3_int],
    )

    assert finite_countdown_remaining_steps(previous, current) == 3


def test_finite_countdown_remaining_steps_rejects_unbounded_recurrence() -> None:
    value, _ = SymbolicValue.symbolic_int("n")
    previous = VMState(local_vars={"k": value})
    current = VMState(
        local_vars={"k": value - SymbolicValue.from_const(1)},
        path_constraints=[value.z3_int >= 0],
    )

    assert finite_countdown_remaining_steps(previous, current) is None


def test_finite_iterator_upper_bound_follows_range_length_alias() -> None:
    stop, _ = SymbolicValue.symbolic_int("stop")
    iterable, type_constraint = SymbolicList.symbolic("range_values")
    state = VMState(
        stack=[SymbolicIterator("range_iter", iterable)],
        path_constraints=[
            type_constraint,
            stop.z3_int >= 0,
            z3.IntVal(6) >= stop.z3_int,
            iterable.z3_len == z3.If(stop.z3_int > 0, stop.z3_int, 0),
        ],
    )

    assert finite_iterator_upper_bound(state) == 6


def test_finite_iterator_upper_bound_accepts_acyclic_modeled_generator() -> None:
    def values():
        yield 1
        yield 2

    generator = ModeledGenerator("values", values, (), ())

    assert finite_iterator_upper_bound(VMState(stack=[generator])) == 2


def test_finite_iterator_upper_bound_rejects_cyclic_modeled_generator() -> None:
    def values():
        while True:
            yield 1

    generator = ModeledGenerator("values", values, (), ())

    assert finite_iterator_upper_bound(VMState(stack=[generator])) is None


def test_finite_generator_progress_uses_later_suspension_point_as_rank() -> None:
    def values():
        yield 1
        yield 2

    instructions = tuple(dis.get_instructions(values))
    generator = ModeledGenerator("values", values, (), (), identity=7)
    previous = VMState(stack=[generator])
    current = VMState(
        stack=[
            ModeledGenerator(
                "values",
                values,
                (),
                (),
                started=True,
                instructions=instructions,
                resume_pc=instructions[-2].offset,
                identity=7,
            )
        ]
    )

    assert generator_remaining_steps(previous, current) is not None


def test_finite_container_descent_uses_concrete_backed_memory_list_as_rank() -> None:
    previous = VMState(memory={1: SymbolicList.from_const([1, 2, 3])})
    current = VMState(memory={1: SymbolicList.from_const([2, 3])})

    assert finite_container_descent_remaining_steps(previous, current) == 2


def test_finite_guarded_affine_ranking_accepts_progress_toward_literal_bound() -> None:
    instructions, _detector, loop, _header_idx = _increasing_loop_fixture()
    previous = VMState(local_vars={"step": SymbolicValue.from_const(0)})
    current = VMState(local_vars={"step": SymbolicValue.from_const(1)})

    assert guarded_affine_remaining_steps(previous, current, instructions, loop) == 2


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
    assert session.degraded_passes == ["resource_limit_iterations"]


def test_apply_loop_bound_policy_reports_no_exit_loop_when_bound_exceeded() -> None:
    instructions, detector, _loop, header_idx = _no_exit_loop_fixture()
    session = ExecutionSession()
    session.loop_detector = detector
    session.loop_detectors[instruction_stream_key(instructions)] = detector
    session.pc_to_line[header_idx] = 2
    state = VMState(pc=header_idx)

    result = apply_loop_bound_policy(
        _context(session, max_loop_iterations=0),
        state,
        instructions,
    )

    assert result is False
    assert session.paths_pruned == 1
    assert session.degraded_passes == ["resource_limit_iterations"]
    assert [issue.kind.name for issue in session.issues] == ["INFINITE_LOOP"]
    assert session.issues[0].line_number == 2


def test_apply_loop_bound_policy_automatic_mode_prunes_exact_recurrence() -> None:
    instructions, detector, _loop, header_idx = _no_exit_loop_fixture()
    session = ExecutionSession()
    session.loop_detector = detector
    session.loop_detectors[instruction_stream_key(instructions)] = detector
    state = VMState(pc=header_idx)

    first_result = apply_loop_bound_policy(
        _context(session, max_loop_iterations=None),
        state,
        instructions,
    )
    second_result = apply_loop_bound_policy(
        _context(session, max_loop_iterations=None),
        state,
        instructions,
    )

    assert first_result is True
    assert second_result is False
    assert session.paths_pruned == 1
    assert session.degraded_passes == []
    assert [issue.kind.name for issue in session.issues] == ["INFINITE_LOOP"]


def test_apply_loop_bound_policy_automatic_mode_widens_changing_locals() -> None:
    instructions, detector, loop, header_idx = _loop_fixture()
    session = ExecutionSession()
    session.loop_detector = detector
    session.loop_detectors[instruction_stream_key(instructions)] = detector
    session.loop_widening = LoopWidening()
    session.worklist = create_path_manager(ExecutionConfig().strategy)
    loop_key = _loop_key(instructions, loop)
    state = VMState(local_vars={"x": 2}, pc=header_idx)
    state.prev_loop_states[loop_key] = VMState(local_vars={"x": 1}, pc=header_idx)

    result = apply_loop_bound_policy(
        _context(session, max_loop_iterations=None),
        state,
        instructions,
    )

    widened = session.worklist.get_next_state()
    assert result is False
    assert widened is not None
    assert widened.pc > header_idx
    assert session.degraded_passes == [LOOP_WIDENING_DEGRADED_PASS]
    assert session.paths_pruned == 1


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


def test_apply_loop_bound_policy_extends_for_exact_enumerate_iterator_source() -> None:
    instructions, detector, loop, header_idx = _for_loop_fixture()
    session = ExecutionSession()
    session.loop_detector = detector
    session.loop_detectors[instruction_stream_key(instructions)] = detector
    loop_key = _loop_key(instructions, loop)
    source = EnumerateIteratorSource(iterable=tuple(range(12)), start=0)
    state = VMState(
        stack=[SymbolicIterator("enumerate_iter", source)],
        pc=header_idx,
    )
    state.loop_iterations[loop_key] = 12

    result = apply_loop_bound_policy(
        _context(session, max_loop_iterations=10),
        state,
        instructions,
    )

    assert result is True
    assert state.loop_iterations[loop_key] == 13
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


def test_apply_loop_bound_policy_enqueues_widened_for_loop_exit_state() -> None:
    instructions, detector, loop, header_idx = _for_loop_fixture()
    config = ExecutionConfig()
    session = ExecutionSession()
    session.loop_detector = detector
    session.loop_detectors[instruction_stream_key(instructions)] = detector
    session.loop_widening = LoopWidening()
    worklist = create_path_manager(config.strategy)
    session.worklist = worklist
    items, _constraint = SymbolicList.symbolic("items")
    state = VMState(stack=[SymbolicIterator("items_iter", items)], pc=header_idx)
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
    exit_opname = instructions[exit_idx].opname
    if sys.version_info >= (3, 12):
        assert exit_opname == "END_FOR"
        assert len(widened.stack) == 2
        assert isinstance(widened.stack[-1], SymbolicNoneType)
    else:
        if exit_opname == "POP_TOP":
            assert len(widened.stack) == 1
            assert isinstance(widened.stack[-1], SymbolicIterator)
        else:
            assert exit_opname == "LOAD_CONST"
            assert widened.stack == []
    assert session.paths_pruned == 1
    assert session.paths_explored == 1
    assert session.degraded_passes == ["resource_limit_iterations"]
    assert events == ["path_explored"]
