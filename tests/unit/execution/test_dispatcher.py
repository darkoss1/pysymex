from __future__ import annotations

import dis
from dataclasses import dataclass

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.state import VMState
from pysymex.execution.dispatcher import (
    OpcodeDispatcher,
    OpcodeResult,
    get_global_dispatcher,
    opcode_handler,
)


def _make_instruction(opname: str, offset: int = 0, argval: int | None = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, offset=offset, argval=argval)


@dataclass
class _ExcEntry:
    start: int
    end: int
    target: int


def _noop_handler(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    _ = instr
    _ = ctx
    return OpcodeResult.continue_with(state.advance_pc())

class TestOpcodeResult:
    """Test suite for pysymex.execution.dispatcher.OpcodeResult."""
    def test_continue_with(self) -> None:
        """Test continue_with behavior."""
        state = VMState()
        issue = Issue(kind=IssueKind.TYPE_ERROR, message="pending")
        state.pending_taint_issues = [issue]

        result = OpcodeResult.continue_with(state)

        assert result.new_states == [state]
        assert issue in result.issues
        assert state.pending_taint_issues == []

    def test_branch(self) -> None:
        """Test branch behavior."""
        s1 = VMState()
        s2 = VMState()
        pending = Issue(kind=IssueKind.KEY_ERROR, message="k")
        explicit = Issue(kind=IssueKind.VALUE_ERROR, message="v")
        s2.pending_taint_issues = [pending]

        result = OpcodeResult.branch([s1, s2], [explicit])

        assert len(result.new_states) == 2
        assert explicit in result.issues
        assert pending in result.issues

    def test_fork(self) -> None:
        """Test fork behavior."""
        s1 = VMState()
        s2 = VMState()
        issue = Issue(kind=IssueKind.INDEX_ERROR, message="idx")

        result = OpcodeResult.fork([s1, s2], [issue, None])

        assert result.new_states == [s1, s2]
        assert issue in result.issues

    def test_terminate(self) -> None:
        """Test terminate behavior."""
        result = OpcodeResult.terminate()

        assert result.terminal is True
        assert result.new_states == []
        assert result.issues == []

    def test_with_issue(self) -> None:
        """Test with_issue behavior."""
        state = VMState()
        issue = Issue(kind=IssueKind.DIVISION_BY_ZERO, message="div")

        result = OpcodeResult.with_issue(state, issue)

        assert result.new_states == [state]
        assert result.issues[-1] == issue

    def test_error(self) -> None:
        """Test error behavior."""
        state = VMState()
        pending = Issue(kind=IssueKind.TYPE_ERROR, message="pending")
        fatal = Issue(kind=IssueKind.TYPE_ERROR, message="fatal")
        state.pending_taint_issues = [pending]

        result = OpcodeResult.error(fatal, state)

        assert result.terminal is True
        assert result.new_states == []
        assert fatal in result.issues
        assert pending in result.issues


class TestOpcodeDispatcher:
    """Test suite for pysymex.execution.dispatcher.OpcodeDispatcher."""
    def test_register(self) -> None:
        """Test register behavior."""
        dispatcher = OpcodeDispatcher()

        @dispatcher.register("A", "B")
        def local_handler(
            instr: dis.Instruction,
            state: VMState,
            ctx: OpcodeDispatcher,
        ) -> OpcodeResult:
            _ = instr
            _ = ctx
            return OpcodeResult.continue_with(state)

        assert dispatcher.has_handler("A") is True
        assert dispatcher.has_handler("B") is True
        assert callable(local_handler)

    def test_register_handler(self) -> None:
        """Test register_handler behavior."""
        dispatcher = OpcodeDispatcher()
        dispatcher.register_handler("LOAD_CONST", _noop_handler)
        assert dispatcher.has_handler("LOAD_CONST") is True

    def test_instructions(self) -> None:
        """Test instructions behavior."""
        dispatcher = OpcodeDispatcher()
        instructions = [_make_instruction("NOP", offset=0)]
        dispatcher.set_instructions(instructions)
        assert dispatcher.instructions == instructions

    def test_set_fallback(self) -> None:
        """Test set_fallback behavior."""
        dispatcher = OpcodeDispatcher()
        dispatcher.set_fallback(_noop_handler)
        state = VMState()
        result = dispatcher.dispatch(_make_instruction("UNKNOWN"), state)
        assert len(result.new_states) == 1

    def test_set_instructions(self) -> None:
        """Test set_instructions behavior."""
        dispatcher = OpcodeDispatcher()
        instructions = [_make_instruction("NOP", offset=8), _make_instruction("NOP", offset=12)]
        dispatcher.set_instructions(instructions)
        assert dispatcher.instruction_count() == 2
        assert dispatcher.offset_to_index(12) == 1

    def test_set_exception_entries(self) -> None:
        """Test set_exception_entries behavior."""
        dispatcher = OpcodeDispatcher()
        dispatcher.set_exception_entries([_ExcEntry(start=0, end=10, target=20)])
        dispatcher.set_instructions([_make_instruction("NOP", 0), _make_instruction("NOP", 20)])
        assert dispatcher.find_exception_handler(5) == 1

    def test_find_exception_handler(self) -> None:
        """Test find_exception_handler behavior."""
        dispatcher = OpcodeDispatcher()
        dispatcher.set_exception_entries([_ExcEntry(start=3, end=5, target=99)])
        dispatcher.set_instructions([_make_instruction("NOP", 99)])
        assert dispatcher.find_exception_handler(2) is None
        assert dispatcher.find_exception_handler(3) == 0

    def test_get_instruction(self) -> None:
        """Test get_instruction behavior."""
        dispatcher = OpcodeDispatcher()
        instructions = [_make_instruction("NOP", 0)]
        dispatcher.set_instructions(instructions)
        assert dispatcher.get_instruction(0) == instructions[0]
        assert dispatcher.get_instruction(5) is None

    def test_offset_to_index(self) -> None:
        """Test offset_to_index behavior."""
        dispatcher = OpcodeDispatcher()
        dispatcher.set_instructions([_make_instruction("NOP", 4)])
        assert dispatcher.offset_to_index(4) == 0
        assert dispatcher.offset_to_index(100) is None

    def test_dispatch(self) -> None:
        """Test dispatch behavior."""
        dispatcher = OpcodeDispatcher()
        dispatcher.register_handler("NOP", _noop_handler)
        state = VMState()
        result = dispatcher.dispatch(_make_instruction("NOP"), state)
        assert len(result.new_states) == 1

    def test_has_handler(self) -> None:
        """Test has_handler behavior."""
        dispatcher = OpcodeDispatcher()
        dispatcher.register_handler("X", _noop_handler)
        assert dispatcher.has_handler("X") is True
        assert dispatcher.has_handler("Y") is False

    def test_registered_opcodes(self) -> None:
        """Test registered_opcodes behavior."""
        dispatcher = OpcodeDispatcher()
        dispatcher.register_handler("ONE", _noop_handler)
        opcodes = dispatcher.registered_opcodes()
        assert "ONE" in opcodes

    def test_register_global(self) -> None:
        """Test register_global behavior."""
        OpcodeDispatcher.register_global("GLOBAL_TEST", _noop_handler)
        dispatcher = OpcodeDispatcher()
        assert dispatcher.has_handler("GLOBAL_TEST") is True

    def test_instruction_count(self) -> None:
        """Test instruction_count behavior."""
        dispatcher = OpcodeDispatcher()
        dispatcher.set_instructions([_make_instruction("NOP", 0), _make_instruction("NOP", 2)])
        assert dispatcher.instruction_count() == 2


def test_get_global_dispatcher() -> None:
    """Test get_global_dispatcher behavior."""
    first = get_global_dispatcher()
    second = get_global_dispatcher()
    assert first is second


def test_opcode_handler() -> None:
    """Test opcode_handler behavior."""
    @opcode_handler("DECORATOR_REGISTERED")
    def decorated(
        instr: dis.Instruction,
        state: VMState,
        ctx: OpcodeDispatcher,
    ) -> OpcodeResult:
        _ = instr
        _ = ctx
        return OpcodeResult.continue_with(state)

    dispatcher = OpcodeDispatcher()
    assert dispatcher.has_handler("DECORATOR_REGISTERED") is True
    assert callable(decorated)
