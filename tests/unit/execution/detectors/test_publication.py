from __future__ import annotations

import dis
from collections.abc import Callable

from pysymex.core.state.record import VMState
from pysymex.execution.detectors.publication import should_defer_dynamic_with_issue
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def _dispatcher_for(
    function: Callable[[], object],
) -> tuple[OpcodeDispatcher, list[dis.Instruction]]:
    instructions = list(dis.get_instructions(function))
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions(instructions)
    dispatcher.set_exception_entries(list(getattr(dis.Bytecode(function), "exception_entries", ())))
    return dispatcher, instructions


def test_raise_inside_with_body_defers_to_context_manager_exit() -> None:
    class Manager:
        def __enter__(self) -> None:
            return None

        def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
            return True

    def target() -> None:
        with Manager():
            raise ValueError("body")

    dispatcher, instructions = _dispatcher_for(target)
    raise_instr = next(instr for instr in instructions if instr.opname == "RAISE_VARARGS")

    assert should_defer_dynamic_with_issue(dispatcher, VMState(), raise_instr) is True


def test_raise_outside_with_body_does_not_defer() -> None:
    def target() -> None:
        raise ValueError("body")

    dispatcher, instructions = _dispatcher_for(target)
    raise_instr = next(instr for instr in instructions if instr.opname == "RAISE_VARARGS")

    assert should_defer_dynamic_with_issue(dispatcher, VMState(), raise_instr) is False
