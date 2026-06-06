from __future__ import annotations

import dis
import types
from dataclasses import dataclass

from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def instr(opname: str, argval: object = None, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, offset=offset)


def code_object(source: str, name: str) -> types.CodeType:
    module_code = compile(source, "<test>", "exec")
    for const in module_code.co_consts:
        if isinstance(const, types.CodeType) and const.co_name == name:
            return const
    raise AssertionError(f"missing code object {name}")


def instruction_by_offset(code: types.CodeType, offset: int) -> dis.Instruction:
    for instruction in dis.get_instructions(code):
        if instruction.offset == offset:
            return instruction
    raise AssertionError(f"missing instruction at offset {offset}")


@dataclass(frozen=True)
class Entry:
    start: int
    end: int
    target: int
    depth: int
    lasti: bool


def dispatcher_for(code: types.CodeType, entries: list[object]) -> OpcodeDispatcher:
    dispatcher = OpcodeDispatcher()
    instructions = list(dis.get_instructions(code))
    dispatcher.set_instructions(instructions)
    dispatcher.set_exception_entries(entries)
    return dispatcher
