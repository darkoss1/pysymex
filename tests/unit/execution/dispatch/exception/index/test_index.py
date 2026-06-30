from __future__ import annotations

import dis
from dataclasses import dataclass

from pysymex._internal.execution.dispatch.exception.index import (
    handler_index_for_offset,
    offset_index_by_instruction_stream,
    select_entries_for_stream,
    store_exception_entries_for_stream,
)


@dataclass
class ExcEntry:
    start: int
    end: int
    target: int


def make_instruction(opname: str, offset: int = 0, argval: int | None = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, offset=offset, argval=argval)


def test_offset_index_by_instruction_stream() -> None:
    instructions = [make_instruction("NOP", offset=4), make_instruction("NOP", offset=12)]

    assert offset_index_by_instruction_stream(instructions) == {4: 0, 12: 1}


def test_select_exception_entries_uses_registered_stream() -> None:
    instructions = [make_instruction("NOP", offset=4)]
    registered: list[object] = [ExcEntry(start=0, end=8, target=4)]
    entries_by_stream: dict[tuple[int, ...], list[object]] = {}
    store_exception_entries_for_stream(instructions, registered, entries_by_stream)

    selected = select_entries_for_stream(
        instructions,
        pending_entries=[],
        entries_by_stream=entries_by_stream,
        previous_stream_was_empty=False,
    )

    assert selected == registered
    assert selected is not registered


def test_select_exception_entries_claims_pending_entries_for_first_stream() -> None:
    instructions = [make_instruction("NOP", offset=4)]
    pending: list[object] = [ExcEntry(start=0, end=8, target=4)]
    entries_by_stream: dict[tuple[int, ...], list[object]] = {}

    selected = select_entries_for_stream(
        instructions,
        pending_entries=pending,
        entries_by_stream=entries_by_stream,
        previous_stream_was_empty=True,
    )

    assert selected == pending
    assert selected is not pending
    assert list(entries_by_stream.values()) == [pending]


def test_exception_handler_index_for_offset() -> None:
    entries: list[object] = [ExcEntry(start=3, end=5, target=99)]
    offset_to_index = {99: 0}
    handler_by_offset: dict[int, int | None] = {}

    assert handler_index_for_offset(2, entries, offset_to_index, handler_by_offset) is None
    assert handler_index_for_offset(3, entries, offset_to_index, handler_by_offset) == 0


def test_exception_handler_index_prefers_innermost_range() -> None:
    entries: list[object] = [
        ExcEntry(start=0, end=10, target=40),
        ExcEntry(start=3, end=6, target=60),
    ]
    offset_to_index = {40: 0, 60: 1}
    handler_by_offset: dict[int, int | None] = {}

    assert handler_index_for_offset(4, entries, offset_to_index, handler_by_offset) == 1
