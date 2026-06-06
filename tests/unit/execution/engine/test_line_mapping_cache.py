"""Tests for cached execution PC-to-line metadata."""

from __future__ import annotations

import dis

from pysymex.core.cache import get_instructions
from pysymex.core.cache import get_exception_entries
from pysymex.execution.engine import build_line_mapping
from pysymex.execution.engine import clear_line_mapping_cache, line_mapping_cache_stats
from pysymex.execution.engine import prepare_bytecode_execution
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.session.state import ExecutionSession


def _sample_line_mapping_target(x: int) -> int:
    total = x + 1
    if total > 3:
        return total
    return total - 1


def _other_line_mapping_target() -> int:
    value = 1
    return value


def _exception_target(value: int) -> int:
    try:
        return 10 // value
    except ZeroDivisionError:
        return 0


def test_build_line_mapping_reuses_cached_code_mapping() -> None:
    clear_line_mapping_cache()
    code = _sample_line_mapping_target.__code__
    cached_instructions = get_instructions(code)

    first_session = ExecutionSession()
    first_session.instructions = list(cached_instructions)
    build_line_mapping(session=first_session, code=code)
    first_cache_stats = line_mapping_cache_stats()

    second_session = ExecutionSession()
    second_session.instructions = list(cached_instructions)
    build_line_mapping(session=second_session, code=code)
    second_cache_stats = line_mapping_cache_stats()

    assert first_session.pc_to_line
    assert second_session.pc_to_line == first_session.pc_to_line
    assert first_cache_stats["misses"] == 1
    assert second_cache_stats["hits"] == 1


def test_build_line_mapping_replaces_stale_session_mapping() -> None:
    clear_line_mapping_cache()
    code = _sample_line_mapping_target.__code__
    cached_instructions = get_instructions(code)
    stale_pc = len(cached_instructions) + 100

    session = ExecutionSession()
    session.instructions = list(cached_instructions)
    session.pc_to_line[stale_pc] = 1
    build_line_mapping(session=session, code=code)

    assert stale_pc not in session.pc_to_line
    assert session.pc_to_line


def test_build_line_mapping_falls_back_for_custom_instruction_stream() -> None:
    clear_line_mapping_cache()
    session = ExecutionSession()
    session.instructions = list(dis.get_instructions(_other_line_mapping_target))

    build_line_mapping(session=session, code=_sample_line_mapping_target.__code__)

    assert line_mapping_cache_stats()["currsize"] == 0
    assert session.pc_to_line
    assert min(session.pc_to_line.values()) >= _other_line_mapping_target.__code__.co_firstlineno


def test_prepare_bytecode_execution_reuses_exception_entry_cache() -> None:
    get_exception_entries.cache_clear()
    code = _exception_target.__code__

    first_session = ExecutionSession()
    first_dispatcher = OpcodeDispatcher()
    prepare_bytecode_execution(
        session=first_session,
        dispatcher=first_dispatcher,
        code=code,
        bytecode_source=_exception_target,
    )
    first_cache_info = get_exception_entries.cache_info()

    second_session = ExecutionSession()
    second_dispatcher = OpcodeDispatcher()
    prepare_bytecode_execution(
        session=second_session,
        dispatcher=second_dispatcher,
        code=code,
        bytecode_source=_exception_target,
    )
    second_cache_info = get_exception_entries.cache_info()

    divide_offset = next(
        instruction.offset
        for instruction in second_session.instructions
        if instruction.opname == "BINARY_OP"
    )
    assert first_cache_info.misses == 1
    assert second_cache_info.hits == 1
    assert second_dispatcher.find_exception_handler(divide_offset) is not None
