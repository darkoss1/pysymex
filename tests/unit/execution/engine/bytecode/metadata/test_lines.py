"""Tests for cached execution PC-to-line metadata."""

from __future__ import annotations

import dis
from types import SimpleNamespace
from typing import cast

from pysymex._internal.core.cache.code.exceptions import get_exception_entries
from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.engine.bytecode.metadata.lines import (
    build_line_mapping,
    clear_line_mapping_cache,
    line_mapping_cache_stats,
    line_mapping_from_instructions,
)
from pysymex._internal.execution.engine.bytecode.metadata.lines import (
    build_line_mapping as direct_build_line_mapping,
)
from pysymex._internal.execution.engine.bytecode.metadata.lines import (
    clear_line_mapping_cache as direct_clear_line_mapping_cache,
)
from pysymex._internal.execution.engine.bytecode.metadata.lines import (
    line_mapping_cache_stats as direct_line_mapping_cache_stats,
)
from pysymex._internal.execution.engine.bytecode.metadata.preparation import (
    prepare_bytecode_execution,
)
from pysymex._internal.execution.engine.bytecode.metadata.preparation import (
    prepare_bytecode_execution as direct_prepare_bytecode_execution,
)
from pysymex._internal.execution.session.state.core import ExecutionSession


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


def test_bytecode_metadata_exports_use_direct_owners() -> None:
    assert build_line_mapping is direct_build_line_mapping
    assert clear_line_mapping_cache is direct_clear_line_mapping_cache
    assert line_mapping_cache_stats is direct_line_mapping_cache_stats
    assert prepare_bytecode_execution is direct_prepare_bytecode_execution


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


def test_line_mapping_ignores_boolean_position_lineno_sentinels() -> None:
    instructions = [
        cast("dis.Instruction", SimpleNamespace(positions=SimpleNamespace(lineno=10))),
        cast("dis.Instruction", SimpleNamespace(positions=SimpleNamespace(lineno=False))),
    ]

    assert line_mapping_from_instructions(instructions) == ((0, 10), (1, 10))


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
