from __future__ import annotations

from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.dispatch.dispatcher.core import (
    OpcodeDispatcher as OpcodeDispatcherOwner,
)
from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.dispatch.dispatcher.decorators import (
    opcode_handler as opcode_handler_owner,
)
from pysymex._internal.execution.dispatch.exception.index import (
    handler_index_for_offset,
    offset_index_by_instruction_stream,
    select_entries_for_stream,
    store_exception_entries_for_stream,
)


def test_dispatcher_package_exports_focused_owners() -> None:
    assert OpcodeDispatcher is OpcodeDispatcherOwner
    assert opcode_handler is opcode_handler_owner
    assert handler_index_for_offset is handler_index_for_offset
    assert offset_index_by_instruction_stream is offset_index_by_instruction_stream
    assert select_entries_for_stream is select_entries_for_stream
    assert store_exception_entries_for_stream is store_exception_entries_for_stream
