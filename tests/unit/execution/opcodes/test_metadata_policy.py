from __future__ import annotations

import dis

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.opcodes.common.metadata import (
    SAFE_METADATA_NOOPS,
    handle_common_instrumented_opcode,
    handle_common_metadata_noop,
    handle_common_reserved_opcode,
)
from pysymex._internal.execution.opcodes.registry import load_opcode_handlers


def make_instruction(opname: str, offset: int = 0, argval: object | None = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, offset=offset, argval=argval)


@pytest.mark.parametrize("opname", sorted(SAFE_METADATA_NOOPS))
def test_metadata_noop_allowlist_advances_only_approved_opcodes(opname: str) -> None:
    result = handle_common_metadata_noop(make_instruction(opname), VMState(), OpcodeDispatcher())

    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 1


def test_metadata_noop_rejects_non_allowlisted_opcode() -> None:
    with pytest.raises(RuntimeError, match="not an approved metadata no-op"):
        handle_common_metadata_noop(make_instruction("LOAD_CONST"), VMState(), OpcodeDispatcher())


def test_reserved_opcode_is_not_a_noop() -> None:
    with pytest.raises(RuntimeError, match="Unsupported internal opcode: RESERVED"):
        handle_common_reserved_opcode(make_instruction("RESERVED"), VMState(), OpcodeDispatcher())


def test_instrumented_opcode_is_not_a_noop() -> None:
    with pytest.raises(RuntimeError, match="Unsupported instrumented pseudo-opcode"):
        handle_common_instrumented_opcode(
            make_instruction("INSTRUMENTED_CALL"), VMState(), OpcodeDispatcher()
        )


@pytest.mark.parametrize("version", [(3, 12), (3, 13)])
def test_registered_reserved_opcode_rejects_across_versions(version: tuple[int, int]) -> None:
    load_opcode_handlers(version)
    dispatcher = OpcodeDispatcher()

    assert dispatcher.has_handler("RESERVED")
    with pytest.raises(RuntimeError, match="Unsupported internal opcode: RESERVED"):
        dispatcher.dispatch(make_instruction("RESERVED"), VMState())


@pytest.mark.parametrize("version", [(3, 12), (3, 13)])
@pytest.mark.parametrize(
    "opname",
    [
        "INSTRUMENTED_CALL",
        "INSTRUMENTED_FOR_ITER",
        "INSTRUMENTED_JUMP_FORWARD",
        "INSTRUMENTED_RETURN_VALUE",
    ],
)
def test_registered_instrumented_opcodes_reject_across_versions(
    version: tuple[int, int], opname: str
) -> None:
    load_opcode_handlers(version)
    dispatcher = OpcodeDispatcher()

    assert dispatcher.has_handler(opname)
    with pytest.raises(RuntimeError, match="Unsupported instrumented pseudo-opcode"):
        dispatcher.dispatch(make_instruction(opname), VMState())


@pytest.mark.parametrize("opname", ["ENTER_EXECUTOR", "EXIT_INIT_CHECK"])
def test_py313_internal_lifecycle_opcodes_reject_instead_of_silent_noop(opname: str) -> None:
    load_opcode_handlers((3, 13))
    dispatcher = OpcodeDispatcher()

    assert dispatcher.has_handler(opname)
    with pytest.raises(RuntimeError, match=f"Unsupported internal opcode: {opname}"):
        dispatcher.dispatch(make_instruction(opname), VMState())
