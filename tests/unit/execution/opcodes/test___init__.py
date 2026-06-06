from __future__ import annotations

import dis
import sys

from pysymex.core.state.record import VMState
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes import (
    detect_python_version,
    validate_version,
    route_to_opcode_dir,
    load_opcode_handlers,
    py311,
    py312,
    py313,
)


def _instr(opname: str, argval: object = None, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, offset=offset)


def testdetect_python_version() -> None:
    """Test detect_python_version returns expected tuple."""
    version = detect_python_version()
    assert version == (sys.version_info.major, sys.version_info.minor)


def testvalidate_version_supported() -> None:
    """Test validate_version with supported version."""
    assert validate_version((3, 12)) is True


def testvalidate_version_unsupported_old() -> None:
    """Test validate_version with unsupported older version."""
    assert validate_version((3, 10)) is False


def testvalidate_version_unsupported_new() -> None:
    """Test validate_version with unsupported newer version."""
    assert validate_version((3, 14)) is False


def testroute_to_opcode_dir_311() -> None:
    """Test route_to_opcode_dir routes to 3.11."""
    module = route_to_opcode_dir((3, 11))
    assert module is py311


def testroute_to_opcode_dir_312() -> None:
    """Test route_to_opcode_dir routes to 3.12."""
    module = route_to_opcode_dir((3, 12))
    assert module is py312


def testroute_to_opcode_dir_313() -> None:
    """Test route_to_opcode_dir routes to 3.13."""
    module = route_to_opcode_dir((3, 13))
    assert module is py313


def testroute_to_opcode_dir_newer() -> None:
    """Test route_to_opcode_dir rejects newer unsupported versions."""
    try:
        route_to_opcode_dir((3, 15))
        assert False, "Should have raised ImportError"
    except ImportError:
        pass


def testroute_to_opcode_dir_unsupported() -> None:
    """Test route_to_opcode_dir raises on too old version."""
    try:
        route_to_opcode_dir((3, 10))
        assert False, "Should have raised ImportError"
    except ImportError:
        pass


def test_load_opcode_handlers_rejects_newer_unsupported_version() -> None:
    """Test load_opcode_handlers rejects newer unsupported versions."""
    try:
        load_opcode_handlers((3, 15))
        assert False, "Should have raised ImportError"
    except ImportError:
        pass


def test_load_opcode_handlers_registers_resume_opcode() -> None:
    """Test loading opcode handlers registers RESUME for the active interpreter family."""
    load_opcode_handlers()
    dispatcher = OpcodeDispatcher()
    assert dispatcher.has_handler("RESUME") is True


def test_load_opcode_handlers_registers_313_setup_with_opcode() -> None:
    """Python 3.13 exposes SETUP_WITH in dis.opmap; the dispatcher must cover it."""
    OpcodeDispatcher.clear_global_handlers()

    load_opcode_handlers((3, 13))

    dispatcher = OpcodeDispatcher()
    if sys.version_info >= (3, 13):
        assert "SETUP_WITH" in dis.opmap
    assert dispatcher.has_handler("SETUP_WITH") is True


def test_load_opcode_handlers_cover_current_313_dis_opmap() -> None:
    if sys.version_info[:2] != (3, 13):
        return
    OpcodeDispatcher.clear_global_handlers()

    load_opcode_handlers((3, 13))

    dispatcher = OpcodeDispatcher()
    assert sorted(set(dis.opmap) - dispatcher.registered_opcodes()) == []
    assert sorted(dispatcher.registered_opcodes() - set(dis.opmap)) == []


def test_load_opcode_handlers_313_does_not_keep_311_only_jump_handlers() -> None:
    OpcodeDispatcher.clear_global_handlers()

    load_opcode_handlers((3, 13))

    dispatcher = OpcodeDispatcher()
    assert dispatcher.has_handler("POP_JUMP_IF_TRUE") is True
    assert dispatcher.has_handler("POP_JUMP_FORWARD_IF_TRUE") is False


def test_load_opcode_handlers_switch_to_311_removes_313_only_handlers() -> None:
    OpcodeDispatcher.clear_global_handlers()
    load_opcode_handlers((3, 13))

    load_opcode_handlers((3, 11))

    dispatcher = OpcodeDispatcher()
    assert dispatcher.has_handler("SET_FUNCTION_ATTRIBUTE") is False
    assert dispatcher.has_handler("POP_JUMP_FORWARD_IF_TRUE") is True


def test_load_opcode_handlers_preserves_non_opcode_global_handlers() -> None:
    OpcodeDispatcher.clear_global_handlers()

    def custom_handler(
        instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
    ) -> OpcodeResult:
        _ = (instr, state, ctx)
        raise AssertionError("not called")

    try:
        OpcodeDispatcher.register_global("CUSTOM_OPCODE", custom_handler)

        load_opcode_handlers((3, 13))

        dispatcher = OpcodeDispatcher()
        assert dispatcher.has_handler("CUSTOM_OPCODE") is True
    finally:
        OpcodeDispatcher.clear_global_handlers()


def test_load_opcode_handlers_reregisters_py312_instrumentation_after_reset() -> None:
    OpcodeDispatcher.clear_global_handlers()
    load_opcode_handlers((3, 13))

    load_opcode_handlers((3, 12))

    assert (
        OpcodeDispatcher.global_handler_module("INSTRUMENTED_CALL")
        == "pysymex.execution.opcodes.py312.instrumentation"
    )


def test_load_opcode_handlers_312_uses_control_call_intrinsic_2() -> None:
    OpcodeDispatcher.clear_global_handlers()

    load_opcode_handlers((3, 12))

    assert (
        OpcodeDispatcher.global_handler_module("CALL_INTRINSIC_2")
        == "pysymex.execution.opcodes.py312.control"
    )
    dispatcher = OpcodeDispatcher()
    result = dispatcher.dispatch(_instr("CALL_INTRINSIC_2", 1), VMState(stack=[1, 2], pc=0))
    assert result.new_states[0].stack == [1]


def test_load_opcode_handlers_313_uses_control_call_intrinsic_2() -> None:
    OpcodeDispatcher.clear_global_handlers()

    load_opcode_handlers((3, 13))

    assert (
        OpcodeDispatcher.global_handler_module("CALL_INTRINSIC_2")
        == "pysymex.execution.opcodes.py313.control"
    )
    dispatcher = OpcodeDispatcher()
    result = dispatcher.dispatch(_instr("CALL_INTRINSIC_2", 1), VMState(stack=[1, 2], pc=0))
    assert result.new_states[0].stack == [1]
