from __future__ import annotations

import dis
import sys
from collections.abc import Callable
from types import ModuleType, SimpleNamespace
from typing import cast

import pytest

import pysymex._internal.execution.opcodes.py311 as py311
import pysymex._internal.execution.opcodes.py312 as py312
import pysymex._internal.execution.opcodes.py313 as py313
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.registry import (
    detect_python_version,
    load_opcode_handlers,
    route_to_opcode_dir,
    validate_version,
)


def _instr(opname: str, argval: object = None, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, offset=offset)


def test_detect_python_version() -> None:
    """Test detect_python_version returns expected tuple."""
    version = detect_python_version()
    assert version == (sys.version_info.major, sys.version_info.minor)


def test_validate_version_supported() -> None:
    """Test validate_version with supported version."""
    assert validate_version((3, 12)) is True


def test_validate_version_unsupported_old() -> None:
    """Test validate_version with unsupported older version."""
    assert validate_version((3, 10)) is False


def test_validate_version_unsupported_new() -> None:
    """Test validate_version with unsupported newer version."""
    assert validate_version((3, 14)) is False


def test_route_to_opcode_dir_311() -> None:
    """Test route_to_opcode_dir routes to 3.11."""
    module = route_to_opcode_dir((3, 11))
    assert module is py311


def test_route_to_opcode_dir_312() -> None:
    """Test route_to_opcode_dir routes to 3.12."""
    module = route_to_opcode_dir((3, 12))
    assert module is py312


def test_route_to_opcode_dir_313() -> None:
    """Test route_to_opcode_dir routes to 3.13."""
    module = route_to_opcode_dir((3, 13))
    assert module is py313


def test_route_to_opcode_dir_newer() -> None:
    """Test route_to_opcode_dir rejects newer unsupported versions."""
    try:
        route_to_opcode_dir((3, 15))
        assert False, "Should have raised ImportError"
    except ImportError:
        pass


def test_route_to_opcode_dir_unsupported() -> None:
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


def test_load_opcode_handlers_reuses_existing_registered_module_without_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Avoid reloading opcode modules when import already registered handlers."""
    import pysymex._internal.execution.opcodes.registry as opcodes_registry

    load_opcode_handlers((3, 13))
    monkeypatch.setattr(opcodes_registry, "_handlers_loaded", False)
    monkeypatch.setattr(opcodes_registry, "_loaded_module_name", None)

    def fail_refresh(module: object) -> None:
        _ = module
        raise AssertionError("opcode handler refresh should be skipped")

    monkeypatch.setattr(opcodes_registry, "_refresh_version_handlers", fail_refresh)

    load_opcode_handlers((3, 13))

    assert OpcodeDispatcher.global_handler_module("STORE_FAST") is not None


def test_refresh_version_handlers_imports_cold_modules_without_reload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cold opcode modules should execute once; reload is only needed after reset."""
    import pysymex._internal.execution.opcodes.registry as opcodes_registry

    package = ModuleType("fake_opcodes")
    package.__path__ = []
    loaded_module = ModuleType("fake_opcodes.loaded")
    imported: list[str] = []
    reloaded: list[str] = []
    monkeypatch.setitem(sys.modules, "fake_opcodes.loaded", loaded_module)

    def fake_walk_packages(path: object, prefix: str = "") -> list[SimpleNamespace]:
        _ = path
        _ = prefix
        return [
            SimpleNamespace(name="fake_opcodes.loaded"),
            SimpleNamespace(name="fake_opcodes.cold"),
        ]

    monkeypatch.setattr(
        opcodes_registry.pkgutil,
        "walk_packages",
        fake_walk_packages,
    )

    def import_fake_module(name: str) -> ModuleType:
        imported.append(name)
        module = ModuleType(name)
        monkeypatch.setitem(sys.modules, name, module)
        return module

    def reload_fake_module(module: ModuleType) -> ModuleType:
        reloaded.append(module.__name__)
        return module

    monkeypatch.setattr(opcodes_registry, "import_module", import_fake_module)
    monkeypatch.setattr(opcodes_registry, "reload", reload_fake_module)

    refresh_version_handlers = cast(
        "Callable[[ModuleType], None]",
        getattr(opcodes_registry, "_refresh_version_handlers"),
    )
    refresh_version_handlers(package)

    assert imported == ["fake_opcodes.cold"]
    assert reloaded == ["fake_opcodes.loaded"]


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


def test_load_opcode_handlers_reregisters_py312_instrumented_stack_after_reset() -> None:
    OpcodeDispatcher.clear_global_handlers()
    load_opcode_handlers((3, 13))

    load_opcode_handlers((3, 12))

    assert (
        OpcodeDispatcher.global_handler_module("INSTRUMENTED_CALL")
        == "pysymex._internal.execution.opcodes.py312.stack"
    )


def test_load_opcode_handlers_312_uses_control_call_intrinsic_2() -> None:
    OpcodeDispatcher.clear_global_handlers()

    load_opcode_handlers((3, 12))

    assert (
        OpcodeDispatcher.global_handler_module("CALL_INTRINSIC_2")
        == "pysymex._internal.execution.opcodes.py312.control"
    )
    dispatcher = OpcodeDispatcher()
    result = dispatcher.dispatch(_instr("CALL_INTRINSIC_2", 1), VMState(stack=[1, 2], pc=0))
    assert result.new_states[0].stack == [1]


def test_load_opcode_handlers_313_uses_control_call_intrinsic_2() -> None:
    OpcodeDispatcher.clear_global_handlers()

    load_opcode_handlers((3, 13))

    assert (
        OpcodeDispatcher.global_handler_module("CALL_INTRINSIC_2")
        == "pysymex._internal.execution.opcodes.py313.control.intrinsics"
    )
    dispatcher = OpcodeDispatcher()
    result = dispatcher.dispatch(_instr("CALL_INTRINSIC_2", 1), VMState(stack=[1, 2], pc=0))
    assert result.new_states[0].stack == [1]
