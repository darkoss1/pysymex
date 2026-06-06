# pysymex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Unit tests for sys/os stdlib models and pre-population imports."""

from __future__ import annotations

import dis
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.models.builtins.base import is_raised_exception_effect
from pysymex.models.stdlib import get_stdlib_model
from pysymex.models.stdlib.os import OsGetcwdModel
from pysymex.models.stdlib.sys import SysExitModel
from pysymex.execution.opcodes.common.functions.misc import handle_common_import_name
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def _state() -> VMState:
    return VMState(pc=0)


def _instr(opname: str, argval: object = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)


def test_sys_exit_model() -> None:
    # Test without args (SystemExit.code defaults to None and str(exc) is empty)
    res = SysExitModel().apply([], {}, _state())
    raised = res.side_effects.get("raised_exception")
    assert is_raised_exception_effect(raised)
    assert raised["exception_type"] == "SystemExit"
    assert raised["message"] == ""

    # Test with concrete exit status
    res = SysExitModel().apply([42], {}, _state())
    raised = res.side_effects.get("raised_exception")
    assert is_raised_exception_effect(raised)
    assert raised["exception_type"] == "SystemExit"
    assert raised["message"] == "42"

    # Test with string message
    res = SysExitModel().apply(["error"], {}, _state())
    raised = res.side_effects.get("raised_exception")
    assert is_raised_exception_effect(raised)
    assert raised["exception_type"] == "SystemExit"
    assert raised["message"] == "error"

    # Extra arguments are rejected by CPython.
    res = SysExitModel().apply([1, 2], {}, _state())
    raised = res.side_effects.get("raised_exception")
    assert is_raised_exception_effect(raised)
    assert raised["exception_type"] == "TypeError"


def test_sys_os_import_pre_population() -> None:
    # 1. Test importing 'sys' module prepopulates argv
    state = VMState(stack=[None, 0], pc=1)  # fromlist=None, level=0
    dispatcher = OpcodeDispatcher()
    instr = _instr("IMPORT_NAME", "sys")
    res = handle_common_import_name(instr, state, dispatcher)

    assert len(res.new_states) == 1
    next_state = res.new_states[0]
    module_val = next_state.stack[-1]
    assert isinstance(module_val, SymbolicObject)
    assert module_val.name == "sys"

    # Load module heap dict
    heap_val = next_state.load_heap(module_val.address)
    assert isinstance(heap_val, dict)
    assert "argv" in heap_val
    assert isinstance(heap_val["argv"], SymbolicList)

    # 2. Test importing 'os' module prepopulates environ
    state2 = VMState(stack=[None, 0], pc=1)  # fromlist=None, level=0
    instr2 = _instr("IMPORT_NAME", "os")
    res2 = handle_common_import_name(instr2, state2, dispatcher)

    assert len(res2.new_states) == 1
    next_state2 = res2.new_states[0]
    module_val2 = next_state2.stack[-1]
    assert isinstance(module_val2, SymbolicObject)
    assert module_val2.name == "os"

    # Load module heap dict
    heap_val2 = next_state2.load_heap(module_val2.address)
    assert isinstance(heap_val2, dict)
    assert "environ" in heap_val2
    assert isinstance(heap_val2["environ"], SymbolicDict)


def test_os_getcwd_model_returns_symbolic_string_without_host_lookup() -> None:
    result = OsGetcwdModel().apply([], {}, _state())

    assert isinstance(result.value, SymbolicString)
    assert result.constraints
    assert isinstance(get_stdlib_model("os.getcwd"), OsGetcwdModel)
