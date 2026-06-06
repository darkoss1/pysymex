# pysymex: python symbolic execution & formal verification
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

"""MAKE_FUNCTION, import, PRECALL/KW_NAMES, and other call-prep opcode handlers.

Bridges bytecode call setup to :mod:`pysymex.execution.calls.model_dispatch`
without owning full interprocedural semantics. Star-import and monitoring hooks are
conservative stubs where noted in per-handler docs.
"""

from __future__ import annotations

import dis
import types
from typing import TYPE_CHECKING

import z3

from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.calls.helpers import (
    as_stack_value,
    is_object_map,
    map_get,
    map_to_stack_dict,
)
from pysymex.execution.calls.payload import (
    function_payload,
    with_annotations,
    with_closure,
    with_defaults,
    with_kwdefaults,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def handle_common_make_function(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Create a function object."""
    code_obj = None
    if state.stack:
        code_obj = state.pop()
    flags = int(instr.argval) if instr.argval else 0
    defaults = None
    kwdefaults = None
    closure = None
    annotations = None
    if flags & 0x08:
        if state.stack:
            closure = state.pop()
    if flags & 0x04:
        if state.stack:
            annotations = state.pop()
    if flags & 0x02:
        if state.stack:
            kwdefaults = state.pop()
    if flags & 0x01:
        if state.stack:
            defaults = state.pop()
    func_val = SymbolicValue(
        _name=f"function_{state.pc}",
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
    )
    if isinstance(code_obj, SymbolicValue):
        stored_code_obj = code_obj.value
        if isinstance(stored_code_obj, types.CodeType):
            code_obj = stored_code_obj
    if isinstance(code_obj, types.CodeType):
        payload = function_payload(code_obj)
        if payload is not None:
            if defaults is not None:
                payload = with_defaults(payload, defaults)
            if kwdefaults is not None:
                payload = with_kwdefaults(payload, kwdefaults)
            if annotations is not None:
                payload = with_annotations(payload, annotations)
            if closure is not None:
                payload = with_closure(payload, closure)
            func_val.attach_modeled_object(payload)
    if annotations is not None:
        if isinstance(annotations, SymbolicDict):
            func_val.set_annotations(annotations)
        elif is_object_map(annotations):
            func_val.set_annotations(map_to_stack_dict(annotations))
    state = state.push(func_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_build_class(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load __build_class__ builtin with modeled class support."""

    builtin_val = SymbolicValue(
        _name="__build_class__",
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="callable",
    )
    builtin_val.model_name = "__build_class__"
    state = state.push(builtin_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_import_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Import a module (import x)."""
    _fromlist = state.pop() if state.stack else None
    level_val = state.pop() if state.stack else 0
    level = int(level_val) if isinstance(level_val, (int, float)) else 0

    module_name = str(instr.argval) if instr.argval else ""

    # Handle relative imports
    full_name = module_name
    if level > 0:
        package = state.global_vars.get("__package__")
        if isinstance(package, str) and package:
            parts = package.split(".")
            if level == 1:
                full_name = f"{package}.{module_name}" if module_name else package
            else:
                up = level - 1
                if up < len(parts):
                    base = ".".join(parts[:-up])
                    full_name = f"{base}.{module_name}" if module_name else base
                else:
                    full_name = module_name

    addr = hash(full_name) & 0xFFFFFFFF
    module_val = SymbolicObject(full_name, addr, get_int_val(addr), {addr})

    module_data: dict[str, StackValue] = {"__module_name__": full_name}
    if full_name == "sys":
        module_data["argv"] = SymbolicList(
            "sys.argv",
            z3.Array("sys.argv_arr", z3.IntSort(), z3.IntSort()),
            z3.Int("sys.argv_len"),
            "str",
        )
    elif full_name == "os":
        module_data["environ"] = SymbolicDict(
            "os.environ",
            z3.Array("os.environ_arr", z3.StringSort(), z3.IntSort()),
            z3.Array("os.environ_keys", z3.StringSort(), z3.BoolSort()),
            z3.Int("os.environ_len"),
        )
        path_addr = hash("os.path") & 0xFFFFFFFF
        path_module = SymbolicObject("os.path", path_addr, get_int_val(path_addr), {path_addr})
        module_data["path"] = path_module
        state = state.store_heap(path_addr, {"__module_name__": "os.path"})
    elif full_name == "contextlib":
        from contextlib import suppress

        module_data["suppress"] = suppress
    elif full_name == "functools":
        import functools

        module_data["lru_cache"] = functools.lru_cache
        module_data["partial"] = functools.partial
        module_data["reduce"] = functools.reduce
        module_data["wraps"] = functools.wraps
    state = state.store_heap(addr, module_data)

    state = state.push(module_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_import_from(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Import attribute from module (from x import y)."""
    attr_name = str(instr.argval) if instr.argval else "unknown_attr"

    # Module is TOS
    module = state.stack[-1] if state.stack else None

    # Special case: typing.TYPE_CHECKING should be False to reduce noise
    module_name = getattr(module, "_name", "")
    if module_name == "typing" and attr_name == "TYPE_CHECKING":
        state = state.push(False)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

        # Preserve the concrete contextlib manager needed for typed suppression checks.
    res_val: StackValue = None
    if isinstance(module, SymbolicObject):
        existing = state.global_vars.get(attr_name)
        if (
            module.name == "contextlib"
            and attr_name == "suppress"
            and getattr(existing, "__module__", None) == "contextlib"
        ):
            res_val = existing
        if module.address != -1:
            obj_state = state.load_heap(module.address)
            if is_object_map(obj_state):
                found, raw_val = map_get(obj_state, attr_name)
                if found:
                    res_val = as_stack_value(raw_val)

    if res_val is None:
        # Model unresolved imported attributes as non-None symbolic objects.
        id_suffix = hash(f"import_{attr_name}_{state.pc}") & 0xFFFF
        import_name = f"import_{attr_name}"
        z3_addr = z3.Int(f"{import_name}_{id_suffix}_addr")
        res_val = SymbolicObject(
            _name=import_name, address=id_suffix, z3_addr=z3_addr, potential_addresses={id_suffix}
        )
        res_val.model_name = attr_name

        # Ensure it's not None
        state = state.add_constraint(z3_addr != 0)

    state = state.push(res_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_call_intrinsic_2(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle CALL_INTRINSIC_2 (Python 3.12+)."""
    _ = state.pop()
    _ = state.pop()

    val, type_constraint = SymbolicValue.symbolic(f"intrinsic2_{state.pc}")
    state = state.add_constraint(type_constraint)
    state = state.push(val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_set_function_attribute(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Attach closure, defaults, or annotations to a symbolic function payload."""
    if len(state.stack) < 2:
        return OpcodeResult.continue_with(state.advance_pc())
    func_obj = state.pop()
    attr_value = state.pop()
    if isinstance(func_obj, SymbolicValue):
        payload = function_payload(getattr(func_obj, "_modeled_object", None))
        if payload is not None:
            flag = int(instr.argval) if instr.argval else 0
            if flag & 0x08:
                func_obj.attach_modeled_object(with_closure(payload, attr_value))
            elif flag & 0x04:
                func_obj.attach_modeled_object(with_annotations(payload, attr_value))
                if isinstance(attr_value, SymbolicDict):
                    func_obj.set_annotations(attr_value)
                elif is_object_map(attr_value):
                    func_obj.set_annotations(map_to_stack_dict(attr_value))
            elif flag & 0x02:
                func_obj.attach_modeled_object(with_kwdefaults(payload, attr_value))
            elif flag & 0x01:
                func_obj.attach_modeled_object(with_defaults(payload, attr_value))
    state = state.push(func_obj)
    return OpcodeResult.continue_with(state.advance_pc())


def handle_common_precall(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle PRECALL (Python 3.11)."""
    return OpcodeResult.continue_with(state.advance_pc())


def handle_common_kw_names(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle KW_NAMES (Python 3.11+)."""
    state.pending_kw_names = instr.argval
    return OpcodeResult.continue_with(state.advance_pc())


def handle_common_import_star(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``IMPORT_STAR``: pop the module object from the stack.

    CPython copies public names into ``locals``; here the module operand is discarded
    and analysis continues without modeling star-import side effects.

    Limitations:
        Does not expand imported bindings into ``VMState`` locals.
    """
    if state.stack:
        state.pop()
    return OpcodeResult.continue_with(state.advance_pc())
