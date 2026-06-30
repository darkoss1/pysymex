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

"""Class body registration, ``__init__``, slots, and instance copy helpers for calls.

Aggregates :mod:`pysymex._internal.execution.opcodes.common.functions.classes` submodules used when
bytecode constructs or mutates modeled local classes (not stdlib types registered elsewhere).
"""

from __future__ import annotations

import types
from typing import TYPE_CHECKING

from pysymex._internal.core.calls.payload import function_payload
from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.state.types import is_bound
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.value.coercion import concrete_string
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.functions.classes.descriptor.assignments import (
    class_body_descriptor_assignments,
)

_contract_decorator_by_name_cache: dict[str, frozenset[object]] | None = None

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def apply_build_class_model(
    state: VMState,
    args: list[StackValue],
    kwargs: dict[str, StackValue] | None = None,
) -> OpcodeResult | None:
    """Model CPython ``__build_class__`` without executing class-body side effects."""
    kwargs = kwargs or {}
    if len(args) < 2:
        return None
    body_func = args[0]
    class_name = concrete_string(args[1])
    if class_name is None:
        class_name = getattr(body_func, "_name", None) or getattr(body_func, "name", None)
    if not isinstance(class_name, str) or not class_name:
        class_name = f"class_{state.pc}"

    code_obj = getattr(body_func, "_modeled_object", None)
    payload = function_payload(code_obj)
    class_val = SymbolicValue(
        _name=class_name,
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_obj=Z3_TRUE,
        is_none=Z3_FALSE,
        is_path=Z3_FALSE,
        affinity_type="type",
    )
    if payload is not None:
        class_val.attach_modeled_object(payload)
        closure_by_name = _payload_closure_by_name(state, payload)
        contract_decorator_names = _recognized_contract_decorator_names(
            state,
            payload.code,
            closure_by_name,
        )
        if contract_decorator_names:
            class_val.set_contract_decorator_names(contract_decorator_names)
        descriptor_assignments = class_body_descriptor_assignments(
            payload.code,
            lambda name: _lookup_class_body_name(state, name, closure_by_name),
        )
        if descriptor_assignments:
            class_val.set_descriptor_assignments(descriptor_assignments)
    elif isinstance(code_obj, types.CodeType):
        class_val.attach_modeled_object(code_obj)
        contract_decorator_names = _recognized_contract_decorator_names(state, code_obj)
        if contract_decorator_names:
            class_val.set_contract_decorator_names(contract_decorator_names)
        descriptor_assignments = class_body_descriptor_assignments(
            code_obj,
            lambda name: _lookup_class_body_name(state, name),
        )
        if descriptor_assignments:
            class_val.set_descriptor_assignments(descriptor_assignments)
    import functools

    if state.global_vars.get("functools") is functools:
        class_val.mark_trusted_cached_property()
    base_values = tuple(args[2:])
    metaclass_value = kwargs.get("metaclass")
    if isinstance(metaclass_value, SymbolicValue):
        class_val.set_metaclass_value(metaclass_value)
    class_val.set_class_bases(
        all(isinstance(base, (SymbolicValue, type)) for base in base_values),
        base_values,
    )
    if not base_values and not kwargs:
        class_val.mark_plain_class_definition()
    state = state.push(class_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _payload_closure_by_name(state: VMState, payload: object) -> dict[str, object]:
    """Return function payload closure entries keyed by free-variable name."""
    resolved = function_payload(payload)
    if resolved is None or not resolved.closure:
        return {}
    return {
        name: _dereference_cell(state, cell)
        for name, cell in zip(resolved.code.co_freevars, resolved.closure, strict=False)
    }


def _lookup_class_body_name(
    state: VMState,
    name: str,
    closure_by_name: dict[str, object] | None = None,
) -> object | None:
    """Resolve a name visible to a class body without executing the body."""
    if closure_by_name is not None and name in closure_by_name:
        return closure_by_name[name]
    local_value = state.get_local(name)
    if is_bound(local_value) and local_value is not None:
        return _dereference_cell(state, local_value)
    return state.get_global(name)


def _recognized_contract_decorator_names(
    state: VMState,
    class_body: types.CodeType,
    closure_by_name: dict[str, object] | None = None,
) -> frozenset[str]:
    """Return PySyMex contract decorators visible to a class body by exact object identity."""
    import dis

    recognized: set[str] = set()
    expected = _contract_decorator_by_name()
    for instr in dis.get_instructions(class_body):
        if instr.opname not in {
            "LOAD_CLASSDEREF",
            "LOAD_DEREF",
            "LOAD_FAST",
            "LOAD_FAST_CHECK",
            "LOAD_FROM_DICT_OR_DEREF",
            "LOAD_GLOBAL",
            "LOAD_NAME",
        } or not isinstance(instr.argval, str):
            continue
        expected_decorators = expected.get(instr.argval)
        if expected_decorators is None:
            continue
        visible_value = _lookup_class_body_name(state, instr.argval, closure_by_name)
        if any(visible_value is decorator for decorator in expected_decorators):
            recognized.add(instr.argval)
            continue
        if visible_value is None and instr.opname in {"LOAD_GLOBAL", "LOAD_NAME"}:
            # Function-local class bodies often reference module-global contract decorators
            # through bytecode globals that are not retained in the modeled class payload.
            # Keep unresolved global contract names recognized, while resolved local or
            # closure shadows above still require exact identity.
            recognized.add(instr.argval)
    return frozenset(recognized)


def _contract_decorator_by_name() -> dict[str, frozenset[object]]:
    """Return known PySyMex contract decorator functions by source-visible name."""
    global _contract_decorator_by_name_cache
    if _contract_decorator_by_name_cache is None:
        from pysymex._internal.contracts.decorators import assigns, assumes, ensures, pure, requires

        try:
            from pysymex import contracts as public_contracts
        except (
            Exception
        ):  # pragma: no cover - public API module may be unavailable during bootstrap
            public_contracts = None

        def accepted(name: str, internal: object) -> frozenset[object]:
            values: list[object] = [internal]
            public = getattr(public_contracts, name, None) if public_contracts is not None else None
            if public is not None and all(public is not value for value in values):
                values.append(public)
            return frozenset(values)

        _contract_decorator_by_name_cache = {
            "assigns": accepted("assigns", assigns),
            "assumes": accepted("assumes", assumes),
            "ensures": accepted("ensures", ensures),
            "pure": accepted("pure", pure),
            "requires": accepted("requires", requires),
        }
    return _contract_decorator_by_name_cache


def _dereference_cell(state: VMState, value: object) -> object | None:
    """Return a cell object's current heap value, or *value* when it is not a cell."""
    if isinstance(value, SymbolicObject) and value.name.startswith("cell_"):
        return state.load_heap(value.address)
    return value
