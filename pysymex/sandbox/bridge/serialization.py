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

from __future__ import annotations

import base64
import json
import sys
from types import CodeType, FunctionType
from typing import cast

from pysymex.sandbox.bridge.schema import EXTRACTION_SCHEMA_VERSION


def serialize_code_metadata(code_obj: CodeType) -> dict[str, object]:
    """Serialize a local ``CodeType`` using the public extraction schema.

    This helper is used by tests and sandbox bridge payload builders. It does
    not relax host-side validation; callers still need ``BytecodeBlob.reconstruct()``.
    """

    return {
        "kind": "code",
        "argcount": code_obj.co_argcount,
        "posonlyargcount": code_obj.co_posonlyargcount,
        "kwonlyargcount": code_obj.co_kwonlyargcount,
        "nlocals": code_obj.co_nlocals,
        "stacksize": code_obj.co_stacksize,
        "flags": code_obj.co_flags,
        "code": base64.b64encode(code_obj.co_code).decode("ascii"),
        "consts": [serialize_safe_constant(constant) for constant in code_obj.co_consts],
        "names": list(code_obj.co_names),
        "varnames": list(code_obj.co_varnames),
        "freevars": list(code_obj.co_freevars),
        "cellvars": list(code_obj.co_cellvars),
        "filename": code_obj.co_filename,
        "name": code_obj.co_name,
        "qualname": code_obj.co_qualname,
        "firstlineno": code_obj.co_firstlineno,
        "linetable": base64.b64encode(code_obj.co_linetable).decode("ascii"),
        "exceptiontable": base64.b64encode(code_obj.co_exceptiontable).decode("ascii"),
    }


def serialize_safe_constant(constant: object) -> object:
    """Serialize a constant kind accepted by the extraction schema."""
    if isinstance(constant, CodeType):
        return serialize_code_metadata(constant)
    if isinstance(constant, tuple):
        items = cast("tuple[object, ...]", constant)
        return {"kind": "tuple", "items": [serialize_safe_constant(item) for item in items]}
    if isinstance(constant, frozenset):
        items = cast("frozenset[object]", constant)
        return {"kind": "frozenset", "items": [serialize_safe_constant(item) for item in items]}
    if isinstance(constant, bytes):
        return {
            "kind": "bytes",
            "data": base64.b64encode(constant).decode("ascii"),
        }
    if isinstance(constant, (int, float, str, type(None), bool)):
        return constant
    raise TypeError(f"Unsupported sandbox constant type: {type(constant).__name__}")


def serialize_safe_annotation(value: object) -> object:
    """Serialize annotation values without invoking arbitrary user code."""
    if isinstance(value, type):
        return value.__qualname__
    return serialize_safe_constant(value)


def create_bytecode_payload(
    code_obj: CodeType,
    *,
    diagnostics: list[object] | None = None,
) -> bytes:
    """Create a versioned bytecode extraction payload for ``code_obj``."""
    payload: dict[str, object] = {
        "schema_version": EXTRACTION_SCHEMA_VERSION,
        "kind": "pysymex.bytecode",
        "producer": {
            "python_implementation": sys.implementation.name,
            "python_version": [
                sys.version_info.major,
                sys.version_info.minor,
                sys.version_info.micro,
            ],
        },
        "module": serialize_code_metadata(code_obj),
        "targets": {},
        "diagnostics": diagnostics or [],
    }
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def create_function_payload(
    function: FunctionType,
    *,
    target_name: str | None = None,
    globals_data: dict[str, object] | None = None,
    diagnostics: list[object] | None = None,
) -> bytes:
    """Create a versioned target-function extraction payload."""
    closure_values: list[object] | None = None
    closure = function.__closure__
    if closure is not None:
        closure_values = [serialize_safe_constant(cell.cell_contents) for cell in closure]

    target: dict[str, object] = {
        "kind": "function",
        "name": function.__name__,
        "qualname": function.__qualname__,
        "module": str(function.__module__ or "__main__"),
        "code": serialize_code_metadata(function.__code__),
        "defaults": None
        if function.__defaults__ is None
        else [serialize_safe_constant(value) for value in function.__defaults__],
        "kwdefaults": None
        if function.__kwdefaults__ is None
        else {
            key: serialize_safe_constant(value) for key, value in function.__kwdefaults__.items()
        },
        "annotations": {
            key: serialize_safe_annotation(value) for key, value in function.__annotations__.items()
        },
        "closure": closure_values,
        "globals": {
            key: serialize_safe_constant(value) for key, value in (globals_data or {}).items()
        },
        "contract": None,
        "diagnostics": diagnostics or [],
    }
    payload: dict[str, object] = {
        "schema_version": EXTRACTION_SCHEMA_VERSION,
        "kind": "pysymex.function",
        "producer": {
            "python_implementation": sys.implementation.name,
            "python_version": [
                sys.version_info.major,
                sys.version_info.minor,
                sys.version_info.micro,
            ],
        },
        "target_name": target_name or function.__name__,
        "target": target,
        "diagnostics": diagnostics or [],
    }
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
