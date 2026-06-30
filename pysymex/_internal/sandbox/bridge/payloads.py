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

import json
import sys
from types import CodeType, FunctionType

from pysymex._internal.contracts.decorator.registry import ContractRegistry
from pysymex._internal.sandbox.bridge.codecs import (
    DecodedFunctionGlobal,
    decode_const_mapping,
    decode_optional_const_mapping,
    decode_optional_const_tuple,
    reconstruct_code_obj,
)
from pysymex._internal.sandbox.bridge.contracts import decode_optional_function_contract, make_cell
from pysymex._internal.sandbox.bridge.schema import (
    DEFAULT_EXTRACTION_LIMITS,
    EXTRACTION_SCHEMA_VERSION,
    FUNCTION_TARGET_KEYS,
    FUNCTIONTOP_LEVEL_KEYS,
    MODULETOP_LEVEL_KEYS,
    TOP_LEVEL_KEYS,
    ExtractionLimits,
    SandboxSchema,
    producer_python_version,
    validate_diagnostics,
)


def _install_decoded_function_globals(
    global_ns: dict[str, object],
    globals_data: dict[str, object],
) -> None:
    """Install decoded globals, preserving one shared module namespace for helpers.

    Same-module helper functions are decoded in two phases so recursive and
    mutually recursive helper references resolve through the same globals dict
    as the target function. Non-function constants are installed first because
    helper defaults and runtime global reads may depend on them.
    """
    for key, value in globals_data.items():
        if not isinstance(value, DecodedFunctionGlobal):
            global_ns[key] = value

    for key, value in globals_data.items():
        if not isinstance(value, DecodedFunctionGlobal):
            continue
        closure = (
            tuple(make_cell(cell_value) for cell_value in value.closure)
            if value.closure is not None
            else None
        )
        try:
            function = FunctionType(value.code, global_ns, value.name, value.defaults, closure)
        except (TypeError, ValueError) as exc:
            msg = f"Invalid sandbox helper function metadata for {key!r}"
            raise ValueError(msg) from exc
        function.__qualname__ = value.qualname
        function.__module__ = value.module
        function.__kwdefaults__ = value.kwdefaults
        function.__annotations__ = value.annotations
        global_ns[key] = function


def reconstruct_code_from_payload(
    payload: bytes,
    *,
    expected_filename: str,
    producer_python: tuple[int, int] | None = None,
    limits: ExtractionLimits = DEFAULT_EXTRACTION_LIMITS,
) -> CodeType:
    """Validate a versioned extraction payload and reconstruct its module code."""
    if not payload:
        msg = "Sandbox bytecode payload is empty"
        raise ValueError(msg)
    if len(payload) > limits.max_payload_bytes:
        msg = "Sandbox bytecode payload exceeds size limit"
        raise ValueError(msg)

    try:
        parsed: object = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = "Invalid sandbox bytecode payload"
        raise ValueError(msg) from exc

    top = SandboxSchema.object(parsed, "payload")
    SandboxSchema.reject_unexpected(top, TOP_LEVEL_KEYS, "payload")

    schema_version = SandboxSchema.int(top["schema_version"], "schema_version")
    if schema_version != EXTRACTION_SCHEMA_VERSION:
        msg = f"Unsupported sandbox extraction schema version: {schema_version}"
        raise ValueError(msg)

    kind = SandboxSchema.str(top["kind"], "kind", max_length=128)
    if kind != "pysymex.bytecode":
        msg = "Sandbox extraction payload kind is not pysymex.bytecode"
        raise ValueError(msg)

    producer = SandboxSchema.object(top["producer"], "producer")
    producer_version = producer_python_version(producer, limits=limits)
    current = (sys.version_info.major, sys.version_info.minor)
    if producer_version[:2] != current:
        msg = "Sandbox bytecode producer Python version does not match host"
        raise ValueError(msg)
    if producer_python is not None and producer_python != current:
        msg = "Sandbox bytecode producer Python version does not match host"
        raise ValueError(msg)

    validate_diagnostics(top["diagnostics"], limits=limits)
    targets = SandboxSchema.object(top["targets"], "targets")
    if targets:
        msg = "Bytecode extraction payload does not support target objects yet"
        raise ValueError(msg)

    code_obj = reconstruct_code_obj(top["module"], limits=limits, depth=0)
    if code_obj.co_filename != expected_filename:
        msg = "Sandbox bytecode payload filename metadata mismatch"
        raise ValueError(msg)
    return code_obj


def reconstruct_function_from_payload(
    payload: bytes,
    *,
    expected_filename: str,
    expected_target_name: str,
    limits: ExtractionLimits = DEFAULT_EXTRACTION_LIMITS,
) -> FunctionType:
    """Validate a versioned function extraction payload and rebuild a function."""
    if not payload:
        msg = "Sandbox function payload is empty"
        raise ValueError(msg)
    if len(payload) > limits.max_payload_bytes:
        msg = "Sandbox function payload exceeds size limit"
        raise ValueError(msg)

    try:
        parsed: object = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = "Invalid sandbox function payload"
        raise ValueError(msg) from exc

    top = SandboxSchema.object(parsed, "payload")
    SandboxSchema.reject_unexpected(top, FUNCTIONTOP_LEVEL_KEYS, "payload")

    schema_version = SandboxSchema.int(top["schema_version"], "schema_version")
    if schema_version != EXTRACTION_SCHEMA_VERSION:
        msg = f"Unsupported sandbox extraction schema version: {schema_version}"
        raise ValueError(msg)

    kind = SandboxSchema.str(top["kind"], "kind", max_length=128)
    if kind != "pysymex.function":
        msg = "Sandbox extraction payload kind is not pysymex.function"
        raise ValueError(msg)

    target_name = SandboxSchema.str(
        top["target_name"],
        "target_name",
        max_length=limits.max_string_length,
    )
    if target_name != expected_target_name:
        msg = "Sandbox function payload target name mismatch"
        raise ValueError(msg)

    producer = SandboxSchema.object(top["producer"], "producer")
    producer_version = producer_python_version(producer, limits=limits)
    current = (sys.version_info.major, sys.version_info.minor)
    if producer_version[:2] != current:
        msg = "Sandbox function producer Python version does not match host"
        raise ValueError(msg)

    validate_diagnostics(top["diagnostics"], limits=limits)

    target = SandboxSchema.object(top["target"], "target")
    SandboxSchema.reject_unexpected(target, FUNCTION_TARGET_KEYS, "target")
    target_kind = SandboxSchema.str(target["kind"], "target.kind", max_length=64)
    if target_kind != "function":
        msg = "Sandbox target is not a function"
        raise ValueError(msg)

    code_obj = reconstruct_code_obj(target["code"], limits=limits, depth=0)
    if code_obj.co_filename != expected_filename:
        msg = "Sandbox function payload filename metadata mismatch"
        raise ValueError(msg)

    name = SandboxSchema.str(target["name"], "target.name", max_length=limits.max_name_length)
    qualname = SandboxSchema.str(
        target["qualname"],
        "target.qualname",
        max_length=limits.max_string_length,
    )
    module_name = SandboxSchema.str(
        target["module"],
        "target.module",
        max_length=limits.max_string_length,
    )
    defaults = decode_optional_const_tuple(target["defaults"], "target.defaults", limits=limits)
    kwdefaults = decode_optional_const_mapping(
        target["kwdefaults"],
        "target.kwdefaults",
        limits=limits,
    )
    annotations = decode_const_mapping(
        target["annotations"],
        "target.annotations",
        limits=limits,
    )
    closure_values = decode_optional_const_tuple(target["closure"], "target.closure", limits=limits)
    globals_data = decode_const_mapping(target["globals"], "target.globals", limits=limits)
    validate_diagnostics(target["diagnostics"], limits=limits)

    global_ns: dict[str, object] = {
        "__builtins__": {},
        "__name__": module_name,
        "__file__": expected_filename,
    }
    _install_decoded_function_globals(global_ns, globals_data)
    closure = (
        tuple(make_cell(value) for value in closure_values) if closure_values is not None else None
    )
    try:
        function = FunctionType(code_obj, global_ns, name, defaults, closure)
    except (TypeError, ValueError) as exc:
        msg = "Invalid sandbox function metadata"
        raise ValueError(msg) from exc
    function.__qualname__ = qualname
    function.__module__ = module_name
    function.__kwdefaults__ = kwdefaults
    function.__annotations__ = annotations
    global_ns.setdefault(name, function)
    contract = decode_optional_function_contract(
        target.get("contract"),
        function_name=name,
        limits=limits,
    )
    if contract is not None:
        ContractRegistry.attach_contract(function, contract)
    return function


def parse_module_payload(
    payload: bytes,
    *,
    expected_filename: str,
    limits: ExtractionLimits,
) -> dict[str, object]:
    """Validate a serialized module extraction payload for later reconstruction.

    Args:
        payload: UTF-8 JSON payload returned by the sandbox module worker.
        expected_filename: Filename required in the reconstructed module code
            metadata.
        limits: Size, name, and diagnostic limits applied during validation.

    Returns:
        The validated top-level module payload mapping.

    Raises:
        ValueError: If the payload is absent, oversized, malformed, uses an
            unsupported schema/kind/Python version, has invalid diagnostics or
            target metadata, or identifies a different source filename.

    Notes:
        This function validates the module code object and target metadata
        envelope. Individual target functions are reconstructed separately.

    """
    if not payload:
        msg = "Sandbox module payload is empty"
        raise ValueError(msg)
    if len(payload) > limits.max_payload_bytes:
        msg = "Sandbox module payload exceeds size limit"
        raise ValueError(msg)
    try:
        parsed: object = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = "Invalid sandbox module payload"
        raise ValueError(msg) from exc
    top = SandboxSchema.object(parsed, "payload")
    SandboxSchema.reject_unexpected(top, MODULETOP_LEVEL_KEYS, "payload")
    schema_version = SandboxSchema.int(top["schema_version"], "schema_version")
    if schema_version != EXTRACTION_SCHEMA_VERSION:
        msg = f"Unsupported sandbox extraction schema version: {schema_version}"
        raise ValueError(msg)
    kind = SandboxSchema.str(top["kind"], "kind", max_length=128)
    if kind != "pysymex.module":
        msg = "Sandbox extraction payload kind is not pysymex.module"
        raise ValueError(msg)
    producer = SandboxSchema.object(top["producer"], "producer")
    producer_version = producer_python_version(producer, limits=limits)
    current = (sys.version_info.major, sys.version_info.minor)
    if producer_version[:2] != current:
        msg = "Sandbox module producer Python version does not match host"
        raise ValueError(msg)
    validate_diagnostics(top["diagnostics"], limits=limits)
    code_obj = reconstruct_code_obj(top["module"], limits=limits, depth=0)
    if code_obj.co_filename != expected_filename:
        msg = "Sandbox module payload filename metadata mismatch"
        raise ValueError(msg)
    targets = SandboxSchema.object(top["targets"], "targets")
    if len(targets) > limits.max_names:
        msg = "targets: mapping exceeds limit"
        raise ValueError(msg)
    for name, target in targets.items():
        if len(name) > limits.max_string_length:
            msg = "targets: key exceeds limit"
            raise ValueError(msg)
        target_data = SandboxSchema.object(target, f"targets[{name!r}]")
        SandboxSchema.reject_unexpected(target_data, FUNCTION_TARGET_KEYS, f"targets[{name!r}]")
    return top
