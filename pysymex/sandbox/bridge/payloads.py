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

from pysymex.sandbox.bridge.codecs import (
    decode_const_mapping,
    decode_optional_const_mapping,
    decode_optional_const_tuple,
    reconstruct_code_obj,
)
from pysymex.sandbox.bridge.contracts import decode_optional_function_contract, make_cell
from pysymex.sandbox.bridge.schema import (
    DEFAULT_EXTRACTION_LIMITS,
    EXTRACTION_SCHEMA_VERSION,
    ExtractionLimits,
    FUNCTION_TARGET_KEYS,
    FUNCTIONTOP_LEVEL_KEYS,
    MODULETOP_LEVEL_KEYS,
    TOP_LEVEL_KEYS,
    producer_python_version,
    reject_unexpected_fields,
    require_json_int,
    require_json_object,
    require_json_str,
    validate_diagnostics,
)


def reconstruct_code_from_payload(
    payload: bytes,
    *,
    expected_filename: str,
    producer_python: tuple[int, int] | None = None,
    limits: ExtractionLimits = DEFAULT_EXTRACTION_LIMITS,
) -> CodeType:
    """Validate a versioned extraction payload and reconstruct its module code."""
    if not payload:
        raise ValueError("Sandbox bytecode payload is empty")
    if len(payload) > limits.max_payload_bytes:
        raise ValueError("Sandbox bytecode payload exceeds size limit")

    try:
        parsed: object = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid sandbox bytecode payload") from exc

    top = require_json_object(parsed, "payload")
    reject_unexpected_fields(top, TOP_LEVEL_KEYS, "payload")

    schema_version = require_json_int(top["schema_version"], "schema_version")
    if schema_version != EXTRACTION_SCHEMA_VERSION:
        raise ValueError(f"Unsupported sandbox extraction schema version: {schema_version}")

    kind = require_json_str(top["kind"], "kind", max_length=128)
    if kind != "pysymex.bytecode":
        raise ValueError("Sandbox extraction payload kind is not pysymex.bytecode")

    producer = require_json_object(top["producer"], "producer")
    producer_version = producer_python_version(producer, limits=limits)
    current = (sys.version_info.major, sys.version_info.minor)
    if producer_version[:2] != current:
        raise ValueError("Sandbox bytecode producer Python version does not match host")
    if producer_python is not None and producer_python != current:
        raise ValueError("Sandbox bytecode producer Python version does not match host")

    validate_diagnostics(top["diagnostics"], limits=limits)
    targets = require_json_object(top["targets"], "targets")
    if targets:
        raise ValueError("Bytecode extraction payload does not support target objects yet")

    code_obj = reconstruct_code_obj(top["module"], limits=limits, depth=0)
    if code_obj.co_filename != expected_filename:
        raise ValueError("Sandbox bytecode payload filename metadata mismatch")
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
        raise ValueError("Sandbox function payload is empty")
    if len(payload) > limits.max_payload_bytes:
        raise ValueError("Sandbox function payload exceeds size limit")

    try:
        parsed: object = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid sandbox function payload") from exc

    top = require_json_object(parsed, "payload")
    reject_unexpected_fields(top, FUNCTIONTOP_LEVEL_KEYS, "payload")

    schema_version = require_json_int(top["schema_version"], "schema_version")
    if schema_version != EXTRACTION_SCHEMA_VERSION:
        raise ValueError(f"Unsupported sandbox extraction schema version: {schema_version}")

    kind = require_json_str(top["kind"], "kind", max_length=128)
    if kind != "pysymex.function":
        raise ValueError("Sandbox extraction payload kind is not pysymex.function")

    target_name = require_json_str(
        top["target_name"],
        "target_name",
        max_length=limits.max_string_length,
    )
    if target_name != expected_target_name:
        raise ValueError("Sandbox function payload target name mismatch")

    producer = require_json_object(top["producer"], "producer")
    producer_version = producer_python_version(producer, limits=limits)
    current = (sys.version_info.major, sys.version_info.minor)
    if producer_version[:2] != current:
        raise ValueError("Sandbox function producer Python version does not match host")

    validate_diagnostics(top["diagnostics"], limits=limits)

    target = require_json_object(top["target"], "target")
    reject_unexpected_fields(target, FUNCTION_TARGET_KEYS, "target")
    target_kind = require_json_str(target["kind"], "target.kind", max_length=64)
    if target_kind != "function":
        raise ValueError("Sandbox target is not a function")

    code_obj = reconstruct_code_obj(target["code"], limits=limits, depth=0)
    if code_obj.co_filename != expected_filename:
        raise ValueError("Sandbox function payload filename metadata mismatch")

    name = require_json_str(target["name"], "target.name", max_length=limits.max_name_length)
    qualname = require_json_str(
        target["qualname"],
        "target.qualname",
        max_length=limits.max_string_length,
    )
    module_name = require_json_str(
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
    global_ns.update(globals_data)
    closure = (
        tuple(make_cell(value) for value in closure_values) if closure_values is not None else None
    )
    try:
        function = FunctionType(code_obj, global_ns, name, defaults, closure)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid sandbox function metadata") from exc
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
        setattr(function, "__contract__", contract)
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
        raise ValueError("Sandbox module payload is empty")
    if len(payload) > limits.max_payload_bytes:
        raise ValueError("Sandbox module payload exceeds size limit")
    try:
        parsed: object = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid sandbox module payload") from exc
    top = require_json_object(parsed, "payload")
    reject_unexpected_fields(top, MODULETOP_LEVEL_KEYS, "payload")
    schema_version = require_json_int(top["schema_version"], "schema_version")
    if schema_version != EXTRACTION_SCHEMA_VERSION:
        raise ValueError(f"Unsupported sandbox extraction schema version: {schema_version}")
    kind = require_json_str(top["kind"], "kind", max_length=128)
    if kind != "pysymex.module":
        raise ValueError("Sandbox extraction payload kind is not pysymex.module")
    producer = require_json_object(top["producer"], "producer")
    producer_version = producer_python_version(producer, limits=limits)
    current = (sys.version_info.major, sys.version_info.minor)
    if producer_version[:2] != current:
        raise ValueError("Sandbox module producer Python version does not match host")
    validate_diagnostics(top["diagnostics"], limits=limits)
    code_obj = reconstruct_code_obj(top["module"], limits=limits, depth=0)
    if code_obj.co_filename != expected_filename:
        raise ValueError("Sandbox module payload filename metadata mismatch")
    targets = require_json_object(top["targets"], "targets")
    if len(targets) > limits.max_names:
        raise ValueError("targets: mapping exceeds limit")
    for name, target in targets.items():
        if len(name) > limits.max_string_length:
            raise ValueError("targets: key exceeds limit")
        target_data = require_json_object(target, f"targets[{name!r}]")
        reject_unexpected_fields(target_data, FUNCTION_TARGET_KEYS, f"targets[{name!r}]")
    return top
