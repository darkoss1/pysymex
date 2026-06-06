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

import dis
from types import CodeType

from pysymex.sandbox.bridge.schema import (
    ExtractionLimits,
    decode_base64_bytes,
    decode_str_tuple,
    reject_unexpected_fields,
    require_json_int,
    require_json_list,
    require_json_object,
    require_json_str,
    validate_bytecode_bytes,
    validate_float_constant,
    validate_int_constant,
    BYTES_CONST_KEYS,
    CODE_KEYS,
    SEQUENCE_CONST_KEYS,
)


def reconstruct_code_obj(
    raw: object,
    *,
    limits: ExtractionLimits,
    depth: int,
) -> CodeType:
    """Validate serialized code metadata and construct a Python code object.

    Args:
        raw: JSON-like code metadata mapping from a sandbox payload.
        limits: Payload limits applied to nesting, names, constants, and byte
            fields.
        depth: Current nesting depth for recursive code-constant decoding.

    Returns:
        A reconstructed `CodeType` whose bytecode can be disassembled.

    Raises:
        ValueError: If metadata, limits, bytecode, constants, or constructed
            code-object validation fails.
    """
    if depth > limits.max_depth:
        raise ValueError("code object nesting exceeds limit")

    data = require_json_object(raw, f"code[{depth}]")
    reject_unexpected_fields(data, CODE_KEYS, f"code[{depth}]")

    kind = require_json_str(data["kind"], f"code[{depth}].kind", max_length=64)
    if kind != "code":
        raise ValueError(f"code[{depth}].kind must be 'code'")

    co_argcount = require_json_int(data["argcount"], f"code[{depth}].argcount", minimum=0)
    co_posonlyargcount = require_json_int(
        data["posonlyargcount"],
        f"code[{depth}].posonlyargcount",
        minimum=0,
    )
    co_kwonlyargcount = require_json_int(
        data["kwonlyargcount"],
        f"code[{depth}].kwonlyargcount",
        minimum=0,
    )
    co_nlocals = require_json_int(data["nlocals"], f"code[{depth}].nlocals", minimum=0)
    co_stacksize = require_json_int(data["stacksize"], f"code[{depth}].stacksize", minimum=0)
    co_flags = require_json_int(data["flags"], f"code[{depth}].flags", minimum=0)
    co_code = decode_base64_bytes(
        data["code"],
        f"code[{depth}].code",
        max_bytes=limits.max_code_bytes,
        limits=limits,
    )
    validate_bytecode_bytes(co_code, f"code[{depth}].code")

    co_consts = tuple(
        _reconstruct_const(item, limits=limits, depth=depth + 1)
        for item in require_json_list(data["consts"], f"code[{depth}].consts", limits.max_consts)
    )
    co_names = decode_str_tuple(data["names"], f"code[{depth}].names", limits=limits)
    co_varnames = decode_str_tuple(
        data["varnames"],
        f"code[{depth}].varnames",
        limits=limits,
    )
    co_freevars = decode_str_tuple(
        data["freevars"],
        f"code[{depth}].freevars",
        limits=limits,
    )
    co_cellvars = decode_str_tuple(
        data["cellvars"],
        f"code[{depth}].cellvars",
        limits=limits,
    )
    co_filename = require_json_str(
        data["filename"],
        f"code[{depth}].filename",
        max_length=limits.max_string_length,
    )
    co_name = require_json_str(
        data["name"],
        f"code[{depth}].name",
        max_length=limits.max_name_length,
    )
    co_qualname = require_json_str(
        data["qualname"],
        f"code[{depth}].qualname",
        max_length=limits.max_string_length,
    )
    co_firstlineno = require_json_int(
        data["firstlineno"],
        f"code[{depth}].firstlineno",
        minimum=0,
    )
    co_linetable = decode_base64_bytes(
        data["linetable"],
        f"code[{depth}].linetable",
        max_bytes=limits.max_linetable_bytes,
        limits=limits,
    )
    co_exceptiontable = decode_base64_bytes(
        data["exceptiontable"],
        f"code[{depth}].exceptiontable",
        max_bytes=limits.max_linetable_bytes,
        limits=limits,
    )

    try:
        code_obj = CodeType(
            co_argcount,
            co_posonlyargcount,
            co_kwonlyargcount,
            co_nlocals,
            co_stacksize,
            co_flags,
            co_code,
            co_consts,
            co_names,
            co_varnames,
            co_filename,
            co_name,
            co_qualname,
            co_firstlineno,
            co_linetable,
            co_exceptiontable,
            co_freevars,
            co_cellvars,
        )
        tuple(dis.get_instructions(code_obj))
    except (TypeError, ValueError, SystemError, RuntimeError) as exc:
        raise ValueError("Invalid sandbox code object metadata") from exc
    return code_obj


def _reconstruct_const(
    value: object,
    *,
    limits: ExtractionLimits,
    depth: int,
) -> object:
    """Decode one supported constant value from serialized payload data.

    Args:
        value: Primitive or tagged serialized constant representation.
        limits: Payload limits applied while decoding.
        depth: Current recursive constant/code nesting depth.

    Returns:
        A decoded primitive, bytes, tuple, frozenset, or nested code object.

    Raises:
        ValueError: If nesting exceeds limits or the constant representation is
            malformed, out of bounds, or unsupported.
    """
    if depth > limits.max_depth:
        raise ValueError("constant nesting exceeds limit")
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return validate_int_constant(value, f"const[{depth}]", limits=limits)
    if isinstance(value, float):
        return validate_float_constant(value, f"const[{depth}]")
    if isinstance(value, str):
        return require_json_str(value, f"const[{depth}]", max_length=limits.max_string_length)

    data = require_json_object(value, f"const[{depth}]")
    kind = require_json_str(data.get("kind"), f"const[{depth}].kind", max_length=64)
    if kind == "code":
        return reconstruct_code_obj(data, limits=limits, depth=depth)
    if kind == "bytes":
        reject_unexpected_fields(data, BYTES_CONST_KEYS, f"const[{depth}]")
        return decode_base64_bytes(
            data["data"],
            f"const[{depth}].data",
            max_bytes=limits.max_payload_bytes,
            limits=limits,
        )
    if kind == "tuple":
        reject_unexpected_fields(data, SEQUENCE_CONST_KEYS, f"const[{depth}]")
        return tuple(
            _reconstruct_const(item, limits=limits, depth=depth + 1)
            for item in require_json_list(data["items"], f"const[{depth}].items", limits.max_consts)
        )
    if kind == "frozenset":
        reject_unexpected_fields(data, SEQUENCE_CONST_KEYS, f"const[{depth}]")
        return frozenset(
            _reconstruct_const(item, limits=limits, depth=depth + 1)
            for item in require_json_list(data["items"], f"const[{depth}].items", limits.max_consts)
        )
    raise ValueError(f"const[{depth}]: unsupported constant kind {kind!r}")


def decode_optional_const_tuple(
    value: object,
    context: str,
    *,
    limits: ExtractionLimits,
) -> tuple[object, ...] | None:
    """Decode an optional serialized sequence of supported constants.

    Args:
        value: Serialized constant list, or `None`.
        context: Context prefix used in validation failure messages.
        limits: Payload limits applied while decoding.

    Returns:
        A tuple of decoded constants, or `None` when `value` is `None`.

    Raises:
        ValueError: If the sequence or any nested constant is invalid.
    """
    if value is None:
        return None
    return tuple(
        _reconstruct_const(item, limits=limits, depth=1)
        for item in require_json_list(value, context, limits.max_consts)
    )


def decode_const_mapping(
    value: object,
    context: str,
    *,
    limits: ExtractionLimits,
) -> dict[str, object]:
    """Decode a bounded JSON mapping whose values are supported constants.

    Args:
        value: Serialized object mapping names to constant representations.
        context: Context prefix used in validation failure messages.
        limits: Payload limits applied to keys and decoded values.

    Returns:
        A mapping of the original keys to decoded constant values.

    Raises:
        ValueError: If the mapping exceeds limits or contains invalid values.
    """
    raw = require_json_object(value, context)
    decoded: dict[str, object] = {}
    if len(raw) > limits.max_names:
        raise ValueError(f"{context}: mapping exceeds limit")
    for key, item in raw.items():
        if len(key) > limits.max_name_length:
            raise ValueError(f"{context}: key exceeds limit")
        decoded[key] = _reconstruct_const(item, limits=limits, depth=1)
    return decoded


def decode_optional_const_mapping(
    value: object,
    context: str,
    *,
    limits: ExtractionLimits,
) -> dict[str, object] | None:
    """Decode a serialized constant mapping when one is present.

    Args:
        value: Serialized mapping, or `None`.
        context: Context prefix used in validation failure messages.
        limits: Payload limits applied while decoding.

    Returns:
        A decoded constant mapping, or `None` when `value` is `None`.

    Raises:
        ValueError: If a present mapping fails `decode_const_mapping`.
    """
    if value is None:
        return None
    return decode_const_mapping(value, context, limits=limits)
