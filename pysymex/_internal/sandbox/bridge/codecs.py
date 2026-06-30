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
from dataclasses import dataclass
from types import CodeType

from pysymex._internal.sandbox.bridge.schema import (
    BYTES_CONST_KEYS,
    CODE_KEYS,
    FUNCTION_GLOBAL_CONST_KEYS,
    SEQUENCE_CONST_KEYS,
    ExtractionLimits,
    SandboxSchema,
    decode_base64_bytes,
    decode_str_tuple,
    validate_bytecode_bytes,
    validate_float_constant,
    validate_int_constant,
)


@dataclass(frozen=True, slots=True)
class DecodedFunctionGlobal:
    """Decoded metadata for a same-module helper function global.

    The actual ``FunctionType`` is built later with the target function's shared
    globals dictionary, so helper functions can call each other and see the same
    safe reconstructed namespace.
    """

    name: str
    qualname: str
    module: str
    code: CodeType
    defaults: tuple[object, ...] | None
    kwdefaults: dict[str, object] | None
    annotations: dict[str, object]
    closure: tuple[object, ...] | None


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
        msg = "code object nesting exceeds limit"
        raise ValueError(msg)

    data = SandboxSchema.object(raw, f"code[{depth}]")
    SandboxSchema.reject_unexpected(data, CODE_KEYS, f"code[{depth}]")

    kind = SandboxSchema.str(data["kind"], f"code[{depth}].kind", max_length=64)
    if kind != "code":
        msg = f"code[{depth}].kind must be 'code'"
        raise ValueError(msg)

    co_argcount = SandboxSchema.int(data["argcount"], f"code[{depth}].argcount", minimum=0)
    co_posonlyargcount = SandboxSchema.int(
        data["posonlyargcount"],
        f"code[{depth}].posonlyargcount",
        minimum=0,
    )
    co_kwonlyargcount = SandboxSchema.int(
        data["kwonlyargcount"],
        f"code[{depth}].kwonlyargcount",
        minimum=0,
    )
    co_nlocals = SandboxSchema.int(data["nlocals"], f"code[{depth}].nlocals", minimum=0)
    co_stacksize = SandboxSchema.int(data["stacksize"], f"code[{depth}].stacksize", minimum=0)
    co_flags = SandboxSchema.int(data["flags"], f"code[{depth}].flags", minimum=0)
    co_code = decode_base64_bytes(
        data["code"],
        f"code[{depth}].code",
        max_bytes=limits.max_code_bytes,
        limits=limits,
    )
    validate_bytecode_bytes(co_code, f"code[{depth}].code")

    co_consts = tuple(
        _reconstruct_const(item, limits=limits, depth=depth + 1)
        for item in SandboxSchema.list(data["consts"], f"code[{depth}].consts", limits.max_consts)
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
    co_filename = SandboxSchema.str(
        data["filename"],
        f"code[{depth}].filename",
        max_length=limits.max_string_length,
    )
    co_name = SandboxSchema.str(
        data["name"],
        f"code[{depth}].name",
        max_length=limits.max_name_length,
    )
    co_qualname = SandboxSchema.str(
        data["qualname"],
        f"code[{depth}].qualname",
        max_length=limits.max_string_length,
    )
    co_firstlineno = SandboxSchema.int(
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
        msg = "Invalid sandbox code object metadata"
        raise ValueError(msg) from exc
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
        msg = "constant nesting exceeds limit"
        raise ValueError(msg)
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return validate_int_constant(value, f"const[{depth}]", limits=limits)
    if isinstance(value, float):
        return validate_float_constant(value, f"const[{depth}]")
    if isinstance(value, str):
        return SandboxSchema.str(value, f"const[{depth}]", max_length=limits.max_string_length)

    data = SandboxSchema.object(value, f"const[{depth}]")
    kind = SandboxSchema.str(data.get("kind"), f"const[{depth}].kind", max_length=64)
    if kind == "code":
        return reconstruct_code_obj(data, limits=limits, depth=depth)
    if kind == "bytes":
        SandboxSchema.reject_unexpected(data, BYTES_CONST_KEYS, f"const[{depth}]")
        return decode_base64_bytes(
            data["data"],
            f"const[{depth}].data",
            max_bytes=limits.max_payload_bytes,
            limits=limits,
        )
    if kind == "tuple":
        SandboxSchema.reject_unexpected(data, SEQUENCE_CONST_KEYS, f"const[{depth}]")
        return tuple(
            _reconstruct_const(item, limits=limits, depth=depth + 1)
            for item in SandboxSchema.list(
                data["items"],
                f"const[{depth}].items",
                limits.max_consts,
            )
        )
    if kind == "frozenset":
        SandboxSchema.reject_unexpected(data, SEQUENCE_CONST_KEYS, f"const[{depth}]")
        return frozenset(
            _reconstruct_const(item, limits=limits, depth=depth + 1)
            for item in SandboxSchema.list(
                data["items"],
                f"const[{depth}].items",
                limits.max_consts,
            )
        )
    if kind == "function_global":
        SandboxSchema.reject_unexpected(data, FUNCTION_GLOBAL_CONST_KEYS, f"const[{depth}]")
        code_obj = reconstruct_code_obj(data["code"], limits=limits, depth=depth + 1)
        defaults = decode_optional_const_tuple(
            data["defaults"],
            f"const[{depth}].defaults",
            limits=limits,
        )
        kwdefaults = decode_optional_const_mapping(
            data["kwdefaults"],
            f"const[{depth}].kwdefaults",
            limits=limits,
        )
        annotations = decode_const_mapping(
            data["annotations"],
            f"const[{depth}].annotations",
            limits=limits,
        )
        closure = decode_optional_const_tuple(
            data["closure"],
            f"const[{depth}].closure",
            limits=limits,
        )
        return DecodedFunctionGlobal(
            name=SandboxSchema.str(
                data["name"],
                f"const[{depth}].name",
                max_length=limits.max_name_length,
            ),
            qualname=SandboxSchema.str(
                data["qualname"],
                f"const[{depth}].qualname",
                max_length=limits.max_string_length,
            ),
            module=SandboxSchema.str(
                data["module"],
                f"const[{depth}].module",
                max_length=limits.max_string_length,
            ),
            code=code_obj,
            defaults=defaults,
            kwdefaults=kwdefaults,
            annotations=annotations,
            closure=closure,
        )
    msg = f"const[{depth}]: unsupported constant kind {kind!r}"
    raise ValueError(msg)


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
        for item in SandboxSchema.list(value, context, limits.max_consts)
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
    raw = SandboxSchema.object(value, context)
    decoded: dict[str, object] = {}
    if len(raw) > limits.max_names:
        msg = f"{context}: mapping exceeds limit"
        raise ValueError(msg)
    for key, item in raw.items():
        if len(key) > limits.max_name_length:
            msg = f"{context}: key exceeds limit"
            raise ValueError(msg)
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
