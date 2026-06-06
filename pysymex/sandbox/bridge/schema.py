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
import binascii
import math
import opcode
from dataclasses import dataclass
from typing import Final

from pysymex.config import is_object_list, is_object_mapping

EXTRACTION_SCHEMA_VERSION: Final[int] = 1

TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "kind",
        "producer",
        "module",
        "targets",
        "diagnostics",
    }
)
MODULETOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "kind",
        "producer",
        "module",
        "targets",
        "diagnostics",
    }
)
PRODUCER_KEYS: Final[frozenset[str]] = frozenset({"python_implementation", "python_version"})
CODE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "kind",
        "argcount",
        "posonlyargcount",
        "kwonlyargcount",
        "nlocals",
        "stacksize",
        "flags",
        "code",
        "consts",
        "names",
        "varnames",
        "freevars",
        "cellvars",
        "filename",
        "name",
        "qualname",
        "firstlineno",
        "linetable",
        "exceptiontable",
    }
)
BYTES_CONST_KEYS: Final[frozenset[str]] = frozenset({"kind", "data"})
SEQUENCE_CONST_KEYS: Final[frozenset[str]] = frozenset({"kind", "items"})
DIAGNOSTIC_KEYS: Final[frozenset[str]] = frozenset({"level", "message"})
FUNCTIONTOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "kind",
        "producer",
        "target_name",
        "target",
        "diagnostics",
    }
)
FUNCTION_TARGET_KEYS: Final[frozenset[str]] = frozenset(
    {
        "kind",
        "name",
        "qualname",
        "module",
        "code",
        "defaults",
        "kwdefaults",
        "annotations",
        "closure",
        "globals",
        "contract",
        "diagnostics",
    }
)
FUNCTION_CONTRACT_KEYS: Final[frozenset[str]] = frozenset(
    {"function_name", "preconditions", "postconditions"}
)
FUNCTION_CONTRACT_CLAUSE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "kind",
        "predicate_kind",
        "predicate",
        "condition",
        "message",
        "severity",
        "line_number",
    }
)


@dataclass(frozen=True, slots=True)
class ExtractionLimits:
    """Host-side limits for untrusted sandbox extraction payloads."""

    max_payload_bytes: int = 10 * 1024 * 1024
    max_code_bytes: int = 2 * 1024 * 1024
    max_linetable_bytes: int = 2 * 1024 * 1024
    max_consts: int = 8192
    max_names: int = 4096
    max_string_length: int = 1 * 1024 * 1024
    max_name_length: int = 4096
    max_depth: int = 64
    max_int_bits: int = 4096


DEFAULT_EXTRACTION_LIMITS: Final[ExtractionLimits] = ExtractionLimits()


@dataclass(frozen=True, slots=True)
class UnsupportedSandboxCallableContract:
    """Contract predicate that cannot be parsed or verified."""

    condition: str

    def __repr__(self) -> str:
        """Return the user-friendly string representation of the unsupported contract."""
        return f"unsupported sandbox callable contract {self.condition!r}"


def normalize_mapping(value: object) -> dict[str, object] | None:
    """Convert a generic mapping-like object into ``dict[str, object]``."""
    if not is_object_mapping(value):
        return None
    normalized: dict[str, object] = {}
    for key, item in value.items():
        normalized[str(key)] = item
    return normalized


def require_json_object(value: object, context: str) -> dict[str, object]:
    """Return ``value`` as a JSON object or raise ``ValueError``."""
    normalized = normalize_mapping(value)
    if normalized is None:
        raise ValueError(f"{context}: expected JSON object")
    return normalized


def require_json_list(value: object, context: str, max_items: int) -> list[object]:
    """Return ``value`` as a bounded JSON list or raise ``ValueError``."""
    if not is_object_list(value):
        raise ValueError(f"{context}: expected JSON list")
    if len(value) > max_items:
        raise ValueError(f"{context}: list exceeds limit")
    return value


def require_json_str(
    value: object,
    context: str,
    *,
    max_length: int,
) -> str:
    """Return ``value`` as a bounded JSON string or raise ``ValueError``."""
    if not isinstance(value, str):
        raise ValueError(f"{context}: expected JSON string")
    if len(value) > max_length:
        raise ValueError(f"{context}: string exceeds limit")
    return value


def require_json_int(value: object, context: str, *, minimum: int | None = None) -> int:
    """Return ``value`` as a JSON integer within bounds or raise ``ValueError``."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{context}: expected JSON integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{context}: integer below minimum")
    return value


def reject_unexpected_fields(
    mapping: dict[str, object],
    expected: frozenset[str],
    context: str,
) -> None:
    """Reject keys outside the expected schema field set."""
    unexpected = sorted(set(mapping) - set(expected))
    if unexpected:
        raise ValueError(f"{context}: unexpected field(s): {', '.join(unexpected)}")


def decode_base64_bytes(
    value: object,
    context: str,
    *,
    max_bytes: int,
    limits: ExtractionLimits,
) -> bytes:
    """Decode a bounded base64 JSON string into raw bytes."""
    text = require_json_str(value, context, max_length=limits.max_string_length)
    try:
        decoded = base64.b64decode(text.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError(f"{context}: invalid base64 data") from exc
    if len(decoded) > max_bytes:
        raise ValueError(f"{context}: decoded bytes exceed limit")
    return decoded


def decode_str_tuple(
    value: object,
    context: str,
    *,
    limits: ExtractionLimits,
) -> tuple[str, ...]:
    """Decode a bounded JSON string list into a tuple."""
    items = require_json_list(value, context, limits.max_names)
    decoded: list[str] = []
    for index, item in enumerate(items):
        decoded.append(
            require_json_str(
                item,
                f"{context}[{index}]",
                max_length=limits.max_name_length,
            )
        )
    return tuple(decoded)


def validate_int_constant(value: int, context: str, *, limits: ExtractionLimits) -> int:
    """Return an integer constant after enforcing the bit-length limit."""
    if value.bit_length() > limits.max_int_bits:
        raise ValueError(f"{context}: integer constant exceeds bit-length limit")
    return value


def validate_float_constant(value: float, context: str) -> float:
    """Return a finite float constant or raise ``ValueError``."""
    if not math.isfinite(value):
        raise ValueError(f"{context}: non-finite float constant is not allowed")
    return value


def validate_bytecode_bytes(code: bytes, context: str) -> None:
    """Validate Python wordcode length and opcode byte values."""
    if len(code) % 2 != 0:
        raise ValueError(f"{context}: Python wordcode length must be even")
    max_opcode = len(opcode.opname) - 1
    for offset in range(0, len(code), 2):
        op = code[offset]
        if op > max_opcode or opcode.opname[op].startswith("<"):
            raise ValueError(f"{context}: invalid opcode byte at offset {offset}")


def validate_diagnostics(value: object, *, limits: ExtractionLimits) -> tuple[str, ...]:
    """Parse and validate diagnostic entries returned by a sandbox worker."""
    raw = require_json_list(value, "diagnostics", 1024)
    diagnostics: list[str] = []
    for index, item in enumerate(raw):
        if isinstance(item, str):
            diagnostics.append(
                require_json_str(
                    item,
                    f"diagnostics[{index}]",
                    max_length=limits.max_string_length,
                )
            )
            continue
        data = require_json_object(item, f"diagnostics[{index}]")
        reject_unexpected_fields(data, DIAGNOSTIC_KEYS, f"diagnostics[{index}]")
        level = require_json_str(
            data["level"],
            f"diagnostics[{index}].level",
            max_length=32,
        )
        message = require_json_str(
            data["message"],
            f"diagnostics[{index}].message",
            max_length=limits.max_string_length,
        )
        diagnostics.append(f"{level}: {message}")
    return tuple(diagnostics)


def producer_python_version(
    producer: dict[str, object],
    *,
    limits: ExtractionLimits,
) -> tuple[int, int, int]:
    """Parse and validate sandbox CPython producer version metadata."""
    reject_unexpected_fields(producer, PRODUCER_KEYS, "producer")
    implementation = require_json_str(
        producer["python_implementation"],
        "producer.python_implementation",
        max_length=64,
    )
    if implementation.lower() != "cpython":
        raise ValueError("Sandbox bytecode producer must be CPython")
    version_items = require_json_list(producer["python_version"], "producer.python_version", 3)
    if len(version_items) != 3:
        raise ValueError("producer.python_version must contain major, minor, micro")
    _ = limits
    return (
        require_json_int(version_items[0], "producer.python_version[0]", minimum=0),
        require_json_int(version_items[1], "producer.python_version[1]", minimum=0),
        require_json_int(version_items[2], "producer.python_version[2]", minimum=0),
    )
