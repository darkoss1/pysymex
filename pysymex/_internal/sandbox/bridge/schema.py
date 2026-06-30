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

from pysymex._internal.config.values import ConfigValues

EXTRACTION_SCHEMA_VERSION: Final[int] = 1

TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    (
        "schema_version",
        "kind",
        "producer",
        "module",
        "targets",
        "diagnostics",
    ),
)
MODULETOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    (
        "schema_version",
        "kind",
        "producer",
        "module",
        "targets",
        "diagnostics",
    ),
)
PRODUCER_KEYS: Final[frozenset[str]] = frozenset(("python_implementation", "python_version"))
CODE_KEYS: Final[frozenset[str]] = frozenset(
    (
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
    ),
)
BYTES_CONST_KEYS: Final[frozenset[str]] = frozenset(("kind", "data"))
SEQUENCE_CONST_KEYS: Final[frozenset[str]] = frozenset(("kind", "items"))
FUNCTION_GLOBAL_CONST_KEYS: Final[frozenset[str]] = frozenset(
    (
        "kind",
        "name",
        "qualname",
        "module",
        "code",
        "defaults",
        "kwdefaults",
        "annotations",
        "closure",
    ),
)
DIAGNOSTIC_KEYS: Final[frozenset[str]] = frozenset(("level", "message"))
FUNCTIONTOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    (
        "schema_version",
        "kind",
        "producer",
        "target_name",
        "target",
        "diagnostics",
    ),
)
FUNCTION_TARGET_KEYS: Final[frozenset[str]] = frozenset(
    (
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
    ),
)
FUNCTION_CONTRACT_KEYS: Final[frozenset[str]] = frozenset(
    ("function_name", "preconditions", "postconditions"),
)
FUNCTION_CONTRACT_CLAUSE_KEYS: Final[frozenset[str]] = frozenset(
    (
        "kind",
        "predicate_kind",
        "predicate",
        "condition",
        "message",
        "severity",
        "line_number",
    ),
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
class UnsupportedSandboxCallable:
    """Contract predicate that cannot be parsed or verified."""

    condition: str

    def __repr__(self) -> str:
        """Return the user-friendly string representation of the unsupported contract."""
        return f"unsupported sandbox callable contract {self.condition!r}"


def _normalize_mapping(value: object) -> dict[str, object] | None:
    """Convert a generic mapping-like object into ``dict[str, object]``."""
    if not ConfigValues.is_object_mapping(value):
        return None
    normalized: dict[str, object] = {}
    for key, item in value.items():
        normalized[str(key)] = item
    return normalized


def _require_object(value: object, context: str) -> dict[str, object]:
    """Return ``value`` as a JSON object or raise ``ValueError``."""
    normalized = SandboxSchema.mapping(value)
    if normalized is None:
        msg = f"{context}: expected JSON object"
        raise ValueError(msg)
    return normalized


def _require_list(value: object, context: str, max_items: int) -> list[object]:
    """Return ``value`` as a bounded JSON list or raise ``ValueError``."""
    if not ConfigValues.is_object_list(value):
        msg = f"{context}: expected JSON list"
        raise ValueError(msg)
    if len(value) > max_items:
        msg = f"{context}: list exceeds limit"
        raise ValueError(msg)
    return value


def _require_str(
    value: object,
    context: str,
    *,
    max_length: int,
) -> str:
    """Return ``value`` as a bounded JSON string or raise ``ValueError``."""
    if not isinstance(value, str):
        msg = f"{context}: expected JSON string"
        raise ValueError(msg)
    if len(value) > max_length:
        msg = f"{context}: string exceeds limit"
        raise ValueError(msg)
    return value


def _require_int(value: object, context: str, *, minimum: int | None = None) -> int:
    """Return ``value`` as a JSON integer within bounds or raise ``ValueError``."""
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"{context}: expected JSON integer"
        raise ValueError(msg)
    if minimum is not None and value < minimum:
        msg = f"{context}: integer below minimum"
        raise ValueError(msg)
    return value


def _reject_unexpected(
    mapping: dict[str, object],
    expected: frozenset[str],
    context: str,
) -> None:
    """Reject keys outside the expected schema field set."""
    unexpected = sorted(set(mapping) - set(expected))
    if unexpected:
        msg = f"{context}: unexpected field(s): {', '.join(unexpected)}"
        raise ValueError(msg)


def decode_base64_bytes(
    value: object,
    context: str,
    *,
    max_bytes: int,
    limits: ExtractionLimits,
) -> bytes:
    """Decode a bounded base64 JSON string into raw bytes."""
    text = SandboxSchema.str(value, context, max_length=limits.max_string_length)
    try:
        decoded = base64.b64decode(text.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        msg = f"{context}: invalid base64 data"
        raise ValueError(msg) from exc
    if len(decoded) > max_bytes:
        msg = f"{context}: decoded bytes exceed limit"
        raise ValueError(msg)
    return decoded


def decode_str_tuple(
    value: object,
    context: str,
    *,
    limits: ExtractionLimits,
) -> tuple[str, ...]:
    """Decode a bounded JSON string list into a tuple."""
    items = SandboxSchema.list(value, context, limits.max_names)
    decoded: list[str] = []
    for index, item in enumerate(items):
        decoded.append(
            SandboxSchema.str(
                item,
                f"{context}[{index}]",
                max_length=limits.max_name_length,
            ),
        )
    return tuple(decoded)


def validate_int_constant(value: int, context: str, *, limits: ExtractionLimits) -> int:
    """Return an integer constant after enforcing the bit-length limit."""
    if value.bit_length() > limits.max_int_bits:
        msg = f"{context}: integer constant exceeds bit-length limit"
        raise ValueError(msg)
    return value


def validate_float_constant(value: float, context: str) -> float:
    """Return a finite float constant or raise ``ValueError``."""
    if not math.isfinite(value):
        msg = f"{context}: non-finite float constant is not allowed"
        raise ValueError(msg)
    return value


def validate_bytecode_bytes(code: bytes, context: str) -> None:
    """Validate Python wordcode length and opcode byte values."""
    if len(code) % 2 != 0:
        msg = f"{context}: Python wordcode length must be even"
        raise ValueError(msg)
    max_opcode = len(opcode.opname) - 1
    for offset in range(0, len(code), 2):
        op = code[offset]
        if op > max_opcode or opcode.opname[op].startswith("<"):
            msg = f"{context}: invalid opcode byte at offset {offset}"
            raise ValueError(msg)


def validate_diagnostics(value: object, *, limits: ExtractionLimits) -> tuple[str, ...]:
    """Parse and validate diagnostic entries returned by a sandbox worker."""
    raw = SandboxSchema.list(value, "diagnostics", 1024)
    diagnostics: list[str] = []
    for index, item in enumerate(raw):
        if isinstance(item, str):
            diagnostics.append(
                SandboxSchema.str(
                    item,
                    f"diagnostics[{index}]",
                    max_length=limits.max_string_length,
                ),
            )
            continue
        data = SandboxSchema.object(item, f"diagnostics[{index}]")
        SandboxSchema.reject_unexpected(data, DIAGNOSTIC_KEYS, f"diagnostics[{index}]")
        level = SandboxSchema.str(
            data["level"],
            f"diagnostics[{index}].level",
            max_length=32,
        )
        message = SandboxSchema.str(
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
    SandboxSchema.reject_unexpected(producer, PRODUCER_KEYS, "producer")
    implementation = SandboxSchema.str(
        producer["python_implementation"],
        "producer.python_implementation",
        max_length=64,
    )
    if implementation.lower() != "cpython":
        msg = "Sandbox bytecode producer must be CPython"
        raise ValueError(msg)
    version_items = SandboxSchema.list(producer["python_version"], "producer.python_version", 3)
    if len(version_items) != 3:
        msg = "producer.python_version must contain major, minor, micro"
        raise ValueError(msg)
    _ = limits
    return (
        SandboxSchema.int(version_items[0], "producer.python_version[0]", minimum=0),
        SandboxSchema.int(version_items[1], "producer.python_version[1]", minimum=0),
        SandboxSchema.int(version_items[2], "producer.python_version[2]", minimum=0),
    )


class SandboxSchema:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    mapping = staticmethod(_normalize_mapping)
    object = staticmethod(_require_object)
    list = staticmethod(_require_list)
    str = staticmethod(_require_str)
    int = staticmethod(_require_int)
    reject_unexpected = staticmethod(_reject_unexpected)
