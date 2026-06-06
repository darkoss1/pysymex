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

from pysymex.config import is_object_list
from pysymex.sandbox.bridge.blobs import BytecodeBlob
from pysymex.sandbox.bridge.blobs import ConcreteResult
from pysymex.sandbox.bridge.blobs import FunctionBlob
from pysymex.sandbox.bridge.blobs import ModuleBlob
from pysymex.sandbox.bridge.payloads import (
    reconstruct_code_from_payload,
)
from pysymex.sandbox.bridge.payloads import (
    reconstruct_function_from_payload,
)
from pysymex.sandbox.bridge.schema import DEFAULT_EXTRACTION_LIMITS
from pysymex.sandbox.bridge.schema import EXTRACTION_SCHEMA_VERSION
from pysymex.sandbox.bridge.schema import ExtractionLimits
from pysymex.sandbox.bridge.schema import normalize_mapping
from pysymex.sandbox.bridge.serialization import create_bytecode_payload
from pysymex.sandbox.bridge.serialization import create_function_payload
from pysymex.sandbox.bridge.serialization import serialize_code_metadata
from pysymex.sandbox.bridge.serialization import (
    serialize_safe_annotation,
)
from pysymex.sandbox.bridge.serialization import serialize_safe_constant

__all__ = [
    "BytecodeBlob",
    "ConcreteResult",
    "DEFAULT_EXTRACTION_LIMITS",
    "EXTRACTION_SCHEMA_VERSION",
    "ExtractionLimits",
    "FunctionBlob",
    "ModuleBlob",
    "create_bytecode_payload",
    "create_function_payload",
    "is_object_list",
    "normalize_mapping",
    "reconstruct_code_from_payload",
    "reconstruct_function_from_payload",
    "serialize_code_metadata",
    "serialize_safe_annotation",
    "serialize_safe_constant",
]
