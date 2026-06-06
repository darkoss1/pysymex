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
from dataclasses import dataclass
from types import CodeType, FunctionType

from pysymex.sandbox.bridge.codecs import reconstruct_code_obj
from pysymex.sandbox.bridge.payloads import (
    parse_module_payload,
    reconstruct_code_from_payload,
    reconstruct_function_from_payload,
)
from pysymex.sandbox.bridge.schema import (
    DEFAULT_EXTRACTION_LIMITS,
    EXTRACTION_SCHEMA_VERSION,
    ExtractionLimits,
    require_json_object,
    validate_diagnostics,
)


@dataclass(slots=True)
class ConcreteResult:
    """Result captured from one sandboxed concrete function invocation.

    Attributes:
        succeeded: Whether the target call completed with a serializable return
            value.
        return_value: Decoded target return value on success.
        exception_type: Captured target exception type name on failure.
        exception_message: Captured target exception message on failure.
        traceback: Captured worker traceback text on failure.
        stdout: Non-protocol standard output emitted by worker execution.
        stderr: Decoded standard error emitted by worker execution.
    """

    succeeded: bool
    return_value: object | None = None
    exception_type: str | None = None
    exception_message: str | None = None
    traceback: str | None = None
    stdout: str = ""
    stderr: str = ""


@dataclass(slots=True, frozen=True)
class BytecodeBlob:
    """Serialized module-bytecode payload and validation context.

    Attributes:
        payload: Serialized extraction payload returned by a sandbox worker.
        filename: Filename required in reconstructed code metadata.
        producer_python: Optional expected host Python major/minor version.
        limits: Validation limits applied during reconstruction.
    """

    payload: bytes
    filename: str
    producer_python: tuple[int, int] | None = None
    limits: ExtractionLimits = DEFAULT_EXTRACTION_LIMITS

    def reconstruct(self) -> CodeType:
        """Validate the stored payload and reconstruct its module code object.

        Returns:
            A reconstructed `CodeType` with matching filename and Python
            version metadata.

        Raises:
            ValueError: If payload structure, size, schema, version, filename,
                or nested code metadata is invalid.
        """
        return reconstruct_code_from_payload(
            self.payload,
            expected_filename=self.filename,
            producer_python=self.producer_python,
            limits=self.limits,
        )


@dataclass(slots=True, frozen=True)
class FunctionBlob:
    """Serialized target-function payload and validation context.

    Attributes:
        payload: Serialized extraction payload returned by a sandbox worker.
        filename: Filename required in reconstructed function code metadata.
        function_name: Target name required in payload metadata.
        limits: Validation limits applied during reconstruction.
    """

    payload: bytes
    filename: str
    function_name: str
    limits: ExtractionLimits = DEFAULT_EXTRACTION_LIMITS

    def reconstruct(self) -> FunctionType:
        """Validate the payload and reconstruct its requested Python function.

        Returns:
            A reconstructed function with validated code and captured metadata.

        Raises:
            ValueError: If payload validation or function reconstruction fails.
        """
        return reconstruct_function_from_payload(
            self.payload,
            expected_filename=self.filename,
            expected_target_name=self.function_name,
            limits=self.limits,
        )


@dataclass(slots=True, frozen=True)
class ModuleBlob:
    """Serialized module extraction payload with target-function metadata.

    Attributes:
        payload: Serialized module payload returned by a sandbox worker.
        filename: Filename required in reconstructed module/function metadata.
        limits: Validation limits applied before reconstruction or lookup.
    """

    payload: bytes
    filename: str
    limits: ExtractionLimits = DEFAULT_EXTRACTION_LIMITS

    def reconstruct_module(self) -> CodeType:
        """Validate the stored module payload and reconstruct module code.

        Returns:
            A reconstructed module-level code object.

        Raises:
            ValueError: If module payload or filename metadata validation fails.
        """
        top = parse_module_payload(
            self.payload, expected_filename=self.filename, limits=self.limits
        )
        code_obj = reconstruct_code_obj(top["module"], limits=self.limits, depth=0)
        if code_obj.co_filename != self.filename:
            raise ValueError("Sandbox module payload filename metadata mismatch")
        return code_obj

    def function_names(self) -> tuple[str, ...]:
        """Return sorted serialized target names after validating the payload.

        Returns:
            A sorted tuple of function target names in the module payload.

        Raises:
            ValueError: If module validation fails or target count exceeds the
                configured extraction limit.
        """
        top = parse_module_payload(
            self.payload, expected_filename=self.filename, limits=self.limits
        )
        targets = require_json_object(top["targets"], "targets")
        if len(targets) > self.limits.max_names:
            raise ValueError("targets: mapping exceeds limit")
        return tuple(sorted(targets))

    def get_function(self, function_name: str) -> FunctionType:
        """Reconstruct one named serialized target function.

        Args:
            function_name: Target function key to look up in this payload.

        Returns:
            A reconstructed Python function.

        Raises:
            ValueError: If payload validation, lookup, or reconstruction fails.
        """
        return self.get_function_blob(function_name).reconstruct()

    def get_function_blob(self, function_name: str) -> FunctionBlob:
        """Create a function payload wrapper for one named module target.

        Args:
            function_name: Target function key to look up in this payload.

        Returns:
            A `FunctionBlob` containing the selected target and inherited
            producer and diagnostic metadata.

        Raises:
            ValueError: If module validation fails, too many targets are
                encoded, or `function_name` is absent from the target mapping.
        """
        top = parse_module_payload(
            self.payload, expected_filename=self.filename, limits=self.limits
        )
        targets = require_json_object(top["targets"], "targets")
        if len(targets) > self.limits.max_names:
            raise ValueError("targets: mapping exceeds limit")
        target = targets.get(function_name)
        if target is None:
            diagnostics = validate_diagnostics(top["diagnostics"], limits=self.limits)
            related = tuple(item for item in diagnostics if function_name in item)
            if related:
                raise ValueError(
                    f"Function '{function_name}' not found in sandbox module payload; "
                    f"diagnostics: {'; '.join(related)}"
                )
            raise ValueError(f"Function '{function_name}' not found in sandbox module payload")
        payload = {
            "schema_version": EXTRACTION_SCHEMA_VERSION,
            "kind": "pysymex.function",
            "producer": top["producer"],
            "target_name": function_name,
            "target": target,
            "diagnostics": top["diagnostics"],
        }
        return FunctionBlob(
            payload=json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8"),
            filename=self.filename,
            function_name=function_name,
            limits=self.limits,
        )
