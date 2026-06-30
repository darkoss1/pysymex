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
import textwrap
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING, Self, cast

from pysymex._internal.config.coercion import ConfigCoercion
from pysymex._internal.config.sandbox.bridge import make_sandbox_config as _make_sandbox_config
from pysymex._internal.config.sandbox.bridge import (
    sandbox_config_fingerprint as _sandbox_config_fingerprint,
)
from pysymex._internal.sandbox.bridge.blobs import BytecodeBlob
from pysymex._internal.sandbox.bridge.errors import sandbox_result_error
from pysymex._internal.sandbox.bridge.schema import EXTRACTION_SCHEMA_VERSION, ExtractionLimits
from pysymex._internal.sandbox.bridge.workers import run_raw_worker as _run_raw_worker

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.sandbox.runner import SandboxRunner

_BYTECODE_MARKER = b"__PYSYMEX_BYTECODE__"
_BYTECODE_SESSION: ContextVar[BytecodeExtractionSession | None] = ContextVar(
    "_BYTECODE_SESSION",
    default=None,
)


def _bytecode_worker_inputs(
    filename: str,
    sandbox_config: Mapping[str, object] | None = None,
) -> tuple[bytes, str, dict[str, object]]:
    """Build the marker, worker script, and sandbox overrides for extraction."""
    import secrets

    dynamic_marker = f"{_BYTECODE_MARKER.decode('utf-8')}_{secrets.token_hex(16)}".encode()

    worker = textwrap.dedent(
        f"""
        import json
        import base64
        import sys

        _source = sys.stdin.buffer.read()
        _code = compile(_source, {filename!r}, "exec")
        def _serialize_code(co):
            d = {{
                "kind": "code",
                "argcount": co.co_argcount,
                "posonlyargcount": getattr(co, "co_posonlyargcount", 0),
                "kwonlyargcount": co.co_kwonlyargcount,
                "nlocals": co.co_nlocals,
                "stacksize": co.co_stacksize,
                "flags": co.co_flags,
                "code": base64.b64encode(co.co_code).decode("ascii"),
                "names": list(co.co_names),
                "varnames": list(co.co_varnames),
                "freevars": list(getattr(co, "co_freevars", [])),
                "cellvars": list(getattr(co, "co_cellvars", [])),
                "filename": co.co_filename,
                "name": co.co_name,
                "qualname": getattr(co, "co_qualname", co.co_name),
                "firstlineno": co.co_firstlineno,
                "linetable": base64.b64encode(getattr(co, "co_linetable", b"")).decode("ascii"),
                "exceptiontable": base64.b64encode(
                    getattr(co, "co_exceptiontable", b"")
                ).decode("ascii"),
            }}

            def _serialize_const(c):
                if isinstance(c, type(co)):
                    return _serialize_code(c)
                if isinstance(c, tuple):
                    return {{"kind": "tuple", "items": [_serialize_const(item) for item in c]}}
                if isinstance(c, frozenset):
                    return {{
                        "kind": "frozenset",
                        "items": [_serialize_const(item) for item in c],
                    }}
                if isinstance(c, bytes):
                    return {{
                        "kind": "bytes",
                        "data": base64.b64encode(c).decode("ascii"),
                    }}
                if isinstance(c, (int, float, str, type(None), bool)):
                    return c
                return None

            d["consts"] = [_serialize_const(c) for c in co.co_consts]
            return d

        _payload = json.dumps(
            {{
                "schema_version": {EXTRACTION_SCHEMA_VERSION!r},
                "kind": "pysymex.bytecode",
                "producer": {{
                    "python_implementation": sys.implementation.name,
                    "python_version": [
                        sys.version_info.major,
                        sys.version_info.minor,
                        sys.version_info.micro,
                    ],
                }},
                "module": _serialize_code(_code),
                "targets": {{}},
                "diagnostics": [],
            }},
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        sys.stdout.buffer.write({dynamic_marker!r} + _payload)
        """,
    ).strip()

    cfg_overrides = dict(sandbox_config or {})
    return dynamic_marker, worker, cfg_overrides


def _bytecode_batch_worker_inputs(
    sandbox_config: Mapping[str, object] | None = None,
) -> tuple[bytes, str, dict[str, object]]:
    """Build the marker, worker script, and sandbox overrides for batch extraction."""
    import secrets

    dynamic_marker = f"{_BYTECODE_MARKER.decode('utf-8')}_{secrets.token_hex(16)}".encode()

    worker = textwrap.dedent(
        f"""
        import json
        import base64
        import sys
        import traceback

        def _serialize_code(co):
            d = {{
                "kind": "code",
                "argcount": co.co_argcount,
                "posonlyargcount": getattr(co, "co_posonlyargcount", 0),
                "kwonlyargcount": co.co_kwonlyargcount,
                "nlocals": co.co_nlocals,
                "stacksize": co.co_stacksize,
                "flags": co.co_flags,
                "code": base64.b64encode(co.co_code).decode("ascii"),
                "names": list(co.co_names),
                "varnames": list(co.co_varnames),
                "freevars": list(getattr(co, "co_freevars", [])),
                "cellvars": list(getattr(co, "co_cellvars", [])),
                "filename": co.co_filename,
                "name": co.co_name,
                "qualname": getattr(co, "co_qualname", co.co_name),
                "firstlineno": co.co_firstlineno,
                "linetable": base64.b64encode(getattr(co, "co_linetable", b"")).decode("ascii"),
                "exceptiontable": base64.b64encode(
                    getattr(co, "co_exceptiontable", b"")
                ).decode("ascii"),
            }}

            def _serialize_const(c):
                if isinstance(c, type(co)):
                    return _serialize_code(c)
                if isinstance(c, tuple):
                    return {{"kind": "tuple", "items": [_serialize_const(item) for item in c]}}
                if isinstance(c, frozenset):
                    return {{
                        "kind": "frozenset",
                        "items": [_serialize_const(item) for item in c],
                    }}
                if isinstance(c, bytes):
                    return {{
                        "kind": "bytes",
                        "data": base64.b64encode(c).decode("ascii"),
                    }}
                if isinstance(c, (int, float, str, type(None), bool)):
                    return c
                return None

            d["consts"] = [_serialize_const(c) for c in co.co_consts]
            return d

        _request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        _results = []
        for _item in _request.get("files", []):
            _filename = str(_item["filename"])
            try:
                _source = base64.b64decode(str(_item["source"]).encode("ascii"))
                _code = compile(_source, _filename, "exec")
                _payload = {{
                    "schema_version": {EXTRACTION_SCHEMA_VERSION!r},
                    "kind": "pysymex.bytecode",
                    "producer": {{
                        "python_implementation": sys.implementation.name,
                        "python_version": [
                            sys.version_info.major,
                            sys.version_info.minor,
                            sys.version_info.micro,
                        ],
                    }},
                    "module": _serialize_code(_code),
                    "targets": {{}},
                    "diagnostics": [],
                }}
                _results.append({{"filename": _filename, "ok": True, "payload": _payload}})
            except Exception as _exc:
                _results.append(
                    {{
                        "filename": _filename,
                        "ok": False,
                        "error": f"{{type(_exc).__name__}}: {{_exc}}",
                        "traceback": traceback.format_exc(),
                    }}
                )

        _payload = json.dumps(
            {{"files": _results}},
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        sys.stdout.buffer.write({dynamic_marker!r} + _payload)
        """,
    ).strip()

    cfg_overrides = dict(sandbox_config or {})
    return dynamic_marker, worker, cfg_overrides


def _bytecode_blob_from_raw(
    raw: bytes,
    dynamic_marker: bytes,
    filename: str,
    cfg_overrides: Mapping[str, object],
) -> BytecodeBlob:
    """Parse worker stdout into a bounded bytecode blob."""
    if not raw.startswith(dynamic_marker):
        from pysymex._internal.sandbox.errors import SandboxProtocolError

        msg = "Sandbox bytecode worker produced no marker"
        raise SandboxProtocolError(msg)
    payload = raw[len(dynamic_marker) :]
    from pysymex._internal.config.sandbox.types import SandboxResourceLimits

    default_limits = SandboxResourceLimits()
    max_result_bytes = ConfigCoercion.to_int(
        cfg_overrides.get("max_result_bytes", default_limits.max_result_bytes),
        default_limits.max_result_bytes,
    )
    if len(payload) > max_result_bytes:
        from pysymex._internal.sandbox.errors import SandboxResourceError

        msg = "Sandbox bytecode payload exceeds configured result size limit"
        raise SandboxResourceError(msg)
    return BytecodeBlob(
        payload=payload,
        filename=filename,
        limits=ExtractionLimits(max_payload_bytes=max_result_bytes),
    )


def _max_result_bytes(cfg_overrides: Mapping[str, object]) -> int:
    """Return the configured maximum extraction payload size."""
    from pysymex._internal.config.sandbox.types import SandboxResourceLimits

    default_limits = SandboxResourceLimits()
    return ConfigCoercion.to_int(
        cfg_overrides.get("max_result_bytes", default_limits.max_result_bytes),
        default_limits.max_result_bytes,
    )


def _bytecode_blobs_from_batch_raw(
    raw: bytes,
    dynamic_marker: bytes,
    cfg_overrides: Mapping[str, object],
) -> dict[str, BytecodeBlob]:
    """Parse a batch worker stdout payload into bytecode blobs keyed by filename."""
    if not raw.startswith(dynamic_marker):
        from pysymex._internal.sandbox.errors import SandboxProtocolError

        msg = "Sandbox bytecode worker produced no marker"
        raise SandboxProtocolError(msg)
    payload = raw[len(dynamic_marker) :]
    max_result_bytes = _max_result_bytes(cfg_overrides)
    if len(payload) > max_result_bytes:
        from pysymex._internal.sandbox.errors import SandboxResourceError

        msg = "Sandbox bytecode batch payload exceeds configured result size limit"
        raise SandboxResourceError(msg)
    try:
        parsed: object = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        from pysymex._internal.sandbox.errors import SandboxProtocolError

        msg = "Sandbox bytecode worker produced malformed batch payload"
        raise SandboxProtocolError(msg) from exc
    if not isinstance(parsed, dict):
        from pysymex._internal.sandbox.errors import SandboxProtocolError

        msg = "Sandbox bytecode worker produced non-object batch payload"
        raise SandboxProtocolError(msg)
    parsed_obj = cast("dict[str, object]", parsed)
    files_obj = parsed_obj.get("files")
    if not isinstance(files_obj, list):
        from pysymex._internal.sandbox.errors import SandboxProtocolError

        msg = "Sandbox bytecode worker produced no batch file list"
        raise SandboxProtocolError(msg)

    file_items = cast("list[object]", files_obj)
    blobs: dict[str, BytecodeBlob] = {}
    for item in file_items:
        if not isinstance(item, dict):
            from pysymex._internal.sandbox.errors import SandboxProtocolError

            msg = "Sandbox bytecode worker produced malformed file result"
            raise SandboxProtocolError(msg)
        item_obj = cast("dict[str, object]", item)
        filename_obj = item_obj.get("filename")
        if not isinstance(filename_obj, str):
            from pysymex._internal.sandbox.errors import SandboxProtocolError

            msg = "Sandbox bytecode worker produced file result without filename"
            raise SandboxProtocolError(msg)
        if item_obj.get("ok") is False:
            continue
        payload_obj = item_obj.get("payload")
        if not isinstance(payload_obj, dict):
            from pysymex._internal.sandbox.errors import SandboxProtocolError

            msg = "Sandbox bytecode worker produced file result without payload"
            raise SandboxProtocolError(msg)
        item_payload = json.dumps(
            payload_obj,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(item_payload) > max_result_bytes:
            from pysymex._internal.sandbox.errors import SandboxResourceError

            msg = "Sandbox bytecode payload exceeds configured result size limit"
            raise SandboxResourceError(msg)
        blobs[filename_obj] = BytecodeBlob(
            payload=item_payload,
            filename=filename_obj,
            limits=ExtractionLimits(max_payload_bytes=max_result_bytes),
        )
    return blobs


class BytecodeExtractionSession:
    """Scoped, non-thread-safe sandbox reuse for bytecode extraction."""

    def __init__(self, sandbox_config: Mapping[str, object] | None = None) -> None:
        """Initialize the extraction session configuration."""
        _marker, _worker, cfg_overrides = _bytecode_worker_inputs(
            "_pysymex_session_probe.py",
            sandbox_config,
        )
        self._cfg_overrides = cfg_overrides
        self._config_fingerprint = _sandbox_config_fingerprint(cfg_overrides)
        self._sandbox: SandboxRunner | None = None
        self._token: Token[BytecodeExtractionSession | None] | None = None

    def __enter__(self) -> Self:
        """Initialize and enter the sandbox process."""
        from pysymex._internal.sandbox.runner import SecureSandbox

        sandbox = SecureSandbox(_make_sandbox_config(self._cfg_overrides))
        sandbox.__enter__()
        self._sandbox = sandbox
        self._token = _BYTECODE_SESSION.set(self)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Clean up the sandbox process and reset context state."""
        token = self._token
        sandbox = self._sandbox
        self._token = None
        self._sandbox = None
        if token is not None:
            _BYTECODE_SESSION.reset(token)
        if sandbox is not None:
            sandbox.__exit__(exc_type, exc_val, exc_tb)

    def matches(self, cfg_overrides: Mapping[str, object]) -> bool:
        """Return whether the session matches the requested sandbox overrides."""
        return self._config_fingerprint == _sandbox_config_fingerprint(cfg_overrides)

    def run_raw_worker(self, worker_script: str, *, input_data: bytes | None = None) -> bytes:
        """Execute a worker script in the active sandbox and return stdout."""
        sandbox = self._sandbox
        if sandbox is None:
            from pysymex._internal.sandbox.errors import SandboxSetupError

            msg = "Sandbox bytecode extraction session is not active"
            raise SandboxSetupError(msg)
        sandbox.reset_workspace()
        result = sandbox.execute_code(
            worker_script,
            filename="_pysymex_sandbox_worker.py",
            input_data=input_data,
        )
        sandbox.reset_workspace()
        if not result.succeeded:
            raise sandbox_result_error(
                result,
                _make_sandbox_config(self._cfg_overrides),
                "Sandbox bytecode worker failed",
            )
        return result.stdout


def bytecode_extraction_session(
    sandbox_config: Mapping[str, object] | None = None,
) -> BytecodeExtractionSession:
    """Create a scoped sandbox session for repeated bytecode extraction."""
    return BytecodeExtractionSession(sandbox_config)


def extract_bytecode(
    source: bytes,
    filename: str,
    sandbox_config: Mapping[str, object] | None = None,
) -> BytecodeBlob:
    """Compile and extract bytecode from source bytes in a sandbox."""
    dynamic_marker, worker, cfg_overrides = _bytecode_worker_inputs(filename, sandbox_config)
    active_session = _BYTECODE_SESSION.get()
    if active_session is not None and active_session.matches(cfg_overrides):
        raw = active_session.run_raw_worker(worker, input_data=source)
        return _bytecode_blob_from_raw(raw, dynamic_marker, filename, cfg_overrides)
    raw = _run_raw_worker(
        worker,
        sandbox_config=cfg_overrides,
        input_data=source,
    )
    return _bytecode_blob_from_raw(raw, dynamic_marker, filename, cfg_overrides)


def extract_bytecode_batch(
    sources: Mapping[str, bytes],
    sandbox_config: Mapping[str, object] | None = None,
) -> dict[str, BytecodeBlob]:
    """Compile and extract bytecode for multiple source files in one sandbox worker."""
    if not sources:
        return {}
    dynamic_marker, worker, cfg_overrides = _bytecode_batch_worker_inputs(sandbox_config)
    request = {
        "files": [
            {
                "filename": filename,
                "source": base64.b64encode(source).decode("ascii"),
            }
            for filename, source in sources.items()
        ],
    }
    request_bytes = json.dumps(
        request,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    active_session = _BYTECODE_SESSION.get()
    if active_session is not None and active_session.matches(cfg_overrides):
        raw = active_session.run_raw_worker(worker, input_data=request_bytes)
        return _bytecode_blobs_from_batch_raw(raw, dynamic_marker, cfg_overrides)
    raw = _run_raw_worker(
        worker,
        sandbox_config=cfg_overrides,
        input_data=request_bytes,
    )
    return _bytecode_blobs_from_batch_raw(raw, dynamic_marker, cfg_overrides)
