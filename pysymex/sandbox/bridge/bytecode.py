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

import textwrap
from collections.abc import Mapping
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING

from pysymex.config.sandbox_bridge import make_sandbox_config as _make_sandbox_config
from pysymex.config.sandbox_bridge import sandbox_config_fingerprint as _sandbox_config_fingerprint
from pysymex.config.sandbox_bridge import to_int
from pysymex.sandbox.bridge.errors import sandbox_result_error
from pysymex.sandbox.bridge.types import BytecodeBlob, EXTRACTION_SCHEMA_VERSION, ExtractionLimits
from pysymex.sandbox.bridge.workers import run_raw_worker as _run_raw_worker

if TYPE_CHECKING:
    from pysymex.sandbox.runner import SandboxRunner

_BYTECODE_MARKER = b"__PYSYMEX_BYTECODE__"
_BYTECODE_SESSION: ContextVar["SandboxBytecodeExtractionSession | None"] = ContextVar(
    "_BYTECODE_SESSION",
    default=None,
)


def _bytecode_worker_inputs(
    filename: str,
    sandbox_config: Mapping[str, object] | None = None,
) -> tuple[bytes, str, dict[str, object]]:
    """Build the marker, worker script, and sandbox overrides for extraction."""
    import secrets

    dynamic_marker = f"{_BYTECODE_MARKER.decode('utf-8')}_{secrets.token_hex(16)}".encode("utf-8")

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
        """
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
        from pysymex.sandbox.errors import SandboxProtocolError

        raise SandboxProtocolError("Sandbox bytecode worker produced no marker")
    payload = raw[len(dynamic_marker) :]
    from pysymex.sandbox.types import ResourceLimits

    default_limits = ResourceLimits()
    max_result_bytes = to_int(
        cfg_overrides.get("max_result_bytes", default_limits.max_result_bytes),
        default_limits.max_result_bytes,
    )
    if len(payload) > max_result_bytes:
        from pysymex.sandbox.errors import SandboxResourceError

        raise SandboxResourceError("Sandbox bytecode payload exceeds configured result size limit")
    return BytecodeBlob(
        payload=payload,
        filename=filename,
        limits=ExtractionLimits(max_payload_bytes=max_result_bytes),
    )


class SandboxBytecodeExtractionSession:
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
        self._token: Token[SandboxBytecodeExtractionSession | None] | None = None

    def __enter__(self) -> SandboxBytecodeExtractionSession:
        """Initialize and enter the sandbox process."""
        from pysymex.sandbox import SecureSandbox

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
            from pysymex.sandbox.errors import SandboxSetupError

            raise SandboxSetupError("Sandbox bytecode extraction session is not active")
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


def sandbox_bytecode_extraction_session(
    sandbox_config: Mapping[str, object] | None = None,
) -> SandboxBytecodeExtractionSession:
    """Create a scoped sandbox session for repeated bytecode extraction."""
    return SandboxBytecodeExtractionSession(sandbox_config)


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
