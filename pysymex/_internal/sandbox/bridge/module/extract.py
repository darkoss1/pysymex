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
from typing import TYPE_CHECKING

from pysymex._internal.config.coercion import ConfigCoercion
from pysymex._internal.core.cache.control import is_process_cache_disabled
from pysymex._internal.sandbox.bridge.blobs import ModuleBlob
from pysymex._internal.sandbox.bridge.cache import (
    MODULE_CACHE,
    module_cache_key,
    remember_module_blob,
)
from pysymex._internal.sandbox.bridge.module.worker import build_module_worker
from pysymex._internal.sandbox.bridge.schema import ExtractionLimits
from pysymex._internal.sandbox.bridge.workers import run_json_worker as _run_json_worker

if TYPE_CHECKING:
    from collections.abc import Mapping

_MODULE_MARKER = "__PYSYMEX_MODULE__"


def extract_module(
    source: bytes,
    filename: str,
    sandbox_config: Mapping[str, object] | None = None,
    *,
    use_cache: bool = True,
) -> ModuleBlob:
    """Execute module initialization once in the sandbox and extract reusable metadata."""
    import secrets

    from pysymex._internal.config.sandbox.types import SandboxResourceLimits

    cache_key = module_cache_key(source, filename, sandbox_config)
    effective_use_cache = use_cache and not is_process_cache_disabled()
    if effective_use_cache:
        cached = MODULE_CACHE.get(cache_key)
        if cached is not None:
            MODULE_CACHE.move_to_end(cache_key)
            return cached

    dynamic_marker = _MODULE_MARKER + secrets.token_hex(16)

    worker = build_module_worker(
        dynamic_marker=dynamic_marker,
        filename=filename,
    )

    cfg_overrides = dict(sandbox_config or {})

    parsed, _cleaned_stdout, _stderr_text = _run_json_worker(
        worker,
        sandbox_config=cfg_overrides,
        input_data=source,
        result_marker=dynamic_marker,
        fail_on_not_ok=True,
    )
    payload_obj = parsed.get("payload")
    if not isinstance(payload_obj, dict):
        from pysymex._internal.sandbox.errors import SandboxProtocolError

        msg = "Sandbox worker produced no module payload"
        raise SandboxProtocolError(msg)
    payload = json.dumps(payload_obj, ensure_ascii=True, separators=(",", ":")).encode("utf-8")

    default_limits = SandboxResourceLimits()
    max_result_bytes = ConfigCoercion.to_int(
        cfg_overrides.get("max_result_bytes", default_limits.max_result_bytes),
        default_limits.max_result_bytes,
    )
    if len(payload) > max_result_bytes:
        from pysymex._internal.sandbox.errors import SandboxResourceError

        msg = "Sandbox module payload exceeds configured result size limit"
        raise SandboxResourceError(msg)
    blob = ModuleBlob(
        payload=payload,
        filename=filename,
        limits=ExtractionLimits(max_payload_bytes=max_result_bytes),
    )
    if effective_use_cache:
        remember_module_blob(cache_key, blob)
    return blob
