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

"""Semantic cache keys for executor-level result reuse."""

from __future__ import annotations

import inspect
import json
from dataclasses import asdict
from typing import TYPE_CHECKING, cast

from pysymex._internal.analysis.runtime.cache.keying import hash_function
from pysymex._internal.execution.entrypoint.globals.containers import EntrypointContainerGlobals
from pysymex._internal.execution.entrypoint.globals.instances import InstanceGlobals
from pysymex._internal.utils.hashing import stable_digest_hex

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from types import CellType, CodeType

    from pysymex._internal.analysis.detectors.detector.contract import Detector
    from pysymex._internal.config.execution.settings import ExecutionConfig


def execution_result_cache_key(
    *,
    func: Callable[..., object],
    symbolic_args_token: str,
    initial_values: Mapping[str, object] | None,
    config: ExecutionConfig,
    active_detectors: Sequence[Detector],
    executor_version: int,
) -> str:
    """Return a conservative semantic key for cached ``execute_function`` results."""
    code = func.__code__
    payload = {
        "function": hash_function(func.__name__, code, symbolic_args_token),
        "initial_values": _stable_mapping_token(initial_values),
        "config": _stable_config_token(config),
        "dependencies": _stable_dependency_token(func, code),
        "detectors": _stable_detector_token(active_detectors),
        "executor_version": executor_version,
    }
    return stable_digest_hex(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def _stable_config_token(config: ExecutionConfig) -> str:
    """Return a stable token for execution options that may affect analysis semantics."""
    payload = asdict(config)
    payload.pop("enable_caching", None)
    return json.dumps(payload, sort_keys=True, default=_normalise_value, separators=(",", ":"))


def _stable_mapping_token(mapping: Mapping[str, object] | None) -> str:
    """Return a stable token for caller-provided concrete initial values."""
    if mapping is None:
        return "null"
    payload = {key: _normalise_value(value) for key, value in sorted(mapping.items())}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _stable_dependency_token(func: Callable[..., object], code: CodeType) -> str:
    """Fingerprint closure cells and same-module globals referenced by the target."""
    payload: dict[str, object] = {}
    closure = cast("tuple[CellType, ...] | None", getattr(func, "__closure__", None))
    freevars = code.co_freevars
    if closure and freevars:
        payload["closure"] = {
            name: _normalise_cell(cell) for name, cell in zip(freevars, closure, strict=False)
        }

    target_module = getattr(func, "__module__", None)
    globals_map = cast("Mapping[str, object]", getattr(func, "__globals__", {}))
    referenced_globals: dict[str, object] = {}
    for name in code.co_names:
        value = globals_map.get(name)
        if inspect.isfunction(value) and getattr(value, "__module__", None) == target_module:
            referenced_globals[name] = hash_function(value.__name__, value.__code__)
        elif inspect.isclass(value) and getattr(value, "__module__", None) == target_module:
            referenced_globals[name] = _normalise_value(value)
    for name, value in InstanceGlobals.select(func, code).items():
        referenced_globals[name] = _normalise_value(value)
    for name, value in EntrypointContainerGlobals.select(func, code).items():
        referenced_globals[name] = _normalise_value(value)
    if referenced_globals:
        payload["globals"] = referenced_globals
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _stable_detector_token(active_detectors: Sequence[Detector]) -> tuple[str, ...]:
    """Return a stable detector identity token for the active runtime detector set."""
    return tuple(
        f"{detector.__class__.__module__}.{detector.__class__.__qualname__}:{detector.name}"
        for detector in active_detectors
    )


def _normalise_cell(cell: CellType) -> object:
    """Return a stable representation for a closure cell."""
    try:
        return _normalise_value(cell.cell_contents)
    except ValueError:
        return {"kind": "empty-cell"}


def _normalise_value(value: object) -> object:
    """Return a JSON-compatible conservative identity for semantic cache inputs."""
    if value is None or isinstance(value, bool | int | float | str):
        return {"kind": type(value).__qualname__, "value": value}
    if isinstance(value, bytes):
        return {"kind": "bytes", "value": value.hex()}
    if isinstance(value, tuple):
        tuple_items = cast("tuple[object, ...]", value)
        return {"kind": "tuple", "items": [_normalise_value(item) for item in tuple_items]}
    if isinstance(value, list):
        list_items = cast("list[object]", value)
        return {"kind": "list", "items": [_normalise_value(item) for item in list_items]}
    if isinstance(value, dict):
        dict_items = cast("Mapping[object, object]", value)
        items = sorted(
            ((_normalise_value(key), _normalise_value(item)) for key, item in dict_items.items()),
            key=repr,
        )
        return {"kind": "dict", "items": items}
    if isinstance(value, set):
        set_items = cast("set[object]", value)
        items = sorted((_normalise_value(item) for item in set_items), key=repr)
        return {"kind": "set", "items": items}
    if isinstance(value, frozenset):
        frozen_items = cast("frozenset[object]", value)
        items = sorted((_normalise_value(item) for item in frozen_items), key=repr)
        return {"kind": "frozenset", "items": items}
    if inspect.isfunction(value):
        return {
            "kind": "function",
            "module": getattr(value, "__module__", ""),
            "name": getattr(value, "__qualname__", getattr(value, "__name__", "")),
            "code": hash_function(value.__name__, value.__code__),
        }
    return {
        "kind": type(value).__qualname__,
        "module": type(value).__module__,
        "repr": repr(value),
    }
