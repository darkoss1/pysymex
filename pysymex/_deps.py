# pysymex: Python Symbolic Execution & Formal Verification
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

"""Dependency guards for pysymex runtime requirements."""

from __future__ import annotations

import logging
import sys
import threading
from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
from types import ModuleType
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

_REQUIRED_Z3_API = ("Int", "Solver", "BoolVal", "sat", "unsat")
_cached_z3: ModuleType | None = None
_z3_lock = threading.Lock()


if TYPE_CHECKING:
    from typing import TypedDict

    class Z3Diagnostics(TypedDict):
        module_repr: str
        module_path: str | None
        z3_version: str | None
        z3_solver_version: str | None
        has_required_api: dict[str, bool]
        missing_api: list[str]


def _package_version(name: str) -> str | None:
    """Return installed package version when available."""
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def _is_z3_ready(module: ModuleType) -> bool:
    """Check whether module exposes solver API expected by pysymex."""
    return all(hasattr(module, api) for api in _REQUIRED_Z3_API)


def z3_diagnostics(module: ModuleType | None = None) -> Z3Diagnostics:
    """Collect diagnostics for the currently imported z3 module."""
    if module is None:
        try:
            module = import_module("z3")
        except ImportError:
            logger.debug("Failed to import z3 for diagnostics", exc_info=True)
            module = None

    has_api = {api: bool(module is not None and hasattr(module, api)) for api in _REQUIRED_Z3_API}
    missing_api = [api for api, ok in has_api.items() if not ok]

    return {
        "module_repr": repr(module),
        "module_path": getattr(module, "__file__", None),
        "z3_version": _package_version("z3"),
        "z3_solver_version": _package_version("z3-solver"),
        "has_required_api": has_api,
        "missing_api": missing_api,
    }


def _build_z3_error() -> RuntimeError:
    """Build z3 error."""
    diag = z3_diagnostics()
    details = [
        "pysymex requires a working z3-solver Python module.",
        "",
        f"Detected module path: {diag['module_path']}",
        f"Detected 'z3' package version: {diag['z3_version']}",
        f"Detected 'z3-solver' package version: {diag['z3_solver_version']}",
        f"Missing API symbols: {', '.join(diag['missing_api']) or 'none'}",
        "",
        "Fix your environment with:",
        "  python -m pip uninstall -y z3",
        "  python -m pip install -U z3-solver",
    ]
    return RuntimeError("\n".join(details))


def ensure_z3_ready(force_recheck: bool = False) -> ModuleType:
    """Return validated z3 module, repairing common import shadowing in-process.

    Thread-safe via double-checked locking.
    """
    global _cached_z3

    if _cached_z3 is not None and not force_recheck:
        if _is_z3_ready(_cached_z3):
            return _cached_z3

    with _z3_lock:
        if _cached_z3 is not None and not force_recheck:
            if _is_z3_ready(_cached_z3):
                return _cached_z3
        _cached_z3 = None

        try:
            z3_module = import_module("z3")
        except ImportError as exc:
            raise _build_z3_error() from exc

        if _is_z3_ready(z3_module):
            _cached_z3 = z3_module
            return z3_module

        try:
            z3_solver_module = import_module("z3.z3")
            sys.modules["z3"] = z3_solver_module
            if _is_z3_ready(z3_solver_module):
                _cached_z3 = z3_solver_module
                return z3_solver_module
        except ImportError:
            logger.debug("Failed to import z3.z3 fallback module", exc_info=True)

        raise _build_z3_error()
