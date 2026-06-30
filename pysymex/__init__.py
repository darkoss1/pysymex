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

"""Flat public API surface for pysymex.

Engine implementation remains under :mod:`pysymex._internal` and is not a
supported import surface for users.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.config.defaults import VERSION

__version__ = VERSION

Z3_AVAILABLE: bool

_z3_checked = False
_z3_import_error: RuntimeError | None = None

if TYPE_CHECKING:
    from pysymex import contracts
    from pysymex import diagnostics
    from pysymex import issues
    from pysymex import reports
    from pysymex import results
    from pysymex import scan
    from pysymex import verify


def __getattr__(name: str) -> object:
    """Resolve lazy attributes."""
    if name == "Z3_AVAILABLE":
        return _z3_available()
    if name in (
        "contracts",
        "diagnostics",
        "issues",
        "reports",
        "results",
        "scan",
        "verify",
    ):
        import importlib

        return importlib.import_module(f"pysymex.{name}")
    msg = f"module '{__name__}' has no attribute '{name}'"
    raise AttributeError(msg)


def _z3_available() -> bool:
    global _z3_checked, _z3_import_error
    if _z3_import_error is not None:
        return False
    if _z3_checked:
        return True
    from pysymex._internal.deps import ensure_z3_ready

    try:
        ensure_z3_ready()
    except RuntimeError as exc:
        _z3_import_error = exc
        _z3_checked = True
        return False
    _z3_checked = True
    return True


__all__ = [
    "Z3_AVAILABLE",
    "__version__",
    "contracts",
    "diagnostics",
    "issues",
    "reports",
    "results",
    "scan",
    "verify",
]
