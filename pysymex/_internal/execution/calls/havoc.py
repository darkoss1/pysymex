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

"""Unmodeled-call havoc provenance helpers."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pysymex._internal.core.types.havoc import HavocValue

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState

UNMODELED_CALL_ABSTRACTION = "unmodeled_call_abstraction"
_MAX_HAVOC_CALL_TOKEN_LENGTH = 80


def create_unmodeled_call_havoc(
    state: VMState,
    func_obj: object,
) -> tuple[HavocValue, z3.BoolRef]:
    """Create an unmodeled-call result while preserving callable provenance."""
    return HavocValue.havoc(f"havoc_call_{_callable_havoc_token(func_obj)}@{state.pc}")


def _callable_havoc_token(func_obj: object) -> str:
    """Return the best stable callable identifier available for diagnostics."""
    for attr_name in ("model_name", "__qualname__", "__name__", "_func_name", "name"):
        candidate = getattr(func_obj, attr_name, None)
        if isinstance(candidate, str) and candidate:
            return _sanitize_havoc_call_token(candidate)
    return _sanitize_havoc_call_token(type(func_obj).__name__)


def _sanitize_havoc_call_token(raw: object) -> str:
    """Return a bounded Z3-symbol token for unmodeled-call provenance."""
    token = re.sub(r"[^0-9A-Za-z_]+", "_", str(raw)).strip("_")
    if not token:
        return "callable"
    if len(token) <= _MAX_HAVOC_CALL_TOKEN_LENGTH:
        return token
    prefix_length = _MAX_HAVOC_CALL_TOKEN_LENGTH // 2
    suffix_length = _MAX_HAVOC_CALL_TOKEN_LENGTH - prefix_length - 1
    return f"{token[:prefix_length]}_{token[-suffix_length:]}"
