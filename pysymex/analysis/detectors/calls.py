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

"""Helpers for extracting call-target information from CPython CALL instructions.

Provides argument-count extraction, callable-name resolution from the
VM stack, and candidate index computation for the CPython 3.11+
``PUSH_NULL`` / ``CALL`` calling convention.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

CALL_TARGET_NAME_ATTRS = ("__name__", "__qualname__", "qualname", "name", "origin")
IGNORED_CALL_TARGET_NAMES = frozenset({"none", "null", "push_null_none"})


def extract_argc(instruction: dis.Instruction) -> int:
    """Return the argument count encoded in *instruction*.

    Prefers ``instruction.argval`` if it is an ``int``, otherwise falls
    back to ``instruction.arg``.  Returns 0 when neither is an ``int``.
    """
    if isinstance(instruction.argval, int):
        return instruction.argval
    if isinstance(instruction.arg, int):
        return instruction.arg
    return 0


def is_plausible_callable_name(name: str) -> bool:
    """Return True when a target-name string looks like a callable identifier."""
    stripped = name.strip()
    if stripped != name or not stripped:
        return False
    for invalid_char in ("'", '"', ",", "(", ")", " "):
        if invalid_char in stripped:
            return False
    return True


def get_call_target_name(
    value: object,
    *,
    require_plausible_callable: bool = False,
) -> str | None:
    """Return the best available callable-like name for a stack candidate."""
    if type(value).__name__ == "SymbolicNone":
        return None
    for attr in CALL_TARGET_NAME_ATTRS:
        attr_value = getattr(value, attr, None)
        if not isinstance(attr_value, str) or not attr_value:
            continue
        lowered = attr_value.lower()
        if lowered in IGNORED_CALL_TARGET_NAMES:
            continue
        if require_plausible_callable and not is_plausible_callable_name(attr_value):
            continue
        return attr_value
    return None


def call_target_candidate_indices(
    stack_size: int,
    argc: int,
    *,
    prefer_pre_null: bool = True,
) -> tuple[int, int]:
    """Return candidate call-target stack indices for the CPython 3.11+ call shape.

    In CPython 3.11+ a ``PUSH_NULL`` (or ``None``) slot sits below the
    callable.  This function returns two indices to probe, ordered by
    *prefer_pre_null*.

    Args:
        stack_size: Current stack depth.
        argc: Number of positional arguments.
        prefer_pre_null: When ``True``, the ``PUSH_NULL`` slot index is
            first in the returned tuple.

    Returns:
        A pair of stack indices ``(primary, secondary)``.
    """
    pre_null_index = stack_size - argc - 2
    post_null_index = stack_size - argc - 1
    if prefer_pre_null:
        return (pre_null_index, post_null_index)
    return (post_null_index, pre_null_index)


def resolve_call_target_name(
    state: VMState,
    argc: int,
    *,
    prefer_pre_null: bool = True,
    require_plausible_callable: bool = False,
) -> str | None:
    """Walk candidate stack positions and return the first resolvable call-target name.

    Args:
        state: Current VM state.
        argc: Number of positional call arguments.
        prefer_pre_null: Passed through to :func:`call_target_candidate_indices`.
        require_plausible_callable: When ``True``, names are validated by
            :func:`is_plausible_callable_name`.

    Returns:
        The resolved callable name string, or ``None`` if none found.
    """
    for index in call_target_candidate_indices(
        len(state.stack),
        argc,
        prefer_pre_null=prefer_pre_null,
    ):
        if index < 0 or index >= len(state.stack):
            continue
        name = get_call_target_name(
            state.stack[index],
            require_plausible_callable=require_plausible_callable,
        )
        if name is not None:
            return name
    return None


__all__ = [
    "CALL_TARGET_NAME_ATTRS",
    "IGNORED_CALL_TARGET_NAMES",
    "call_target_candidate_indices",
    "extract_argc",
    "get_call_target_name",
    "is_plausible_callable_name",
    "resolve_call_target_name",
]
