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

"""CALL-family ValueError detection for conversions and empty iterables."""

from __future__ import annotations

import builtins
from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.calls import (
    call_target_candidate_indices,
    extract_argc,
    get_call_target_name,
    resolve_call_target_name,
)
from pysymex._internal.analysis.detectors.runtime.value.conversions import (
    conversion_value_error_issue,
)
from pysymex._internal.analysis.detectors.runtime.value.empty.iterables import (
    empty_iterable_value_error_issue,
)
from pysymex._internal.analysis.detectors.runtime.value.ranges import range_zero_step_issue

if TYPE_CHECKING:
    import dis

    from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
    from pysymex._internal.core.state.record import VMState

_TRUSTED_BUILTIN_VALUE_TARGETS = {
    "bytes.fromhex": bytes.fromhex,
    "builtins.float": builtins.float,
    "builtins.int": builtins.int,
    "builtins.max": builtins.max,
    "builtins.min": builtins.min,
    "builtins.range": builtins.range,
    "float": builtins.float,
    "fromhex": bytes.fromhex,
    "int": builtins.int,
    "max": builtins.max,
    "min": builtins.min,
    "range": builtins.range,
}


def call_value_error_issue(
    state: VMState,
    instruction: dis.Instruction,
    solver_check: IsSatFn,
) -> Issue | None:
    """Check CALL-family instructions for modeled ValueError-producing builtins."""
    argc = extract_argc(instruction)
    if argc <= 0 or len(state.stack) < argc:
        return None
    args = list(state.stack[-argc:])
    target_name = resolve_call_target_name(state, argc, prefer_pre_null=False)
    if target_name is None:
        return None

    lowered_target = target_name.lower()
    if _is_shadowed_builtin_value_target(state, argc, lowered_target):
        return None
    if lowered_target in {"range", "builtins.range"}:
        range_issue = range_zero_step_issue(state, args, solver_check)
        if range_issue is not None:
            return range_issue
    conversion_issue = conversion_value_error_issue(state, solver_check, lowered_target, argc, args)
    if conversion_issue is not None:
        return conversion_issue
    return empty_iterable_value_error_issue(state, solver_check, lowered_target, argc, args)


def _is_shadowed_builtin_value_target(state: VMState, argc: int, lowered_target: str) -> bool:
    """Return whether a ValueError builtin name resolves to a source-defined callable."""
    expected_builtin = _TRUSTED_BUILTIN_VALUE_TARGETS.get(lowered_target)
    if expected_builtin is None:
        return False
    target = _resolved_named_call_target(state, argc, lowered_target)
    if target is None:
        return False
    if _is_trusted_builtin_value_target(target, expected_builtin):
        return False
    model_name = getattr(target, "model_name", None)
    trusted_model_names = {lowered_target}
    if not lowered_target.startswith("builtins."):
        trusted_model_names.add(f"builtins.{lowered_target}")
    return model_name not in trusted_model_names


def _is_trusted_builtin_value_target(target: object, expected_builtin: object) -> bool:
    """Return whether *target* is the real builtin modeled by *expected_builtin*."""
    if target is expected_builtin:
        return True
    if _is_bytes_fromhex_method(expected_builtin):
        return _is_bytes_fromhex_method(target)
    return False


def _is_bytes_fromhex_method(value: object) -> bool:
    """Return whether *value* is the CPython ``bytes.fromhex`` builtin method."""
    return (
        getattr(value, "__self__", None) is bytes
        and getattr(value, "__name__", None) == "fromhex"
        and getattr(value, "__qualname__", None) == "bytes.fromhex"
    )


def _resolved_named_call_target(state: VMState, argc: int, lowered_target: str) -> object | None:
    """Return the stack candidate whose display name matches *lowered_target*."""
    for index in call_target_candidate_indices(
        len(state.stack),
        argc,
        prefer_pre_null=False,
    ):
        if index < 0 or index >= len(state.stack):
            continue
        candidate = state.stack[index]
        candidate_name = get_call_target_name(candidate)
        if candidate_name is not None and candidate_name.lower() == lowered_target:
            return candidate
    return None
