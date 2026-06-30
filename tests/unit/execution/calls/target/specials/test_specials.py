"""Tests for special call-target adapter ownership."""

from __future__ import annotations

from typing import cast

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.execution.calls.target.specials.context.managers import (
    context_manager_normal_exit,
)
from pysymex._internal.execution.calls.target.specials.dispatch import dispatch_special_call_target
from pysymex._internal.execution.calls.target.specials.dispatch import (
    dispatch_special_call_target as dispatch_special_call_target_owner,
)
from pysymex._internal.typing.protocols import StackValue


def test_target_specials_public_export_points_to_direct_owner() -> None:
    assert dispatch_special_call_target is dispatch_special_call_target_owner


def test_context_manager_normal_exit_accepts_only_none_like_arguments() -> None:
    assert context_manager_normal_exit([None, SymbolicNoneType(), None]) is True
    assert context_manager_normal_exit([None, cast(StackValue, ValueError("boom")), None]) is False
