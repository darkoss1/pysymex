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

"""Thin public API wrapping :class:`~pysymex.execution.executors.verified.executor.VerifiedExecutor`.

Provides scanner-friendly helpers for contract checking, optional bounded-arithmetic
analysis, and termination placeholders without constructing executors manually.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Unpack

from pysymex.execution.executors.verified.executor import VerifiedExecutor
from pysymex.execution.executors.verified.types import (
    ArithmeticIssue,
    ContractIssue,
    VerifiedExecutionConfig,
    VerifiedExecutionOverrides,
    VerifiedExecutionResult,
)
from pysymex.execution.termination import TerminationProof, TerminationStatus


def verify(
    func: Callable[..., object],
    symbolic_args: dict[str, str] | None = None,
    **config_overrides: Unpack[VerifiedExecutionOverrides],
) -> VerifiedExecutionResult:
    """Run symbolic execution with contracts and optional property checks.

    Args:
        func: Target callable.
        symbolic_args: Parameter name to symbolic type-hint mapping.
        **config_overrides: Fields applied to ``VerifiedExecutionConfig``.

    Returns:
        Aggregated verification outcome including symbolic issues and contract
        results.
    """
    config = VerifiedExecutionConfig(symbolic_args=symbolic_args or {}, **config_overrides)
    executor = VerifiedExecutor(config)
    return executor.execute_function(func, symbolic_args or {})


def check_contracts(
    func: Callable[..., object], symbolic_args: dict[str, str] | None = None
) -> list[ContractIssue]:
    """Return only contract obligation results for ``func``.

    Enables precondition and postcondition checking without requiring callers
    to inspect the full ``VerifiedExecutionResult``.
    """
    result = verify(
        func,
        symbolic_args,
        check_preconditions=True,
        check_postconditions=True,
    )
    return result.contract_issues


def check_arithmetic(
    func: Callable[..., object], symbolic_args: dict[str, str] | None = None
) -> list[ArithmeticIssue]:
    """Return opt-in bounded-arithmetic and division-safety issues for a function.

    Ordinary :func:`verify` follows Python's arbitrary-precision ``int``
    semantics. This helper explicitly enables the configurable fixed-width
    overflow policy in addition to division-by-zero checks.
    """
    result = verify(
        func,
        symbolic_args,
        check_division_safety=True,
        detect_division_by_zero=True,
        detect_overflow=True,
    )
    return result.arithmetic_issues


def prove_termination(
    func: Callable[..., object], symbolic_args: dict[str, str] | None = None
) -> TerminationProof:
    """Return a termination proof placeholder."""
    _ = func, symbolic_args
    return TerminationProof(
        status=TerminationStatus.UNKNOWN,
        message="Termination analysis not implemented in this wrapper",
    )
