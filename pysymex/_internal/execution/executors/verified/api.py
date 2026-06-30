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

"""Thin public API wrapping :class:`~pysymex._internal.execution.executors.verified.executor.VerifiedExecutor`.

Provides scanner-friendly helpers for contract checking, optional bounded-arithmetic
analysis, and bounded termination evidence without constructing executors manually.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Unpack

from pysymex._internal.config.execution.verification import (
    ExecutionVerificationConfig,
    ExecutionVerificationOverrides,
)
from pysymex._internal.execution.executors.verified.executor.runner import VerifiedExecutor
from pysymex._internal.execution.termination import (
    TerminationProof,
    termination_proof_from_bounded_execution,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.contracts.reports.issues import ContractIssue
    from pysymex._internal.execution.executors.verified.types import (
        ArithmeticIssue,
        VerifiedExecutionResult,
    )


def verify(
    func: Callable[..., object],
    symbolic_args: dict[str, str] | None = None,
    **config_overrides: Unpack[ExecutionVerificationOverrides],
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
    config = ExecutionVerificationConfig(symbolic_args=symbolic_args or {}, **config_overrides)
    executor = VerifiedExecutor(config)
    return executor.execute_function(func, symbolic_args or {})


def check_contracts(
    func: Callable[..., object],
    symbolic_args: dict[str, str] | None = None,
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
    func: Callable[..., object],
    symbolic_args: dict[str, str] | None = None,
) -> list[ArithmeticIssue]:
    """Return opt-in bounded-arithmetic and division-safety issues for a function.

    Ordinary :func:`verify` follows Python's arbitrary-precision ``int``
    semantics. This helper explicitly enables the configurable fixed-width
    overflow policy in addition to division-by-zero checks.
    """
    result = verify(
        func,
        symbolic_args,
        detect_division_by_zero=True,
        detect_overflow=True,
    )
    return result.arithmetic_issues


def prove_termination(
    func: Callable[..., object],
    symbolic_args: dict[str, str] | None = None,
    **config_overrides: Unpack[ExecutionVerificationOverrides],
) -> TerminationProof:
    """Return conservative bounded termination evidence for ``func``.

    ``TERMINATES`` means verified symbolic execution completed its accounted
    paths without degraded passes under the supplied bounds. Resource limits,
    unsupported semantics, solver uncertainty, and incomplete path accounting
    remain ``UNKNOWN``.
    """
    result = verify(func, symbolic_args, **config_overrides)
    return termination_proof_from_bounded_execution(
        paths_explored=result.paths_explored,
        paths_completed=result.paths_completed,
        paths_pruned=result.paths_pruned,
        degraded_passes=result.degraded_passes,
    )
