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

"""Canonical formal-verification workflows."""

from __future__ import annotations

from typing import TYPE_CHECKING, Unpack

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.config.execution.verification import ExecutionVerificationOverrides
    from pysymex._internal.contracts.reports.issues import ContractIssue
    from pysymex._internal.execution.executors.verified.types import (
        ArithmeticIssue,
        VerifiedExecutionResult,
    )
    from pysymex._internal.execution.termination import TerminationProof


def run(
    target: Callable[..., object],
    symbolic_args: dict[str, str] | None = None,
    **options: Unpack[ExecutionVerificationOverrides],
) -> VerifiedExecutionResult:
    """Verify a callable under contracts and selected property checks."""
    from pysymex._internal.execution.executors.verified.api import verify

    return verify(target, symbolic_args, **options)


def contracts(
    target: Callable[..., object],
    symbolic_args: dict[str, str] | None = None,
) -> list[ContractIssue]:
    """Check precondition and postcondition obligations for a callable."""
    from pysymex._internal.execution.executors.verified.api import check_contracts

    return check_contracts(target, symbolic_args)


def arithmetic(
    target: Callable[..., object],
    symbolic_args: dict[str, str] | None = None,
) -> list[ArithmeticIssue]:
    """Check division safety and opt-in bounded arithmetic for a callable."""
    from pysymex._internal.execution.executors.verified.api import check_arithmetic

    return check_arithmetic(target, symbolic_args)


def termination(
    target: Callable[..., object],
    symbolic_args: dict[str, str] | None = None,
    **options: Unpack[ExecutionVerificationOverrides],
) -> TerminationProof:
    """Produce conservative bounded termination evidence for a callable."""
    from pysymex._internal.execution.executors.verified.api import prove_termination

    return prove_termination(target, symbolic_args, **options)


__all__ = [
    "arithmetic",
    "contracts",
    "run",
    "termination",
]
