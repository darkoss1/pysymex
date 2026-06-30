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

"""Declared contract-obligation planning for verified execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.contracts.decorator.registry import ContractRegistry
from pysymex._internal.contracts.enums import EffectKind, VerificationResult
from pysymex._internal.contracts.invariants.targets import InvariantTargets
from pysymex._internal.contracts.reports.issues import ContractIssue
from pysymex.contracts import ContractKind

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.config.execution.verification import ExecutionVerificationConfig
    from pysymex._internal.contracts.types import Contract


@dataclass(frozen=True, slots=True)
class VerifiedContractPlan:
    """Declared contract counters and static unsupported issues for one target."""

    contract_issues: list[ContractIssue]
    contracts_checked: int


def _unsupported_contract(kind: ContractKind, condition: str, message: str) -> ContractIssue:
    """Build a visible result for a declared obligation without execution semantics."""
    return ContractIssue(
        kind=kind,
        condition=condition,
        message=message,
        result=VerificationResult.UNSUPPORTED,
    )


def collect_verified_contract_plan(
    func: Callable[..., object],
    config: ExecutionVerificationConfig,
) -> VerifiedContractPlan:
    """Collect declared contract counts and static unsupported obligations."""
    func_contract = ContractRegistry.get(func)
    preconditions: list[Contract] = []
    postconditions: list[Contract] = []
    unsupported_issues: list[ContractIssue] = []
    runtime_obligation_count = 0

    if func_contract is not None:
        if config.check_preconditions:
            preconditions.extend(func_contract.preconditions)
        if config.check_postconditions:
            postconditions.extend(func_contract.postconditions)
        if config.check_loop_invariants:
            for clauses in func_contract.loop_invariants.values():
                unsupported_issues.extend(
                    _unsupported_contract(
                        ContractKind.LOOP_INVARIANT,
                        clause.condition,
                        "Loop invariant checking is not integrated into verified execution",
                    )
                    for clause in clauses
                )
        if func_contract.assigns_declared:
            runtime_obligation_count += 1
        if func_contract.effect_type is EffectKind.PURE:
            runtime_obligation_count += 1
    if config.check_class_invariants:
        runtime_obligation_count += InvariantTargets.obligation_count(func)

    contracts_checked = (
        len(preconditions)
        + len(postconditions)
        + len(unsupported_issues)
        + runtime_obligation_count
    )
    return VerifiedContractPlan(
        contract_issues=list(unsupported_issues),
        contracts_checked=contracts_checked,
    )
