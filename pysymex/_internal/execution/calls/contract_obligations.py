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

"""Shared contract-obligation checks for modeled call summarization."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


def has_enabled_runtime_contract_obligations(
    func: Callable[..., object],
    config: object | None,
) -> bool:
    """Return whether summarizing *func* would skip enabled contract checks."""
    if not (config and getattr(config, "enable_contract_verification", False)):
        return False

    from pysymex._internal.contracts.decorator.registry import ContractRegistry
    from pysymex._internal.contracts.invariants.targets import InvariantTargets
    from pysymex._internal.contracts.types import EffectKind

    contract = ContractRegistry.get(func)
    has_precondition_obligation = bool(
        contract
        and contract.preconditions
        and getattr(config, "check_contract_preconditions", True),
    )
    has_assumption_obligation = bool(contract and contract.assumptions)
    has_postcondition_obligation = bool(
        contract
        and contract.postconditions
        and getattr(config, "check_contract_postconditions", True),
    )
    has_effect_obligation = bool(
        contract and (contract.assigns_declared or contract.effect_type is EffectKind.PURE),
    )
    has_invariant_exit = bool(
        getattr(config, "check_contract_class_invariants", True)
        and InvariantTargets.has_exit_obligations(func),
    )
    return (
        has_precondition_obligation
        or has_assumption_obligation
        or has_postcondition_obligation
        or has_effect_obligation
        or has_invariant_exit
    )
