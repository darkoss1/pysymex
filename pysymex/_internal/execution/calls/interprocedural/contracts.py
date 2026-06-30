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

"""Runtime contract entry checks for interprocedural calls."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import types
    from collections.abc import Callable, Mapping, Sequence

    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


@dataclass(frozen=True, slots=True)
class ContractEntryFrame:
    """Contract-frame metadata attached to a nested call frame."""

    frame: object | None
    owns_frame: bool


def prepare_contract_entry_frame(
    config: object | None,
    contract_callable: Callable[..., object] | None,
    func_code: types.CodeType,
    new_locals: Mapping[str, StackValue],
    state: VMState,
) -> ContractEntryFrame:
    """Capture old contract state needed by callee exit obligations."""
    has_postcondition_obligation = False
    has_effect_obligation = False
    has_invariant_exit = False

    if (
        config
        and getattr(config, "enable_contract_verification", False)
        and contract_callable is not None
    ):
        from pysymex._internal.contracts.decorator.registry import ContractRegistry
        from pysymex._internal.contracts.invariants.targets import InvariantTargets
        from pysymex._internal.contracts.types import EffectKind

        contract = ContractRegistry.get(contract_callable)
        has_effect_obligation = bool(
            contract and (contract.assigns_declared or contract.effect_type is EffectKind.PURE),
        )
        has_postcondition_obligation = bool(
            contract
            and contract.postconditions
            and getattr(config, "check_contract_postconditions", True),
        )
        has_invariant_exit = bool(
            getattr(config, "check_contract_class_invariants", True)
            and InvariantTargets.has_exit_obligations(contract_callable),
        )

    owns_frame = bool(
        contract_callable is not None
        and (has_postcondition_obligation or has_effect_obligation or has_invariant_exit),
    )
    if not owns_frame:
        return ContractEntryFrame(frame=None, owns_frame=False)
    assert contract_callable is not None

    from pysymex._internal.contracts.binding.snapshots import runtime_contract_frame

    contract_frame = runtime_contract_frame(
        contract_callable,
        new_locals,
        state.memory,
        effect_start_index=len(state.write_events),
        closure_visible_names=frozenset(getattr(func_code, "co_freevars", ())),
    )
    return ContractEntryFrame(frame=contract_frame, owns_frame=True)


def check_runtime_contract_entry(
    state: VMState,
    config: object | None,
    contract_callable: Callable[..., object] | None,
    args: Sequence[StackValue],
    kwargs: Mapping[str, StackValue],
    contract_frame: object | None,
) -> tuple[VMState | None, list[Issue]]:
    """Apply call-site contracts and class invariants before entering callee bytecode."""
    contract_issues: list[Issue] = []
    if not (
        config
        and getattr(config, "enable_contract_verification", False)
        and contract_callable is not None
    ):
        return state, contract_issues

    from pysymex._internal.contracts.runtime.calls import inject_call_preconditions

    checked_state, contract_issues = inject_call_preconditions(
        state,
        contract_callable,
        args,
        kwargs,
        include_preconditions=getattr(config, "check_contract_preconditions", True),
    )
    if checked_state is None:
        return None, contract_issues
    state = checked_state

    if getattr(config, "check_contract_class_invariants", True):
        from pysymex._internal.contracts.invariants.checks import check_class_invariants
        from pysymex._internal.contracts.invariants.policy import InvariantCheckPoint

        contract_issues.extend(
            check_class_invariants(
                state,
                contract_callable,
                InvariantCheckPoint.ENTRY,
            ),
        )
    if contract_frame is not None:
        state.contract_frames.append(contract_frame)
    return state, contract_issues
