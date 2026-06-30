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

"""Contract-entry obligation injection for initial function states."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.session.state.core import ExecutionSession


def inject_initial_obligations(
    state: VMState,
    func: Callable[..., object],
    *,
    config: ExecutionConfig,
    session: ExecutionSession,
) -> VMState:
    """Inject runtime contract obligations into an initial function state."""
    if not config.enable_contract_verification:
        return state

    from pysymex._internal.contracts.runtime.entry import inject_preconditions_initial

    state, contract_issues, post_ok = inject_preconditions_initial(
        state,
        func,
        include_preconditions=config.check_contract_preconditions,
        include_postconditions=config.check_contract_postconditions,
    )
    session.issues.extend(contract_issues)
    from pysymex._internal.contracts.decorator.registry import ContractRegistry
    from pysymex._internal.contracts.invariants.checks import check_class_invariants
    from pysymex._internal.contracts.invariants.policy import InvariantCheckPoint
    from pysymex._internal.contracts.invariants.targets import InvariantTargets
    from pysymex._internal.contracts.types import EffectKind

    if config.check_contract_class_invariants:
        session.issues.extend(check_class_invariants(state, func, InvariantCheckPoint.ENTRY))
        has_invariant_exit = InvariantTargets.has_exit_obligations(func)
    else:
        has_invariant_exit = False

    contract = ContractRegistry.get(func)
    has_effect_obligation = bool(
        contract and (contract.assigns_declared or contract.effect_type is EffectKind.PURE),
    )
    should_track_return_obligations = (
        post_ok and (config.check_contract_postconditions or has_effect_obligation)
    ) or has_invariant_exit
    if should_track_return_obligations:
        from pysymex._internal.contracts.binding.snapshots import runtime_contract_frame

        state.contract_frames.append(
            runtime_contract_frame(
                func,
                dict(state.local_vars.items()),
                state.memory,
                effect_start_index=len(state.write_events),
                closure_visible_names=frozenset(getattr(func.__code__, "co_freevars", ())),
            ),
        )

    return state
