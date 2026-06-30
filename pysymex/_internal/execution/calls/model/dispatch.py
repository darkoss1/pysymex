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

"""Call target model dispatch and modeled invocation.

Consumes resolved call targets from opcode stack lowering, routes builtins and user functions,
and applies side effects from modeled invocations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.analysis.detectors.feasibility import hard_theory_witness_model
from pysymex._internal.core.solver.engine.policies import path_may_be_feasible
from pysymex._internal.core.solver.engine.queries import check_sat_result
from pysymex._internal.core.solver.feasibility_context import bind_path_feasibility_oracle
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.execution.calls.model.exceptions.potential import (
    branch_on_caught_potential_exception,
)
from pysymex._internal.execution.calls.model.exceptions.raised import (
    branch_on_caught_raised_exception,
)
from pysymex._internal.execution.calls.model.side.effects.application import (
    apply_model_side_effects,
)
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.fallback.types import (
    FallbackEvent,
    FallbackKind,
    RiskLevel,
    SoundnessTag,
)
from pysymex._internal.execution.feasibility.unknowns import append_fallback_events
from pysymex._internal.models.contracts.capabilities import bind_model_invoker
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects
from pysymex._internal.models.registry import RuntimeModelRegistry

if TYPE_CHECKING:
    import dis

    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.models.builtins.registry.models import RegisteredModel, RegisteredResult
    from pysymex._internal.typing.protocols import StackValue


def reportable_issue_path_is_sat(constraints: list[z3.BoolRef]) -> bool:
    """Require definite satisfiability before emitting model-side-effect issues."""
    if hard_theory_witness_model(constraints) is not None:
        return True
    return check_sat_result(constraints).is_sat


def _append_model_degradations(
    opcode_result: OpcodeResult,
    model_result: RegisteredResult,
    pc: int,
) -> OpcodeResult:
    """Translate model-owned limitations into execution fallback events."""
    kind_map = {
        "precision_loss": (FallbackKind.PRECISION_LOSS, SoundnessTag.PRECISION_LOSS),
        "unknown": (FallbackKind.UNKNOWN, SoundnessTag.INCONCLUSIVE),
        "unsupported": (FallbackKind.UNSUPPORTED, SoundnessTag.UNSUPPORTED),
    }
    events: list[FallbackEvent] = []
    for degradation in model_result.degradations:
        kind, soundness = kind_map[degradation.kind]
        events.append(
            FallbackEvent(
                kind=kind,
                label=degradation.label,
                owner=degradation.owner,
                reason=degradation.reason,
                pc=pc,
                soundness=soundness,
                false_positive_risk=RiskLevel.UNKNOWN,
                false_negative_risk=RiskLevel.HIGH,
            ),
        )
    return append_fallback_events(opcode_result, events)


MAX_SUMMARY_CACHE_CONSTRAINTS = 24
MAX_SUMMARY_CACHE_ARGS = 12


def _apply_registered_model(
    model: RegisteredModel,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    state: VMState,
) -> RegisteredResult:
    """Invoke a model with execution-owned capabilities bound to this call."""
    with (
        bind_path_feasibility_oracle(path_may_be_feasible),
        bind_model_invoker(_invoke_model_by_name),
    ):
        return model.apply(args, kwargs, state)


def _invoke_model_by_name(
    name: str,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    state: VMState,
) -> ModelResult | None:
    model = RuntimeModelRegistry.default().get(name)
    if not isinstance(model, FunctionModel):
        return None
    return model.apply(args, kwargs, state)


def apply_model(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue] | None = None,
    ctx: OpcodeDispatcher | None = None,
    instr: dis.Instruction | None = None,
) -> OpcodeResult | None:
    """Apply a built-in or stdlib model if available."""
    kwargs = kwargs or {}
    from pysymex._internal.execution.opcodes.common.generators.lifecycle import (
        try_resume_generator_call,
    )

    generator_result = try_resume_generator_call(state, func_obj, args, kwargs, ctx, instr)
    if generator_result is not None:
        return generator_result
    model_name = func_obj if isinstance(func_obj, str) else getattr(func_obj, "model_name", None)
    func_name = getattr(func_obj, "_name", "") or getattr(func_obj, "name", "")
    from pysymex._internal.execution.opcodes.common.functions.protocol.builtins.dispatch import (
        dispatch_modeled_protocol_builtin,
    )

    protocol_result = dispatch_modeled_protocol_builtin(
        state,
        func_obj,
        model_name,
        args,
        kwargs,
        ctx,
    )
    if protocol_result is not None:
        return protocol_result
    if func_name == "__build_class__":
        from pysymex._internal.execution.opcodes.common.functions.classes.builder import (
            apply_build_class_model,
        )

        return apply_build_class_model(state, args, kwargs)
    if model_name is None and isinstance(func_name, str) and func_name.endswith(".close"):
        model_name = func_name
    if isinstance(model_name, str) and model_name.endswith(".close"):
        state = state.push(SymbolicNoneType())
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    model_pc = state.pc
    if model_name:
        model = RuntimeModelRegistry.default().resolve(model_name)
        if not model:
            return None

        if not hasattr(model, "apply"):
            return None

        result = _apply_registered_model(model, args, kwargs, state)
    else:
        model = RuntimeModelRegistry.default().resolve_callable(func_obj)
        if model is None or not hasattr(model, "apply"):
            return None
        result = _apply_registered_model(model, args, kwargs, state)

    exception_branch = branch_on_caught_raised_exception(state, ctx, instr, result)
    if exception_branch is None:
        exception_branch = branch_on_caught_potential_exception(
            state,
            ctx,
            instr,
            result,
            reportable_issue_path_is_sat,
        )
    if exception_branch is not None:
        return _append_model_degradations(exception_branch, result, model_pc)

    if SideEffects.is_raised_exception(result.side_effects.get("raised_exception")):
        side_effect_application = apply_model_side_effects(
            state,
            args,
            result.side_effects,
            reportable_issue_path_is_sat,
        )
        return _append_model_degradations(
            OpcodeResult(
                new_states=[],
                issues=side_effect_application.issues,
                terminal=True,
            ),
            result,
            model_pc,
        )

    generated_issues = []
    if result.side_effects:
        side_effect_application = apply_model_side_effects(
            state,
            args,
            result.side_effects,
            reportable_issue_path_is_sat,
        )
        state = side_effect_application.state
        generated_issues = side_effect_application.issues

    state = state.push(result.value)
    for constraint in result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    state = state.advance_pc()
    return _append_model_degradations(
        OpcodeResult(new_states=[state], issues=generated_issues),
        result,
        model_pc,
    )
