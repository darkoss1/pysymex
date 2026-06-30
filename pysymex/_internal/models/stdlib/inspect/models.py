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

"""Models for the inspect standard-library module."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelDegradation, ModelResult, SideEffects
from pysymex._internal.models.stdlib.coercion import symbolic_object

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class InspectPredicateModel(FunctionModel):
    """Model for common inspect.is* predicates."""

    aliases: tuple[str, ...]

    def __init__(self, qualname: str) -> None:
        self.qualname = qualname
        self.name = qualname.rsplit(".", 1)[-1]
        self.aliases = ()

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if args and not isinstance(args[0], SymbolicValue):
            predicate = getattr(inspect, self.name)
            return ModelResult(value=SymbolicValue.from_const(bool(predicate(args[0]))))
        value, constraint = SymbolicValue.symbolic_bool(f"{self.name}_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


class InspectSignatureModel(FunctionModel):
    """Preserve concrete signatures when introspection is safe and available."""

    name = "signature"
    qualname = "inspect.signature"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1:
            value, constraint = symbolic_object(f"signature_{state.pc}", "inspect.Signature")
            return ModelResult(
                value=value,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    self.qualname,
                    "signature() takes one callable",
                ),
            )
        if not isinstance(args[0], SymbolicValue):
            try:
                signature_fn = cast("Callable[..., inspect.Signature]", inspect.signature)
                signature = signature_fn(args[0], **kwargs)
                value, constraint = symbolic_object(f"signature_{state.pc}", "inspect.Signature")
                value.attach_modeled_object(signature)
                return ModelResult(value=value, constraints=[constraint])
            except (TypeError, ValueError):
                pass
        value, constraint = symbolic_object(f"signature_{state.pc}", "inspect.Signature")
        return ModelResult(
            value=value,
            constraints=[constraint],
            degradations=[_inspect_degradation("callable signature is symbolic or unavailable")],
        )


def _inspect_degradation(reason: str) -> ModelDegradation:
    return ModelDegradation(
        kind="precision_loss",
        label="inspect",
        owner="inspect models",
        reason=reason,
    )


class InspectGetmembersModel(FunctionModel):
    """Return a symbolic member sequence without invoking user descriptors."""

    name = "getmembers"
    qualname = "inspect.getmembers"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args or len(args) > 2 or kwargs:
            value, constraint = SymbolicList.symbolic(f"getmembers_{state.pc}")
            return ModelResult(
                value=value,
                constraints=[constraint],
                side_effects=SideEffects.type_error(self.qualname, "invalid getmembers() call"),
            )
        value, constraint = SymbolicList.symbolic(f"getmembers_{state.pc}")
        return ModelResult(
            value=value,
            constraints=[constraint],
            degradations=[_inspect_degradation("descriptor execution is intentionally suppressed")],
        )


class InspectGetsourceModel(FunctionModel):
    """Represent source lookup as explicit external I/O."""

    name = "getsource"
    qualname = "inspect.getsource"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        value, constraint = SymbolicString.symbolic(f"getsource_{state.pc}")
        if len(args) != 1 or kwargs:
            return ModelResult(
                value=value,
                constraints=[constraint],
                side_effects=SideEffects.type_error(self.qualname, "getsource() takes one object"),
            )
        return ModelResult(
            value=value,
            constraints=[constraint],
            side_effects={"io": True},
            degradations=[_inspect_degradation("source files are not read during analysis")],
        )


inspect_models: list[FunctionModel] = [
    InspectPredicateModel("inspect.isfunction"),
    InspectPredicateModel("inspect.isclass"),
    InspectPredicateModel("inspect.ismodule"),
    InspectPredicateModel("inspect.ismethod"),
    InspectPredicateModel("inspect.iscoroutinefunction"),
    InspectSignatureModel(),
    InspectGetmembersModel(),
    InspectGetsourceModel(),
]
