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

"""Symbol tables and receiver lowering for runtime class invariants."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, cast

from pysymex._internal.contracts.binding.receivers import (
    ContractReceiverProxy,
    receiver_proxy_for_symbols,
)
from pysymex._internal.contracts.binding.snapshots import (
    collect_current_derived_symbols,
    scalar_snapshot_expression,
)
from pysymex._internal.contracts.compiler import ContractCompiler
from pysymex._internal.contracts.invariants.policy import InvariantCheckPoint
from pysymex._internal.contracts.value.expressions import expression_for_contract_value

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    import z3

    from pysymex._internal.contracts.types import Contract
    from pysymex._internal.core.state.record import VMState


def compile_invariant_clause(
    clause: Contract,
    symbols: Mapping[str, z3.ExprRef],
) -> z3.BoolRef:
    """Compile an invariant clause with callable receiver-attribute support."""
    if not callable(clause.predicate):
        return clause.compile(symbols)
    receiver_parameter = _single_callable_parameter(clause.predicate)
    if receiver_parameter is None:
        return clause.compile(symbols)
    receiver_proxy = _invariant_receiver_proxy(symbols, receiver_parameter)
    if receiver_proxy is None:
        receiver_proxy = ContractReceiverProxy(receiver_name=receiver_parameter, attributes={})
    return ContractCompiler.compile_predicate(
        clause.predicate,
        cast("Mapping[str, z3.ExprRef]", {receiver_parameter: receiver_proxy}),
    )


def invariant_symbol_table(
    state: VMState,
    func: Callable[..., object],
    checkpoint: InvariantCheckPoint,
) -> Mapping[str, z3.ExprRef]:
    """Build a side-effect-free symbol table for invariant predicates."""
    if checkpoint is InvariantCheckPoint.ENTRY or "self" not in state.local_vars:
        symbols: dict[str, z3.ExprRef] = dict(_bound_receiver_symbols(func))
    else:
        symbols = {}
    for name, stack_value in state.local_vars.items():
        expr = expression_for_contract_value(stack_value)
        if expr is not None:
            symbols[name] = expr

    local_snapshot = dict(state.local_vars.items())
    symbols.update(collect_current_derived_symbols(local_snapshot, state.memory))
    return symbols


def _single_callable_parameter(predicate: Callable[..., object]) -> str | None:
    """Return the only positional parameter name accepted by a callable predicate."""
    try:
        signature = inspect.signature(predicate)
    except (TypeError, ValueError):
        return None
    parameters = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    if len(parameters) != 1:
        return None
    return parameters[0].name


def _invariant_receiver_proxy(
    symbols: Mapping[str, z3.ExprRef],
    receiver_parameter: str,
) -> ContractReceiverProxy | None:
    """Build a callable invariant receiver proxy from modeled receiver symbols."""
    receiver_proxy = receiver_proxy_for_symbols(symbols, receiver_parameter)
    if receiver_proxy is not None or receiver_parameter == "self":
        return receiver_proxy

    self_proxy = receiver_proxy_for_symbols(symbols, "self")
    if self_proxy is None:
        return None
    return ContractReceiverProxy(
        receiver_name=receiver_parameter,
        attributes=self_proxy.attributes,
    )


def _bound_receiver_symbols(func: Callable[..., object]) -> Mapping[str, z3.ExprRef]:
    """Expose shallow scalar attributes for a concrete bound receiver."""
    receiver = getattr(func, "__self__", None)
    if receiver is None or isinstance(receiver, type):
        return {}
    try:
        attrs = object.__getattribute__(receiver, "__dict__")
    except AttributeError:
        return {}
    if not isinstance(attrs, dict):
        return {}

    typed_attrs = cast("dict[object, object]", attrs)
    symbols: dict[str, z3.ExprRef] = {}
    for attr_name, attr_value in sorted(typed_attrs.items(), key=lambda item: str(item[0])):
        if not isinstance(attr_name, str):
            continue
        expr = scalar_snapshot_expression(attr_value)
        if expr is not None:
            symbols[f"self.{attr_name}"] = expr
    return symbols
