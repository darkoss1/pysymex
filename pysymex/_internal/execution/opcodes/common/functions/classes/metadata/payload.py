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

"""Retain class-body function metadata for modeled methods and properties."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from pysymex._internal.core.calls.payload import SymbolicFunctionPayload
from pysymex._internal.execution.opcodes.common.functions.classes.metadata.contracts import (
    contract_from_class_body_decorators,
    with_contract_metadata,
)
from pysymex._internal.execution.opcodes.common.functions.classes.metadata.payloads import (
    closure_from_names,
    has_call_semantic_metadata,
    payload_from_make_function,
    payload_with_closure,
)

if TYPE_CHECKING:
    import dis
    import types
    from collections.abc import Mapping, Sequence

    from pysymex._internal.contracts.types import FunctionContract


def class_body_function_payload(
    instructions: Sequence[dis.Instruction],
    code: types.CodeType | None,
    closure_by_name: Mapping[str, object] | None,
    contract_decorator_names: frozenset[str] = frozenset(),
) -> types.CodeType | SymbolicFunctionPayload | None:
    """Return method code plus class-body defaults, annotations, and closures when retained."""
    if code is None:
        return None

    contract = contract_from_class_body_decorators(instructions, code, contract_decorator_names)
    payload = payload_from_make_function(instructions, code, closure_by_name)
    if payload is None:
        return with_contract_metadata(payload_with_closure(code, closure_by_name), contract)

    if payload.closure:
        return with_contract_metadata(payload, contract)
    if not code.co_freevars or not closure_by_name:
        return _payload_or_code(code, payload, contract)

    closure = closure_from_names(code, closure_by_name)
    if closure is None:
        return _payload_or_code(code, payload, contract)
    return with_contract_metadata(replace(payload, closure=closure), contract)


def _payload_or_code(
    code: types.CodeType,
    payload: SymbolicFunctionPayload,
    contract: FunctionContract | None,
) -> types.CodeType | SymbolicFunctionPayload:
    """Return retained payload only when metadata can affect later call semantics."""
    payload_with_contract = with_contract_metadata(payload, contract)
    if isinstance(payload_with_contract, SymbolicFunctionPayload) and has_call_semantic_metadata(
        payload_with_contract,
    ):
        return payload_with_contract
    return code
