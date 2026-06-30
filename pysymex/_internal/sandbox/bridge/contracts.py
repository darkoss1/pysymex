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

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.sandbox.bridge.schema import (
    FUNCTION_CONTRACT_CLAUSE_KEYS,
    FUNCTION_CONTRACT_KEYS,
    ExtractionLimits,
    SandboxSchema,
    UnsupportedSandboxCallable,
)

if TYPE_CHECKING:
    from types import CellType

    from pysymex._internal.contracts.types import Contract, FunctionContract


def decode_optional_function_contract(
    value: object,
    *,
    function_name: str,
    limits: ExtractionLimits,
) -> FunctionContract | None:
    """Decode serialized function-contract metadata from a target payload.

    Args:
        value: Serialized contract mapping, or `None` when no contract was
            captured by the extraction worker.
        function_name: Fallback target name when the serialized contract name
            is empty.
        limits: String and collection limits applied while decoding.

    Returns:
        A reconstructed `FunctionContract`, or `None` when `value` is `None`.

    Raises:
        ValueError: If the contract mapping, fields, or nested clauses violate
            the bridge schema or declared limits.

    Notes:
        Callable predicates are represented by
        `UnsupportedSandboxCallableContract`; this function does not execute
        callable contract code from the sandbox payload.

    """
    if value is None:
        return None

    from pysymex._internal.contracts.types import ContractKind, FunctionContract

    data = SandboxSchema.object(value, "target.contract")
    SandboxSchema.reject_unexpected(data, FUNCTION_CONTRACT_KEYS, "target.contract")

    declared_name = SandboxSchema.str(
        data["function_name"],
        "target.contract.function_name",
        max_length=limits.max_name_length,
    )
    contract = FunctionContract(function_name=declared_name or function_name)
    contract.preconditions.extend(
        _decode_contract_clauses(
            data["preconditions"],
            context="target.contract.preconditions",
            expected_kind=ContractKind.REQUIRES,
            limits=limits,
        ),
    )
    contract.postconditions.extend(
        _decode_contract_clauses(
            data["postconditions"],
            context="target.contract.postconditions",
            expected_kind=ContractKind.ENSURES,
            limits=limits,
        ),
    )
    return contract


def _decode_contract_clauses(
    value: object,
    *,
    context: str,
    expected_kind: object,
    limits: ExtractionLimits,
) -> list[Contract]:
    """Decode one precondition or postcondition clause collection.

    Args:
        value: Serialized clause list from a function-contract payload.
        context: Context prefix used in validation failure messages.
        expected_kind: Contract kind required for every decoded clause.
        limits: String and collection limits applied while decoding.

    Returns:
        Decoded contract clauses preserving message, severity, condition text,
        and optional line metadata.

    Raises:
        ValueError: If a clause has unexpected fields, an unexpected contract
            kind, an unknown severity, or an unsupported predicate encoding.

    """
    from pysymex._internal.contracts.types import (
        Contract,
        ContractKind,
        ContractSeverity,
        ContractPredicate,
    )

    clauses: list[Contract] = []
    raw_clauses = SandboxSchema.list(value, context, limits.max_consts)
    for index, item in enumerate(raw_clauses):
        clause_context = f"{context}[{index}]"
        data = SandboxSchema.object(item, clause_context)
        SandboxSchema.reject_unexpected(data, FUNCTION_CONTRACT_CLAUSE_KEYS, clause_context)
        kind_name = SandboxSchema.str(
            data["kind"],
            f"{clause_context}.kind",
            max_length=limits.max_name_length,
        )
        kind = ContractKind.__members__.get(kind_name)
        if kind is None:
            msg = f"{clause_context}.kind: unknown contract kind {kind_name!r}"
            raise ValueError(msg)
        if kind is not expected_kind:
            msg = f"{clause_context}.kind: unexpected contract kind {kind_name!r}"
            raise ValueError(msg)
        predicate_kind = SandboxSchema.str(
            data["predicate_kind"],
            f"{clause_context}.predicate_kind",
            max_length=limits.max_name_length,
        )
        condition = SandboxSchema.str(
            data["condition"],
            f"{clause_context}.condition",
            max_length=limits.max_string_length,
        )
        if predicate_kind == "string":
            predicate = SandboxSchema.str(
                data["predicate"],
                f"{clause_context}.predicate",
                max_length=limits.max_string_length,
            )
        elif predicate_kind == "unsupported_callable":
            predicate = cast(
                "ContractPredicate",
                UnsupportedSandboxCallable(condition=condition),
            )
        else:
            msg = f"{clause_context}.predicate_kind: unsupported predicate kind {predicate_kind!r}"
            raise ValueError(
                msg,
            )
        message = SandboxSchema.str(
            data["message"],
            f"{clause_context}.message",
            max_length=limits.max_string_length,
        )
        severity_name = SandboxSchema.str(
            data["severity"],
            f"{clause_context}.severity",
            max_length=limits.max_name_length,
        )
        severity = ContractSeverity.__members__.get(severity_name)
        if severity is None:
            msg = f"{clause_context}.severity: unknown severity {severity_name!r}"
            raise ValueError(msg)
        line_value = data["line_number"]
        if line_value is None:
            line_number = None
        else:
            line_number = SandboxSchema.int(
                line_value,
                f"{clause_context}.line_number",
                minimum=0,
            )
        clauses.append(
            Contract(
                kind=kind,
                predicate=predicate,
                message=message,
                severity=severity,
                line_number=line_number,
                _condition_repr=condition,
            ),
        )
    return clauses


def make_cell(value: object) -> CellType:
    """Create one closure cell containing a decoded closure value.

    Args:
        value: Reconstructed value to capture in the returned cell.

    Returns:
        A Python closure cell containing `value`.

    Raises:
        ValueError: If Python does not expose the closure cell created by the
            local capture function.

    """

    def _inner() -> object:
        """Expose `value` through a closure cell for reconstruction."""
        return value

    closure = _inner.__closure__
    if closure is None:
        msg = "Failed to create closure cell"
        raise ValueError(msg)
    return closure[0]
