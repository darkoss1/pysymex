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

"""Extract retained PySyMex contract decorators from class-body bytecode."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.contracts.enums import EffectKind
from pysymex._internal.contracts.types import ContractPredicate, FunctionContract
from pysymex._internal.core.calls.payload import SymbolicFunctionPayload, with_contract
from pysymex._internal.execution.opcodes.common.functions.classes.metadata.stack import (
    UNKNOWN_METADATA,
    ConstToken,
    ContractFactoryToken,
    NameToken,
    build_tuple,
    previous_class_body_store_index,
)

if TYPE_CHECKING:
    import dis
    import types
    from collections.abc import Sequence

_CONTRACT_FACTORY_DECORATORS = frozenset(("requires", "ensures", "assumes", "assigns"))
_CONTRACT_DIRECT_DECORATORS = frozenset(("pure",))


def with_contract_metadata(
    value: types.CodeType | SymbolicFunctionPayload,
    contract: FunctionContract | None,
) -> types.CodeType | SymbolicFunctionPayload:
    """Attach statically extracted contract metadata when present."""
    if contract is None:
        return value
    payload = (
        value if isinstance(value, SymbolicFunctionPayload) else SymbolicFunctionPayload(value)
    )
    return with_contract(payload, contract)


def contract_from_class_body_decorators(
    instructions: Sequence[dis.Instruction],
    code: types.CodeType,
    contract_decorator_names: frozenset[str],
) -> FunctionContract | None:
    """Return contract metadata from recognized PySyMex class-body decorators."""
    if not contract_decorator_names:
        return None
    code_index = _code_index_for_code(instructions, code)
    if code_index is None:
        return None
    boundary = previous_class_body_store_index(instructions, code_index)
    specs = _contract_decorator_specs(
        instructions[boundary + 1 : code_index],
        contract_decorator_names,
    )
    if not specs:
        return None

    contract = FunctionContract(function_name=code.co_name)
    for name, args in specs:
        line = code.co_firstlineno
        if name == "requires" and args:
            contract.add_precondition(
                cast("ContractPredicate", args[0]),
                _optional_message(args),
                line,
            )
        elif name == "ensures" and args:
            contract.add_postcondition(
                cast("ContractPredicate", args[0]),
                _optional_message(args),
                line,
            )
        elif name == "assumes" and args:
            contract.add_assumption(
                cast("ContractPredicate", args[0]),
                _optional_message(args),
                line,
            )
        elif name == "assigns":
            locations = tuple(arg for arg in args if isinstance(arg, str))
            if len(locations) == len(args):
                contract.set_assigns(frozenset(locations))
        elif name == "pure":
            contract.set_pure()
    if (
        contract.preconditions
        or contract.postconditions
        or contract.assumptions
        or contract.assigns_declared
        or contract.effect_type is EffectKind.PURE
    ):
        return contract
    return None


def _code_index_for_code(
    instructions: Sequence[dis.Instruction],
    code: types.CodeType,
) -> int | None:
    """Return the ``LOAD_CONST`` index that pushes *code* for ``MAKE_FUNCTION``."""
    for index, instr in enumerate(instructions):
        if instr.opname == "LOAD_CONST" and instr.argval is code:
            return index
    return None


def _contract_decorator_specs(
    instructions: Sequence[dis.Instruction],
    contract_decorator_names: frozenset[str],
) -> tuple[tuple[str, tuple[object, ...]], ...]:
    """Extract bounded contract decorator specs from pre-function bytecode."""
    stack: list[object] = []
    for instr in instructions:
        if instr.opname in {"CACHE", "COPY_FREE_VARS", "LOAD_LOCALS", "PRECALL", "PUSH_NULL"}:
            continue
        if instr.opname in {
            "LOAD_CLASSDEREF",
            "LOAD_DEREF",
            "LOAD_FAST",
            "LOAD_FAST_CHECK",
            "LOAD_FROM_DICT_OR_DEREF",
            "LOAD_GLOBAL",
            "LOAD_NAME",
        } and isinstance(instr.argval, str):
            stack.append(NameToken(instr.argval))
        elif instr.opname == "LOAD_CONST":
            stack.append(ConstToken(instr.argval))
        elif instr.opname == "CALL":
            _apply_contract_decorator_call(stack, int(instr.arg or 0), contract_decorator_names)
        elif instr.opname == "BUILD_TUPLE":
            build_tuple(stack, int(instr.arg or 0))
        else:
            stack.append(UNKNOWN_METADATA)

    specs: list[tuple[str, tuple[object, ...]]] = []
    for item in stack:
        if isinstance(item, NameToken) and _is_direct_contract_decorator(
            item,
            contract_decorator_names,
        ):
            specs.append((item.name, ()))
        elif isinstance(item, ContractFactoryToken) and item.name in contract_decorator_names:
            specs.append((item.name, item.args))
    return tuple(specs)


def _apply_contract_decorator_call(
    stack: list[object],
    arg_count: int,
    contract_decorator_names: frozenset[str],
) -> None:
    """Apply a bounded decorator-factory call on the simulated stack."""
    if arg_count < 0 or len(stack) < arg_count + 1:
        stack.append(UNKNOWN_METADATA)
        return
    raw_args = stack[-arg_count:] if arg_count else []
    callee = stack[-arg_count - 1]
    del stack[-arg_count - 1 :]
    if not isinstance(callee, NameToken) or not _is_named_contract_factory(
        callee,
        contract_decorator_names,
    ):
        stack.append(UNKNOWN_METADATA)
        return
    literal_args: list[object] = []
    for raw_arg in raw_args:
        if not isinstance(raw_arg, ConstToken) or not _is_literal_contract_arg(raw_arg):
            stack.append(UNKNOWN_METADATA)
            return
        literal_args.append(raw_arg.value)
    stack.append(ContractFactoryToken(callee.name, tuple(literal_args)))


def _is_named_contract_factory(
    item: NameToken,
    contract_decorator_names: frozenset[str],
) -> bool:
    return item.name in _CONTRACT_FACTORY_DECORATORS and item.name in contract_decorator_names


def _is_direct_contract_decorator(
    item: NameToken,
    contract_decorator_names: frozenset[str],
) -> bool:
    return item.name in _CONTRACT_DIRECT_DECORATORS and item.name in contract_decorator_names


def _is_literal_contract_arg(item: ConstToken) -> bool:
    return isinstance(item.value, (bool, int, float, str, bytes, type(None)))


def _optional_message(args: tuple[object, ...]) -> str | None:
    if len(args) >= 2 and isinstance(args[1], str):
        return args[1]
    return None
