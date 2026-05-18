# pysymex: Python Symbolic Execution & Formal Verification
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

import dis
from collections.abc import Iterable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState

import z3
from pysymex._typing import is_list_of_objects as _is_list_of_objects
from pysymex._typing import is_tuple_of_objects as _is_tuple_of_objects
from pysymex.core.solver.engine import get_model
from pysymex.core.types import SymbolicString, SymbolicValue
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn
from pysymex.analysis.detectors.runtime.division_by_zero import extract_argc
from pysymex.analysis.detectors.runtime.overflow import as_symbolic_int, resolve_binary_op_symbol


def _resolve_call_target_name(state: VMState, argc: int) -> str | None:
    """Resolve call target name from stack around call arguments."""
    candidate_indices = (len(state.stack) - argc - 1, len(state.stack) - argc - 2)
    for index in candidate_indices:
        if index < 0 or index >= len(state.stack):
            continue
        candidate = state.stack[index]
        candidate_type_name = type(candidate).__name__
        if candidate_type_name == "SymbolicNone":
            continue
        for attr in ("__name__", "__qualname__", "qualname", "name", "origin"):
            value = getattr(candidate, attr, None)
            if isinstance(value, str) and value:
                lowered = value.lower()
                if lowered in {"none", "null", "push_null_none"}:
                    continue
                return value
    return None


def _iter_potential_exception_values(state: VMState) -> Iterable[tuple[str, object]]:
    """Yield possible exception-bearing values from locals and stack."""
    for local_name, local_value in state.local_vars.items():
        yield local_name, local_value
    for idx, stack_value in enumerate(state.stack):
        yield f"stack_{idx}", stack_value


def _value_error_marker(value: object) -> str | None:
    """Return a marker string when *value* indicates a potential ValueError."""
    potential_exception = getattr(value, "_potential_exception", None)
    if isinstance(potential_exception, str) and potential_exception == "ValueError":
        return "ValueError"
    if _is_tuple_of_objects(potential_exception):
        for tuple_item in potential_exception:
            if isinstance(tuple_item, str) and tuple_item == "ValueError":
                return "ValueError"
    if _is_list_of_objects(potential_exception):
        for list_item in potential_exception:
            if isinstance(list_item, str) and list_item == "ValueError":
                return "ValueError"

    message = getattr(value, "error", None)
    if isinstance(message, str) and "ValueError" in message:
        return message
    return None


def _is_invalid_int_literal(value: object) -> bool:
    """Return True when ``int(value)`` would raise ValueError for common cases."""
    literal = _extract_string_literal(value)
    if literal is None:
        return False
    stripped = literal.strip()
    if not stripped:
        return True
    try:
        int(stripped, 10)
    except ValueError:
        return True
    return False


def _extract_int_base(base_value: object) -> int | None:
    """Extract a concrete integer base when possible."""
    if isinstance(base_value, int):
        return base_value
    if isinstance(base_value, SymbolicValue) and isinstance(base_value.value, int):
        return base_value.value
    return None


def _is_invalid_int_literal_with_base(value: object, base_value: object) -> bool:
    """Return True when ``int(value, base)`` would raise ValueError for concrete inputs."""
    literal = _extract_string_literal(value)
    base = _extract_int_base(base_value)
    if literal is None or base is None:
        return False
    stripped = literal.strip()
    if not stripped:
        return True
    try:
        int(stripped, base)
    except ValueError:
        return True
    return False


def _is_invalid_float_literal(value: object) -> bool:
    """Return True when ``float(value)`` would raise ValueError for common cases."""
    literal = _extract_string_literal(value)
    if literal is None:
        return False
    stripped = literal.strip()
    if not stripped:
        return True
    try:
        float(stripped)
    except ValueError:
        return True
    return False


def _extract_string_literal(value: object) -> str | None:
    """Extract a concrete string literal from concrete or symbolic string values."""
    if isinstance(value, str):
        return value
    if isinstance(value, SymbolicString):
        if z3.is_string_value(value.z3_str):
            return value.z3_str.as_string()
        return None
    if isinstance(value, SymbolicValue):
        if isinstance(value.value, str):
            return value.value
        if z3.is_string_value(value.z3_str):
            return value.z3_str.as_string()
        return None
    return None


def _is_invalid_hex_literal(value: object) -> bool:
    """Return True when ``bytes.fromhex(value)`` would raise ValueError."""
    literal = _extract_string_literal(value)
    if literal is None:
        return False
    try:
        bytes.fromhex(literal)
    except ValueError:
        return True
    return False


_EMPTY_EXACT_TYPES = {
    list,
    tuple,
    set,
    frozenset,
    dict,
    range,
    str,
    bytes,
    bytearray,
}


def _is_known_empty_iterable(value: object, constraints: list[z3.BoolRef]) -> bool:
    """Return True when CPython min/max would see a definitely empty iterable."""
    if type(value) in _EMPTY_EXACT_TYPES:
        return not value

    z3_len = getattr(value, "z3_len", None)
    if isinstance(z3_len, z3.ArithRef):
        solver = z3.Solver()
        solver.add(*constraints)
        solver.add(z3_len != 0)
        return solver.check() == z3.unsat

    return False


class ValueErrorDetector(Detector):
    """Detects potential ValueError exceptions.

    Checks for:
    - str.index() when substring may not be found
    - list.remove() when element may not exist
    - int() with non-numeric strings
    """

    name = "value-error"
    description = "Detects potential ValueError exceptions"
    issue_kind = IssueKind.VALUE_ERROR
    relevant_opcodes = frozenset({"BINARY_OP", "CALL", "CALL_FUNCTION", "CALL_METHOD"})

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check."""
        if instruction.opname == "BINARY_OP":
            return self._check_negative_shift(state, instruction, _solver_check)
        if instruction.opname not in ("CALL", "CALL_FUNCTION", "CALL_METHOD"):
            return None

        def _sat_constraints() -> list[z3.BoolRef] | None:
            constraints = list(state.path_constraints)
            if not _solver_check(constraints):
                return None
            return constraints

        for source_name, source_value in _iter_potential_exception_values(state):
            marker = _value_error_marker(source_value)
            if marker is None:
                continue
            constraints = _sat_constraints()
            if constraints is None:
                return None
            return Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Potential ValueError from {source_name}: {marker}",
                constraints=constraints,
                model=get_model(constraints),
                pc=state.pc,
            )

        argc = extract_argc(instruction)
        if argc <= 0 or len(state.stack) < argc:
            return None
        args = list(state.stack[-argc:])
        target_name = _resolve_call_target_name(state, argc)
        if target_name is None:
            return None

        lowered_target = target_name.lower()
        if lowered_target in {"fromhex", "bytes.fromhex"} and _is_invalid_hex_literal(args[0]):
            constraints = _sat_constraints()
            if constraints is None:
                return None
            return Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Potential ValueError: bytes.fromhex() invalid literal {args[0]!r}",
                constraints=constraints,
                model=get_model(constraints),
                pc=state.pc,
            )
        if lowered_target in {"int", "builtins.int"} and _is_invalid_int_literal(args[0]):
            constraints = _sat_constraints()
            if constraints is None:
                return None
            return Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Potential ValueError: int() invalid literal {args[0]!r}",
                constraints=constraints,
                model=get_model(constraints),
                pc=state.pc,
            )
        if (
            lowered_target in {"int", "builtins.int"}
            and argc >= 2
            and _is_invalid_int_literal_with_base(args[0], args[1])
        ):
            constraints = _sat_constraints()
            if constraints is None:
                return None
            return Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Potential ValueError: int() invalid literal/base combination {args[0]!r}, {args[1]!r}",
                constraints=constraints,
                model=get_model(constraints),
                pc=state.pc,
            )
        if lowered_target in {"float", "builtins.float"} and _is_invalid_float_literal(args[0]):
            constraints = _sat_constraints()
            if constraints is None:
                return None
            return Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Potential ValueError: float() invalid literal {args[0]!r}",
                constraints=constraints,
                model=get_model(constraints),
                pc=state.pc,
            )
        if lowered_target in {"min", "builtins.min", "max", "builtins.max"}:
            if argc != 1:
                return None
            constraints = _sat_constraints()
            if constraints is None or not _is_known_empty_iterable(args[0], constraints):
                return None
            return Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Potential ValueError: {lowered_target}() arg is an empty sequence",
                constraints=constraints,
                model=get_model(constraints),
                pc=state.pc,
            )
        return None

    @staticmethod
    def _check_negative_shift(
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        op_symbol = resolve_binary_op_symbol(instruction)
        op = op_symbol[:-1] if op_symbol.endswith("=") else op_symbol
        if op not in {"<<", ">>"}:
            return None
        if len(state.stack) < 2:
            return None
        right = as_symbolic_int(state.stack[-1])
        if right is None:
            return None
        constraints = [
            *state.path_constraints,
            z3.Or(right.is_int, right.is_bool),
            right.z3_int < 0,
        ]
        if not is_satisfiable_fn(constraints):
            return None
        return Issue(
            kind=IssueKind.VALUE_ERROR,
            message=f"Potential ValueError: negative shift count for {op}",
            constraints=constraints,
            model=get_model(constraints),
            pc=state.pc,
        )
