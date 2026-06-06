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

"""Detect ``ValueError`` exceptions raised by type conversions, empty-sequence operations, and shifts.

Bug class:
    ``ValueError`` — invalid literal passed to ``int()``/``float()``/``bytes.fromhex()``,
    empty sequence passed to ``min()``/``max()``, or negative shift count.

Evidence:
    Path constraints are satisfiable when the bad input is constrained to an
    invalid literal or provably empty/negative value.

Issue kind:
    ``IssueKind.VALUE_ERROR``.
"""

from __future__ import annotations

import dis
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

import z3
from pysymex.typing import is_list_of_objects
from pysymex.typing import is_tuple_of_objects
from pysymex.analysis.detectors.calls import (
    extract_argc,
    resolve_call_target_name as _resolve_call_target_name,
)
from pysymex.analysis.detectors.detector.contract import Detector
from pysymex.analysis.detectors.detector.types import IsSatFn, Issue, IssueKind
from pysymex.analysis.detectors.feasibility import get_model_if_satisfiable
from pysymex.analysis.detectors.runtime.value_error.literals import (
    extract_string_literal,
    is_invalid_float_literal,
    is_invalid_hex_literal,
    is_invalid_int_literal,
    is_invalid_int_literal_with_base,
    is_known_empty_iterable,
)
from pysymex.analysis.detectors.runtime.overflow import as_symbolic_int, resolve_binary_op_symbol


def resolve_call_target_name(state: VMState, argc: int) -> str | None:
    """Resolve call target name from stack around call arguments."""
    return _resolve_call_target_name(state, argc, prefer_pre_null=False)


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
    if is_tuple_of_objects(potential_exception):
        for tuple_item in potential_exception:
            if isinstance(tuple_item, str) and tuple_item == "ValueError":
                return "ValueError"
    if is_list_of_objects(potential_exception):
        for list_item in potential_exception:
            if isinstance(list_item, str) and list_item == "ValueError":
                return "ValueError"

    message = getattr(value, "error", None)
    if isinstance(message, str) and "ValueError" in message:
        return message
    return None


def _string_literal_repr(value: object) -> str:
    """Get a string representation of the value, extracting literal strings when possible.

    Args:
        value (object): The value to represent.

    Returns:
        str: The repr string.
    """
    literal = extract_string_literal(value)
    if literal is not None:
        return repr(literal)
    return repr(value)


class ValueErrorDetector(Detector):
    """Detect ``ValueError`` exceptions from type conversions and sequence operations.

    Bug class:
        ``ValueError`` from: ``int()``/``float()``/``bytes.fromhex()`` called
        with an invalid literal, ``min()``/``max()`` on an empty sequence, or
        left/right bit-shift with a negative shift count.

    Evidence:
        Satisfiable path constraints when the bad-value condition holds.

    Issue kind:
        ``IssueKind.VALUE_ERROR``.

    Known false-positive conditions:
        - Invalid-literal checks are purely syntactic; symbolic strings that
          happen to be invalid are detected but concrete-valid strings are not.
        - Empty-sequence check delegates to :func:`is_known_empty_iterable`;
          dynamic/unknown-length iterables are not checked.
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
        """Inspect *instruction* for a potential ``ValueError``.

        Dispatches to :meth:`_check_negative_shift` for ``BINARY_OP``, or
        checks stack state and call target for CALL opcodes.
        """
        if instruction.opname == "BINARY_OP":
            return self._check_negative_shift(state, instruction, _solver_check)
        if instruction.opname not in ("CALL", "CALL_FUNCTION", "CALL_METHOD"):
            return None

        def _sat_constraints() -> tuple[list[z3.BoolRef], z3.ModelRef | dict[str, object]] | None:
            constraints = list(state.path_constraints)
            model = get_model_if_satisfiable(constraints, _solver_check)
            if model is None:
                return None
            return constraints, model

        for source_name, source_value in _iter_potential_exception_values(state):
            marker = _value_error_marker(source_value)
            if marker is None:
                continue
            sat_evidence = _sat_constraints()
            if sat_evidence is None:
                return None
            constraints, model = sat_evidence
            return Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Potential ValueError from {source_name}: {marker}",
                constraints=constraints,
                model=model,
                pc=state.pc,
            )

        argc = extract_argc(instruction)
        if argc <= 0 or len(state.stack) < argc:
            return None
        args = list(state.stack[-argc:])
        target_name = resolve_call_target_name(state, argc)
        if target_name is None:
            return None

        lowered_target = target_name.lower()
        if lowered_target in {"range", "builtins.range"}:
            range_issue = self._check_range_zero_step(state, args, _solver_check)
            if range_issue is not None:
                return range_issue
        if (
            lowered_target in {"fromhex", "bytes.fromhex"}
            and argc == 1
            and is_invalid_hex_literal(args[0])
        ):
            sat_evidence = _sat_constraints()
            if sat_evidence is None:
                return None
            constraints, model = sat_evidence
            literal_repr = _string_literal_repr(args[0])
            return Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Potential ValueError: bytes.fromhex() invalid literal {literal_repr}",
                constraints=constraints,
                model=model,
                pc=state.pc,
            )
        if (
            lowered_target in {"int", "builtins.int"}
            and argc == 1
            and is_invalid_int_literal(args[0])
        ):
            sat_evidence = _sat_constraints()
            if sat_evidence is None:
                return None
            constraints, model = sat_evidence
            literal_repr = _string_literal_repr(args[0])
            return Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Potential ValueError: int() invalid literal {literal_repr}",
                constraints=constraints,
                model=model,
                pc=state.pc,
            )
        if (
            lowered_target in {"int", "builtins.int"}
            and argc == 2
            and is_invalid_int_literal_with_base(args[0], args[1])
        ):
            sat_evidence = _sat_constraints()
            if sat_evidence is None:
                return None
            constraints, model = sat_evidence
            literal_repr = _string_literal_repr(args[0])
            return Issue(
                kind=IssueKind.VALUE_ERROR,
                message=(
                    "Potential ValueError: int() invalid literal/base combination "
                    f"{literal_repr}, {args[1]!r}"
                ),
                constraints=constraints,
                model=model,
                pc=state.pc,
            )
        if (
            lowered_target in {"float", "builtins.float"}
            and argc == 1
            and is_invalid_float_literal(args[0])
        ):
            sat_evidence = _sat_constraints()
            if sat_evidence is None:
                return None
            constraints, model = sat_evidence
            literal_repr = _string_literal_repr(args[0])
            return Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Potential ValueError: float() invalid literal {literal_repr}",
                constraints=constraints,
                model=model,
                pc=state.pc,
            )
        if lowered_target in {"min", "builtins.min", "max", "builtins.max"}:
            if argc != 1:
                return None
            sat_evidence = _sat_constraints()
            if sat_evidence is None:
                return None
            constraints, model = sat_evidence
            if not is_known_empty_iterable(args[0], constraints):
                return None
            return Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Potential ValueError: {lowered_target}() arg is an empty sequence",
                constraints=constraints,
                model=model,
                pc=state.pc,
            )
        return None

    @staticmethod
    def _check_range_zero_step(
        state: VMState,
        args: Sequence[object],
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check ``range(start, stop, step)`` for a satisfiable zero step."""
        if len(args) != 3:
            return None
        step = as_symbolic_int(args[2])
        if step is None:
            return None
        constraints = [
            *state.path_constraints,
            z3.Or(step.is_int, step.is_bool),
            step.z3_int == 0,
        ]
        model = get_model_if_satisfiable(constraints, is_satisfiable_fn)
        if model is None:
            return None
        return Issue(
            kind=IssueKind.VALUE_ERROR,
            message="Potential ValueError: range() arg 3 must not be zero",
            constraints=constraints,
            model=model,
            pc=state.pc,
        )

    @staticmethod
    def _check_negative_shift(
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check for a bitwise shift with a potentially negative shift count.

        Args:
            state: The virtual machine state.
            instruction: The ``BINARY_OP`` shift instruction.
            is_satisfiable_fn: SAT oracle callback.

        Returns:
            An :class:`Issue` if a negative shift count is satisfiable,
            ``None`` otherwise.
        """
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
        model = get_model_if_satisfiable(constraints, is_satisfiable_fn)
        if model is None:
            return None
        return Issue(
            kind=IssueKind.VALUE_ERROR,
            message=f"Potential ValueError: negative shift count for {op}",
            constraints=constraints,
            model=model,
            pc=state.pc,
        )
