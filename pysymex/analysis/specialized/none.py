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

"""None-check awareness for reducing false positives.

This module tracks `if x is not None` guards to understand when
variables have been validated, reducing false positives for None-related issues.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from enum import Enum, auto


class NoneCheckType(Enum):
    """Types of None checks."""

    IS_NONE = auto()
    IS_NOT_NONE = auto()
    EQUALS_NONE = auto()
    NOT_EQUALS_NONE = auto()
    TRUTHINESS = auto()
    FALSINESS = auto()


@dataclass(frozen=True, slots=True)
class NoneCheck:
    """Information about a None check in the code."""

    variable_name: str
    check_type: NoneCheckType
    line_number: int | None = None
    pc: int | None = None
    is_parameter: bool = False


@dataclass(slots=True)
class NoneCheckState:
    """Tracks which variables have been None-checked in the current path."""

    confirmed_not_none: set[str] = field(default_factory=set[str])

    confirmed_none: set[str] = field(default_factory=set[str])

    unchecked: set[str] = field(default_factory=set[str])

    def mark_not_none(self, var_name: str) -> None:
        """Mark a variable as confirmed not None."""
        self.confirmed_not_none.add(var_name)
        self.confirmed_none.discard(var_name)
        self.unchecked.discard(var_name)

    def mark_none(self, var_name: str) -> None:
        """Mark a variable as confirmed None."""
        self.confirmed_none.add(var_name)
        self.confirmed_not_none.discard(var_name)
        self.unchecked.discard(var_name)

    def mark_unchecked(self, var_name: str) -> None:
        """Mark a variable as needing checking."""
        self.unchecked.add(var_name)
        self.confirmed_not_none.discard(var_name)
        self.confirmed_none.discard(var_name)

    def is_known_not_none(self, var_name: str) -> bool:
        """Check if variable is confirmed not None."""
        return var_name in self.confirmed_not_none

    def is_known_none(self, var_name: str) -> bool:
        """Check if variable is confirmed None."""
        return var_name in self.confirmed_none

    def copy(self) -> NoneCheckState:
        """Create a copy of the state."""
        return NoneCheckState(
            confirmed_not_none=set(self.confirmed_not_none),
            confirmed_none=set(self.confirmed_none),
            unchecked=set(self.unchecked),
        )

    def merge(self, other: NoneCheckState) -> NoneCheckState:
        """Merge two states (for joining branches)."""
        return NoneCheckState(
            confirmed_not_none=self.confirmed_not_none & other.confirmed_not_none,
            confirmed_none=self.confirmed_none & other.confirmed_none,
            unchecked=self.unchecked | other.unchecked,
        )


class NoneCheckAnalyzer:
    """Analyzes code to detect and track None checks."""

    NONE_CHECK_PATTERNS = [
        (r"\b(\w+)\s+is\s+not\s+None\b", NoneCheckType.IS_NOT_NONE),
        (r"\b(\w+)\s+is\s+None\b", NoneCheckType.IS_NONE),
        (r"\b(\w+)\s*!=\s*None\b", NoneCheckType.NOT_EQUALS_NONE),
        (r"\b(\w+)\s*==\s*None\b", NoneCheckType.EQUALS_NONE),
        (r"\bif\s+(\w+)\s*:", NoneCheckType.TRUTHINESS),
        (r"\bif\s+not\s+(\w+)\s*:", NoneCheckType.FALSINESS),
    ]

    def __init__(self) -> None:
        """Initialize the analyzer."""
        self._state = NoneCheckState()
        self._checks: list[NoneCheck] = []

    def analyze_source(self, source_code: str) -> list[NoneCheck]:
        """Extract None checks from source code.

        Args:
            source_code: The source code to analyze

        Returns:
            List of detected None checks
        """
        checks: list[NoneCheck] = []

        for line_num, line in enumerate(source_code.split("\n"), 1):
            for pattern, check_type in self.NONE_CHECK_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    var_name = match.group(1)
                    checks.append(
                        NoneCheck(
                            variable_name=var_name,
                            check_type=check_type,
                            line_number=line_num,
                        )
                    )

        return checks

    def analyze_ast_condition(self, node: ast.Compare) -> NoneCheck | None:
        """Analyze an AST Compare node for None checks.

        Args:
            node: AST Compare node

        Returns:
            NoneCheck if this is a None check, None otherwise
        """
        if len(node.ops) != 1 or len(node.comparators) != 1:
            return None

        op = node.ops[0]
        comparator = node.comparators[0]

        if not isinstance(comparator, ast.Constant) or comparator.value is not None:
            if not isinstance(node.left, ast.Constant) or node.left.value is not None:
                return None
            var_node = comparator
        else:
            var_node = node.left

        if isinstance(var_node, ast.Name):
            var_name = var_node.id
        elif isinstance(var_node, ast.Attribute):
            var_name = f"{self._get_attr_name(var_node)}"
        else:
            return None

        match op:
            case ast.Is():
                check_type = NoneCheckType.IS_NONE
            case ast.IsNot():
                check_type = NoneCheckType.IS_NOT_NONE
            case ast.Eq():
                check_type = NoneCheckType.EQUALS_NONE
            case ast.NotEq():
                check_type = NoneCheckType.NOT_EQUALS_NONE
            case _:
                return None

        return NoneCheck(variable_name=var_name, check_type=check_type)

    def _get_attr_name(self, node: ast.Attribute) -> str:
        """Get the full attribute name (e.g., 'self.x')."""
        if isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        if isinstance(node.value, ast.Attribute):
            return f"{self._get_attr_name(node.value)}.{node.attr}"
        return node.attr

    def update_state_for_check(
        self,
        check: NoneCheck,
        in_true_branch: bool,
    ) -> None:
        """Update state based on a None check and which branch we're in.

        Args:
            check: The None check that was performed
            in_true_branch: Whether we're in the true branch of the condition
        """
        self._state = apply_none_check(self._state, check, in_true_branch)

    def is_none_safe(self, var_name: str) -> bool:
        """Check if a variable dereference is safe (known not None).

        Args:
            var_name: Variable name to check

        Returns:
            True if the variable is known to not be None
        """
        return self._state.is_known_not_none(var_name)

    def get_state(self) -> NoneCheckState:
        """Get the current state."""
        return self._state

    def set_state(self, state: NoneCheckState) -> None:
        """Set the current state."""
        self._state = state


def apply_none_check(
    state: NoneCheckState,
    check: NoneCheck,
    in_true_branch: bool,
) -> NoneCheckState:
    """Pure function: apply a None check to a state, returning a new state.

    Args:
        state: The current NoneCheckState
        check: The None check that was performed
        in_true_branch: Whether we're in the true branch of the condition

    Returns:
        A new NoneCheckState with the check applied
    """
    new_state = state.copy()
    if check.check_type in (NoneCheckType.IS_NOT_NONE, NoneCheckType.NOT_EQUALS_NONE):
        if in_true_branch:
            new_state.mark_not_none(check.variable_name)
        else:
            new_state.mark_none(check.variable_name)

    elif check.check_type in (NoneCheckType.IS_NONE, NoneCheckType.EQUALS_NONE):
        if in_true_branch:
            new_state.mark_none(check.variable_name)
        else:
            new_state.mark_not_none(check.variable_name)

    elif check.check_type == NoneCheckType.TRUTHINESS:
        if in_true_branch:
            new_state.mark_not_none(check.variable_name)

    elif check.check_type == NoneCheckType.FALSINESS:
        if not in_true_branch:
            new_state.mark_not_none(check.variable_name)

    return new_state


def extract_variable_from_expression(expr: str) -> str | None:
    """Extract the base variable name from an expression.

    Args:
        expr: Expression string like 'x.y.z' or 'x[0]'

    Returns:
        Base variable name or None
    """
    if "." in expr:
        return expr.split(".", maxsplit=1)[0]

    if "[" in expr:
        return expr.split("[", maxsplit=1)[0]

    if re.match(r"^\w+$", expr):
        return expr

    return None


def is_none_check_in_message(message: str) -> tuple[bool, str | None]:
    """Check if an issue message indicates a None-related error.

    Args:
        message: The issue message

    Returns:
        Tuple of (is_none_related, variable_name)
    """
    patterns = [
        r"'(\w+)' may be None",
        r"NoneType.*'(\w+)'",
        r"(\w+) could be None",
        r"accessing attribute on None.*'(\w+)'",
    ]

    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return True, match.group(1)

    return False, None
