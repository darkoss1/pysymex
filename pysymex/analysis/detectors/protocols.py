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

"""Protocol checking for structural typing verification.

Checks whether concrete types satisfy protocol requirements using
the type constraint checker.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol as TypingProtocol, runtime_checkable

if TYPE_CHECKING:
    from pysymex.analysis.type_constraints.types import SymbolicType, TypeIssue
    from pysymex.analysis.type_constraints import TypeConstraintChecker


def _new_symbolic_type_map() -> dict[str, SymbolicType]:
    """Create an empty ``str -> SymbolicType`` mapping."""
    return {}


@dataclass
class Protocol:
    """Represents a structural protocol (like typing.Protocol)."""

    name: str
    required_methods: dict[str, SymbolicType] = field(default_factory=_new_symbolic_type_map)
    required_attributes: dict[str, SymbolicType] = field(default_factory=_new_symbolic_type_map)


class ProtocolChecker:
    """Checks if types satisfy protocols."""

    def __init__(self, type_checker: TypeConstraintChecker) -> None:
        self.type_checker = type_checker

    def check_protocol_satisfaction(
        self,
        concrete_type: SymbolicType,
        protocol: Protocol,
        available_methods: dict[str, SymbolicType],
        available_attributes: dict[str, SymbolicType],
    ) -> list[TypeIssue]:
        """Check if concrete type satisfies protocol requirements."""
        from pysymex.analysis.type_constraints.types import TypeIssue, TypeIssueKind

        issues: list[TypeIssue] = []
        for method_name, expected_type in protocol.required_methods.items():
            if method_name not in available_methods:
                issues.append(
                    TypeIssue(
                        kind=TypeIssueKind.PROTOCOL_NOT_SATISFIED,
                        message=f"Missing method '{method_name}' required by protocol '{protocol.name}'",
                        expected_type=expected_type,
                    )
                )
            else:
                actual_type = available_methods[method_name]
                is_sub, _reason = self.type_checker.is_subtype(actual_type, expected_type)
                if not is_sub:
                    issues.append(
                        TypeIssue(
                            kind=TypeIssueKind.PROTOCOL_NOT_SATISFIED,
                            message=f"Method '{method_name}' has incompatible type for protocol '{protocol.name}'",
                            expected_type=expected_type,
                            actual_type=actual_type,
                        )
                    )
        for attr_name, expected_type in protocol.required_attributes.items():
            if attr_name not in available_attributes:
                issues.append(
                    TypeIssue(
                        kind=TypeIssueKind.PROTOCOL_NOT_SATISFIED,
                        message=f"Missing attribute '{attr_name}' required by protocol '{protocol.name}'",
                        expected_type=expected_type,
                    )
                )
            else:
                actual_type = available_attributes[attr_name]
                is_sub, _reason = self.type_checker.is_subtype(actual_type, expected_type)
                if not is_sub:
                    issues.append(
                        TypeIssue(
                            kind=TypeIssueKind.PROTOCOL_NOT_SATISFIED,
                            message=f"Attribute '{attr_name}' has incompatible type for protocol '{protocol.name}'",
                            expected_type=expected_type,
                            actual_type=actual_type,
                        )
                    )
        return issues


class ScanReporter(TypingProtocol):
    """Protocol for scanner reporting sinks used by scanner.core."""

    def on_status(self, message: str) -> None: ...
    def on_issue(self, issue: dict[str, object]) -> None: ...
    def on_error(self, file_path: object, error: str) -> None: ...
    def on_progress(
        self, completed: int, total: int, file_path: object, result: object | None
    ) -> None: ...
    def on_summary(self, results: Sequence[object], total_files: int) -> None: ...


@runtime_checkable
class ExecutionContextLike(TypingProtocol):
    """Minimal hook-registration protocol used by executor integration tests."""

    def register_hook(self, hook_name: str, callback: object) -> None: ...


__all__ = [
    "Protocol",
    "ProtocolChecker",
    "ScanReporter",
]
