# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""
Function Summary type definitions for pysymex.
Phase 20: Inter-procedural analysis through function summaries.
A function summary captures:
- Preconditions (what must hold before call)
- Postconditions (what holds after call)
- Modified variables (side effects)
- Read variables (dependencies)
- Called functions (call graph edges)
- Raised exceptions
"""

from __future__ import annotations

from dataclasses import dataclass, field

import z3


@dataclass(frozen=True, slots=True)
class ParameterInfo:
    """Information about a function parameter."""

    name: str
    index: int
    type_hint: str | None = None
    default_value: object = None
    is_symbolic: bool = True
    z3_var: z3.ExprRef | None = None

    def to_z3(self, prefix: str = "") -> z3.ExprRef:
        """Create or get Z3 variable for this parameter."""
        if self.z3_var is not None:
            return self.z3_var
        name = f"{prefix}{self.name}" if prefix else self.name
        if self.type_hint == "int":
            return z3.Int(name)
        elif self.type_hint == "bool":
            return z3.Bool(name)
        elif self.type_hint == "float":
            return z3.Real(name)
        else:
            return z3.Int(name)


@dataclass(frozen=True, slots=True)
class ModifiedVariable:
    """Information about a modified variable."""

    name: str
    scope: str = "local"
    object_path: str | None = None
    old_value: z3.ExprRef | None = None
    new_value: z3.ExprRef | None = None


@dataclass(frozen=True, slots=True)
class ReadVariable:
    """Information about a read variable."""

    name: str
    scope: str = "local"
    object_path: str | None = None
    value: z3.ExprRef | None = None


@dataclass(frozen=True, slots=True)
class CallSite:
    """Information about a function call site."""

    callee: str
    args: list[object] = field(default_factory=list[object])
    kwargs: dict[str, object] = field(default_factory=dict[str, object])
    pc: int = 0
    is_method: bool = False
    receiver: str | None = None


@dataclass(frozen=True, slots=True)
class ExceptionInfo:
    """Information about an exception that may be raised."""

    exc_type: str
    condition: z3.BoolRef | None = None
    message: str | None = None


@dataclass
class FunctionSummary:
    """
    Complete summary of a function's behavior.
    Captures everything needed to reason about calls to this function
    without re-analyzing its body.
    """

    name: str
    qualname: str = ""
    module: str = ""
    parameters: list[ParameterInfo] = field(default_factory=list[ParameterInfo])
    return_type: str | None = None
    preconditions: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
    postconditions: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
    modified: list[ModifiedVariable] = field(default_factory=list[ModifiedVariable])
    reads: list[ReadVariable] = field(default_factory=list[ReadVariable])
    calls: list[CallSite] = field(default_factory=list[CallSite])
    may_raise: list[ExceptionInfo] = field(default_factory=list[ExceptionInfo])
    is_pure: bool = False
    is_deterministic: bool = True
    is_recursive: bool = False
    complexity: str = "unknown"
    return_constraint: z3.BoolRef | None = None
    return_var: z3.ExprRef | None = None

    def __post_init__(self) -> None:
        """Post init."""
        if not self.qualname:
            self.qualname = self.name
        if self.return_var is None:
            self.return_var = z3.Int(f"{self.name}_result")

    def get_parameter(self, name: str) -> ParameterInfo | None:
        """Get parameter by name."""
        for param in self.parameters:
            if param.name == name:
                return param
        return None

    def get_parameter_z3(self, name: str, prefix: str = "") -> z3.ExprRef | None:
        """Get Z3 variable for parameter."""
        param = self.get_parameter(name)
        if param:
            return param.to_z3(prefix)
        return None

    def add_precondition(self, cond: z3.BoolRef) -> None:
        """Add a precondition."""
        self.preconditions.append(cond)

    def add_postcondition(self, cond: z3.BoolRef) -> None:
        """Add a postcondition."""
        self.postconditions.append(cond)

    def add_modified(self, var: ModifiedVariable) -> None:
        """Add a modified variable."""
        self.modified.append(var)

    def add_reads(self, var: ReadVariable) -> None:
        """Add a read variable."""
        self.reads.append(var)

    def add_call(self, call: CallSite) -> None:
        """Add a call site."""
        self.calls.append(call)

    def add_exception(self, exc: ExceptionInfo) -> None:
        """Add a potential exception."""
        self.may_raise.append(exc)

    def modifies_globals(self) -> bool:
        """Check if function modifies global variables."""
        return any(v.scope == "global" for v in self.modified)

    def reads_globals(self) -> bool:
        """Check if function reads global variables."""
        return any(v.scope == "global" for v in self.reads)

    def get_all_preconditions(self) -> z3.BoolRef:
        """Get conjunction of all preconditions."""
        if not self.preconditions:
            return z3.BoolVal(True)
        return z3.And(*self.preconditions)

    def get_all_postconditions(self) -> z3.BoolRef:
        """Get conjunction of all postconditions."""
        if not self.postconditions:
            return z3.BoolVal(True)
        return z3.And(*self.postconditions)

    def clone(self) -> FunctionSummary:
        """Create a copy of this summary."""
        return FunctionSummary(
            name=self.name,
            qualname=self.qualname,
            module=self.module,
            parameters=list(self.parameters),
            return_type=self.return_type,
            preconditions=list(self.preconditions),
            postconditions=list(self.postconditions),
            modified=list(self.modified),
            reads=list(self.reads),
            calls=list(self.calls),
            may_raise=list(self.may_raise),
            is_pure=self.is_pure,
            is_deterministic=self.is_deterministic,
            is_recursive=self.is_recursive,
            complexity=self.complexity,
            return_constraint=self.return_constraint,
            return_var=self.return_var,
        )
