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

"""Construct function summary objects from bytecode analysis results."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from pysymex._internal.analysis.runtime.summaries.types import (
    CallSite,
    FunctionSummary,
    ModifiedVariable,
    ParameterInfo,
    ReadVariable,
    SummaryExceptionInfo,
)

if TYPE_CHECKING:
    import z3


class _SummaryBuilderState:
    summary: FunctionSummary
    _param_index: int


class _SummaryMetadataMixin(_SummaryBuilderState):
    def set_qualname(self, qualname: str) -> Self:
        """Set qualified name."""
        self.summary.qualname = qualname
        return self

    def set_module(self, module: str) -> Self:
        """Set module name."""
        self.summary.module = module
        return self

    def add_parameter(
        self,
        name: str,
        type_hint: str | None = None,
        default: object = None,
    ) -> Self:
        """Add a parameter."""
        param = ParameterInfo(
            name=name,
            index=self._param_index,
            type_hint=type_hint,
            default_value=default,
        )
        self.summary.parameters.append(param)
        self._param_index += 1
        return self

    def set_return_type(self, type_hint: str) -> Self:
        """Set return type."""
        self.summary.return_type = type_hint
        return self

    def set_complexity(self, complexity: str) -> Self:
        """Set complexity class."""
        self.summary.complexity = complexity
        return self


class _SummaryContractMixin(_SummaryBuilderState):
    def require(self, condition: z3.BoolRef) -> Self:
        """Add a precondition."""
        self.summary.add_precondition(condition)
        return self

    def ensure(self, condition: z3.BoolRef) -> Self:
        """Add a postcondition."""
        self.summary.add_postcondition(condition)
        return self

    def may_raise_exception(
        self,
        exc_type: str,
        condition: z3.BoolRef | None = None,
    ) -> Self:
        """Add a potential exception."""
        self.summary.add_exception(SummaryExceptionInfo(exc_type, condition))
        return self

    def set_return_constraint(self, constraint: z3.BoolRef) -> Self:
        """Set return value constraint."""
        self.summary.return_constraint = constraint
        return self


class _SummaryEffectsMixin(_SummaryBuilderState):
    def modifies(
        self,
        name: str,
        scope: str = "local",
        object_path: str | None = None,
    ) -> Self:
        """Add a modified variable."""
        self.summary.add_modified(ModifiedVariable(name, scope, object_path))
        return self

    def reads_var(
        self,
        name: str,
        scope: str = "local",
        object_path: str | None = None,
    ) -> Self:
        """Add a read variable."""
        self.summary.add_reads(ReadVariable(name, scope, object_path))
        return self

    def calls_function(
        self,
        callee: str,
        args: list[object] | None = None,
        kwargs: dict[str, object] | None = None,
        pc: int = 0,
    ) -> Self:
        """Add a function call."""
        self.summary.add_call(
            CallSite(
                callee=callee,
                args=args or [],
                kwargs=kwargs or {},
                pc=pc,
            ),
        )
        return self

    def mark_pure(self) -> Self:
        """Mark as pure function."""
        self.summary.is_pure = True
        return self

    def mark_recursive(self) -> Self:
        """Mark as recursive."""
        self.summary.is_recursive = True
        return self


class SummaryBuilder(_SummaryMetadataMixin, _SummaryContractMixin, _SummaryEffectsMixin):
    """Builds function summaries from analysis results."""

    def __init__(self, name: str) -> None:
        self.summary = FunctionSummary(name=name)
        self._param_index = 0
        self._initial_args: list[object] = []

    @property
    def initial_args(self) -> list[object]:
        return self._initial_args

    def set_initial_args(self, args: list[object]) -> SummaryBuilder:
        self._initial_args = list(args)
        return self

    def clone(self) -> SummaryBuilder:
        """Create an independent copy for VM state forking."""
        new = SummaryBuilder.__new__(SummaryBuilder)
        new.summary = self.summary.clone()
        new._param_index = self._param_index
        new._initial_args = list(self._initial_args)
        return new

    def build(self) -> FunctionSummary:
        """Build the summary."""
        return self.summary
