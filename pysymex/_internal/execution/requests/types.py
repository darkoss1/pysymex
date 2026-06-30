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

"""Normalized execution request objects for executor entrypoints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from types import CodeType


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    """Normalized input for a function execution run."""

    func: Callable[..., object]
    symbolic_args: dict[str, str] | None
    initial_values: dict[str, object] | None
    cache_symbolic_args_repr: str

    @classmethod
    def from_inputs(
        cls,
        func: Callable[..., object],
        symbolic_args: Mapping[str, str] | None,
        initial_values: Mapping[str, object] | None,
    ) -> ExecutionRequest:
        """Create a request while preserving the existing cache-key token."""
        return cls(
            func=func,
            symbolic_args=dict(symbolic_args) if symbolic_args is not None else None,
            initial_values=dict(initial_values) if initial_values is not None else None,
            cache_symbolic_args_repr=str(symbolic_args),
        )

    @property
    def code(self) -> CodeType:
        """Return the code object executed by this request."""
        return self.func.__code__

    @property
    def function_name(self) -> str:
        """Return the public function name used in execution results."""
        return self.func.__name__

    def symbolic_arg_map(self) -> dict[str, str]:
        """Return a mutable symbolic-argument map for state construction."""
        return dict(self.symbolic_args or {})


@dataclass(frozen=True, slots=True)
class CodeExecutionRequest:
    """Normalized input for a code-object execution run."""

    code: CodeType
    symbolic_vars: dict[str, str] | None
    initial_globals: dict[str, object] | None

    @classmethod
    def from_inputs(
        cls,
        code: CodeType,
        symbolic_vars: Mapping[str, str] | None,
        initial_globals: Mapping[str, object] | None,
    ) -> CodeExecutionRequest:
        """Create a request for code-object execution."""
        return cls(
            code=code,
            symbolic_vars=dict(symbolic_vars) if symbolic_vars is not None else None,
            initial_globals=dict(initial_globals) if initial_globals is not None else None,
        )
