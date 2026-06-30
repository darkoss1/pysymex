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

"""TypeError result construction for modeled class calls."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    from pysymex._internal.core.classes.classes import SymbolicClass
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def abstract_class_error_result(
    state: VMState,
    modeled_cls: SymbolicClass,
) -> OpcodeResult | None:
    """Return a TypeError result when a modeled abstract class is instantiated."""
    if not modeled_cls.is_abstract:
        return None
    return OpcodeResult.error(
        Issue(
            kind=IssueKind.TYPE_ERROR,
            message=f"Possible TypeError: {modeled_cls.abstract_instantiation_message()}",
            constraints=list(state.path_constraints),
            pc=state.pc,
        ),
    )


def named_tuple_error_result(
    state: VMState,
    modeled_cls: SymbolicClass,
    class_name: str,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Return a TypeError result for unsupported concrete named-tuple construction."""
    from pysymex._internal.execution.calls.classes.stdlib import (
        named_tuple_call_error,
    )

    named_tuple_error = named_tuple_call_error(modeled_cls, class_name, args, kwargs)
    if named_tuple_error is None:
        return None
    return OpcodeResult.error(
        Issue(
            kind=IssueKind.TYPE_ERROR,
            message=f"Possible TypeError: {named_tuple_error}",
            constraints=list(state.path_constraints),
            pc=state.pc,
        ),
    )
