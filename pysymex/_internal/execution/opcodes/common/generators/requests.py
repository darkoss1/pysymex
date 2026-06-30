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

"""Request parsing for modeled generator resume protocols."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.core.types.containers.generators import ModeledGenerator

if TYPE_CHECKING:
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.typing.protocols import StackValue

GENERATOR_RESUME_PROTOCOL = "__generator_resume__"


@dataclass(frozen=True, slots=True)
class ResumeRequest:
    generator: ModeledGenerator
    operation: str = "resume"
    has_default: bool = False
    default: StackValue | None = None
    for_iter_exit_pc: int | None = None
    push_for_iter_exit_sentinel: bool = True
    pop_for_iter_exit_iterator: bool = False
    yield_from_return_pc: int | None = None


def request_for_frame(frame: CallFrame | None) -> ResumeRequest | None:
    """Return the generator resume request stored on *frame*, if any."""
    value = frame.protocol_retained_operand if frame is not None else None
    return value if isinstance(value, ResumeRequest) else None


def resume_request_from_call(
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> tuple[ResumeRequest | None, StackValue | None]:
    """Recognize ``next``/``send``/``throw``/``close`` calls on a generator."""
    if kwargs:
        return None, None
    func_name = (
        func_obj
        if isinstance(func_obj, str)
        else getattr(func_obj, "__name__", None)
        or getattr(func_obj, "model_name", None)
        or getattr(func_obj, "_name", None)
    )
    if (
        (func_obj is next or func_name in {"next", "builtins.next"})
        and len(args) in {1, 2}
        and isinstance(args[0], ModeledGenerator)
    ):
        return (
            ResumeRequest(
                args[0],
                has_default=len(args) == 2,
                default=args[1] if len(args) == 2 else None,
            ),
            None,
        )
    owner = getattr(func_obj, "__self__", None)
    method_name = getattr(func_obj, "__name__", None)
    if isinstance(owner, ModeledGenerator) and method_name == "send":
        if len(args) == 1:
            return ResumeRequest(owner), args[0]
        return None, None
    if isinstance(owner, ModeledGenerator) and method_name == "throw":
        if args:
            return ResumeRequest(owner, operation="throw"), None
        return None, None
    if isinstance(owner, ModeledGenerator) and method_name == "close":
        if not args:
            return ResumeRequest(owner, operation="close"), None
        return None, None
    return None, None
