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

"""Typed records and copy helpers consumed by execution-path VM state."""

from __future__ import annotations

from collections.abc import Hashable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, TypeGuard, TypeVar

from pysymex.core.memory.cow.collections import CowDict, CowSet
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.typing import StackValue

logger = get_logger(__name__)


class UnboundType:
    """Sentinel type identifying an unbound local variable.

    Notes:
        A dedicated type permits type narrowing around the singleton
        :data:`UNBOUND` marker.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        """Return the display form of the unbound sentinel."""
        return "UNBOUND"


UNBOUND: UnboundType = UnboundType()


class VMStateError(RuntimeError):
    """Raised when bytecode execution would violate VM state invariants."""


if TYPE_CHECKING:

    def is_bound(value: StackValue | UnboundType) -> TypeGuard[StackValue]:
        """TypeGuard that checks if a value is NOT the UNBOUND sentinel."""
        ...
else:

    def is_bound(value: object) -> bool:
        """Check if a value is NOT the UNBOUND sentinel."""
        return value is not UNBOUND


class HashableValue(Protocol):
    """Value exposing the structural hash consumed by VM state hashing."""

    def hash_value(self) -> int:
        """Return a structural hash used by state deduplication."""
        ...


def is_hashable_value(value: object) -> TypeGuard[HashableValue]:
    """Return whether ``value`` exposes the state structural-hash protocol."""
    return hasattr(value, "hash_value") and callable(getattr(value, "hash_value", None))


def structural_hash_or_none(value: object) -> int | None:
    """Return a structural hash for ``value`` when one can be computed directly."""
    hash_value = getattr(value, "hash_value", None)
    if callable(hash_value):
        result = hash_value()
        if isinstance(result, int):
            return result
        return hash(result)
    try:
        return hash(value)
    except TypeError:
        return None


K = TypeVar("K")
T = TypeVar("T")
S = TypeVar("S", bound=Hashable)

LoopCounterKey = int | tuple[int, ...]


def wrap_cow_dict(val: dict[K, T] | CowDict[K, T] | None) -> CowDict[K, T]:
    """Return ``val`` as a copy-on-write mapping wrapper."""
    if isinstance(val, CowDict):
        return val
    return CowDict(val) if val else CowDict()


def wrap_cow_set(val: set[S] | CowSet[S] | None) -> CowSet[S]:
    """Return ``val`` as a copy-on-write set wrapper."""
    if isinstance(val, CowSet):
        return val
    return CowSet(val) if val else CowSet()


def copy_summary_builder(builder: object) -> object:
    """Clone a call-frame summary builder through its required clone method.

    Returns:
        The result returned by the builder's ``clone()`` method.

    Raises:
        VMStateError: If ``builder`` has no callable ``clone()`` method or
            cloning fails with a supported clone-contract error.

    Notes:
        Forked call frames must not share mutable summary-builder progress.
        The builder implementation remains responsible for its clone depth.
    """
    builder_clone = getattr(builder, "clone", None)
    if callable(builder_clone):
        try:
            return builder_clone()
        except (TypeError, AttributeError, RecursionError) as exc:
            raise VMStateError(
                f"Failed to clone call-frame summary builder of type {type(builder).__qualname__}"
            ) from exc

    raise VMStateError(
        f"Call-frame summary builder of type {type(builder).__qualname__} must define clone()"
    )


@dataclass(frozen=True, slots=True)
class BlockInfo:
    """Metadata for a control-flow block (loop, try/except, with, etc.).

    Attributes:
        block_type: Kind of block (``"loop"``, ``"try"``, ``"finally"``, etc.).
        start_pc: Bytecode index where the block starts.
        end_pc: Bytecode index where the block ends.
        handler_pc: Target PC for exception handlers (``None`` if N/A).
    """

    block_type: str
    start_pc: int
    end_pc: int
    handler_pc: int | None = None

    def hash_value(self) -> int:
        """Return a structural hash of the block metadata in this process."""
        return hash((self.block_type, self.start_pc, self.end_pc, self.handler_pc))


@dataclass(frozen=True, slots=True)
class ProtocolCallCandidate:
    """A deferred modeled protocol call attempted after ``NotImplemented``."""

    owner: StackValue
    method_name: str
    argument: StackValue


@dataclass(frozen=True, slots=True)
class CallFrame:
    """Saved state for a function call during inter-procedural analysis.

    Attributes:
        function_name: Qualified name of the called function.
        return_pc: PC to resume at after the call returns.
        local_vars: Caller's copy-on-write local-variable mapping.
        stack_depth: Operand-stack depth at the call site.
        caller_stack: Saved caller operand stack for exact resumption after callee handlers.
        caller_instructions: Instruction list of the caller (for returns).
        summary_builder: Optional function-summary builder being populated;
            it must be cloned when the containing state forks.
    """

    function_name: str
    return_pc: int
    local_vars: CowDict[str, StackValue]
    stack_depth: int
    caller_stack: tuple[StackValue, ...] | None = None
    caller_instructions: list[object] | None = None
    summary_builder: object | None = None
    is_init_call: bool = False
    init_instance: StackValue | None = None
    protocol_method: str | None = None
    protocol_retained_operand: StackValue | None = None
    protocol_fallbacks: tuple[ProtocolCallCandidate, ...] = ()
    argument_aliases: tuple[tuple[str, StackValue], ...] = ()
    caller_offset: int | None = None

    def hash_value(self) -> int:
        """Return a structural hash used for path deduplication.

        Notes:
            The hash incorporates selected resumption and caller-value data.
            It is not a semantic-equivalence proof for call frames.
        """
        frame_hash = (
            hash((self.function_name, self.return_pc, self.stack_depth))
            ^ self.local_vars.hash_value()
        )
        for value in self.caller_stack or ():
            value_hash = structural_hash_or_none(value)
            if value_hash is None:
                frame_hash *= 31
                continue
            frame_hash = (frame_hash * 31) ^ value_hash
        return frame_hash


__all__ = [
    "BlockInfo",
    "CallFrame",
    "HashableValue",
    "LoopCounterKey",
    "UNBOUND",
    "VMStateError",
    "is_bound",
    "wrap_cow_dict",
    "wrap_cow_set",
    "structural_hash_or_none",
]
