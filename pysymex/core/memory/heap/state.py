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

"""Stack, globals, and heap coordination for the VM memory aggregate."""

from __future__ import annotations

from pysymex.core.memory.heap.snapshots import MemorySnapshot
from pysymex.core.memory.heap.store import SymbolicHeap
from pysymex.core.memory.types import StackFrame, SymbolicAddress


class MemoryState:
    """Mutable stack/heap/global aggregate with snapshot and restore support.

    This owner coordinates concrete frame bookkeeping with
    :class:`SymbolicHeap`; it does not itself decide path feasibility or
    interpret symbolic alias-query uncertainty.
    """

    def __init__(self) -> None:
        """Initialize an empty heap, global mapping, and frame stack."""
        self.heap = SymbolicHeap()
        self.globals: dict[str, object] = {}
        self.stack: list[StackFrame] = []
        self._current_frame: StackFrame | None = None

    def push_frame(self, function_name: str) -> StackFrame:
        """Push and return a new current frame linked to the previous frame."""
        frame = StackFrame(function_name=function_name, parent_frame=self._current_frame)
        self.stack.append(frame)
        self._current_frame = frame
        return frame

    def pop_frame(self) -> StackFrame | None:
        """Pop and return the current frame, or ``None`` when the stack is empty."""
        if not self.stack:
            return None
        frame = self.stack.pop()
        self._current_frame = frame.parent_frame
        return frame

    @property
    def current_frame(self) -> StackFrame | None:
        """Return the current topmost stack frame, if one exists."""
        return self._current_frame

    def get_local(self, name: str) -> object:
        """Return a current-frame local, or ``None`` without a frame/binding."""
        if self._current_frame:
            return self._current_frame.get_local(name)
        return None

    def set_local(self, name: str, value: object) -> None:
        """Store a current-frame local when a frame exists.

        Limitations:
            With no current frame, this method silently leaves state unchanged.
        """
        if self._current_frame:
            self._current_frame.set_local(name, value)

    def get_global(self, name: str) -> object:
        """Return a global value, using ``None`` for an absent binding."""
        return self.globals.get(name)

    def set_global(self, name: str, value: object) -> None:
        """Store ``value`` under global-variable name ``name``."""
        self.globals[name] = value

    def allocate_object(
        self,
        type_name: str,
        initial_fields: dict[str, object] | None = None,
        is_mutable: bool = True,
    ) -> SymbolicAddress:
        """Allocate an object and initialize supplied fields on the new record."""
        addr = self.heap.allocate(type_name, is_mutable=is_mutable)
        if initial_fields:
            obj = self.heap.get_object(addr)
            if obj:
                for name, value in initial_fields.items():
                    obj.set_field(name, value)
        return addr

    def read_field(self, address: SymbolicAddress, field: str) -> object:
        """Delegate a field read to the symbolic heap."""
        return self.heap.read(address, field)

    def write_field(self, address: SymbolicAddress, field: str, value: object) -> None:
        """Delegate a field write to the symbolic heap."""
        self.heap.write(address, value, field)

    def snapshot(self) -> MemorySnapshot:
        """Capture the heap, globals, and frame locals for later restoration."""
        return MemorySnapshot(self)

    def restore(self, snapshot: MemorySnapshot) -> None:
        """Replace this memory aggregate with data captured in ``snapshot``.

        Side Effects:
            Restores heap state, replaces global and stack collections, and
            rebuilds current-frame parent links in captured order.
        """
        self.heap.restore(snapshot.heap_snapshot)
        self.globals = dict(snapshot.globals)
        self.stack = []
        prev_frame = None
        for frame_copy in snapshot.stack_copies:
            frame = StackFrame(
                function_name=frame_copy["function_name"],
                locals=dict(frame_copy["locals"]),
                return_address=frame_copy["return_address"],
                parent_frame=prev_frame,
            )
            self.stack.append(frame)
            prev_frame = frame
        self._current_frame = self.stack[-1] if self.stack else None
