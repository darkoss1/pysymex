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

"""Detect variables stored but never read before the next store or control-flow exit."""

from __future__ import annotations

import dis
from collections.abc import Sequence
from types import CodeType
from typing import cast

from pysymex.analysis.static.dead_code.bytecode_helpers import (
    as_object_tuple,
    cached_get_instructions,
)
from pysymex.analysis.static.dead_code.types import DeadCode, DeadCodeKind


class DeadStoreDetector:
    """Detects stores that are immediately overwritten without being read."""

    def detect(self, code: CodeType, file_path: str = "<unknown>") -> list[DeadCode]:
        """Scan bytecode instructions for stores immediately overwritten without a read."""
        dead_code: list[DeadCode] = []
        instructions = cached_get_instructions(code)
        current_line = code.co_firstlineno
        jump_targets = {instr.offset for instr in instructions if instr.is_jump_target}
        loop_vars = self._collect_loop_vars(instructions)
        last_store: dict[str, tuple[int, int]] = {}
        for instr in instructions:
            if instr.starts_line and type(instr.starts_line) is int:
                current_line = instr.starts_line
            if instr.offset in jump_targets:
                last_store.clear()
            opname = instr.opname
            arg = instr.argval
            if opname in {"STORE_FAST", "STORE_NAME"}:
                self._handle_store(
                    str(arg),
                    current_line,
                    instr.offset,
                    loop_vars,
                    last_store,
                    dead_code,
                    file_path,
                )
            elif opname in {
                "LOAD_FAST",
                "LOAD_NAME",
                "LOAD_FAST_AND_CLEAR",
                "DELETE_FAST",
                "DELETE_NAME",
            }:
                last_store.pop(str(arg), None)
            elif opname == "STORE_FAST_LOAD_FAST":
                self._handle_store_fast_load_fast(
                    arg, current_line, instr.offset, loop_vars, last_store
                )
            elif opname == "STORE_FAST_STORE_FAST" and isinstance(arg, tuple):
                for name_obj in cast("tuple[object, ...]", arg):
                    self._remember_store(
                        str(name_obj), current_line, instr.offset, loop_vars, last_store
                    )
            elif opname == "LOAD_FAST_LOAD_FAST" and isinstance(arg, tuple):
                for name_obj in cast("tuple[object, ...]", arg):
                    last_store.pop(str(name_obj), None)
            elif opname in _CONTROL_FLOW_OPS:
                last_store.clear()
        return dead_code

    def _handle_store(
        self,
        name: str,
        current_line: int,
        offset: int,
        loop_vars: set[str],
        last_store: dict[str, tuple[int, int]],
        dead_code: list[DeadCode],
        file_path: str,
    ) -> None:
        """Handle a variable store instruction by checking for prior unread stores.

        Detects the DEAD_STORE bug class when a variable is written to, but its previous
        value was never read.

        Args:
            name: The name of the variable being stored.
            current_line: The line number of the store.
            offset: The bytecode offset of the store instruction.
            loop_vars: A set of variable names bound by loops.
            last_store: Dictionary tracking the last store line/PC for each variable.
            dead_code: List of detected dead code occurrences to append to.
            file_path: The file path being analyzed.
        """
        if name in loop_vars:
            last_store.pop(name, None)
            return
        if name in last_store:
            prev_line, prev_pc = last_store[name]
            dead_code.append(
                DeadCode(
                    kind=DeadCodeKind.DEAD_STORE,
                    file=file_path,
                    line=prev_line,
                    name=name,
                    pc=prev_pc,
                    message=f"Value of '{name}' is overwritten without being read",
                    confidence=0.8,
                )
            )
        last_store[name] = (current_line, offset)

    @staticmethod
    def _remember_store(
        name: str,
        current_line: int,
        offset: int,
        loop_vars: set[str],
        last_store: dict[str, tuple[int, int]],
    ) -> None:
        """Record the line and offset of a store for a variable.

        Args:
            name: The name of the variable stored.
            current_line: The line number of the store.
            offset: The bytecode offset of the store instruction.
            loop_vars: A set of variable names bound by loops.
            last_store: Dictionary tracking the last store line/PC for each variable.
        """
        if name in loop_vars:
            last_store.pop(name, None)
        else:
            last_store[name] = (current_line, offset)

    def _handle_store_fast_load_fast(
        self,
        arg: object,
        current_line: int,
        offset: int,
        loop_vars: set[str],
        last_store: dict[str, tuple[int, int]],
    ) -> None:
        """Handle combined STORE_FAST_LOAD_FAST bytecode instruction.

        Pops the loaded variable from tracked stores, and remembers the stored variable.

        Args:
            arg: Argument tuple containing the stored and loaded variable names.
            current_line: The line number of the instruction.
            offset: The bytecode offset of the instruction.
            loop_vars: A set of variable names bound by loops.
            last_store: Dictionary tracking the last store line/PC for each variable.
        """
        arg_tuple = as_object_tuple(arg)
        if len(arg_tuple) < 2:
            return
        sname, lname = str(arg_tuple[0]), str(arg_tuple[1])
        last_store.pop(lname, None)
        self._remember_store(sname, current_line, offset, loop_vars, last_store)

    @staticmethod
    def _collect_loop_vars(instructions: Sequence[dis.Instruction]) -> set[str]:
        """Identify variable names used as loop targets from a sequence of instructions.

        Args:
            instructions: Sequence of bytecode instructions.

        Returns:
            A set of variable names that serve as loop targets.
        """
        loop_vars: set[str] = set()
        for i, instr in enumerate(instructions):
            if instr.opname not in {"FOR_ITER", "GET_ITER"}:
                continue
            for j in range(i + 1, min(i + 4, len(instructions))):
                next_instr = instructions[j]
                opname = next_instr.opname
                argval = next_instr.argval
                if opname in {"STORE_FAST", "STORE_NAME"}:
                    loop_vars.add(str(argval))
                    break
                if opname == "STORE_FAST_LOAD_FAST":
                    arg_tuple = as_object_tuple(argval)
                    if arg_tuple:
                        loop_vars.add(str(arg_tuple[0]))
                    break
                if opname == "STORE_FAST_STORE_FAST":
                    for name_obj in as_object_tuple(argval):
                        loop_vars.add(str(name_obj))
                    break
                if opname == "UNPACK_SEQUENCE" and isinstance(argval, int):
                    DeadStoreDetector._collect_unpack_targets(instructions, j, argval, loop_vars)
                    break
        return loop_vars

    @staticmethod
    def _collect_unpack_targets(
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        unpack_count: int,
        loop_vars: set[str],
    ) -> None:
        """Collect loop variables from UNPACK_SEQUENCE target stores.

        Args:
            instructions: Sequence of bytecode instructions.
            start_idx: The starting index in the instruction sequence.
            unpack_count: The number of items to unpack.
            loop_vars: A set of loop variables to add identified variables to.
        """
        for k in range(start_idx + 1, min(start_idx + 1 + unpack_count, len(instructions))):
            instr = instructions[k]
            if instr.opname in {"STORE_FAST", "STORE_NAME"}:
                loop_vars.add(str(instr.argval))
            elif instr.opname == "STORE_FAST_STORE_FAST":
                for name_obj in as_object_tuple(instr.argval):
                    loop_vars.add(str(name_obj))


_CONTROL_FLOW_OPS = {
    "JUMP_FORWARD",
    "JUMP_BACKWARD",
    "JUMP_ABSOLUTE",
    "POP_JUMP_IF_TRUE",
    "POP_JUMP_IF_FALSE",
    "POP_JUMP_FORWARD_IF_TRUE",
    "POP_JUMP_FORWARD_IF_FALSE",
    "POP_JUMP_IF_NONE",
    "POP_JUMP_IF_NOT_NONE",
    "POP_JUMP_FORWARD_IF_NONE",
    "POP_JUMP_FORWARD_IF_NOT_NONE",
    "RERAISE",
}

__all__ = ["DeadStoreDetector"]
