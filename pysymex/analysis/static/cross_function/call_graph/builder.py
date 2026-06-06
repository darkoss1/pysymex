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

"""Call graph bytecode builder."""

from __future__ import annotations

from types import CodeType

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.static.cross_function.call_graph import CallGraph
from pysymex.core.cache import get_instructions as cached_get_instructions


class CallGraphBuilder:
    """Builds a call graph from bytecode."""

    def __init__(self) -> None:
        """Initialize the CallGraphBuilder with an empty call graph."""
        self.call_graph = CallGraph()

    def build_from_module(self, module_code: CodeType) -> CallGraph:
        """Build call graph from a module's code object."""
        self.call_graph = CallGraph()
        self._process_code(module_code, "<module>")
        self._find_functions(module_code)
        if "<module>" in self.call_graph.nodes:
            self.call_graph.nodes["<module>"].is_entry_point = True
            self.call_graph.entry_points.add("<module>")
        self.call_graph.find_recursive()
        return self.call_graph

    def _find_functions(self, code: CodeType, prefix: str = "") -> None:
        """Find all functions in a code object."""
        for const in code.co_consts:
            if isinstance(const, CodeType):
                func_name = const.co_name
                qualified_name = f"{prefix}.{func_name}" if prefix else func_name
                self.call_graph.add_function(func_name, qualified_name)
                self._process_code(const, func_name)
                self._find_functions(const, qualified_name)

    def _process_code(self, code: CodeType, func_name: str) -> None:
        """Process a code object for call sites."""
        instructions = cached_get_instructions(code)
        current_line = code.co_firstlineno
        stack_items: list[str] = []
        pending_kw_names = False
        for instr in instructions:
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            arg = instr.argval
            if opname == "KW_NAMES":
                pending_kw_names = True
                continue
            if opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
                stack_items.append(str(arg))
            elif opname == "LOAD_CONST":
                stack_items.append(f"const:{arg}")
            elif opname in {"LOAD_ATTR", "LOAD_METHOD"}:
                self._handle_load_attr(stack_items, arg)
            elif opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
                if pending_kw_names:
                    self._handle_kw_call(
                        stack_items,
                        func_name,
                        current_line,
                        instr.offset,
                        arg,
                        metadata_on_stack=False,
                    )
                else:
                    self._handle_call(stack_items, func_name, current_line, instr.offset, arg)
                pending_kw_names = False
            elif opname in {"CALL_KW", "CALL_FUNCTION_KW"}:
                self._handle_kw_call(
                    stack_items,
                    func_name,
                    current_line,
                    instr.offset,
                    arg,
                    metadata_on_stack=True,
                )
                pending_kw_names = False
            elif opname == "CALL_FUNCTION_EX":
                self._handle_call_function_ex(
                    stack_items, func_name, current_line, instr.offset, arg
                )
                pending_kw_names = False
            elif opname == "POP_TOP":
                if stack_items:
                    stack_items.pop()
            elif opname == "DUP_TOP":
                if stack_items:
                    stack_items.append(stack_items[-1])
            elif opname == "ROT_TWO":
                if len(stack_items) >= 2:
                    stack_items[-1], stack_items[-2] = stack_items[-2], stack_items[-1]
            elif opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL"}:
                if stack_items:
                    stack_items.pop()
            elif opname in {"BUILD_LIST", "BUILD_TUPLE", "BUILD_SET"}:
                self._pop_build_args(stack_items, arg or 0)
                stack_items.append(opname.replace("BUILD_", "").lower())
            elif opname == "BUILD_MAP":
                self._pop_build_args(stack_items, (arg or 0) * 2)
                stack_items.append("dict")
            elif opname in {"BINARY_OP", "BINARY_SUBSCR", "COMPARE_OP"}:
                if len(stack_items) >= 2:
                    stack_items.pop()
                    stack_items.pop()
                stack_items.append("expr")
            elif opname.startswith("UNARY_"):
                if stack_items:
                    stack_items.pop()
                stack_items.append("expr")
            elif opname == "DICT_MERGE":
                if stack_items:
                    stack_items.pop()

    @staticmethod
    def _handle_load_attr(stack_items: list[str], arg: object) -> None:
        """Process LOAD_ATTR or LOAD_METHOD by updating the top stack item.

        Args:
            stack_items: The simulated bytecode stack of names.
            arg: The attribute name being loaded.
        """
        if stack_items:
            base = stack_items.pop()
            stack_items.append(f"{base}.{arg}")
        else:
            stack_items.append(f"?.{arg}")

    def _handle_call(
        self,
        stack_items: list[str],
        func_name: str,
        current_line: int,
        pc: int,
        arg: object,
    ) -> None:
        """Handle standard CALL, CALL_FUNCTION, or CALL_METHOD opcodes.

        Pops the arguments and the callable object from the simulated stack,
        registers the call edge in the call graph, and pushes the call result.

        Args:
            stack_items: The simulated bytecode stack of names.
            func_name: The name of the caller function.
            current_line: The source code line of the call.
            pc: The bytecode program counter offset of the instruction.
            arg: Opcode argument representing the positional argument count.
        """
        arg_count = int(arg) if isinstance(arg, int) else 0
        self._pop_build_args(stack_items, arg_count)
        callee = stack_items.pop() if stack_items else "?"
        is_method = "." in callee and not callee.startswith("const:")
        self.call_graph.add_call(
            caller=func_name,
            callee=callee,
            line=current_line,
            pc=pc,
            arg_count=arg_count,
            is_method_call=is_method,
            is_dynamic=callee.startswith("?"),
        )
        stack_items.append(f"result:{callee}")

    def _handle_kw_call(
        self,
        stack_items: list[str],
        func_name: str,
        current_line: int,
        pc: int,
        arg: object,
        *,
        metadata_on_stack: bool,
    ) -> None:
        """Handle CALL_KW or CALL_FUNCTION_KW opcodes.

        Pops the keyword arguments tuple, positional arguments, and the
        callable object from the simulated stack, registers the keyword call
        edge in the call graph, and pushes the call result.

        Args:
            stack_items: The simulated bytecode stack of names.
            func_name: The name of the caller function.
            current_line: The source code line of the call.
            pc: The bytecode program counter offset of the instruction.
            arg: Opcode argument representing the total argument count.
        """
        arg_count = int(arg) if isinstance(arg, int) else 0
        if metadata_on_stack and stack_items:
            stack_items.pop()
        self._pop_build_args(stack_items, arg_count)
        callee = stack_items.pop() if stack_items else "?"
        self.call_graph.add_call(
            caller=func_name,
            callee=callee,
            line=current_line,
            pc=pc,
            arg_count=arg_count,
            has_kwargs=True,
            is_method_call="." in callee and not callee.startswith("const:"),
            is_dynamic=callee.startswith("?"),
        )
        stack_items.append(f"result:{callee}")

    def _handle_call_function_ex(
        self,
        stack_items: list[str],
        func_name: str,
        current_line: int,
        pc: int,
        flags: object,
    ) -> None:
        """Handle CALL_FUNCTION_EX opcode for extended call args (*args, **kwargs).

        Pops the keyword dictionary (if present), the positional arguments iterable,
        and the callable object from the simulated stack, registers the call edge
        with varargs (and keyword flags) in the call graph, and pushes a generic result.

        Args:
            stack_items: The simulated bytecode stack of names.
            func_name: The name of the caller function.
            current_line: The source code line of the call.
            pc: The bytecode program counter offset of the instruction.
            flags: An integer flag where the lowest bit indicates if keyword arguments are passed.
        """
        has_kwargs = isinstance(flags, int) and bool(flags & 1)
        if has_kwargs and stack_items:
            stack_items.pop()
        if stack_items:
            stack_items.pop()
        callee = stack_items.pop() if stack_items else "?"
        self.call_graph.add_call(
            caller=func_name,
            callee=callee,
            line=current_line,
            pc=pc,
            has_kwargs=has_kwargs,
            has_varargs=True,
            is_method_call="." in callee and not callee.startswith("const:"),
            is_dynamic=callee.startswith("?"),
        )
        stack_items.append("result:?")

    @staticmethod
    def _pop_build_args(stack_items: list[str], count: object) -> None:
        """Pop the specified number of arguments from the simulated stack.

        Args:
            stack_items: The simulated bytecode stack of names.
            count: The number of arguments/items to pop.
        """
        arg_count = int(count) if isinstance(count, int) else 0
        for _ in range(arg_count):
            if stack_items:
                stack_items.pop()


__all__ = ["CallGraphBuilder"]
