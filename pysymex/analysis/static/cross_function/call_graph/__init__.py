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

"""Call graph data structure."""

from __future__ import annotations

from collections import defaultdict, deque

from pysymex.typing import is_set_of_objects
from pysymex.analysis.static.cross_function.types import CallGraphNode, CallSiteInfo


class CallGraph:
    """Call graph representing function call relationships."""

    def __init__(self) -> None:
        """Initialize an empty CallGraph instance."""
        self.nodes: dict[str, CallGraphNode] = {}
        self.entry_points: set[str] = set()

    def add_function(self, name: str, qualified_name: str = "") -> CallGraphNode:
        """Add a function to the call graph."""
        if name not in self.nodes:
            self.nodes[name] = CallGraphNode(name=name, qualified_name=qualified_name or name)
        return self.nodes[name]

    def add_call(self, caller: str, callee: str, line: int, pc: int, **kwargs: object) -> None:
        """Add a call edge to the graph."""
        caller_node = self.add_function(caller)
        callee_node = self.add_function(callee)
        raw_arg_count = kwargs.get("arg_count", 0)
        arg_count = int(raw_arg_count) if isinstance(raw_arg_count, (int, float, str)) else 0
        possible_callees: set[str] = set()
        possible_callees_obj = kwargs.get("possible_callees")
        if is_set_of_objects(possible_callees_obj):
            for item in possible_callees_obj:
                if isinstance(item, str):
                    possible_callees.add(item)
        call_site = CallSiteInfo(
            caller=caller,
            callee=callee,
            line=line,
            pc=pc,
            arg_count=arg_count,
            has_kwargs=bool(kwargs.get("has_kwargs", False)),
            has_varargs=bool(kwargs.get("has_varargs", False)),
            is_method_call=bool(kwargs.get("is_method_call", False)),
            is_static=bool(kwargs.get("is_static", False)),
            is_super_call=bool(kwargs.get("is_super_call", False)),
            is_dynamic=bool(kwargs.get("is_dynamic", False)),
            possible_callees=possible_callees,
        )
        caller_node.callees.append(call_site)
        callee_node.callers.add(caller)

    def get_callees(self, func: str) -> list[str]:
        """Get all functions called by a function."""
        if func not in self.nodes:
            return []
        return [call_site.callee for call_site in self.nodes[func].callees]

    def get_callers(self, func: str) -> set[str]:
        """Get all functions that call a function."""
        if func not in self.nodes:
            return set()
        return self.nodes[func].callers

    def find_recursive(self) -> set[str]:
        """Find all recursive functions."""
        recursive: set[str] = set()
        for name in self.nodes:
            if self._is_recursive(name, set()):
                recursive.add(name)
                self.nodes[name].is_recursive = True
        return recursive

    def _is_recursive(self, func: str, visited: set[str]) -> bool:
        """Check if a function is recursively reachable."""
        if func in visited:
            return True
        visited = visited | {func}
        for callee in self.get_callees(func):
            if callee in visited or self._is_recursive(callee, visited):
                return True
        return False

    def topological_order(self) -> list[str]:
        """Get functions in topological order (callees before callers)."""
        in_degree: dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            for call_site in node.callees:
                in_degree[call_site.callee] += 1
        queue = deque(name for name in self.nodes if in_degree[name] == 0)
        result: list[str] = []
        while queue:
            func = queue.popleft()
            result.append(func)
            for callee in self.get_callees(func):
                if callee in in_degree:
                    in_degree[callee] -= 1
                    if in_degree[callee] == 0:
                        queue.append(callee)
        for name in self.nodes:
            if name not in result:
                result.append(name)
        result.reverse()
        return result

    def get_reachable(self, from_func: str) -> set[str]:
        """Get all functions reachable from a starting function."""
        if from_func not in self.nodes:
            return set()
        reachable: set[str] = set()
        worklist = [from_func]
        while worklist:
            func = worklist.pop()
            if func in reachable:
                continue
            reachable.add(func)
            worklist.extend(self.get_callees(func))
        return reachable


__all__ = ["CallGraph"]
