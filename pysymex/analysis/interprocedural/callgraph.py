# pysymex: Python Symbolic Execution & Formal Verification
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

"""
Call Graph Analysis for pysymex.
Phase 20: Build and analyze call graphs from bytecode.
A call graph represents:
- Nodes: Functions/methods
- Edges: Calls between functions
- Properties: Direct, indirect, recursive calls
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from types import CodeType

from pysymex.core.cache import get_instructions as _cached_get_instructions


@dataclass
class CallGraphNode:
    """
    A node in the call graph representing a function.
    Attributes:
        name: Function name
        qualname: Qualified name
        module: Module containing the function
        bytecode: The function's bytecode (if available)
        is_method: Whether this is a method
        class_name: Containing class (for methods)
    """

    name: str
    qualname: str = ""
    module: str = ""
    bytecode: CodeType | None = None
    is_method: bool = False
    class_name: str | None = None
    _callers: set[str] = field(default_factory=set[str])
    _callees: set[str] = field(default_factory=set[str])

    def __post_init__(self) -> None:
        if not self.qualname:
            self.qualname = self.name

    @property
    def full_name(self) -> str:
        """Get full qualified name."""
        if self.module:
            return f"{self.module}.{self.qualname}"
        return self.qualname

    @property
    def callers(self) -> set[str]:
        """Functions that call this function."""
        return self._callers

    @property
    def callees(self) -> set[str]:
        """Functions this function calls."""
        return self._callees

    def add_caller(self, caller: str) -> None:
        """Add a caller."""
        self._callers.add(caller)

    def add_callee(self, callee: str) -> None:
        """Add a callee."""
        self._callees.add(callee)

    def __hash__(self) -> int:
        """Return the hash value of the object."""
        return hash(self.full_name)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CallGraphNode):
            return self.full_name == other.full_name
        return False


@dataclass
class CallGraphEdge:
    """
    An edge in the call graph representing a call.
    Attributes:
        caller: Calling function
        callee: Called function
        call_sites: PC locations of call instructions
        is_method_call: Whether this is a method call
        is_conditional: Whether call is conditional
        is_in_loop: Whether call is inside a loop
    """

    caller: str
    callee: str
    call_sites: list[int] = field(default_factory=list[int])
    is_method_call: bool = False
    is_conditional: bool = False
    is_in_loop: bool = False

    def add_call_site(self, pc: int) -> None:
        """Add a call site."""
        if pc not in self.call_sites:
            self.call_sites.append(pc)

    @property
    def call_count(self) -> int:
        """Number of call sites."""
        return len(self.call_sites)


class CallGraph:
    """
    Complete call graph for a module or program.
    Supports:
    - Adding nodes and edges
    - Querying callers/callees
    - Finding cycles (recursion)
    - Topological ordering
    - Reachability analysis
    """

    def __init__(self, name: str = "") -> None:
        self.name = name
        self._nodes: dict[str, CallGraphNode] = {}
        self._edges: dict[tuple[str, str], CallGraphEdge] = {}

    def add_node(self, node: CallGraphNode) -> None:
        """Add a node to the graph."""
        self._nodes[node.full_name] = node

    def get_node(self, name: str) -> CallGraphNode | None:
        """Get a node by name."""
        return self._nodes.get(name)

    def has_node(self, name: str) -> bool:
        """Check if node exists."""
        return name in self._nodes

    def nodes(self) -> list[CallGraphNode]:
        """Get all nodes."""
        return list(self._nodes.values())

    def node_names(self) -> set[str]:
        """Get all node names."""
        return set(self._nodes.keys())

    def add_edge(
        self,
        caller: str,
        callee: str,
        pc: int = 0,
        is_method_call: bool = False,
    ) -> CallGraphEdge:
        """Add an edge (call relationship)."""
        key = (caller, callee)
        if key in self._edges:
            edge = self._edges[key]
            edge.add_call_site(pc)
        else:
            edge = CallGraphEdge(
                caller=caller,
                callee=callee,
                call_sites=[pc] if pc else [],
                is_method_call=is_method_call,
            )
            self._edges[key] = edge
            if caller in self._nodes:
                self._nodes[caller].add_callee(callee)
            if callee in self._nodes:
                self._nodes[callee].add_caller(caller)
        return edge

    def get_edge(self, caller: str, callee: str) -> CallGraphEdge | None:
        """Get edge between two nodes."""
        return self._edges.get((caller, callee))

    def has_edge(self, caller: str, callee: str) -> bool:
        """Check if edge exists."""
        return (caller, callee) in self._edges

    def edges(self) -> list[CallGraphEdge]:
        """Get all edges."""
        return list(self._edges.values())

    def get_callers(self, name: str) -> set[str]:
        """Get all callers of a function."""
        node = self.get_node(name)
        if node:
            return node.callers
        return set()

    def get_callees(self, name: str) -> set[str]:
        """Get all callees of a function."""
        node = self.get_node(name)
        if node:
            return node.callees
        return set()

    def get_transitive_callers(self, name: str) -> set[str]:
        """Get all transitive callers (functions that lead to this one)."""
        result: set[str] = set()
        queue: deque[str] = deque([name])
        visited: set[str] = set()
        while queue:
            current = queue.popleft()
            callers = self.get_callers(current)
            for caller in callers:
                if caller not in visited:
                    visited.add(caller)
                    result.add(caller)
                    queue.append(caller)
        return result

    def get_transitive_callees(self, name: str) -> set[str]:
        """Get all transitive callees (functions reachable from this one)."""
        result: set[str] = set()
        queue: deque[str] = deque([name])
        visited: set[str] = set()
        while queue:
            current = queue.popleft()
            callees = self.get_callees(current)
            for callee in callees:
                if callee not in visited:
                    visited.add(callee)
                    result.add(callee)
                    queue.append(callee)
        return result

    def is_reachable(self, source: str, target: str) -> bool:
        """Check if target is reachable from source."""
        return target in self.get_transitive_callees(source)

    def find_cycles(self) -> list[list[str]]:
        """Find all cycles in the call graph (recursive call chains)."""
        cycles: list[list[str]] = []
        visited: set[str] = set()
        rec_stack: list[str] = []

        def dfs(node: str, path: list[str]) -> None:
            """Dfs."""
            visited.add(node)
            rec_stack.append(node)
            path = [*path, node]
            for callee in self.get_callees(node):
                if callee not in visited:
                    dfs(callee, path)
                elif callee in rec_stack:
                    cycle_start = path.index(callee)
                    cycle = [*path[cycle_start:], callee]
                    cycles.append(cycle)
            rec_stack.pop()

        for node_name in self._nodes:
            if node_name not in visited:
                dfs(node_name, [])
        return cycles

    def is_recursive(self, name: str) -> bool:
        """Check if function is directly or indirectly recursive."""
        return name in self.get_transitive_callees(name)

    def is_directly_recursive(self, name: str) -> bool:
        """Check if function is directly recursive (calls itself)."""
        return name in self.get_callees(name)

    def get_recursive_functions(self) -> set[str]:
        """Get all recursive functions."""
        return {name for name in self._nodes if self.is_recursive(name)}

    def topological_order(self) -> list[str]:
        """
        Get topological ordering of functions.
        Functions are ordered so that callees come before callers.
        Useful for bottom-up analysis.
        Returns empty list if graph has cycles.
        """
        in_degree = dict.fromkeys(self._nodes, 0)
        for edge in self._edges.values():
            if edge.callee in in_degree:
                in_degree[edge.callee] += 1
        queue: deque[str] = deque([n for n, d in in_degree.items() if d == 0])
        result: list[str] = []
        while queue:
            node = queue.popleft()
            result.append(node)
            for callee in self.get_callees(node):
                if callee in in_degree:
                    in_degree[callee] -= 1
                    if in_degree[callee] == 0:
                        queue.append(callee)
        if len(result) != len(self._nodes):
            return []
        result.reverse()
        return result

    def reverse_topological_order(self) -> list[str]:
        """Get reverse topological order (callers before callees)."""
        order = self.topological_order()
        order.reverse()
        return order

    def strongly_connected_components(self) -> list[set[str]]:
        """
        Find strongly connected components using Tarjan's algorithm.
        Each SCC represents a group of mutually recursive functions.
        """
        index_counter: list[int] = [0]
        stack: list[str] = []
        lowlinks: dict[str, int] = {}
        index: dict[str, int] = {}
        on_stack: dict[str, bool] = {}
        sccs: list[set[str]] = []

        def strongconnect(node: str) -> None:
            """Strongconnect."""
            index[node] = index_counter[0]
            lowlinks[node] = index_counter[0]
            index_counter[0] += 1
            stack.append(node)
            on_stack[node] = True
            for callee in self.get_callees(node):
                if callee not in index:
                    strongconnect(callee)
                    lowlinks[node] = min(lowlinks[node], lowlinks[callee])
                elif on_stack.get(callee, False):
                    lowlinks[node] = min(lowlinks[node], index[callee])
            if lowlinks[node] == index[node]:
                scc: set[str] = set()
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.add(w)
                    if w == node:
                        break
                sccs.append(scc)

        for node in self._nodes:
            if node not in index:
                strongconnect(node)
        return sccs

    def entry_points(self) -> set[str]:
        """Get entry points (functions not called by others)."""
        return {n for n in self._nodes if not self.get_callers(n)}

    def leaf_functions(self) -> set[str]:
        """Get leaf functions (functions that don't call others)."""
        return {n for n in self._nodes if not self.get_callees(n)}

    def call_depth(self, name: str) -> int:
        """
        Get maximum call depth from a function.
        Returns -1 if there's a cycle reachable from this function.
        """
        if self.is_recursive(name):
            return -1
        visited: set[str] = set()

        def dfs(node: str, depth: int) -> int:
            """Dfs."""
            if node in visited:
                return depth - 1
            visited.add(node)
            max_depth = depth
            for callee in self.get_callees(node):
                callee_depth = dfs(callee, depth + 1)
                max_depth = max(max_depth, callee_depth)
            visited.remove(node)
            return max_depth

        return dfs(name, 0)

    def merge(self, other: CallGraph) -> None:
        """Merge another call graph into this one."""
        for node in other.nodes():
            if not self.has_node(node.full_name):
                self.add_node(node)
        for edge in other.edges():
            self.add_edge(
                edge.caller,
                edge.callee,
                is_method_call=edge.is_method_call,
            )
            for pc in edge.call_sites:
                self._edges[(edge.caller, edge.callee)].add_call_site(pc)

    def subgraph(self, nodes: set[str]) -> CallGraph:
        """Create a subgraph containing only specified nodes."""
        result = CallGraph(name=f"{self.name}_subgraph")
        for name in nodes:
            if name in self._nodes:
                result.add_node(self._nodes[name])
        for edge in self._edges.values():
            if edge.caller in nodes and edge.callee in nodes:
                result.add_edge(
                    edge.caller,
                    edge.callee,
                    is_method_call=edge.is_method_call,
                )
        return result

    def __str__(self) -> str:
        """Return a human-readable string representation."""
        return f"CallGraph({self.name}, {len(self._nodes)} nodes, {len(self._edges)} edges)"

    def __repr__(self) -> str:
        return self.__str__()


class CallGraphBuilder:
    """
    Builds call graphs from bytecode.
    """

    def __init__(self) -> None:
        self.graph = CallGraph()

    def add_function(
        self,
        func: Callable[..., object],
        module: str = "",
    ) -> CallGraphNode:
        """Add a function to the graph."""
        name = func.__name__
        qualname = getattr(func, "__qualname__", name)
        node = CallGraphNode(
            name=name,
            qualname=qualname,
            module=module,
            bytecode=func.__code__,
            is_method="." in qualname,
        )
        if node.is_method:
            parts = qualname.rsplit(".", 1)
            if len(parts) == 2:
                node.class_name = parts[0]
        self.graph.add_node(node)
        return node

    def analyze_function(self, func: Callable[..., object]) -> list[str]:
        """
        Analyze a function's bytecode to find call sites.
        Returns list of called function names.
        """
        code = func.__code__
        callees: list[str] = []
        for instr in _cached_get_instructions(code):
            if instr.opname in (
                "CALL",
                "CALL_FUNCTION",
                "CALL_METHOD",
                "CALL_FUNCTION_KW",
                "CALL_FUNCTION_EX",
            ):
                if instr.argval:
                    callees.append(str(instr.argval))
        return callees

    def build_from_functions(
        self,
        functions: list[Callable[..., object]],
        module: str = "",
    ) -> CallGraph:
        """Build call graph from a list of functions."""
        func_map: dict[str, Callable[..., object]] = {}
        for func in functions:
            self.add_function(func, module)
            func_map[func.__name__] = func
            if hasattr(func, "__qualname__"):
                func_map[func.__qualname__] = func
        for func in functions:
            caller = func.__qualname__ if hasattr(func, "__qualname__") else func.__name__
            callees = self.analyze_function(func)
            for callee_name in callees:
                if callee_name in func_map:
                    self.graph.add_edge(caller, callee_name)
        return self.graph

    def build(self) -> CallGraph:
        """Return the built graph."""
        return self.graph


def get_analysis_order(graph: CallGraph) -> list[str]:
    """
    Get optimal order for analyzing functions.
    For bottom-up analysis: callees before callers.
    Handles recursive functions by grouping SCCs.
    """
    sccs = graph.strongly_connected_components()
    scc_map: dict[str, int] = {}
    for i, scc in enumerate(sccs):
        for node in scc:
            scc_map[node] = i
    scc_graph = CallGraph("scc_graph")
    for i, _scc in enumerate(sccs):
        scc_node = CallGraphNode(name=f"scc_{i}")
        scc_graph.add_node(scc_node)
    for edge in graph.edges():
        caller_scc = scc_map.get(edge.caller)
        callee_scc = scc_map.get(edge.callee)
        if caller_scc is not None and callee_scc is not None:
            if caller_scc != callee_scc:
                scc_graph.add_edge(f"scc_{caller_scc}", f"scc_{callee_scc}")
    scc_order = scc_graph.topological_order()
    result: list[str] = []
    for scc_name in scc_order:
        scc_idx = int(scc_name.split("_")[1])
        result.extend(sorted(sccs[scc_idx]))
    return result


def find_mutual_recursion(graph: CallGraph) -> list[set[str]]:
    """
    Find groups of mutually recursive functions.
    Returns SCCs with more than one node.
    """
    sccs = graph.strongly_connected_components()
    return [scc for scc in sccs if len(scc) > 1]


def compute_dominators(graph: CallGraph, entry: str) -> dict[str, set[str]]:
    """
    Compute dominators for each node.
    A node D dominates node N if every path from entry to N goes through D.
    """
    nodes = graph.node_names()
    dom = {n: nodes.copy() for n in nodes}
    dom[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for node in nodes:
            if node == entry:
                continue
            callers = graph.get_callers(node)
            if not callers:
                continue
            new_dom = nodes.copy()
            for caller in callers:
                new_dom &= dom.get(caller, set())
            new_dom.add(node)
            if new_dom != dom[node]:
                dom[node] = new_dom
                changed = True
    return dom
