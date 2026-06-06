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

"""Detect functions defined but never called, using call-graph reachability."""

from __future__ import annotations

from pysymex.analysis.static.cross_function import CallGraph
from pysymex.analysis.static.dead_code.types import DeadCode, DeadCodeKind


class UnusedFunctionDetector:
    """Detects functions that are defined but never called."""

    EXEMPT_PATTERNS: set[str] = {
        "__init__",
        "__new__",
        "__del__",
        "__enter__",
        "__exit__",
        "__iter__",
        "__next__",
        "__getitem__",
        "__setitem__",
        "__delitem__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
        "__call__",
        "__len__",
        "__bool__",
        "__str__",
        "__repr__",
        "__hash__",
        "__eq__",
        "__lt__",
        "__le__",
        "__gt__",
        "__ge__",
        "__ne__",
        "__add__",
        "__sub__",
        "__mul__",
        "__div__",
        "main",
        "setup",
        "teardown",
        "setUp",
        "tearDown",
        "setUpClass",
        "tearDownClass",
    }

    def detect(self, call_graph: CallGraph, file_path: str = "<unknown>") -> list[DeadCode]:
        """Return findings for functions unreachable from the module-level call graph."""
        dead_code: list[DeadCode] = []
        for name, node in call_graph.nodes.items():
            if name in self.EXEMPT_PATTERNS:
                continue
            if name.startswith("test_"):
                continue
            if name.startswith("_") and not name.startswith("__"):
                continue
            if not node.callers and not node.is_entry_point:
                dead_code.append(
                    DeadCode(
                        kind=DeadCodeKind.UNUSED_FUNCTION,
                        file=file_path,
                        line=0,
                        name=name,
                        message=f"Function '{name}' is defined but never called",
                        confidence=0.7,
                    )
                )
        return dead_code


__all__ = ["UnusedFunctionDetector"]
