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

"""Infer function side effects (reads, writes, IO, raises) from bytecode.

Walks bytecode instructions to classify each function's effects, then
propagates effects interprocedurally along the call graph in topological
order.
"""

from __future__ import annotations

import hashlib
from types import CodeType

from pysymex.analysis.static.cross_function.call_graph import CallGraph
from pysymex.analysis.static.cross_function.types import Effect, EffectSummary
from pysymex.core.cache import get_instructions as cached_get_instructions


def _stable_const_repr(value: object) -> str:
    """Return a deterministic string for *value* suitable for hashing.

    Code objects are represented by their BLAKE2s fingerprint.
    Primitives use ``type:repr``; other objects use just the type name.

    Args:
        value: The constant object from ``co_consts``.

    Returns:
        A stable string representation.
    """
    if isinstance(value, CodeType):
        return f"code:{_code_fingerprint(value)}"
    if isinstance(value, (str, bytes, int, float, complex, bool, type(None))):
        return f"{type(value).__qualname__}:{value!r}"
    return type(value).__qualname__


def _code_fingerprint(code: CodeType) -> str:
    """Compute a BLAKE2s-128 fingerprint of a code object.

    Hashes bytecode, argument metadata, name tuples, and constants
    (recursively fingerprinting nested code objects).

    Args:
        code: The code object to fingerprint.

    Returns:
        32-character hexadecimal digest.
    """
    digest = hashlib.blake2s(digest_size=16)
    digest.update(code.co_code)
    for field in (
        code.co_argcount,
        code.co_posonlyargcount,
        code.co_kwonlyargcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags,
    ):
        digest.update(str(field).encode("utf-8"))
        digest.update(b"\0")
    for values in (code.co_names, code.co_varnames, code.co_freevars, code.co_cellvars):
        for value in values:
            digest.update(value.encode("utf-8"))
            digest.update(b"\0")
        digest.update(b"\1")
    for const in code.co_consts:
        digest.update(_stable_const_repr(const).encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


class EffectAnalyzer:
    """Bytecode-level side-effect classifier with result caching.

    Walks instructions of a function to identify read/write/IO/raise
    effects, caches results by function name or code fingerprint, and
    supports interprocedural propagation via :meth:`analyze_with_call_graph`.

    Attributes:
        PURE_FUNCTIONS: Built-in names assumed side-effect-free.
        IO_FUNCTIONS: Built-in names assumed to perform I/O.
    """

    PURE_FUNCTIONS: set[str] = {
        "len",
        "str",
        "int",
        "float",
        "bool",
        "bytes",
        "list",
        "dict",
        "set",
        "tuple",
        "frozenset",
        "range",
        "enumerate",
        "zip",
        "map",
        "filter",
        "sorted",
        "reversed",
        "min",
        "max",
        "sum",
        "abs",
        "round",
        "pow",
        "divmod",
        "chr",
        "ord",
        "hex",
        "oct",
        "bin",
        "isinstance",
        "issubclass",
        "hasattr",
        "getattr",
        "type",
        "id",
        "hash",
        "repr",
        "ascii",
        "format",
        "vars",
    }
    IO_FUNCTIONS: set[str] = {
        "print",
        "input",
        "open",
        "read",
        "write",
        "readline",
        "readlines",
        "writelines",
    }

    def __init__(self) -> None:
        """Initialize an EffectAnalyzer instance with empty caches."""
        self.cache: dict[str, EffectSummary] = {}
        self._cache_code_fingerprints: dict[str, str] = {}

    @staticmethod
    def _cache_key(code: CodeType, name: str) -> str:
        """Return a stable cache key for named functions and distinct unnamed code objects."""
        if name:
            return name
        return f"<code:{_code_fingerprint(code)}>"

    def analyze_function(self, code: CodeType, name: str = "") -> EffectSummary:
        """Classify a single function's effects from its bytecode.

        Results are cached by name (or code fingerprint for unnamed objects)
        and invalidated when the fingerprint changes.

        Args:
            code: The function's code object.
            name: Optional qualified name for cache keying.

        Returns:
            An :class:`EffectSummary` with all detected effects.
        """
        cache_key = self._cache_key(code, name)
        code_fingerprint = _code_fingerprint(code)
        if (
            cache_key in self.cache
            and self._cache_code_fingerprints.get(cache_key) == code_fingerprint
        ):
            return self.cache[cache_key]
        effects = Effect.NONE
        reads_globals: set[str] = set()
        writes_globals: set[str] = set()
        reads_attributes: set[str] = set()
        writes_attributes: set[str] = set()
        may_raise: set[str] = set()
        allocates: set[str] = set()
        for instr in cached_get_instructions(code):
            opname = instr.opname
            arg = instr.argval
            if opname == "LOAD_GLOBAL":
                effects |= Effect.READ_GLOBAL
                reads_globals.add(str(arg))
            elif opname in {"STORE_GLOBAL", "DELETE_GLOBAL"}:
                effects |= Effect.WRITE_GLOBAL
                writes_globals.add(str(arg))
            elif opname == "LOAD_ATTR":
                effects |= Effect.READ_HEAP
                reads_attributes.add(str(arg))
            elif opname in {"STORE_ATTR", "DELETE_ATTR"}:
                effects |= Effect.WRITE_HEAP
                writes_attributes.add(str(arg))
            elif opname == "BINARY_SUBSCR":
                effects |= Effect.READ_HEAP
            elif opname in {"STORE_SUBSCR", "DELETE_SUBSCR"}:
                effects |= Effect.WRITE_HEAP
            elif opname in {"BUILD_LIST", "BUILD_TUPLE", "BUILD_SET", "BUILD_MAP"}:
                effects |= Effect.ALLOCATE
                allocates.add(opname.replace("BUILD_", "").lower())
            elif opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD", "CALL_KW", "CALL_FUNCTION_EX"}:
                effects |= Effect.READ_LOCAL
            elif opname == "RAISE_VARARGS":
                effects |= Effect.RAISE
                may_raise.add("Exception")
        summary = EffectSummary(
            effects=effects,
            reads_globals=frozenset(reads_globals),
            writes_globals=frozenset(writes_globals),
            reads_attributes=frozenset(reads_attributes),
            writes_attributes=frozenset(writes_attributes),
            may_raise=frozenset(may_raise),
            allocates=frozenset(allocates),
        )
        self.cache[cache_key] = summary
        self._cache_code_fingerprints[cache_key] = code_fingerprint
        return summary

    def analyze_with_call_graph(
        self,
        call_graph: CallGraph,
        code_objects: dict[str, CodeType],
    ) -> dict[str, EffectSummary]:
        """Propagate effects interprocedurally along the call graph.

        Analyses functions in topological order so that callee effects
        are merged into callers.  Functions without code objects are
        assigned built-in effect estimates.

        Args:
            call_graph: The resolved call graph.
            code_objects: Map of function name to code object.

        Returns:
            A mapping of function name to combined :class:`EffectSummary`.
        """
        summaries: dict[str, EffectSummary] = {}
        for func_name in call_graph.topological_order():
            if func_name not in code_objects:
                summaries[func_name] = self._get_builtin_effects(func_name)
                continue
            local_effects = self.analyze_function(code_objects[func_name], func_name)
            node = call_graph.nodes.get(func_name)
            if node:
                for call_site in node.callees:
                    if call_site.callee in summaries:
                        local_effects = local_effects.merge_with(summaries[call_site.callee])
            summaries[func_name] = local_effects
        return summaries

    def _get_builtin_effects(self, func_name: str) -> EffectSummary:
        """Return a conservative effect estimate for a built-in or external function.

        Known-pure functions get ``NONE``; known-IO functions get ``IO | RAISE``;
        everything else is treated as ``IMPURE``.
        """
        base_name = func_name.rsplit(".", maxsplit=1)[-1]
        if base_name in self.PURE_FUNCTIONS:
            return EffectSummary(effects=Effect.NONE)
        if base_name in self.IO_FUNCTIONS:
            return EffectSummary(effects=Effect.IO | Effect.RAISE)
        return EffectSummary(effects=Effect.IMPURE)


__all__ = ["EffectAnalyzer"]
