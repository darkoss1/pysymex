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
pysymex Scanner - core logic
===============================
Analysis functions, directory scanning, CLI entry point.
"""

import argparse
import ast
import concurrent.futures
import contextvars
import dataclasses
import importlib
import logging
import os
import sys
import time
import re
import types
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast

from pysymex._constants import SANDBOX_BLOCKED_MODULES
from pysymex.config import is_object_dict


_LIST_VAR_RE = re.compile(r"collection|items|sequence|data|arr|list")
_DICT_VAR_RE = re.compile(r"mapping|config|settings|dict|map")
_NULLABLE_VAR_RE = re.compile(r"(^obj$|object|instance|target|receiver|node)")
_MAX_SCANNER_SOLVER_TIMEOUT_MS = 1000


class _AccelBackendType(Protocol):
    name: str


class _AccelBackendInfo(Protocol):
    available: bool
    backend_type: _AccelBackendType


class _AccelDispatcher(Protocol):
    selected_backend: _AccelBackendType

    def list_backends(self) -> Sequence[_AccelBackendInfo]: ...


class _AccelDispatcherModule(Protocol):
    def get_dispatcher(self) -> _AccelDispatcher: ...


from pysymex.analysis.complexity import tune_execution_config
from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.analysis.detectors.protocols import ScanReporter
from pysymex.analysis.specialized.ranges import ValueRangeChecker
from pysymex.cli.reporter import ConsoleScanReporter
from pysymex.core.builtins import get_all_builtins
from pysymex.core.solver.engine import clear_solver_caches
from pysymex.execution.executors import ExecutionConfig, SymbolicExecutor
from pysymex.pathing import normalize_input_path

# Import opcodes early to ensure @opcode_handler decorators are registered
from pysymex.execution.opcodes import load_opcode_handlers

load_opcode_handlers()  # triggers opcode handler registration
from pysymex.scanner.types import IssueRecord, ScanResult, ScanSession

logger = logging.getLogger(__name__)

_session_var: contextvars.ContextVar[ScanSession | None] = contextvars.ContextVar(
    "_session_var",
    default=None,
)


def _descending_issue_count(item: tuple[str, int]) -> int:
    return -item[1]


class TypeHintExtractor(ast.NodeVisitor):
    """AST visitor to extract type hints from function signatures."""

    def __init__(self) -> None:
        self.hints: dict[tuple[str, str | None], dict[str, str]] = {}
        self.current_class: str | None = None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        arg_hints: dict[str, str] = {}
        for arg in node.args.args:
            if arg.annotation:
                arg_hints[arg.arg] = self._get_type_str(arg.annotation)
        # Also handle kwonlyargs
        for arg in node.args.kwonlyargs:
            if arg.annotation:
                arg_hints[arg.arg] = self._get_type_str(arg.annotation)

        self.hints[(node.name, self.current_class)] = arg_hints
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _get_type_str(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Subscript):
            # Handle Optional[int], List[str], etc.
            return self._get_type_str(node.value)
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            # Handle int | None (Python 3.10+)
            left = self._get_type_str(node.left)
            if left != "NoneType" and left != "None":
                return left
            return self._get_type_str(node.right)
        return "any"


def _scanner_solver_timeout_ms(timeout_seconds: float) -> int:
    """Return the per-query SMT timeout used during scanner execution."""
    return min(_MAX_SCANNER_SOLVER_TIMEOUT_MS, max(1, int(timeout_seconds * 1000)))


def _build_symbolic_vars(
    code: types.CodeType,
    class_name: str | None = None,
    type_hints: dict[str, str] | None = None,
    *,
    include_collection_heuristics: bool,
) -> dict[str, str]:
    """Build symbolic argument type hints from code object parameter names and opcode-captured hints."""
    symbolic_vars: dict[str, str] = {}
    hints = type_hints or {}

    def _hint_has_token(hint_lower: str, token: str) -> bool:
        return re.search(rf"(?<![a-z0-9_]){re.escape(token)}(?![a-z0-9_])", hint_lower) is not None

    for i, name in enumerate(code.co_varnames[: code.co_argcount]):
        if i == 0 and name in {"self", "cls"}:
            symbolic_vars[name] = "object"
            continue

        # Use opcode-captured hint if available
        hint = hints.get(name)
        if hint:
            hint_lower = str(hint).lower()
            if (
                "list" in hint_lower
                or "sequence" in hint_lower
                or "iterable" in hint_lower
                or "iterator" in hint_lower
            ):
                symbolic_vars[name] = "list"
            elif "dict" in hint_lower or "mapping" in hint_lower:
                symbolic_vars[name] = "dict"
            elif _hint_has_token(hint_lower, "bool"):
                symbolic_vars[name] = "bool"
            elif _hint_has_token(hint_lower, "int"):
                symbolic_vars[name] = "int"
            elif _hint_has_token(hint_lower, "str"):
                symbolic_vars[name] = "str"
            elif _hint_has_token(hint_lower, "float") or _hint_has_token(hint_lower, "real"):
                symbolic_vars[name] = "float"
            elif hint_lower in {"none", "nonetype"}:
                symbolic_vars[name] = "none"
            else:
                # Likely a class or complex object
                symbolic_vars[name] = "object"
            continue

        if include_collection_heuristics:
            name_lower = name.lower()
            if _NULLABLE_VAR_RE.search(name_lower):
                symbolic_vars[name] = "nullable"
                continue
            if _LIST_VAR_RE.search(name_lower):
                symbolic_vars[name] = "list"
                continue
            if _DICT_VAR_RE.search(name_lower):
                symbolic_vars[name] = "dict"
                continue
        symbolic_vars[name] = "int"
    return symbolic_vars


def _effective_worker_count(file_count: int, desired_workers: int) -> int:
    """Clamp worker count to a useful range for the current file set size."""
    if file_count <= 1:
        return 1
    if desired_workers <= 1:
        return 1

    # Avoid over-parallelizing tiny directories where process overhead dominates.
    max_useful_for_files = max(1, file_count // 2)
    return max(1, min(desired_workers, max_useful_for_files))


def _auto_worker_count(
    *,
    use_sandbox: bool,
    file_count: int | None = None,
    trace_enabled: bool | None = None,
) -> int:
    """Return a conservative default worker count for symbolic scans.

    Symbolic execution is memory-heavy, and sandbox compilation may spawn
    extra short-lived helper processes per file. Aggressive CPU-count defaults
    can oversubscribe hosts (especially on Windows), causing high RSS and
    scheduler thrash.
    """
    cpu_count = max(1, os.cpu_count() or 1)
    half_cpu = max(1, cpu_count // 2)
    cap = 4 if use_sandbox else 8
    desired_workers = min(cap, half_cpu)

    # Trace-heavy runs generate more I/O and metadata; keep concurrency slightly lower.
    if trace_enabled:
        desired_workers = max(1, desired_workers - 1)

    if file_count is None:
        return desired_workers
    return _effective_worker_count(file_count, desired_workers)


def _hardware_acceleration_status(*, use_h_acceleration: bool, use_chtd: bool) -> str:
    """Return a human-readable summary of active acceleration backends."""
    if not use_h_acceleration or not use_chtd:
        return "none (disabled by configuration)"

    try:
        dispatcher_module = cast(
            _AccelDispatcherModule,
            importlib.import_module("pysymex.accel.dispatcher"),
        )
        dispatcher = dispatcher_module.get_dispatcher()
        backends = dispatcher.list_backends()
        has_sat = any(b.available and b.backend_type.name == "SAT" for b in backends)
        has_cpu = any(b.available and b.backend_type.name in {"CPU", "REFERENCE"} for b in backends)

        if has_sat and has_cpu:
            availability = "both (SAT+CPU)"
        elif has_sat:
            availability = "sat"
        elif has_cpu:
            availability = "cpu"
        else:
            availability = "none"

        selected = dispatcher.selected_backend.name.lower()
        return f"{availability}; dispatcher_selected={selected}"
    except Exception:
        logger.debug("Unable to determine acceleration backend status", exc_info=True)
        return "unknown (backend probe failed)"


def get_code_objects_with_context(
    code: types.CodeType, parent_path: str | None = None
) -> list[tuple[types.CodeType, str | None, str | None]]:
    """
    Recursively extract all code objects with their full hierarchical path.

    Returns:
        List of tuples: (code_object, immediate_parent, full_path)
        - immediate_parent: Direct parent name (for class instantiation)
        - full_path: Full dotted path (for nested class imports like Outer.Inner)
    """
    current_name: str = code.co_name
    if current_name == "<module>":
        full_path: str | None = None
        immediate_parent: str | None = None
    else:
        full_path = f"{parent_path}.{current_name}" if parent_path else current_name
        immediate_parent = parent_path
    results: list[tuple[types.CodeType, str | None, str | None]] = [
        (code, immediate_parent, full_path)
    ]
    child_parent: str | None = full_path if current_name != "<module>" else None
    for const in code.co_consts:
        if hasattr(const, "co_code"):
            results.extend(get_code_objects_with_context(const, child_parent))
    return results


def _is_test_file(file_path: Path) -> bool:
    """Return True when a path looks like a pytest test module."""
    return file_path.name.startswith("test_") or any(part == "tests" for part in file_path.parts)


def _should_scan_source_function(name: str, file_path: Path) -> bool:
    """Return whether scanner should analyze a source-level function body."""
    if name.startswith("_"):
        return False
    if _is_test_file(file_path) and name.startswith("test_"):
        return False
    return True


def _collect_source_scan_paths(content: str, file_path: Path) -> set[str]:
    """Collect callable code-object paths that can be scanned out of module context."""
    tree = ast.parse(content)
    paths: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _should_scan_source_function(node.name, file_path):
                paths.add(node.name)
            continue
        if isinstance(node, ast.ClassDef):
            if node.name.startswith("_"):
                continue
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if _should_scan_source_function(child.name, file_path):
                        paths.add(f"{node.name}.{child.name}")
    return paths


def _collect_top_level_function_names(content: str, file_path: Path) -> set[str]:
    """Collect top-level functions that are safe to bind as FunctionType objects."""
    tree = ast.parse(content)
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _should_scan_source_function(node.name, file_path):
                names.add(node.name)
    return names


def _collect_top_level_class_names(content: str) -> set[str]:
    """Collect top-level class names that can be bound without executing module code."""
    tree = ast.parse(content)
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and not (
            node.name.startswith("__") and node.name.endswith("__")
        ):
            names.add(node.name)
    return names


def _bind_top_level_class_definitions(
    content: str,
    all_code_with_context: list[tuple[types.CodeType, str | None, str | None]],
    module_globals: dict[str, object],
) -> None:
    """Bind source-defined classes as symbolic class values for function scans."""
    import z3

    from pysymex.core.types import SymbolicValue

    class_names = _collect_top_level_class_names(content)
    if not class_names:
        return

    for code, _class_name, full_path in all_code_with_context:
        if code.co_name not in class_names or full_path != code.co_name or code.co_freevars:
            continue
        class_val = SymbolicValue(
            _name=code.co_name,
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=z3.BoolVal(False),
            is_bool=z3.BoolVal(False),
            is_obj=z3.BoolVal(True),
            is_none=z3.BoolVal(False),
            is_path=z3.BoolVal(False),
            affinity_type="type",
        )
        class_val.attach_enhanced_object(code)
        module_globals.setdefault(code.co_name, class_val)


def _stdlib_root(module_name: str) -> str:
    """Return the root package name for an import target."""
    return module_name.partition(".")[0]


def _is_safe_stdlib_import(module_name: str) -> bool:
    """Return True for import targets the scanner may bind concretely."""
    root = _stdlib_root(module_name)
    if root in SANDBOX_BLOCKED_MODULES:
        return False
    stdlib_names = getattr(sys, "stdlib_module_names", frozenset[str]())
    return root in stdlib_names or root in {"builtins", "__future__"}


def _populate_concrete_stdlib_imports(content: str, globals_map: dict[str, object]) -> None:
    """Populate scanner globals with concrete stdlib imports used by the file."""
    tree = ast.parse(content)
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not _is_safe_stdlib_import(alias.name):
                    continue
                try:
                    module = importlib.import_module(alias.name)
                except (ImportError, AttributeError, TypeError, ValueError):
                    continue
                globals_map[alias.asname or alias.name.partition(".")[0]] = module
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or not _is_safe_stdlib_import(node.module):
                continue
            try:
                module = importlib.import_module(node.module)
            except (ImportError, AttributeError, TypeError, ValueError):
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                try:
                    globals_map[alias.asname or alias.name] = getattr(module, alias.name)
                except AttributeError:
                    continue


def _attribute_chain(node: ast.AST) -> list[str] | None:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        parent = _attribute_chain(node.value)
        if parent is None:
            return None
        return [*parent, node.attr]
    return None


class _BlockedModuleCallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.alias_scopes: list[dict[str, str]] = [{}]
        self.class_stack: list[str] = []
        self.function_stack: list[str] = []
        self.issues: list[IssueRecord] = []
        self.resolution_sites: set[tuple[int, str | None, str | None, str | None]] = set()

    def _current_aliases(self) -> dict[str, str]:
        return self.alias_scopes[-1]

    def _set_alias(self, name: str, target: str) -> None:
        self._current_aliases()[name] = target

    def _clear_alias(self, name: str) -> None:
        self._current_aliases()[name] = ""

    def _lookup_alias(self, name: str) -> str | None:
        for scope in reversed(self.alias_scopes):
            if name in scope:
                target = scope[name]
                if not target:
                    return None
                return target
        return None

    def _resolve_blocked_chain(self, chain: list[str]) -> str | None:
        alias_target = self._lookup_alias(chain[0])
        if alias_target is None:
            return None
        return ".".join([alias_target, *chain[1:]])

    def _blocked_target_from_expr(self, node: ast.AST) -> str | None:
        chain = _attribute_chain(node)
        if chain is not None:
            return self._resolve_blocked_chain(chain)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
        ):
            receiver = self._blocked_target_from_expr(node.args[0])
            if receiver is not None:
                self.resolution_sites.add(
                    (
                        node.lineno,
                        self.function_stack[-1] if self.function_stack else None,
                        self.class_stack[-1] if self.class_stack else None,
                        ".".join([*self.class_stack, *self.function_stack])
                        if (self.class_stack or self.function_stack)
                        else None,
                    )
                )
                attr_arg = node.args[1]
                if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                    return f"{receiver}.{attr_arg.value}"
                return f"{receiver}.<dynamic>"
        return None

    def _target_names(self, node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            # TODO: Handle list/tuple destructuring properly without flattening.
            names: list[str] = []
            for element in node.elts:
                names.extend(self._target_names(element))
            return names
        return []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = _stdlib_root(alias.name)
            if root in SANDBOX_BLOCKED_MODULES:
                self._set_alias(alias.asname or root, root)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return
        root = _stdlib_root(node.module)
        if root not in SANDBOX_BLOCKED_MODULES:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            self._set_alias(alias.asname or alias.name, f"{node.module}.{alias.name}")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_stack.append(node.name)
        self.alias_scopes.append({})
        self.generic_visit(node)
        self.alias_scopes.pop()
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.function_stack.append(node.name)
        self.alias_scopes.append({})
        self.generic_visit(node)
        self.alias_scopes.pop()
        self.function_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        self.alias_scopes.append({})
        self.generic_visit(node)
        self.alias_scopes.pop()
        self.class_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        blocked_target = self._blocked_target_from_expr(node.value)
        for target in node.targets:
            for name in self._target_names(target):
                if blocked_target is None:
                    self._clear_alias(name)
                else:
                    self._set_alias(name, blocked_target)
            self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            blocked_target = self._blocked_target_from_expr(node.value)
        else:
            blocked_target = None
        for name in self._target_names(node.target):
            if blocked_target is None:
                self._clear_alias(name)
            else:
                self._set_alias(name, blocked_target)
        self.visit(node.target)
        self.visit(node.annotation)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        for name in self._target_names(node.target):
            self._clear_alias(name)
        self.visit(node.target)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            for name in self._target_names(target):
                self._clear_alias(name)
            self.visit(target)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._blocked_target_from_expr(node.func)
        if call_name is not None:
            self.issues.append(
                {
                    "kind": "UNKNOWN",
                    "message": (
                        f"Unsupported sandbox boundary: {call_name} is blocked by sandbox policy"
                    ),
                    "line": node.lineno,
                    "pc": 0,
                    "function_name": self.function_stack[-1] if self.function_stack else None,
                    "class_name": self.class_stack[-1] if self.class_stack else None,
                    "full_path": ".".join([*self.class_stack, *self.function_stack])
                    if (self.class_stack or self.function_stack)
                    else None,
                    "counterexample": None,
                }
            )
        self.generic_visit(node)


def _collect_blocked_module_diagnostics(
    content: str,
) -> tuple[list[IssueRecord], set[tuple[int, str | None, str | None, str | None]]]:
    tree = ast.parse(content)
    collector = _BlockedModuleCallCollector()
    collector.visit(tree)
    return collector.issues, collector.resolution_sites


def _bytearray_literal_size(node: ast.AST) -> int | None:
    """Return the concrete size for simple ``bytearray([...])`` constructors."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if not isinstance(func, ast.Name) or func.id != "bytearray" or not node.args:
        return None
    first_arg = node.args[0]
    if isinstance(first_arg, (ast.List, ast.Tuple)):
        return len(first_arg.elts)
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, (bytes, bytearray)):
        return len(first_arg.value)
    return None


def _attribute_chain_leaf(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _modulus_upper_bound(index_expr: ast.AST, assignments: dict[str, ast.AST]) -> int | None:
    """Return the exclusive upper bound for ``expr % constant`` indexes."""
    expr = index_expr
    if isinstance(expr, ast.Name):
        expr = assignments.get(expr.id, expr)
    if not isinstance(expr, ast.BinOp) or not isinstance(expr.op, ast.Mod):
        return None
    if isinstance(expr.right, ast.Constant) and isinstance(expr.right.value, int):
        modulus = expr.right.value
        if modulus > 0:
            return modulus
    return None


def _index_name(index_expr: ast.AST) -> str | None:
    if isinstance(index_expr, ast.Name):
        return index_expr.id
    return None


class _BytearrayModuloIndexCollector(ast.NodeVisitor):
    """Find unguarded bytearray indexes whose modulo range exceeds concrete size."""

    def __init__(self) -> None:
        self.issues: list[IssueRecord] = []
        self._bytearray_attrs: dict[str, int] = {}
        self._class_stack: list[str] = []
        self._function_stack: list[str] = []
        self._local_sizes_stack: list[dict[str, int]] = []
        self._assignments_stack: list[dict[str, ast.AST]] = []
        self._index_upper_bounds_stack: list[dict[str, int]] = []
        self._seen: set[tuple[int, str, int]] = set()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self._local_sizes_stack.append({})
        self._assignments_stack.append({})
        self._index_upper_bounds_stack.append({})
        self.generic_visit(node)
        self._index_upper_bounds_stack.pop()
        self._assignments_stack.pop()
        self._local_sizes_stack.pop()
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._assignments_stack:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._assignments_stack[-1][target.id] = node.value

        size = _bytearray_literal_size(node.value)
        if size is not None:
            for target in node.targets:
                if isinstance(target, ast.Name) and self._local_sizes_stack:
                    self._local_sizes_stack[-1][target.id] = size
                elif (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "self"
                    and self._class_stack
                ):
                    self._bytearray_attrs[target.attr] = size
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        guarded_bounds = self._guarded_upper_bounds(node.test)
        if not guarded_bounds:
            self.generic_visit(node)
            return
        current_bounds = (
            self._index_upper_bounds_stack[-1] if self._index_upper_bounds_stack else {}
        )
        merged_bounds = dict(current_bounds)
        for name, upper in guarded_bounds.items():
            old_upper = merged_bounds.get(name)
            merged_bounds[name] = upper if old_upper is None else min(old_upper, upper)
        self._index_upper_bounds_stack.append(merged_bounds)
        for child in node.body:
            self.visit(child)
        self._index_upper_bounds_stack.pop()
        for child in node.orelse:
            self.visit(child)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        size = self._resolve_container_size(node.value)
        if size is None:
            self.generic_visit(node)
            return

        assignments = self._assignments_stack[-1] if self._assignments_stack else {}
        modulus_upper = _modulus_upper_bound(node.slice, assignments)
        index_name = _index_name(node.slice)
        if index_name is not None and self._index_upper_bounds_stack:
            guarded_upper = self._index_upper_bounds_stack[-1].get(index_name)
            if guarded_upper is not None and guarded_upper <= size:
                self.generic_visit(node)
                return
        if modulus_upper is not None and modulus_upper > size:
            function_name = self._function_stack[-1] if self._function_stack else None
            class_name = self._class_stack[-1] if self._class_stack else None
            full_path = ".".join([*self._class_stack, *self._function_stack])
            key = (node.lineno, full_path, size)
            if key not in self._seen:
                self._seen.add(key)
                self.issues.append(
                    {
                        "kind": "INDEX_ERROR",
                        "message": (
                            "Possible bytearray index out of bounds: modulo "
                            f"{modulus_upper} can exceed size {size}"
                        ),
                        "line": node.lineno,
                        "pc": 0,
                        "function_name": function_name,
                        "class_name": class_name,
                        "full_path": full_path or None,
                        "counterexample": None,
                    }
                )
        self.generic_visit(node)

    def _resolve_container_size(self, node: ast.AST) -> int | None:
        if isinstance(node, ast.Name) and self._local_sizes_stack:
            return self._local_sizes_stack[-1].get(node.id)
        attr_name = _attribute_chain_leaf(node)
        if attr_name is None:
            return None
        return self._bytearray_attrs.get(attr_name)

    def _guarded_upper_bounds(self, test: ast.AST) -> dict[str, int]:
        if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
            return {}
        left = test.left
        right = test.comparators[0]
        if (
            isinstance(left, ast.Name)
            and isinstance(right, ast.Constant)
            and isinstance(right.value, int)
            and isinstance(test.ops[0], ast.Lt)
        ):
            return {left.id: right.value}
        return {}


def _collect_bytearray_modulo_index_diagnostics(content: str) -> list[IssueRecord]:
    tree = ast.parse(content)
    collector = _BytearrayModuloIndexCollector()
    collector.visit(tree)
    return collector.issues


def _expr_mentions_name(node: ast.AST, name: str) -> bool:
    return any(isinstance(child, ast.Name) and child.id == name for child in ast.walk(node))


class _MaskedZeroDivisionCollector(ast.NodeVisitor):
    """Find ``if (masked == 0): ... // masked``-style division by zero."""

    def __init__(self) -> None:
        self.issues: list[IssueRecord] = []
        self._class_stack: list[str] = []
        self._function_stack: list[str] = []
        self._masked_vars_stack: list[set[str]] = []
        self._zero_guard_stack: list[set[str]] = []
        self._seen: set[tuple[int, str, str]] = set()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self._masked_vars_stack.append(set())
        self._zero_guard_stack.append(set())
        self.generic_visit(node)
        self._zero_guard_stack.pop()
        self._masked_vars_stack.pop()
        self._function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        masked_assignment = (
            isinstance(node.value, ast.BinOp)
            and isinstance(node.value.op, ast.BitAnd)
            and isinstance(node.value.right, ast.Constant)
            and isinstance(node.value.right.value, int)
            and node.value.right.value >= 0
        )
        if self._masked_vars_stack:
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if masked_assignment:
                    self._masked_vars_stack[-1].add(target.id)
                else:
                    self._masked_vars_stack[-1].discard(target.id)
                    if self._zero_guard_stack:
                        self._zero_guard_stack[-1].discard(target.id)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        guarded_zero = self._zero_guard_names(node.test)
        if not guarded_zero:
            self.generic_visit(node)
            return
        self._zero_guard_stack.append(set(self._zero_guard_stack[-1]) | guarded_zero)
        for child in node.body:
            self.visit(child)
        self._zero_guard_stack.pop()
        for child in node.orelse:
            self.visit(child)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            for name in self._zero_guard_stack[-1] if self._zero_guard_stack else ():
                if _expr_mentions_name(node.right, name):
                    self._report(node, name)
                    break
        self.generic_visit(node)

    def _zero_guard_names(self, test: ast.AST) -> set[str]:
        if not self._masked_vars_stack or not isinstance(test, ast.Compare):
            return set()
        if len(test.ops) != 1 or len(test.comparators) != 1 or not isinstance(test.ops[0], ast.Eq):
            return set()
        left = test.left
        right = test.comparators[0]
        if isinstance(left, ast.Name) and isinstance(right, ast.Constant) and right.value == 0:
            return {left.id} & self._masked_vars_stack[-1]
        if isinstance(right, ast.Name) and isinstance(left, ast.Constant) and left.value == 0:
            return {right.id} & self._masked_vars_stack[-1]
        return set()

    def _report(self, node: ast.BinOp, name: str) -> None:
        function_name = self._function_stack[-1] if self._function_stack else None
        class_name = self._class_stack[-1] if self._class_stack else None
        full_path = ".".join([*self._class_stack, *self._function_stack])
        key = (node.lineno, full_path, name)
        if key in self._seen:
            return
        self._seen.add(key)
        self.issues.append(
            {
                "kind": "DIVISION_BY_ZERO",
                "message": f"Possible division by zero: {name} is guarded equal to 0",
                "line": node.lineno,
                "pc": 0,
                "function_name": function_name,
                "class_name": class_name,
                "full_path": full_path or None,
                "counterexample": None,
            }
        )


def _collect_masked_zero_division_diagnostics(content: str) -> list[IssueRecord]:
    tree = ast.parse(content)
    collector = _MaskedZeroDivisionCollector()
    collector.visit(tree)
    return collector.issues


def _get_default_scanner_globals() -> dict[str, object]:
    """Provide a default global environment for the scanner.

    Includes symbolic objects for common standard library modules to
    prevent the engine from assuming they could be None.
    Also sets TYPE_CHECKING to False to reduce noise from type-only imports.
    """
    import z3

    from pysymex.core.types import SymbolicObject

    defaults: dict[str, object] = {
        "TYPE_CHECKING": False,
    }
    defaults.update(get_all_builtins())

    common_modules = [
        "sys",
        "os",
        "functools",
        "re",
        "json",
        "math",
        "time",
        "random",
        "datetime",
        "io",
        "itertools",
        "collections",
        "pathlib",
        "abc",
        "typing",
    ]

    for mod_name in common_modules:
        addr = hash(mod_name) & 0xFFFFFFFF
        obj = SymbolicObject(mod_name, addr, z3.IntVal(addr), {addr})
        defaults[mod_name] = obj

    return defaults


def _detect_package_name(file_path: Path) -> tuple[str, str]:
    """Detect the module name and package name for a given file.

    Walks up the directory tree looking for __init__.py files.
    Returns:
        tuple: (full_module_name, package_name)
    """
    parts: list[str] = [file_path.stem]
    current = file_path.parent
    package_parts: list[str] = []

    while current and (current / "__init__.py").exists():
        parts.insert(0, current.name)
        package_parts.insert(0, current.name)
        current = current.parent

    full_name = ".".join(parts)
    package_name = ".".join(package_parts)
    return full_name, package_name


def _find_package_root(file_path: Path) -> Path | None:
    """Find the root of the package containing the given file."""
    current = file_path.resolve().parent
    root = None
    while current and (current / "__init__.py").exists():
        root = current.parent
        current = current.parent
    return root


def scan_file(
    file_path: str | Path,
    verbose: bool = False,
    max_paths: int = 100,
    timeout: float = 30.0,
    auto_tune: bool = False,
    reporter: ScanReporter | None = None,
    use_sandbox: bool = True,
    use_chtd: bool = True,
    use_h_acceleration: bool = True,
    deterministic_mode: bool = False,
    random_seed: int = 42,
    no_cache: bool = False,
    max_iterations: int = 0,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = "delta_only",
    enable_fp_filtering: bool = True,
) -> ScanResult:
    """
    Scan a single Python file for potential bugs.
    Args:
        file_path: Path to the Python file
        verbose: Print detailed output
        max_paths: Maximum paths per function
        timeout: Timeout in seconds
        auto_tune: Automatically adjust config based on complexity
    Returns:
        ScanResult with issues found
    Example:
        >>> result = scan_file("mycode.py")
        >>> for issue in result.issues:
        ...     print(f"{issue['kind']}: {issue['message']}")
    """
    file_path = normalize_input_path(file_path)
    session = _session_var.get()
    result = ScanResult(
        file_path=str(file_path),
        timestamp=datetime.now().isoformat(),
    )
    start_time = time.perf_counter()
    tracer = None
    try:
        content = file_path.read_text(encoding="utf-8")
        full_module_name, package_name = _detect_package_name(file_path)
        type_hint_extractor = TypeHintExtractor()
        type_hint_extractor.visit(ast.parse(content))
        source_type_hints = type_hint_extractor.hints

        if use_sandbox:
            from pysymex.sandbox.bridge import extract_bytecode

            bytecode_blob = extract_bytecode(
                content.encode("utf-8"),
                str(file_path),
                sandbox_config={"allow_compat_fallback": True},
            )
            code_obj = bytecode_blob.reconstruct()
        else:
            code_obj = compile(content, str(file_path), "exec")
        all_code_with_context = get_code_objects_with_context(code_obj)
        source_scan_paths = _collect_source_scan_paths(content, file_path)
        scan_code_with_context = [
            item for item in all_code_with_context if item[2] in source_scan_paths
        ]
        result.code_objects = len(scan_code_with_context)
        config = ExecutionConfig(
            max_paths=max_paths,
            max_depth=1000,
            max_iterations=max_iterations if max_iterations > 0 else max(5000, max_paths * 100),
            timeout_seconds=timeout,
            solver_timeout_ms=_scanner_solver_timeout_ms(timeout),
            enable_solver_cache=not no_cache,
            enable_cross_function=False,
            enable_chtd=use_chtd,
            enable_h_acceleration=use_h_acceleration,
            deterministic_mode=deterministic_mode,
            random_seed=random_seed,
            enable_fp_filtering=enable_fp_filtering,
        )
        base_config = config
        executor = SymbolicExecutor(config=config)

        # Initialize module globals with package context
        from pysymex.core.types import SymbolicString, SymbolicValue

        module_globals = _get_default_scanner_globals()
        module_globals["__file__"] = str(file_path)
        module_globals["__name__"] = full_module_name
        module_globals["__package__"] = package_name
        _populate_concrete_stdlib_imports(content, module_globals)

        # Bind top-level functions so helper calls can resolve without symbolically
        # executing module decorators, imports, or test-framework setup.
        top_level_function_names = _collect_top_level_function_names(content, file_path)
        for code, _class_name, full_path in all_code_with_context:
            if (
                full_path is None
                or "." in full_path
                or code.co_name not in top_level_function_names
                or code.co_freevars
            ):
                continue
            module_globals.setdefault(
                code.co_name,
                types.FunctionType(code, module_globals, code.co_name),
            )
        _bind_top_level_class_definitions(content, all_code_with_context, module_globals)

        # Add package root to sys.path for import resolution
        package_root = _find_package_root(file_path)
        if package_root and str(package_root) not in sys.path:
            sys.path.insert(0, str(package_root))

        tracer = None
        if trace_enabled is not False:
            from pysymex.tracing.schemas import TracerConfig, VerbosityLevel
            from pysymex.tracing.tracer import ExecutionTracer

            verbosity_value = trace_verbosity.strip().lower()
            verbosity = {
                "quiet": VerbosityLevel.QUIET,
                "delta_only": VerbosityLevel.DELTA_ONLY,
                "full": VerbosityLevel.FULL,
            }.get(verbosity_value, VerbosityLevel.DELTA_ONLY)

            cfg_overrides: dict[str, object] = {"verbosity": verbosity}
            if trace_enabled is not None:
                cfg_overrides["enabled"] = trace_enabled
            if trace_output_dir:
                cfg_overrides["output_dir"] = trace_output_dir

            tracer_cfg = TracerConfig.from_env(**cfg_overrides)
            if tracer_cfg.enabled:
                tracer = ExecutionTracer(config=tracer_cfg)
                tracer.start_session(
                    func_name=f"scan:{file_path.stem}",
                    signature_str="(module-scan)",
                    initial_args={},
                    config_snapshot=dataclasses.asdict(config),
                    source_file=str(file_path),
                )
                tracer.install(executor)

        blocked_issues, blocked_resolution_sites = _collect_blocked_module_diagnostics(content)
        bytearray_modulo_issues = _collect_bytearray_modulo_index_diagnostics(content)
        masked_zero_issues = _collect_masked_zero_division_diagnostics(content)
        seen: set[str] = set()
        dedup_enabled = os.getenv("PYSYMEX_DISABLE_ISSUE_DEDUP", "0") not in {"1", "true", "TRUE"}

        def _handle_issue(issue: Issue | IssueRecord) -> None:
            """Process and deduplicate a detected issue for reporting."""

            issue_dict: IssueRecord

            if is_object_dict(issue):
                issue_dict = {}
                for key_obj, value_obj in issue.items():
                    issue_dict[str(key_obj)] = value_obj
                raw_kind = str(issue_dict.get("kind", "UNKNOWN"))
                raw_message = str(issue_dict.get("message", ""))
                raw_line = issue_dict.get("line", "?")
                raw_pc = issue_dict.get("pc", 0)
            elif isinstance(issue, Issue):
                issue_obj = issue
                raw_kind = issue_obj.kind.name
                raw_message = issue_obj.message
                raw_line = issue_obj.line_number
                raw_pc = issue_obj.pc
                counterexample = issue_obj.get_counterexample()
                issue_dict = {
                    "kind": raw_kind,
                    "message": raw_message,
                    "line": raw_line,
                    "pc": raw_pc,
                    "function_name": issue_obj.function_name,
                    "class_name": getattr(issue_obj, "class_name", None),
                    "full_path": getattr(issue_obj, "full_path", None),
                    "counterexample": counterexample,
                }
            else:
                return

            raw_function_name = issue_dict.get("function_name")
            raw_class_name = issue_dict.get("class_name")
            raw_full_path = issue_dict.get("full_path")
            if (
                raw_kind == "ATTRIBUTE_ERROR"
                and isinstance(raw_line, int)
                and (
                    raw_line,
                    str(raw_function_name) if raw_function_name is not None else None,
                    str(raw_class_name) if raw_class_name is not None else None,
                    str(raw_full_path) if raw_full_path is not None else None,
                )
                in blocked_resolution_sites
            ):
                return

            msg_key = f"[{raw_kind}] @ {raw_line}:{raw_pc}"

            if dedup_enabled:
                if msg_key in seen:
                    return
                seen.add(msg_key)

            result.issues.append(issue_dict)
            if verbose and reporter:
                reporter.on_issue(issue_dict)

        def _has_matching_reported_issue(
            *,
            kind: str,
            line: int | None,
            function_name: str,
            class_name: str | None,
            full_path: str | None,
        ) -> bool:
            for existing in result.issues:
                if str(existing.get("kind")) != kind:
                    continue
                if existing.get("line") != line:
                    continue
                if existing.get("function_name") != function_name:
                    continue
                if existing.get("class_name") != class_name:
                    continue
                if existing.get("full_path") != full_path:
                    continue
                return True
            return False

        for blocked_issue in blocked_issues:
            _handle_issue(blocked_issue)
        for bytearray_modulo_issue in bytearray_modulo_issues:
            _handle_issue(bytearray_modulo_issue)
        for masked_zero_issue in masked_zero_issues:
            _handle_issue(masked_zero_issue)

        total_paths = 0
        total_time = 0.0
        memory_samples: list[float] = []
        module_item: tuple[types.CodeType, str | None, str | None] | None = None
        other_items: list[tuple[types.CodeType, str | None, str | None]] = []
        for item in scan_code_with_context:
            if item[0].co_name == "<module>":
                module_item = item
            else:
                other_items.append(item)

        seen_codes_scan: set[int] = set()

        if module_item:
            code, class_name, full_path = module_item
            seen_codes_scan.add(id(code))
            symbolic_vars = _build_symbolic_vars(
                code, class_name=class_name, include_collection_heuristics=True
            )
            try:
                exec_result = executor.execute_code(
                    code, symbolic_vars=symbolic_vars, initial_globals=module_globals
                )
                # Combine final locals into module globals for subsequent function scans
                module_globals.update(exec_result.final_locals)
                for raw_issue in exec_result.issues:
                    processed_issue = dataclasses.replace(
                        raw_issue,
                        function_name=code.co_name,
                        class_name=class_name,
                        full_path=full_path,
                    )
                    _handle_issue(processed_issue)
                total_paths += exec_result.paths_explored
                total_time += exec_result.total_time_seconds
                if exec_result.avg_memory_mb > 0:
                    memory_samples.append(exec_result.avg_memory_mb)
            except Exception as e:
                logger.debug("Module execution failed for %s: %s", str(file_path), e, exc_info=True)
                _handle_issue(
                    Issue(
                        kind=IssueKind.RUNTIME_ERROR,
                        message=f"Internal Error during symbolic execution: {type(e).__name__}({e})",
                        function_name=code.co_name,
                        class_name=class_name,
                        full_path=full_path,
                    )
                )

        for code, class_name, full_path in other_items:
            if id(code) in seen_codes_scan:
                continue
            seen_codes_scan.add(id(code))
            if auto_tune:
                tune_config = tune_execution_config(code, base_config)
                tune_config = dataclasses.replace(
                    tune_config,
                    enable_state_merging=base_config.enable_state_merging,
                    enable_caching=base_config.enable_caching,
                )
                executor = SymbolicExecutor(config=tune_config)
                if tracer:
                    tracer.install(executor)

            # Try to find annotations in module_globals for this function
            hints: dict[str, str] = dict(source_type_hints.get((code.co_name, class_name), {}))
            func_val = module_globals.get(code.co_name)
            annotations = getattr(func_val, "__annotations__", None)
            if annotations is None and isinstance(func_val, SymbolicValue):
                annotations = getattr(func_val, "annotations", None)
            if is_object_dict(annotations):
                for key_obj, value in annotations.items():
                    if not isinstance(key_obj, str):
                        continue
                    key = key_obj
                    if isinstance(value, str):
                        hints[key] = value
                        continue
                    if isinstance(value, SymbolicString):
                        symbolic_name = value.name.strip()
                        if symbolic_name:
                            hints[key] = symbolic_name
                        continue
                    if isinstance(value, type):
                        hints[key] = value.__name__
                        continue
                    hints[key] = str(value)

            symbolic_vars = _build_symbolic_vars(
                code, class_name=class_name, type_hints=hints, include_collection_heuristics=True
            )
            try:
                exec_result = executor.execute_code(
                    code, symbolic_vars=symbolic_vars, initial_globals=module_globals
                )
                for raw_issue in exec_result.issues:
                    processed_issue = dataclasses.replace(
                        raw_issue,
                        function_name=code.co_name,
                        class_name=class_name,
                        full_path=full_path,
                    )
                    _handle_issue(processed_issue)
                total_paths += exec_result.paths_explored
                if exec_result.avg_memory_mb > 0:
                    memory_samples.append(exec_result.avg_memory_mb)
            except Exception as e:
                logger.debug("Symbolic execution failed for %s", code.co_name, exc_info=True)
                _handle_issue(
                    Issue(
                        kind=IssueKind.RUNTIME_ERROR,
                        message=f"Internal Error during symbolic execution: {type(e).__name__}({e})",
                        function_name=code.co_name,
                        class_name=class_name,
                        full_path=full_path,
                    )
                )
        result.paths_explored = total_paths

        range_checker = ValueRangeChecker()
        seen_codes_range_scan: set[int] = set()
        for code, class_name, full_path in scan_code_with_context:
            if id(code) in seen_codes_range_scan:
                continue
            seen_codes_range_scan.add(id(code))
            try:
                range_warnings = range_checker.check_function(code, str(file_path))
                for warning in range_warnings:
                    if _has_matching_reported_issue(
                        kind=warning.kind,
                        line=warning.line,
                        function_name=code.co_name,
                        class_name=class_name,
                        full_path=full_path,
                    ):
                        continue
                    _handle_issue(
                        {
                            "kind": warning.kind,
                            "message": f"[Abstract Interpreter] {warning.message}",
                            "line": warning.line,
                            "pc": warning.pc,
                            "function_name": code.co_name,
                            "class_name": class_name,
                            "full_path": full_path,
                            "counterexample": None,
                        }
                    )
            except (RuntimeError, TypeError, ValueError):
                logger.debug("Value range analysis failed for %s", code.co_name, exc_info=True)

        result.elapsed_time = time.perf_counter() - start_time
        result.avg_memory_mb = sum(memory_samples) / len(memory_samples) if memory_samples else 0.0

        if verbose and not reporter:
            status_msg = f"{len(result.issues)} issues found" if result.issues else "No issues"
            print(f"{'[!]' if result.issues else '[OK]'} {file_path}: {status_msg}")
    except SyntaxError as e:
        result.error = f"Syntax Error: {e}"
        if reporter:
            reporter.on_error(file_path, result.error)
        elif verbose:
            print(f"\n[X] {result.error}")
    except Exception as e:
        result.error = f"Analysis Error: {e}"
        if reporter:
            reporter.on_error(file_path, result.error)
        elif verbose:
            print(f"\n[X] {result.error}")
    finally:
        if tracer is not None:
            try:
                tracer.end_session()
            except Exception:
                logger.debug("Failed to close trace session for %s", file_path, exc_info=True)
    if session:
        session.add_result(result)
    return result


def scan_directory(
    dir_path: str | Path,
    pattern: str = "**/*.py",
    verbose: bool = True,
    max_paths: int = 200,
    timeout: int = 30,
    workers: int | None = None,
    recursive: bool = False,
    mode: str = "symbolic",
    auto_tune: bool = False,
    reporter: ScanReporter | None = None,
    use_sandbox: bool = True,
    use_chtd: bool = True,
    use_h_acceleration: bool = True,
    deterministic_mode: bool = False,
    random_seed: int = 42,
    no_cache: bool = False,
    max_iterations: int = 0,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = "delta_only",
    enable_fp_filtering: bool = True,
) -> list[ScanResult]:
    """Scan all Python files in a directory for potential bugs."""
    _ = mode  # Backward-compat no-op; symbolic mode selection is handled by CLI command routing.
    dir_path = normalize_input_path(dir_path)
    effective_pattern = pattern
    if pattern == "**/*.py":
        effective_pattern = "**/*.py" if recursive else "*.py"
    files = sorted(dir_path.glob(effective_pattern))

    if not reporter:
        from pysymex.cli.reporter import ConsoleScanReporter

        reporter = ConsoleScanReporter()
    assert reporter is not None

    if files:
        reporter.on_status(f"Scanning {len(files)} Python files in {dir_path}...\n")
    else:
        if verbose and reporter:
            reporter.on_summary([], 0)
        elif verbose:
            print(f"No Python files found in {dir_path}")
        return []

    if workers is None or workers <= 0:
        workers_count = _auto_worker_count(
            use_sandbox=use_sandbox,
            file_count=len(files),
            trace_enabled=trace_enabled,
        )
    else:
        workers_count = _effective_worker_count(len(files), workers)

    logical_cores = max(1, os.cpu_count() or 1)
    execution_mode = "parallel" if workers_count > 1 else "sequential"
    hacc_status = _hardware_acceleration_status(
        use_h_acceleration=use_h_acceleration,
        use_chtd=use_chtd,
    )
    if reporter:
        reporter.on_status(
            f"Runtime: mode={execution_mode}; workers={workers_count}; logical_cores={logical_cores}"
        )
        reporter.on_status(f"Hardware acceleration: {hacc_status}\n")
    elif verbose:
        print(
            f"Runtime: mode={execution_mode}; workers={workers_count}; logical_cores={logical_cores}"
        )
        print(f"Hardware acceleration: {hacc_status}")

    if workers_count <= 1:
        return _scan_sequential(
            files,
            verbose,
            max_paths,
            timeout,
            auto_tune,
            reporter,
            use_sandbox,
            use_chtd,
            use_h_acceleration,
            deterministic_mode,
            random_seed,
            no_cache,
            max_iterations,
            trace_enabled,
            trace_output_dir,
            trace_verbosity,
            enable_fp_filtering,
        )

    return _scan_parallel(
        files,
        workers_count,
        verbose,
        max_paths,
        timeout,
        auto_tune,
        reporter,
        use_sandbox,
        use_chtd,
        use_h_acceleration,
        deterministic_mode,
        random_seed,
        no_cache,
        max_iterations,
        trace_enabled,
        trace_output_dir,
        trace_verbosity,
        enable_fp_filtering,
    )


def _scan_sequential(
    files: list[Path],
    verbose: bool,
    max_paths: int,
    timeout: float,
    auto_tune: bool,
    reporter: ScanReporter | None = None,
    use_sandbox: bool = True,
    use_chtd: bool = True,
    use_h_acceleration: bool = True,
    deterministic_mode: bool = False,
    random_seed: int = 42,
    no_cache: bool = False,
    max_iterations: int = 0,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = "delta_only",
    enable_fp_filtering: bool = True,
) -> list[ScanResult]:
    """Scan *files* one-by-one in the current process."""
    results: list[ScanResult] = []
    total = len(files)
    if verbose and not reporter:
        print(f"Scanning {total} file{'s' if total != 1 else ''} sequentially...")
    for i, file_path in enumerate(files, 1):
        if verbose and not reporter:
            print(f"[{i}/{total}] {file_path.name}...", end=" ", flush=True)
        try:
            result = scan_file(
                file_path,
                verbose=False,
                max_paths=max_paths,
                timeout=timeout,
                auto_tune=auto_tune,
                reporter=reporter,
                use_sandbox=use_sandbox,
                use_chtd=use_chtd,
                use_h_acceleration=use_h_acceleration,
                deterministic_mode=deterministic_mode,
                random_seed=random_seed,
                no_cache=no_cache,
                max_iterations=max_iterations,
                trace_enabled=trace_enabled,
                trace_output_dir=trace_output_dir,
                trace_verbosity=trace_verbosity,
                enable_fp_filtering=enable_fp_filtering,
            )
            results.append(result)
            clear_solver_caches()
            if verbose:
                if reporter:
                    reporter.on_progress(i, total, file_path, result)
                else:
                    if result.error:
                        print("\u274c Error")
                    elif result.issues:
                        print(f"\u26a0\ufe0f  {len(result.issues)} issues")
                    else:
                        print("\u2705")
        except Exception as e:
            if verbose:
                if reporter:
                    reporter.on_error(file_path, str(e))
                else:
                    print(f"\u274c Error: {e}")
    if verbose:
        if reporter:
            reporter.on_summary(results, total)
        else:
            _print_scan_summary(results, total)
    return results


def _scan_parallel(
    files: list[Path],
    workers_count: int,
    verbose: bool,
    max_paths: int,
    timeout: float,
    auto_tune: bool,
    reporter: ScanReporter | None = None,
    use_sandbox: bool = True,
    use_chtd: bool = True,
    use_h_acceleration: bool = True,
    deterministic_mode: bool = False,
    random_seed: int = 42,
    no_cache: bool = False,
    max_iterations: int = 0,
    trace_enabled: bool | None = None,
    trace_output_dir: str | None = None,
    trace_verbosity: str = "delta_only",
    enable_fp_filtering: bool = True,
) -> list[ScanResult]:
    """Scan *files* across multiple worker processes.

    Handles *KeyboardInterrupt* gracefully by cancelling pending futures
    and returning whatever results have been collected so far.
    """
    total = len(files)
    if verbose and not reporter:
        print(f"Scanning {total} file{'s' if total != 1 else ''} using {workers_count} workers...")

    results: list[ScanResult] = []
    completed = 0
    cancelled = False
    scan_errors: list[Exception] = []

    try:
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=workers_count,
        ) as executor:
            future_to_file: dict[concurrent.futures.Future[ScanResult], Path] = {}
            file_iter = iter(files)

            for _ in range(workers_count):
                try:
                    f = next(file_iter)
                    fut = executor.submit(
                        scan_file,
                        file_path=f,
                        verbose=False,
                        max_paths=max_paths,
                        timeout=timeout,
                        auto_tune=auto_tune,
                        use_sandbox=use_sandbox,
                        use_chtd=use_chtd,
                        use_h_acceleration=use_h_acceleration,
                        deterministic_mode=deterministic_mode,
                        random_seed=random_seed,
                        no_cache=no_cache,
                        max_iterations=max_iterations,
                        trace_enabled=trace_enabled,
                        trace_output_dir=trace_output_dir,
                        trace_verbosity=trace_verbosity,
                        enable_fp_filtering=enable_fp_filtering,
                    )
                    future_to_file[fut] = f
                except StopIteration:
                    break

            while future_to_file:
                if cancelled:
                    break

                done, _ = concurrent.futures.wait(
                    future_to_file.keys(), return_when=concurrent.futures.FIRST_COMPLETED
                )

                for future in done:
                    file_path = future_to_file.pop(future)
                    result = None
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as exc:
                        scan_errors.append(exc)
                        if verbose:
                            if reporter:
                                reporter.on_error(file_path, str(exc))
                            else:
                                print(f"[X] Error scanning {file_path.name}: {exc}")

                    completed += 1
                    if verbose:
                        if reporter:
                            reporter.on_progress(completed, total, file_path, result)
                        else:
                            _print_parallel_progress(completed, total, file_path, result)

                    try:
                        f = next(file_iter)
                        fut = executor.submit(
                            scan_file,
                            file_path=f,
                            verbose=False,
                            max_paths=max_paths,
                            timeout=timeout,
                            auto_tune=auto_tune,
                            use_sandbox=use_sandbox,
                            use_chtd=use_chtd,
                            use_h_acceleration=use_h_acceleration,
                            deterministic_mode=deterministic_mode,
                            random_seed=random_seed,
                            no_cache=no_cache,
                            max_iterations=max_iterations,
                            trace_enabled=trace_enabled,
                            trace_output_dir=trace_output_dir,
                            trace_verbosity=trace_verbosity,
                            enable_fp_filtering=enable_fp_filtering,
                        )
                        future_to_file[fut] = f
                    except StopIteration:
                        continue
    except KeyboardInterrupt:
        cancelled = True
        if verbose and not reporter:
            print(f"\n\u26a1 Interrupted \u2013 returning {len(results)} results collected so far.")
    except (RuntimeError, concurrent.futures.process.BrokenProcessPool) as exc:
        logger.warning("Parallel scanning failed (%s), falling back to sequential", exc)
        if reporter:
            reporter.on_status(
                "[!] Parallel scanning unavailable, falling back to sequential mode (workers=1)."
            )
        elif verbose:
            print("[!] Parallel scanning unavailable, falling back to sequential mode (workers=1).")
        return _scan_sequential(
            files=files,
            verbose=verbose,
            max_paths=max_paths,
            timeout=timeout,
            auto_tune=auto_tune,
            reporter=reporter,
            use_sandbox=use_sandbox,
            use_chtd=use_chtd,
            use_h_acceleration=use_h_acceleration,
            deterministic_mode=deterministic_mode,
            random_seed=random_seed,
            no_cache=no_cache,
            max_iterations=max_iterations,
            trace_enabled=trace_enabled,
            trace_output_dir=trace_output_dir,
            trace_verbosity=trace_verbosity,
            enable_fp_filtering=enable_fp_filtering,
        )

    if scan_errors and not cancelled:
        try:
            raise ExceptionGroup(
                f"scan: {len(scan_errors)} file(s) had errors",
                scan_errors,
            )
        except* OSError as eg:
            logger.warning("%d OS error(s) during parallel scan", len(eg.exceptions))
        except* Exception as eg:
            logger.warning("%d error(s) during parallel scan", len(eg.exceptions))

    if verbose and not cancelled:
        if reporter:
            reporter.on_summary(results, total)
        else:
            _print_scan_summary(results, total)
    return results


def _print_parallel_progress(
    completed: int,
    total: int,
    file_path: Path,
    result: ScanResult | None,
) -> None:
    """Print a single progress line for parallel scanning."""
    pct = completed * 100 // total if total > 0 else 0
    status = "[OK]"
    if result is None or result.error:
        status = "[X]"
    elif result.issues:
        status = f"[!] {len(result.issues)}"
    print(f"[{completed}/{total}] ({pct}%) {file_path.name} {status}")


def _print_scan_summary(results: list[ScanResult], total_files: int) -> None:
    """Print end-of-scan summary."""
    total_issues = sum(len(r.issues) for r in results)
    files_with_issues = sum(1 for r in results if r.issues)
    errors = sum(1 for r in results if r.error)
    print(f"\nSummary: {total_issues} issues in {files_with_issues}/{len(results)} files", end="")
    if errors:
        print(f" ({errors} errors)")
    else:
        print()
    if len(results) < total_files:
        print(f"  [!] {total_files - len(results)} file(s) could not be scanned")


def print_final_summary(reporter: ScanReporter | None = None) -> None:
    """Print a formatted session summary to stdout.

    Reads the current :class:`ScanSession` from *_session_var* and
    displays file counts, issue breakdown, and the log-file path.
    Does nothing if no session is active.
    """
    session = _session_var.get()
    if not session:
        return
    if reporter:
        on_session_summary = getattr(reporter, "on_session_summary", None)
        if callable(on_session_summary):
            on_session_summary(session)
            return
    summary = session.get_summary()
    print(f"\n\n{'=' * 70}")
    print("\U0001f4cb SESSION SUMMARY")
    print("=" * 70)
    print(f"   Files scanned:     {summary['files_scanned']}")
    print(f"   Files with issues: {summary['files_with_issues']}")
    print(f"   Files clean:       {summary['files_clean']}")
    print(f"   Files with errors: {summary['files_error']}")
    print(f"   Total issues:      {summary['total_issues']}")
    print()
    issue_breakdown = summary["issue_breakdown"]
    if issue_breakdown:
        print("   Issue breakdown:")
        for kind, count in sorted(issue_breakdown.items(), key=_descending_issue_count):
            bar = "\u2588" * min(count, 30)
            print(f"      {kind:<25} {count:>4} {bar}")
    print(f"\n   \U0001f4c1 Log saved to: {session.log_file}")
    print("=" * 70)


def main() -> None:
    """CLI entry point for the scanner.

    Parses ``--dir``, ``--log``, and ``--recursive`` arguments,
    performs a scan of existing files.
    """
    reporter: ScanReporter = ConsoleScanReporter()

    parser = argparse.ArgumentParser(description="pysymex Scanner")
    parser.add_argument(
        "--dir",
        "-d",
        type=str,
        default=".",
        help="Directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--log",
        "-l",
        type=str,
        default=None,
        help="Log file path (default: scan_log_TIMESTAMP.json)",
    )
    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        default=True,
        help="Scan subdirectories recursively (default: True)",
    )
    parser.add_argument(
        "--auto-tune",
        "-at",
        action="store_true",
        help="Automatically tune execution parameters based on code complexity",
    )
    parser.add_argument(
        "--max-paths",
        type=int,
        default=200,
        help="Maximum paths to explore (default: 200)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Timeout per file in seconds (default: 30.0)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help="Number of worker processes (0=auto)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable all caching",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=0,
        help="Maximum iterations per function",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Enable detailed execution tracing (generates JSONL logs)",
    )
    args = parser.parse_args()
    scan_dir = Path(args.dir)
    log_file = Path(args.log) if args.log else None
    if not scan_dir.exists():
        reporter.on_error(scan_dir, f"Directory '{scan_dir}' does not exist")
        sys.exit(1)
    session = ScanSession(log_file=log_file)
    _session_var.set(session)
    pattern = "**/*.py" if args.recursive else "*.py"
    existing_files = list(scan_dir.glob(pattern))
    if existing_files:
        results = scan_directory(
            scan_dir,
            pattern=pattern,
            max_paths=args.max_paths,
            timeout=args.timeout,
            workers=args.workers,
            auto_tune=args.auto_tune,
            reporter=reporter,
            no_cache=args.no_cache,
            max_iterations=args.max_iterations,
            trace_enabled=args.trace,
        )
        if session:
            for r in results:
                session.add_result(r)
    else:
        reporter.on_status(f"No Python files found in {scan_dir}")
    print_final_summary(reporter=reporter)
    reporter.on_status("\nDone.")


if __name__ == "__main__":
    main()
