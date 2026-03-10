"""
Z3 Engine — Bytecode opcode handlers.

Mixin class providing symbolic execution handlers for Python bytecode opcodes.
Mixed into FunctionAnalyzer to keep file sizes manageable.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from pysymex.analysis.solver.graph import SymbolicState
from pysymex.analysis.solver.types import (
    BugType,
    CallSite,
    CrashCondition,
    Severity,
    SymType,
    SymValue,
    TaintInfo,
    z3,
)

logger = logging.getLogger(__name__)


class OpcodeHandlersMixin:
    """Mixin providing bytecode opcode handlers for FunctionAnalyzer.

    All methods here are designed to be mixed into FunctionAnalyzer,
    which provides the class attributes and helper methods they depend on
    (e.g. _make_const, _add_crash, _check_division, DANGEROUS_SINKS, etc.).
    """

    if TYPE_CHECKING:
        BINARY_OPS: dict[int, str]
        COMPARE_OPS: dict[str, Callable[[object, object], object]]
        DANGEROUS_SINKS: set[str]
        current_function: str
        current_line: int
        current_file: str

        def _make_const(self, value: object, state: SymbolicState) -> SymValue: ...
        def _add_crash(
            self,
            bug_type: BugType,
            condition: object,
            state: SymbolicState,
            crashes: list[CrashCondition],
            description: str,
            variables: dict[str, object],
            severity: Severity = ...,
            taint_info: TaintInfo | None = ...,
        ) -> None: ...
        def _do_binary_op(
            self, left: SymValue, right: SymValue, op: str, state: SymbolicState
        ) -> SymValue: ...
        def _check_division(
            self,
            divisor: SymValue,
            op: str,
            state: SymbolicState,
            crashes: list[CrashCondition],
        ) -> None: ...
        def _check_modulo(
            self,
            divisor: SymValue,
            state: SymbolicState,
            crashes: list[CrashCondition],
        ) -> None: ...
        def _check_shift(
            self,
            amount: SymValue,
            op: str,
            state: SymbolicState,
            crashes: list[CrashCondition],
        ) -> None: ...
        def _check_index_bounds(
            self,
            index: SymValue,
            container: SymValue,
            state: SymbolicState,
            crashes: list[CrashCondition],
        ) -> None: ...

    def _op_LOAD_CONST(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        state.push(self._make_const(arg, state))
        return None

    def _op_LOAD_FAST(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        name = str(arg)
        val = state.get_var(name)
        if val is None:
            val = SymValue(z3.Int(name), name, SymType.INT, origin=f"local:{name}")
            state.set_var(name, val)
        state.push(val)
        return None

    def _op_LOAD_FAST_LOAD_FAST(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if isinstance(arg, tuple):
            for name in arg:
                self._op_LOAD_FAST(name, state, crashes, call_sites)
        return None

    def _op_LOAD_GLOBAL(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        name = str(arg)
        val = SymValue(
            z3.Int(state.fresh_name(name)), name, SymType.UNKNOWN, origin=f"global:{name}"
        )
        state.push(val)
        return None

    def _op_LOAD_NAME(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return self._op_LOAD_GLOBAL(arg, state, crashes, call_sites)

    def _op_LOAD_ATTR(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        obj = state.pop()
        obj_is_none = getattr(obj, "is_none", False)

        if obj is not None and obj_is_none:
            obj_name = getattr(obj, "name", None)
            obj_expr = getattr(obj, "expr", None)
            self._add_crash(
                BugType.NONE_DEREFERENCE,
                z3.BoolVal(True),
                state,
                crashes,
                f"Attribute access on None: {arg}",
                {obj_name: obj_expr} if obj_name else {},
            )

        obj_name = getattr(obj, "name", None)
        obj_taint = getattr(obj, "taint", None)

        val = SymValue(
            z3.Int(state.fresh_name(f"attr_{arg}")),
            f"{obj_name if obj_name else '?'}.{arg}",
            SymType.UNKNOWN,
            taint=(
                obj_taint.propagate(f"attr:{arg}")
                if obj_taint and hasattr(obj_taint, "propagate")
                else TaintInfo()
            ),
        )
        state.push(val)
        return None

    def _op_LOAD_DEREF(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return self._op_LOAD_GLOBAL(arg, state, crashes, call_sites)

    def _op_STORE_FAST(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            val = state.pop()
            if val is not None:
                state.set_var(str(arg), val)
        return None

    def _op_STORE_NAME(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return self._op_STORE_FAST(arg, state, crashes, call_sites)

    def _op_STORE_FAST_STORE_FAST(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if isinstance(arg, tuple):
            for name in reversed(arg):
                if state.stack:
                    val = state.pop()
                    if val is not None:
                        state.set_var(str(name), val)
        return None

    def _op_STORE_GLOBAL(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()
        state.globals_modified.add(str(arg))
        return None

    def _op_STORE_ATTR(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if len(state.stack) >= 2:
            obj = state.pop()
            state.pop()

            if obj is not None and getattr(obj, "is_none", False):
                self._add_crash(
                    BugType.NONE_DEREFERENCE,
                    z3.BoolVal(True),
                    state,
                    crashes,
                    f"Attribute assignment on None: {arg}",
                    {},
                )
        return None

    def _op_STORE_SUBSCR(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if len(state.stack) >= 3:
            index = state.pop()
            container = state.pop()
            state.pop()

            container_is_list = getattr(container, "is_list", False)
            container_length = getattr(container, "length", None)
            if (
                index is not None
                and container is not None
                and container_is_list
                and container_length is not None
            ):
                self._check_index_bounds(index, container, state, crashes)
        return None

    def _op_STORE_DEREF(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()
        return None

    def _op_BINARY_OP(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if len(state.stack) < 2:
            return None
        right = state.pop()
        left = state.pop()
        if right is None or left is None:
            return None

        op_str = str(self.BINARY_OPS.get(arg if isinstance(arg, int) else 0, "+"))
        base_op = op_str.rstrip("=")

        if base_op in ("/", "//"):
            self._check_division(right, base_op, state, crashes)
        elif base_op == "%":
            self._check_modulo(right, state, crashes)
        elif base_op in ("<<", ">>"):
            self._check_shift(right, base_op, state, crashes)

        result: SymValue | None = self._do_binary_op(left, right, base_op, state)
        if result is not None and isinstance(result, SymValue):
            state.push(result)
        return None

    def _op_BINARY_SUBSCR(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if len(state.stack) < 2:
            return None
        index = state.pop()
        container = state.pop()
        if index is None or container is None:
            return None

        container_is_list = getattr(container, "is_list", False)
        container_length = getattr(container, "length", None)
        if container_is_list and container_length is not None:
            self._check_index_bounds(index, container, state, crashes)

        container_name = getattr(container, "name", None)
        index_name = getattr(index, "name", None)
        container_taint = getattr(container, "taint", None)

        result = SymValue(
            z3.Int(state.fresh_name("item")),
            f"{container_name if container_name else '?'}[{index_name if index_name else '?'}]",
            SymType.UNKNOWN,
            taint=(
                container_taint.propagate("subscr")
                if container_taint and hasattr(container_taint, "propagate")
                else TaintInfo()
            ),
        )
        state.push(result)
        return None

    def _op_COMPARE_OP(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if len(state.stack) < 2:
            return None
        right = state.pop()
        left = state.pop()
        if right is None or left is None:
            return None

        op_str = str(arg)
        try:
            op_func = self.COMPARE_OPS.get(op_str)
            left_expr = getattr(left, "expr", None)
            right_expr = getattr(right, "expr", None)

            if op_func and left_expr is not None and right_expr is not None:
                result = SymValue(op_func(left_expr, right_expr), sym_type=SymType.BOOL)
            else:
                result = SymValue(z3.Bool(state.fresh_name("cmp")), sym_type=SymType.BOOL)
        except z3.Z3Exception:
            logger.debug("Z3 comparison %s failed", op_str, exc_info=True)
            result = SymValue(z3.Bool(state.fresh_name("cmp")), sym_type=SymType.BOOL)

        state.push(result)
        return result

    def _op_IS_OP(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if len(state.stack) < 2:
            return None
        right = state.pop()
        left = state.pop()
        if right is None or left is None:
            return None

        try:
            right_is_none = getattr(right, "is_none", False)
            left_is_none = getattr(left, "is_none", False)
            right_expr = getattr(right, "expr", None)
            left_expr = getattr(left, "expr", None)

            if right_is_none and left_is_none:
                result = SymValue(z3.BoolVal(True), sym_type=SymType.BOOL)
            elif right_is_none != left_is_none:
                result = SymValue(z3.BoolVal(False), sym_type=SymType.BOOL)
            elif right_expr is not None and left_expr is not None and left_expr.eq(right_expr):
                result = SymValue(z3.BoolVal(True), sym_type=SymType.BOOL)
            else:

                result = SymValue(z3.Bool(state.fresh_name("is")), sym_type=SymType.BOOL)
        except z3.Z3Exception:
            logger.debug("Z3 IS_OP failed", exc_info=True)
            result = SymValue(z3.Bool(state.fresh_name("is")), sym_type=SymType.BOOL)

        if arg == 1 and result.expr is not None:
            try:
                result = SymValue(z3.Not(result.expr), sym_type=SymType.BOOL)
            except z3.Z3Exception:
                pass

        state.push(result)
        return result

    def _op_CONTAINS_OP(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if len(state.stack) >= 2:
            state.pop()
            state.pop()
        result = SymValue(z3.Bool(state.fresh_name("in")), sym_type=SymType.BOOL)
        state.push(result)
        return result

    def _op_TO_BOOL(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if not state.stack:
            return None
        val = state.pop()
        if val is None:
            return None

        try:
            val_expr = getattr(val, "expr", None)
            if val_expr is not None and z3.is_bool(val_expr):
                state.push(val)
            elif val_expr is not None:
                val_name = getattr(val, "name", None)
                val_taint = getattr(val, "taint", None)
                result = SymValue(val_expr != 0, val_name, SymType.BOOL, taint=val_taint)
                state.push(result)
            else:
                state.push(SymValue(z3.Bool(state.fresh_name("bool")), sym_type=SymType.BOOL))
        except z3.Z3Exception:
            logger.debug("Z3 TO_BOOL conversion failed", exc_info=True)
            state.push(SymValue(z3.Bool(state.fresh_name("bool")), sym_type=SymType.BOOL))
        return None

    def _op_POP_JUMP_IF_FALSE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            return state.pop()
        return None

    def _op_POP_JUMP_IF_TRUE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return self._op_POP_JUMP_IF_FALSE(arg, state, crashes, call_sites)

    def _op_POP_JUMP_IF_NONE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return self._op_POP_JUMP_IF_FALSE(arg, state, crashes, call_sites)

    def _op_POP_JUMP_IF_NOT_NONE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return self._op_POP_JUMP_IF_FALSE(arg, state, crashes, call_sites)

    def _op_UNARY_NEGATIVE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            val = state.pop()
            if val is None:
                return None
            try:
                val_expr = getattr(val, "expr", None)
                val_name = getattr(val, "name", "unknown")
                val_taint = getattr(val, "taint", None)
                if val_expr is not None:
                    state.push(SymValue(-val_expr, f"-{val_name}", SymType.INT, taint=val_taint))
                else:
                    state.push(SymValue(z3.Int(state.fresh_name("neg")), sym_type=SymType.INT))
            except z3.Z3Exception:
                logger.debug("Z3 UNARY_NEGATIVE failed", exc_info=True)
                state.push(SymValue(z3.Int(state.fresh_name("neg")), sym_type=SymType.INT))
        return None

    def _op_UNARY_NOT(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            val = state.pop()
            if val is None:
                return None
            try:
                val_expr = getattr(val, "expr", None)
                if val_expr is not None and z3.is_bool(val_expr):
                    state.push(SymValue(z3.Not(val_expr), sym_type=SymType.BOOL))
                elif val_expr is not None:
                    state.push(SymValue(val_expr == 0, sym_type=SymType.BOOL))
                else:
                    state.push(SymValue(z3.Bool(state.fresh_name("not")), sym_type=SymType.BOOL))
            except z3.Z3Exception:
                logger.debug("Z3 UNARY_NOT failed", exc_info=True)
                state.push(SymValue(z3.Bool(state.fresh_name("not")), sym_type=SymType.BOOL))
        return None

    def _op_UNARY_INVERT(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            val = state.pop()
            if val is None:
                return None
            try:
                val_expr = getattr(val, "expr", None)
                val_name = getattr(val, "name", "unknown")
                val_taint = getattr(val, "taint", None)
                if val_expr is not None:
                    state.push(SymValue(~val_expr, f"~{val_name}", SymType.INT, taint=val_taint))
                else:
                    state.push(SymValue(z3.Int(state.fresh_name("inv")), sym_type=SymType.INT))
            except z3.Z3Exception:
                logger.debug("Z3 UNARY_INVERT failed", exc_info=True)
                state.push(SymValue(z3.Int(state.fresh_name("inv")), sym_type=SymType.INT))
        return None

    def _op_CALL(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        n = arg if isinstance(arg, int) else 0
        args: list[SymValue] = []

        for _ in range(n):
            if state.stack:
                popped = state.pop()
                if popped is not None:
                    args.insert(0, popped)

        if state.stack:
            state.pop()

        func = state.pop() if state.stack else None

        if func and func.name:
            call_sites.append(
                CallSite(
                    caller=self.current_function,
                    callee=func.name,
                    line=self.current_line,
                    arguments=[a.name for a in args],
                    file_path=self.current_file,
                )
            )
            if func.name in self.DANGEROUS_SINKS:
                for a in args:
                    is_tainted = getattr(a, "is_tainted", False)
                    taint_info = getattr(a, "taint", None)
                    if is_tainted:
                        self._add_crash(
                            BugType.TAINTED_SINK,
                            z3.BoolVal(True),
                            state,
                            crashes,
                            f"Tainted data passed to dangerous function: {func.name}",
                            {},
                            Severity.CRITICAL,
                            taint_info,
                        )

        result = SymValue(
            z3.Int(state.fresh_name("call")),
            f"{func.name if func else '?'}(...)" if func else "call(...)",
            SymType.UNKNOWN,
        )
        state.push(result)
        return None

    def _op_CALL_FUNCTION_EX(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        flags = arg if isinstance(arg, int) else 0
        has_kwargs = (flags & 0x01) == 0x01

        if has_kwargs and state.stack:
            state.pop()

        if state.stack:
            state.pop()

        if state.stack:
            state.pop()

        state.push(SymValue(z3.Int(state.fresh_name("call")), sym_type=SymType.UNKNOWN))
        return None

    def _op_PUSH_NULL(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        state.push(SymValue(z3.IntVal(0), "NULL", SymType.NONE, is_none=True))
        return None

    def _op_BUILD_LIST(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        n = arg if isinstance(arg, int) else 0
        for _ in range(n):
            if state.stack:
                state.pop()
        result = SymValue(
            z3.Int(state.fresh_name("list")),
            f"[...{n}]",
            SymType.LIST,
            is_list=True,
            length=z3.IntVal(n),
        )
        state.push(result)
        return None

    def _op_BUILD_TUPLE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        n = arg if isinstance(arg, int) else 0
        for _ in range(n):
            if state.stack:
                state.pop()
        state.push(
            SymValue(z3.Int(state.fresh_name("tuple")), sym_type=SymType.TUPLE, length=z3.IntVal(n))
        )
        return None

    def _op_BUILD_SET(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        n = arg if isinstance(arg, int) else 0
        for _ in range(n):
            if state.stack:
                state.pop()
        state.push(SymValue(z3.Int(state.fresh_name("set")), sym_type=SymType.SET))
        return None

    def _op_BUILD_MAP(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        n = arg if isinstance(arg, int) else 0
        for _ in range(n * 2):
            if state.stack:
                state.pop()
        state.push(SymValue(z3.Int(state.fresh_name("dict")), sym_type=SymType.DICT))
        return None

    def _op_BUILD_CONST_KEY_MAP(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        n = arg if isinstance(arg, int) else 0
        for _ in range(n + 1):
            if state.stack:
                state.pop()
        state.push(SymValue(z3.Int(state.fresh_name("dict")), sym_type=SymType.DICT))
        return None

    def _op_BUILD_STRING(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        n = arg if isinstance(arg, int) else 0
        for _ in range(n):
            if state.stack:
                state.pop()
        state.push(SymValue(z3.Int(state.fresh_name("str")), sym_type=SymType.STRING))
        return None

    def _op_LIST_EXTEND(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()
        return None

    def _op_SET_UPDATE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()
        return None

    def _op_DICT_UPDATE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()
        return None

    def _op_DICT_MERGE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()
        return None

    def _op_POP_TOP(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()
        return None

    def _op_COPY(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        n = arg if isinstance(arg, int) else 1
        if state.stack and len(state.stack) >= n:
            if state.stack[-n] is not None:
                state.push(state.stack[-n])
        return None

    def _op_SWAP(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        n = arg if isinstance(arg, int) else 2
        if len(state.stack) >= n:
            if all(state.stack[-i] is not None for i in range(1, n + 1)):
                state.stack[-1], state.stack[-n] = state.stack[-n], state.stack[-1]
        return None

    def _op_DUP_TOP(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            if state.stack[-1] is not None:
                state.push(state.stack[-1])
        return None

    def _op_ROT_TWO(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if len(state.stack) >= 2:
            if state.stack[-1] is not None and state.stack[-2] is not None:
                state.stack[-1], state.stack[-2] = state.stack[-2], state.stack[-1]
        return None

    def _op_ROT_THREE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if len(state.stack) >= 3:
            if all(s is not None for s in state.stack[-3:]):
                state.stack[-1], state.stack[-2], state.stack[-3] = (
                    state.stack[-2],
                    state.stack[-3],
                    state.stack[-1],
                )
        return None

    def _op_GET_ITER(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        container = state.pop() if state.stack else None
        container_taint = getattr(container, "taint", None)

        state.push(
            SymValue(
                z3.Int(state.fresh_name("iter")),
                sym_type=SymType.UNKNOWN,
                taint=container_taint if container_taint else TaintInfo(),
            )
        )
        return None

    def _op_FOR_ITER(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        state.push(SymValue(z3.Int(state.fresh_name("item")), sym_type=SymType.UNKNOWN))
        return None

    def _op_END_FOR(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        for _ in range(2):
            if state.stack:
                state.pop()
        return None

    def _op_RETURN_VALUE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()
        return None

    def _op_RETURN_CONST(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return None

    def _op_YIELD_VALUE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()
        state.push(SymValue(z3.Int(state.fresh_name("sent")), sym_type=SymType.UNKNOWN))
        return None

    def _op_RESUME(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return None

    def _op_NOP(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return None

    def _op_PRECALL(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return None

    def _op_KW_NAMES(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return None

    def _op_MAKE_FUNCTION(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()
        state.push(SymValue(z3.Int(state.fresh_name("func")), sym_type=SymType.CALLABLE))
        return None

    def _op_FORMAT_VALUE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        flags = arg if isinstance(arg, int) else 0
        has_fmt_spec = (flags & 0x04) == 0x04

        if has_fmt_spec and state.stack:
            state.pop()

        if state.stack:
            val = state.pop()
            if val is not None:
                val_taint = getattr(val, "taint", None)
                if val_taint is not None and hasattr(val_taint, "propagate"):
                    taint = val_taint.propagate("format")
                else:
                    taint = TaintInfo()

                state.push(
                    SymValue(
                        z3.Int(state.fresh_name("fmt")),
                        sym_type=SymType.STRING,
                        taint=taint,
                    )
                )
        return None

    def _op_UNPACK_SEQUENCE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        seq = state.pop() if state.stack else None
        n = arg if isinstance(arg, int) else 1
        seq_taint = getattr(seq, "taint", None)

        for _ in range(n):
            state.push(
                SymValue(
                    z3.Int(state.fresh_name("unpack")),
                    sym_type=SymType.UNKNOWN,
                    taint=seq_taint if seq_taint else TaintInfo(),
                )
            )
        return None

    def _op_DELETE_FAST(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        name = str(arg)
        if name in state.variables:
            del state.variables[name]
        return None

    def _op_RAISE_VARARGS(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        n = arg if isinstance(arg, int) else 0
        for _ in range(n):
            if state.stack:
                state.pop()
        return None

    def _op_RERAISE(
        self,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return None

    def _op_unknown(
        self,
        op: str,
        arg: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        """Handle unknown opcodes gracefully."""
        return None
