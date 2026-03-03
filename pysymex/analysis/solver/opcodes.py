"""
Z3 Engine — Bytecode opcode handlers.

Mixin class providing symbolic execution handlers for Python bytecode opcodes.
Mixed into FunctionAnalyzer to keep file sizes manageable.
"""

from __future__ import annotations


import logging

from typing import Any


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

from pysymex.analysis.solver.graph import SymbolicState

logger = logging.getLogger(__name__)


class OpcodeHandlersMixin:
    """Mixin providing bytecode opcode handlers for FunctionAnalyzer.

    All methods here are designed to be mixed into FunctionAnalyzer,
    which provides the class attributes and helper methods they depend on
    (e.g. _make_const, _add_crash, _check_division, DANGEROUS_SINKS, etc.).
    """

    def _op_LOAD_CONST(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        state.push(self._make_const(arg, state))

        return None

    def _op_LOAD_FAST(
        self,
        arg: Any,
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
        arg: Any,
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
        arg: Any,
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
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return self._op_LOAD_GLOBAL(arg, state, crashes, call_sites)

    def _op_LOAD_ATTR(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        obj = state.pop()

        if obj and obj.is_none:
            self._add_crash(
                BugType.NONE_DEREFERENCE,
                z3.BoolVal(True),
                state,
                crashes,
                f"Attribute access on None: {arg}",
                {obj.name: obj.expr} if obj.name else {},
            )

        val = SymValue(
            z3.Int(state.fresh_name(f"attr_{arg}")),
            f"{obj.name if obj else '?'}.{arg}",
            SymType.UNKNOWN,
            taint=obj.taint.propagate(f"attr:{arg}") if obj else TaintInfo(),
        )

        state.push(val)

        return None

    def _op_LOAD_DEREF(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return self._op_LOAD_GLOBAL(arg, state, crashes, call_sites)

    def _op_STORE_FAST(
        self,
        arg: Any,
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
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return self._op_STORE_FAST(arg, state, crashes, call_sites)

    def _op_STORE_FAST_STORE_FAST(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if isinstance(arg, tuple):
            for name in arg:
                if state.stack:
                    val = state.pop()

                    if val is not None:
                        state.set_var(str(name), val)

        return None

    def _op_STORE_GLOBAL(
        self,
        arg: Any,
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
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if len(state.stack) >= 2:
            obj = state.pop()

            state.pop()

            if obj and obj.is_none:
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
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if len(state.stack) >= 3:
            index = state.pop()

            container = state.pop()

            state.pop()

            if (
                index is not None
                and container is not None
                and container.is_list
                and container.length is not None
            ):
                self._check_index_bounds(index, container, state, crashes)

        return None

    def _op_STORE_DEREF(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()

        return None

    def _op_BINARY_OP(
        self,
        arg: Any,
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

        op_str = str(self.BINARY_OPS.get(arg, "+"))

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
        arg: Any,
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

        if container.is_list and container.length is not None:
            self._check_index_bounds(index, container, state, crashes)

        result = SymValue(
            z3.Int(state.fresh_name("item")),
            f"{container.name if container else '?'}[{index.name if index else '?'}]",
            SymType.UNKNOWN,
            taint=container.taint.propagate("subscr") if container else TaintInfo(),
        )

        state.push(result)

        return None

    def _op_COMPARE_OP(
        self,
        arg: Any,
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

        for key in sorted(self.COMPARE_OPS, key=len, reverse=True):
            if op_str == key:
                break

        else:
            op_str = op_str

        try:
            op_func = self.COMPARE_OPS.get(op_str)

            if op_func and left.expr is not None and right.expr is not None:
                result = SymValue(op_func(left.expr, right.expr), sym_type=SymType.BOOL)

            else:
                result = SymValue(z3.Bool(state.fresh_name("cmp")), sym_type=SymType.BOOL)

        except Exception:
            logger.debug("Z3 comparison %s failed", op_str, exc_info=True)

            result = SymValue(z3.Bool(state.fresh_name("cmp")), sym_type=SymType.BOOL)

        state.push(result)

        return result

    def _op_IS_OP(
        self,
        arg: Any,
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
            if right.is_none:
                if left.is_none:
                    result = SymValue(z3.BoolVal(True), sym_type=SymType.BOOL)

                else:
                    result = SymValue(left.expr == 0, sym_type=SymType.BOOL)

            else:
                result = SymValue(left.expr == right.expr, sym_type=SymType.BOOL)

        except Exception:
            logger.debug("Z3 IS_OP failed", exc_info=True)

            result = SymValue(z3.Bool(state.fresh_name("is")), sym_type=SymType.BOOL)

        if arg == 1 and result.expr is not None:
            try:
                result = SymValue(z3.Not(result.expr), sym_type=SymType.BOOL)

            except Exception:
                pass

        state.push(result)

        return result

    def _op_CONTAINS_OP(
        self,
        arg: Any,
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
        arg: Any,
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
            if z3.is_bool(val.expr):
                state.push(val)

            else:
                result = SymValue(val.expr != 0, val.name, SymType.BOOL, taint=val.taint)

                state.push(result)

        except Exception:
            logger.debug("Z3 TO_BOOL conversion failed", exc_info=True)

            state.push(SymValue(z3.Bool(state.fresh_name("bool")), sym_type=SymType.BOOL))

        return None

    def _op_POP_JUMP_IF_FALSE(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            return state.pop()

        return None

    def _op_POP_JUMP_IF_TRUE(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return self._op_POP_JUMP_IF_FALSE(arg, state, crashes, call_sites)

    def _op_POP_JUMP_IF_NONE(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return self._op_POP_JUMP_IF_FALSE(arg, state, crashes, call_sites)

    def _op_POP_JUMP_IF_NOT_NONE(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return self._op_POP_JUMP_IF_FALSE(arg, state, crashes, call_sites)

    def _op_UNARY_NEGATIVE(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            val = state.pop()

            if val is None:
                return None

            try:
                state.push(SymValue(-val.expr, f"-{val.name}", SymType.INT, taint=val.taint))

            except Exception:
                logger.debug("Z3 UNARY_NEGATIVE failed", exc_info=True)

                state.push(SymValue(z3.Int(state.fresh_name("neg")), sym_type=SymType.INT))

        return None

    def _op_UNARY_NOT(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            val = state.pop()

            if val is None:
                return None

            try:
                if z3.is_bool(val.expr):
                    state.push(SymValue(z3.Not(val.expr), sym_type=SymType.BOOL))

                else:
                    state.push(SymValue(val.expr == 0, sym_type=SymType.BOOL))

            except Exception:
                logger.debug("Z3 UNARY_NOT failed", exc_info=True)

                state.push(SymValue(z3.Bool(state.fresh_name("not")), sym_type=SymType.BOOL))

        return None

    def _op_UNARY_INVERT(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            val = state.pop()

            if val is None:
                return None

            try:
                state.push(SymValue(~val.expr, f"~{val.name}", SymType.INT, taint=val.taint))

            except Exception:
                logger.debug("Z3 UNARY_INVERT failed", exc_info=True)

                state.push(SymValue(z3.Int(state.fresh_name("inv")), sym_type=SymType.INT))

        return None

    def _op_CALL(
        self,
        arg: Any,
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
                    if a.is_tainted:
                        self._add_crash(
                            BugType.TAINTED_SINK,
                            z3.BoolVal(True),
                            state,
                            crashes,
                            f"Tainted data passed to dangerous function: {func.name}",
                            {},
                            Severity.CRITICAL,
                            a.taint,
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
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()

        if state.stack:
            state.pop()

        state.push(SymValue(z3.Int(state.fresh_name("call")), sym_type=SymType.UNKNOWN))

        return None

    def _op_PUSH_NULL(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        state.push(SymValue(z3.IntVal(0), "NULL", SymType.NONE, is_none=True))

        return None

    def _op_BUILD_LIST(
        self,
        arg: Any,
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
        arg: Any,
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
        arg: Any,
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
        arg: Any,
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
        arg: Any,
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
        arg: Any,
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
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()

        return None

    def _op_SET_UPDATE(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()

        return None

    def _op_DICT_UPDATE(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()

        return None

    def _op_DICT_MERGE(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()

        return None

    def _op_POP_TOP(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()

        return None

    def _op_COPY(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        n = arg if isinstance(arg, int) else 1

        if state.stack and len(state.stack) >= n:
            state.push(state.stack[-n])

        return None

    def _op_SWAP(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        n = arg if isinstance(arg, int) else 2

        if len(state.stack) >= n:
            state.stack[-1], state.stack[-n] = state.stack[-n], state.stack[-1]

        return None

    def _op_DUP_TOP(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.push(state.stack[-1])

        return None

    def _op_ROT_TWO(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if len(state.stack) >= 2:
            state.stack[-1], state.stack[-2] = state.stack[-2], state.stack[-1]

        return None

    def _op_ROT_THREE(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if len(state.stack) >= 3:
            state.stack[-1], state.stack[-2], state.stack[-3] = (
                state.stack[-2],
                state.stack[-3],
                state.stack[-1],
            )

        return None

    def _op_GET_ITER(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        container = state.pop() if state.stack else None

        state.push(
            SymValue(
                z3.Int(state.fresh_name("iter")),
                sym_type=SymType.UNKNOWN,
                taint=container.taint if container else TaintInfo(),
            )
        )

        return None

    def _op_FOR_ITER(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        state.push(SymValue(z3.Int(state.fresh_name("item")), sym_type=SymType.UNKNOWN))

        return None

    def _op_END_FOR(
        self,
        arg: Any,
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
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            state.pop()

        return None

    def _op_RETURN_CONST(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return None

    def _op_YIELD_VALUE(
        self,
        arg: Any,
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
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return None

    def _op_NOP(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return None

    def _op_PRECALL(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return None

    def _op_KW_NAMES(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return None

    def _op_MAKE_FUNCTION(
        self,
        arg: Any,
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
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        if state.stack:
            val = state.pop()

            if val is not None:
                state.push(
                    SymValue(
                        z3.Int(state.fresh_name("fmt")),
                        sym_type=SymType.STRING,
                        taint=val.taint.propagate("format"),
                    )
                )

        return None

    def _op_UNPACK_SEQUENCE(
        self,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        seq = state.pop() if state.stack else None

        n = arg if isinstance(arg, int) else 1

        for _ in range(n):
            state.push(
                SymValue(
                    z3.Int(state.fresh_name("unpack")),
                    sym_type=SymType.UNKNOWN,
                    taint=seq.taint if seq else TaintInfo(),
                )
            )

        return None

    def _op_DELETE_FAST(
        self,
        arg: Any,
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
        arg: Any,
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
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        return None

    def _op_unknown(
        self,
        op: str,
        arg: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        """Handle unknown opcodes gracefully."""

        return None
