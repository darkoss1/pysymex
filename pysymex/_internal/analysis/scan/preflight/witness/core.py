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

"""Source-level concrete witness diagnostics.

This preflight does not consume declared experiment metadata. It evaluates a
small side-effect-contained Python subset starting from ordinary in-source calls
or short strings fully pinned by equality guards. When such a call reaches a
Python runtime exception, the scanner records the actual concrete behavior as a
diagnostic instead of trusting oracle comments.
"""

from __future__ import annotations

import ast
from collections.abc import Container, Iterable, Sized
from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn, Protocol, cast, runtime_checkable

from pysymex._internal.analysis.scan.preflight.witness.inference import (
    equality_derived_string_calls,
)

if TYPE_CHECKING:
    from pysymex._internal.analysis.records import IssueRecord

_EXCEPTION_KINDS: dict[type[BaseException], str] = {
    ZeroDivisionError: "DIVISION_BY_ZERO",
    IndexError: "INDEX_ERROR",
    KeyError: "KEY_ERROR",
    AttributeError: "ATTRIBUTE_ERROR",
    AssertionError: "ASSERTION_ERROR",
    TypeError: "TYPE_ERROR",
    ValueError: "VALUE_ERROR",
    NameError: "NAME_ERROR",
}

_BUILTIN_GLOBALS: dict[str, object] = {
    "bool": bool,
    "bytearray": bytearray,
    "bytes": bytes,
    "dict": dict,
    "float": float,
    "int": int,
    "list": list,
    "set": set,
    "str": str,
    "tuple": tuple,
}


@dataclass(slots=True)
class _RaisedIssue(Exception):
    kind: str
    message: str
    node: ast.AST


@dataclass(slots=True)
class _ReturnSignal(Exception):
    value: object


class _UnsupportedWitness(Exception):
    pass


@runtime_checkable
class _SupportsGetItem(Protocol):
    def __getitem__(self, key: object) -> object: ...


@runtime_checkable
class _SupportsSetItem(Protocol):
    def __setitem__(self, key: object, value: object) -> None: ...


@runtime_checkable
class _SupportsAdd(Protocol):
    def __add__(self, other: object) -> object: ...


@runtime_checkable
class _SupportsSub(Protocol):
    def __sub__(self, other: object) -> object: ...


@runtime_checkable
class _SupportsMul(Protocol):
    def __mul__(self, other: object) -> object: ...


@runtime_checkable
class _SupportsTrueDiv(Protocol):
    def __truediv__(self, other: object) -> object: ...


@runtime_checkable
class _SupportsFloorDiv(Protocol):
    def __floordiv__(self, other: object) -> object: ...


@runtime_checkable
class _SupportsMod(Protocol):
    def __mod__(self, other: object) -> object: ...


@runtime_checkable
class _SupportsLt(Protocol):
    def __lt__(self, other: object) -> bool: ...


@runtime_checkable
class _SupportsLe(Protocol):
    def __le__(self, other: object) -> bool: ...


@runtime_checkable
class _SupportsGt(Protocol):
    def __gt__(self, other: object) -> bool: ...


@runtime_checkable
class _SupportsGe(Protocol):
    def __ge__(self, other: object) -> bool: ...


@dataclass(frozen=True, slots=True)
class _WitnessInvocation:
    call: ast.Call
    counterexample: dict[str, object] | None = None


class _ConcreteWitnessInterpreter:
    def __init__(self, tree: ast.Module) -> None:
        self._tree = tree
        self._functions = {
            stmt.name: stmt for stmt in tree.body if isinstance(stmt, ast.FunctionDef)
        }
        self._globals: dict[str, object] = dict(_BUILTIN_GLOBALS)
        self._active_calls: set[tuple[str, tuple[object, ...]]] = set()
        self._collect_module_constants()

    def can_resolve_call(self, call: ast.Call) -> bool:
        if not isinstance(call.func, ast.Name) or call.func.id not in self._functions:
            return False
        if call.keywords or not call.args:
            return False
        try:
            _ = [self._eval(arg, self._globals.copy()) for arg in call.args]
        except (_UnsupportedWitness, _RaisedIssue):
            return False
        return True

    def evaluate_call(self, call: ast.Call) -> object:
        if not isinstance(call.func, ast.Name) or call.func.id not in self._functions:
            raise _UnsupportedWitness
        if call.keywords:
            raise _UnsupportedWitness
        args = [self._eval(arg, self._globals.copy()) for arg in call.args]
        return self._call_function(call.func.id, args, call)

    def _collect_module_constants(self) -> None:
        self._collect_module_constants_from_statements(self._tree.body)

    def _collect_module_constants_from_statements(self, statements: list[ast.stmt]) -> None:
        for stmt in statements:
            if isinstance(stmt, ast.FunctionDef):
                continue
            if isinstance(stmt, ast.Assign):
                try:
                    value = self._eval(stmt.value, self._globals.copy())
                except (_UnsupportedWitness, _RaisedIssue):
                    continue
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        self._globals[target.id] = value
                continue
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                if stmt.value is None:
                    continue
                try:
                    self._globals[stmt.target.id] = self._eval(stmt.value, self._globals.copy())
                except (_UnsupportedWitness, _RaisedIssue):
                    continue
                continue
            if isinstance(stmt, ast.If):
                self._collect_module_constants_from_statements(stmt.body)
                self._collect_module_constants_from_statements(stmt.orelse)

    def _call_function(self, name: str, args: list[object], node: ast.AST) -> object:
        self._tick(node)
        call_key = (name, tuple(_witness_value_key(arg) for arg in args))
        if call_key in self._active_calls:
            raise _UnsupportedWitness
        func = self._functions[name]
        positional = [arg.arg for arg in func.args.args]
        if len(args) != len(positional):
            raise _UnsupportedWitness
        env = self._globals.copy()
        env.update(dict(zip(positional, args, strict=True)))
        self._active_calls.add(call_key)
        try:
            try:
                self._exec_block(func.body, env)
            except _ReturnSignal as signal:
                return signal.value
        finally:
            self._active_calls.remove(call_key)
        return None

    def _exec_block(self, body: list[ast.stmt], env: dict[str, object]) -> None:
        for stmt in body:
            self._exec_stmt(stmt, env)

    def _exec_stmt(self, stmt: ast.stmt, env: dict[str, object]) -> None:
        self._tick(stmt)
        try:
            if isinstance(stmt, ast.Assign):
                value = self._eval(stmt.value, env)
                for target in stmt.targets:
                    self._assign(target, value, env)
                return
            if isinstance(stmt, ast.AugAssign):
                old = self._eval(stmt.target, env)
                value = self._eval(stmt.value, env)
                self._assign(stmt.target, self._apply_binop(stmt.op, old, value, stmt), env)
                return
            if isinstance(stmt, ast.If):
                branch = stmt.body if self._truthy(self._eval(stmt.test, env)) else stmt.orelse
                self._exec_block(branch, env)
                return
            if isinstance(stmt, ast.For):
                iterable = self._eval(stmt.iter, env)
                if not isinstance(iterable, Iterable) or isinstance(iterable, (bytes, bytearray)):
                    raise _UnsupportedWitness
                for item in cast("Iterable[object]", iterable):
                    self._assign(stmt.target, item, env)
                    self._exec_block(stmt.body, env)
                if stmt.orelse:
                    self._exec_block(stmt.orelse, env)
                return
            if isinstance(stmt, ast.Return):
                raise _ReturnSignal(None if stmt.value is None else self._eval(stmt.value, env))
            if isinstance(stmt, ast.Assert):
                if not self._truthy(self._eval(stmt.test, env)):
                    msg = "assertion failed"
                    raise AssertionError(msg)
                return
            if isinstance(stmt, ast.Expr):
                self._eval(stmt.value, env)
                return
        except _RaisedIssue:
            raise
        except tuple(_EXCEPTION_KINDS) as exc:
            self._raise_issue(exc, stmt)
        raise _UnsupportedWitness

    def _eval(self, expr: ast.AST, env: dict[str, object]) -> object:
        self._tick(expr)
        try:
            if isinstance(expr, ast.Constant):
                return expr.value
            if isinstance(expr, ast.Name):
                try:
                    return env[expr.id]
                except KeyError as exc:
                    raise NameError(expr.id) from exc
            if isinstance(expr, ast.List):
                return [self._eval(item, env) for item in expr.elts]
            if isinstance(expr, ast.Tuple):
                return tuple(self._eval(item, env) for item in expr.elts)
            if isinstance(expr, ast.Dict):
                return {
                    self._eval(key, env): self._eval(value, env)
                    for key, value in zip(expr.keys, expr.values, strict=True)
                    if key is not None
                }
            if isinstance(expr, ast.ListComp):
                return self._eval_list_comp(expr, env)
            if isinstance(expr, ast.BinOp):
                return self._apply_binop(
                    expr.op,
                    self._eval(expr.left, env),
                    self._eval(expr.right, env),
                    expr,
                )
            if isinstance(expr, ast.UnaryOp):
                return self._apply_unary(expr.op, self._eval(expr.operand, env), expr)
            if isinstance(expr, ast.BoolOp):
                return self._eval_boolop(expr, env)
            if isinstance(expr, ast.Compare):
                return self._eval_compare(expr, env)
            if isinstance(expr, ast.IfExp):
                branch = expr.body if self._truthy(self._eval(expr.test, env)) else expr.orelse
                return self._eval(branch, env)
            if isinstance(expr, ast.Subscript):
                container = self._eval(expr.value, env)
                return self._getitem(container, self._eval_slice(expr.slice, env), expr)
            if isinstance(expr, ast.Call):
                return self._eval_call(expr, env)
            if isinstance(expr, ast.Attribute):
                return getattr(self._eval(expr.value, env), expr.attr)
        except _RaisedIssue:
            raise
        except tuple(_EXCEPTION_KINDS) as exc:
            self._raise_issue(exc, expr)
        raise _UnsupportedWitness

    def _eval_call(self, expr: ast.Call, env: dict[str, object]) -> object:
        if expr.keywords:
            raise _UnsupportedWitness
        args = [self._eval(arg, env) for arg in expr.args]
        if isinstance(expr.func, ast.Name):
            name = expr.func.id
            if name in self._functions:
                return self._call_function(name, args, expr)
            if name == "range":
                return range(*[self._require_int(arg, expr) for arg in args])
            if name == "enumerate" and len(args) in {1, 2}:
                return self._call_enumerate(args, expr)
            if name == "len" and len(args) == 1:
                return self._call_len(args[0], expr)
            if name == "ord" and len(args) == 1:
                return self._call_ord(args[0], expr)
            if name == "bin" and len(args) == 1:
                return bin(self._require_int(args[0], expr))
            if name == "bytes" and len(args) in {0, 1}:
                return self._call_bytes(args, expr)
            if name == "int" and len(args) in {1, 2}:
                return self._call_int(args, expr)
            raise _UnsupportedWitness
        if isinstance(expr.func, ast.Attribute):
            receiver = self._eval(expr.func.value, env)
            name = expr.func.attr
            if name == "bit_count" and not args:
                return self._require_int(receiver, expr).bit_count()
            if name == "count" and len(args) in {1, 2, 3}:
                return self._call_count(receiver, args, expr)
            if name == "decode" and isinstance(receiver, (bytes, bytearray)) and len(args) <= 2:
                return self._call_decode(receiver, args, expr)
            if name == "startswith" and len(args) in {1, 2, 3}:
                return self._call_startswith(receiver, args, expr)
            raise _UnsupportedWitness
        raise _UnsupportedWitness

    def _getitem(self, container: object, key: object, node: ast.AST) -> object:
        if not isinstance(container, _SupportsGetItem):
            self._raise_issue(TypeError("object is not subscriptable"), node)
        return container[key]

    def _setitem(self, container: object, key: object, value: object, node: ast.AST) -> None:
        if not isinstance(container, _SupportsSetItem):
            self._raise_issue(TypeError("object does not support item assignment"), node)
        container[key] = value

    def _call_enumerate(self, args: list[object], node: ast.AST) -> enumerate[object]:
        if not args or len(args) > 2:
            raise _UnsupportedWitness
        iterable = args[0]
        if not isinstance(iterable, Iterable):
            self._raise_issue(TypeError("enumerate() argument must be iterable"), node)
        iterable_obj = cast("Iterable[object]", iterable)
        if len(args) == 1:
            return enumerate(iterable_obj)
        start = self._require_int(args[1], node)
        return enumerate(iterable_obj, start)

    def _call_len(self, value: object, node: ast.AST) -> int:
        if not isinstance(value, Sized):
            self._raise_issue(TypeError("object has no len()"), node)
        return len(value)

    def _call_ord(self, value: object, node: ast.AST) -> int:
        if not isinstance(value, str) or len(value) != 1:
            self._raise_issue(TypeError("ord() expected a character"), node)
        return ord(value)

    def _call_bytes(self, args: list[object], node: ast.AST) -> bytes:
        if not args:
            return b""
        if len(args) != 1:
            raise _UnsupportedWitness
        value = args[0]
        if isinstance(value, int):
            return bytes(value)
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if isinstance(value, Iterable) and not isinstance(value, (str, bytes, bytearray)):
            iterable = cast("Iterable[object]", value)
            return bytes(self._require_int(item, node) for item in iterable)
        raise _UnsupportedWitness

    def _call_int(self, args: list[object], node: ast.AST) -> int:
        if len(args) == 1:
            value = args[0]
            if isinstance(value, bool | int | float | str | bytes | bytearray):
                return int(value)
            self._raise_issue(TypeError("int() argument has unsupported type"), node)
        if len(args) == 2:
            value, base = args
            base_int = self._require_int(base, node)
            if isinstance(value, str | bytes | bytearray):
                return int(value, base_int)
            self._raise_issue(TypeError("int() base conversion requires a string-like value"), node)
        raise _UnsupportedWitness

    def _call_count(self, receiver: object, args: list[object], node: ast.AST) -> int:
        if isinstance(receiver, list) and len(args) == 1:
            return cast("list[object]", receiver).count(args[0])
        if isinstance(receiver, tuple) and len(args) == 1:
            return cast("tuple[object, ...]", receiver).count(args[0])
        if isinstance(receiver, str) and len(args) in {1, 2, 3}:
            needle = args[0]
            if not isinstance(needle, str):
                self._raise_issue(TypeError("str.count() argument must be str"), node)
            if len(args) == 1:
                return receiver.count(needle)
            start = self._require_int(args[1], node)
            if len(args) == 2:
                return receiver.count(needle, start)
            return receiver.count(needle, start, self._require_int(args[2], node))
        if isinstance(receiver, bytes) and len(args) in {1, 2, 3}:
            return self._bytes_count(receiver, args, node)
        if isinstance(receiver, bytearray) and len(args) in {1, 2, 3}:
            return self._bytes_count(receiver, args, node)
        raise _UnsupportedWitness

    def _bytes_count(self, receiver: bytes | bytearray, args: list[object], node: ast.AST) -> int:
        needle = args[0]
        if not isinstance(needle, (int, bytes, bytearray)):
            self._raise_issue(TypeError("bytes.count() argument must be int or bytes-like"), node)
        if len(args) == 1:
            return receiver.count(needle)
        start = self._require_int(args[1], node)
        if len(args) == 2:
            return receiver.count(needle, start)
        return receiver.count(needle, start, self._require_int(args[2], node))

    def _call_decode(self, receiver: bytes | bytearray, args: list[object], node: ast.AST) -> str:
        if len(args) > 2:
            raise _UnsupportedWitness
        if not args:
            return receiver.decode()
        encoding = args[0]
        if not isinstance(encoding, str):
            self._raise_issue(TypeError("decode() encoding must be str"), node)
        if len(args) == 1:
            return receiver.decode(encoding)
        errors = args[1]
        if not isinstance(errors, str):
            self._raise_issue(TypeError("decode() errors must be str"), node)
        return receiver.decode(encoding, errors)

    def _call_startswith(self, receiver: object, args: list[object], node: ast.AST) -> bool:
        if isinstance(receiver, str) and len(args) in {1, 2, 3}:
            prefix = args[0]
            if not isinstance(prefix, str):
                self._raise_issue(TypeError("str.startswith() prefix must be str"), node)
            if len(args) == 1:
                return receiver.startswith(prefix)
            start = self._require_int(args[1], node)
            if len(args) == 2:
                return receiver.startswith(prefix, start)
            return receiver.startswith(prefix, start, self._require_int(args[2], node))
        if isinstance(receiver, bytes) and len(args) in {1, 2, 3}:
            return self._bytes_startswith(receiver, args, node)
        if isinstance(receiver, bytearray) and len(args) in {1, 2, 3}:
            return self._bytes_startswith(receiver, args, node)
        raise _UnsupportedWitness

    def _bytes_startswith(
        self,
        receiver: bytes | bytearray,
        args: list[object],
        node: ast.AST,
    ) -> bool:
        prefix = args[0]
        if not isinstance(prefix, (bytes, bytearray)):
            self._raise_issue(TypeError("bytes.startswith() prefix must be bytes-like"), node)
        if len(args) == 1:
            return receiver.startswith(prefix)
        start = self._require_int(args[1], node)
        if len(args) == 2:
            return receiver.startswith(prefix, start)
        return receiver.startswith(prefix, start, self._require_int(args[2], node))

    def _apply_dynamic_binop(
        self,
        left: object,
        right: object,
        protocol: type[object],
        node: ast.AST,
    ) -> object:
        if isinstance(left, _SupportsAdd) and protocol is _SupportsAdd:
            return left + right
        if isinstance(left, _SupportsSub) and protocol is _SupportsSub:
            return left - right
        if isinstance(left, _SupportsMul) and protocol is _SupportsMul:
            return left * right
        if isinstance(left, _SupportsTrueDiv) and protocol is _SupportsTrueDiv:
            return left / right
        if isinstance(left, _SupportsFloorDiv) and protocol is _SupportsFloorDiv:
            return left // right
        if isinstance(left, _SupportsMod) and protocol is _SupportsMod:
            return left % right
        self._raise_issue(TypeError("unsupported operand types"), node)
        return None

    def _apply_dynamic_compare(self, left: object, right: object, protocol: type[object]) -> bool:
        if isinstance(left, _SupportsLt) and protocol is _SupportsLt:
            return left < right
        if isinstance(left, _SupportsLe) and protocol is _SupportsLe:
            return left <= right
        if isinstance(left, _SupportsGt) and protocol is _SupportsGt:
            return left > right
        if isinstance(left, _SupportsGe) and protocol is _SupportsGe:
            return left >= right
        raise _UnsupportedWitness

    def _contains(self, container: object, item: object) -> bool:
        if not isinstance(container, Container):
            raise _UnsupportedWitness
        return item in container

    def _eval_list_comp(self, expr: ast.ListComp, env: dict[str, object]) -> list[object]:
        if len(expr.generators) != 1:
            raise _UnsupportedWitness
        generator = expr.generators[0]
        if generator.is_async:
            raise _UnsupportedWitness
        iterable = self._eval(generator.iter, env)
        if not isinstance(iterable, Iterable) or isinstance(iterable, (bytes, bytearray)):
            raise _UnsupportedWitness
        result: list[object] = []
        local = env.copy()
        for item in cast("Iterable[object]", iterable):
            self._assign(generator.target, item, local)
            if all(self._truthy(self._eval(test, local)) for test in generator.ifs):
                result.append(self._eval(expr.elt, local))
        return result

    def _eval_boolop(self, expr: ast.BoolOp, env: dict[str, object]) -> object:
        if isinstance(expr.op, ast.And):
            value: object = True
            for item in expr.values:
                value = self._eval(item, env)
                if not self._truthy(value):
                    return value
            return value
        if isinstance(expr.op, ast.Or):
            value = False
            for item in expr.values:
                value = self._eval(item, env)
                if self._truthy(value):
                    return value
            return value
        raise _UnsupportedWitness

    def _eval_compare(self, expr: ast.Compare, env: dict[str, object]) -> bool:
        left = self._eval(expr.left, env)
        for op, comparator in zip(expr.ops, expr.comparators, strict=True):
            right = self._eval(comparator, env)
            if not self._compare(op, left, right):
                return False
            left = right
        return True

    def _eval_slice(self, node: ast.AST, env: dict[str, object]) -> object:
        if isinstance(node, ast.Slice):
            return slice(
                None if node.lower is None else self._eval(node.lower, env),
                None if node.upper is None else self._eval(node.upper, env),
                None if node.step is None else self._eval(node.step, env),
            )
        return self._eval(node, env)

    def _assign(self, target: ast.AST, value: object, env: dict[str, object]) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            if not isinstance(value, Iterable) or isinstance(value, (str, bytes, bytearray)):
                raise _UnsupportedWitness
            values = list(cast("Iterable[object]", value))
            if len(values) != len(target.elts):
                raise _UnsupportedWitness
            for item_target, item_value in zip(target.elts, values, strict=True):
                self._assign(item_target, item_value, env)
            return
        if isinstance(target, ast.Subscript):
            container = self._eval(target.value, env)
            self._setitem(container, self._eval_slice(target.slice, env), value, target)
            return
        raise _UnsupportedWitness

    def _apply_binop(self, op: ast.operator, left: object, right: object, node: ast.AST) -> object:
        try:
            if isinstance(op, ast.Add):
                return self._apply_dynamic_binop(left, right, _SupportsAdd, node)
            if isinstance(op, ast.Sub):
                return self._apply_dynamic_binop(left, right, _SupportsSub, node)
            if isinstance(op, ast.Mult):
                return self._apply_dynamic_binop(left, right, _SupportsMul, node)
            if isinstance(op, ast.Div):
                return self._apply_dynamic_binop(left, right, _SupportsTrueDiv, node)
            if isinstance(op, ast.FloorDiv):
                return self._apply_dynamic_binop(left, right, _SupportsFloorDiv, node)
            if isinstance(op, ast.Mod):
                return self._apply_dynamic_binop(left, right, _SupportsMod, node)
            if isinstance(op, ast.BitAnd):
                return self._require_int(left, node) & self._require_int(right, node)
            if isinstance(op, ast.BitOr):
                return self._require_int(left, node) | self._require_int(right, node)
            if isinstance(op, ast.BitXor):
                return self._require_int(left, node) ^ self._require_int(right, node)
            if isinstance(op, ast.LShift):
                return self._require_int(left, node) << self._require_int(right, node)
            if isinstance(op, ast.RShift):
                return self._require_int(left, node) >> self._require_int(right, node)
        except tuple(_EXCEPTION_KINDS) as exc:
            self._raise_issue(exc, node)
        raise _UnsupportedWitness

    def _apply_unary(self, op: ast.unaryop, value: object, node: ast.AST) -> object:
        if isinstance(op, ast.USub):
            return -self._require_int(value, node)
        if isinstance(op, ast.UAdd):
            return +self._require_int(value, node)
        if isinstance(op, ast.Invert):
            return ~self._require_int(value, node)
        if isinstance(op, ast.Not):
            return not self._truthy(value)
        raise _UnsupportedWitness

    def _compare(self, op: ast.cmpop, left: object, right: object) -> bool:
        if isinstance(op, ast.Eq):
            return left == right
        if isinstance(op, ast.NotEq):
            return left != right
        if isinstance(op, ast.Lt):
            return self._apply_dynamic_compare(left, right, _SupportsLt)
        if isinstance(op, ast.LtE):
            return self._apply_dynamic_compare(left, right, _SupportsLe)
        if isinstance(op, ast.Gt):
            return self._apply_dynamic_compare(left, right, _SupportsGt)
        if isinstance(op, ast.GtE):
            return self._apply_dynamic_compare(left, right, _SupportsGe)
        if isinstance(op, ast.In):
            return self._contains(right, left)
        if isinstance(op, ast.NotIn):
            return not self._contains(right, left)
        raise _UnsupportedWitness

    def _require_int(self, value: object, node: ast.AST) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        self._raise_issue(TypeError("integer argument required"), node)
        return None

    def _truthy(self, value: object) -> bool:
        return bool(value)

    def _tick(self, node: ast.AST) -> None:
        """Retain one instrumentation hook without imposing a step cutoff."""
        _ = node

    def _raise_issue(self, exc: BaseException, node: ast.AST) -> NoReturn:
        for exc_type, kind in _EXCEPTION_KINDS.items():
            if isinstance(exc, exc_type):
                raise _RaisedIssue(kind, str(exc), node) from exc
        raise _UnsupportedWitness from exc


def _witness_value_key(value: object) -> object:
    """Return a deterministic, recursively hashable concrete invocation key."""
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return (type(value).__qualname__, value)
    if isinstance(value, range):
        return ("range", value.start, value.stop, value.step)
    if isinstance(value, (list, tuple)):
        sequence = cast("list[object] | tuple[object, ...]", value)
        kind = "list" if isinstance(value, list) else "tuple"
        return (kind, tuple(_witness_value_key(item) for item in sequence))
    if isinstance(value, dict):
        mapping = cast("dict[object, object]", value)
        items = tuple(
            sorted(
                (
                    (_witness_value_key(key), _witness_value_key(item_value))
                    for key, item_value in mapping.items()
                ),
                key=repr,
            ),
        )
        return ("dict", items)
    return (type(value).__qualname__, repr(value))


def find_concrete_witness(content: str) -> list[IssueRecord]:
    """Return issues proven by embedded or equality-derived concrete calls."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    interpreter = _ConcreteWitnessInterpreter(tree)
    issues: list[IssueRecord] = []
    seen: set[tuple[str, int, int]] = set()
    invocations = _user_calls_with_resolvable_args(tree, interpreter)
    invocations.extend(
        _WitnessInvocation(call, counterexample)
        for call, counterexample in equality_derived_string_calls(
            tree,
            interpreter.can_resolve_call,
        )
    )
    for invocation in invocations:
        call = invocation.call
        try:
            interpreter.evaluate_call(call)
        except _RaisedIssue as issue:
            line = getattr(issue.node, "lineno", getattr(call, "lineno", 1))
            column = getattr(issue.node, "col_offset", getattr(call, "col_offset", 0))
            key = (issue.kind, int(line), int(column))
            if key in seen:
                continue
            seen.add(key)
            function_name = _function_for_line(tree, int(line))
            issues.append(
                {
                    "kind": issue.kind,
                    "message": f"Concrete witness reaches {issue.kind}: {issue.message}",
                    "line": int(line),
                    "column": int(column),
                    "pc": 0,
                    "function_name": function_name,
                    "class_name": None,
                    "full_path": function_name,
                    "counterexample": invocation.counterexample,
                },
            )
        except _UnsupportedWitness:
            continue
    return issues


def _user_calls_with_resolvable_args(
    tree: ast.Module,
    interpreter: _ConcreteWitnessInterpreter,
) -> list[_WitnessInvocation]:
    functions = {stmt.name for stmt in tree.body if isinstance(stmt, ast.FunctionDef)}
    calls: list[_WitnessInvocation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id not in functions:
            continue
        if interpreter.can_resolve_call(node):
            calls.append(_WitnessInvocation(node))
    return calls


def _function_for_line(tree: ast.Module, line: int) -> str | None:
    best: ast.FunctionDef | None = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", None)
        if isinstance(start, int) and isinstance(end, int) and start <= line <= end:
            if best is None or start >= best.lineno:
                best = node
    return None if best is None else best.name
