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

"""Input, IO, import, and dynamic execution builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_TRUE
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from ..base import FunctionModel, ModelResult, NoneResultFunctionModel, SideEffectValue
from ..core.helpers import type_error_side_effect, value_error_side_effect


def _arity_type_error(source: str, message: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"{source}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=type_error_side_effect(f"builtins.{source}", message),
    )


def _invalid_call_binding(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    positional_parameters: tuple[str, ...],
    required_count: int,
    *,
    positional_only: frozenset[str] = frozenset(),
    keyword_only: frozenset[str] = frozenset(),
) -> bool:
    allowed_keywords = (set(positional_parameters) - positional_only) | keyword_only
    if len(args) > len(positional_parameters) or set(kwargs) - allowed_keywords:
        return True
    if any(name in kwargs for name in positional_parameters[: len(args)]):
        return True
    return any(
        index >= len(args) and name not in kwargs
        for index, name in enumerate(positional_parameters[:required_count])
    )


def _definite_invalid_code_source(value: StackValue) -> bool:
    return value is None or isinstance(value, (int, float, bool, list, tuple, dict, set))


def _definite_non_text_argument(value: StackValue, *, allow_bytes: bool = False) -> bool:
    if allow_bytes and isinstance(value, bytes):
        return False
    return value is None or isinstance(value, (int, float, bool, bytes, list, tuple, dict, set))


def _definite_non_integer_level(value: StackValue) -> bool:
    return value is None or isinstance(
        value, (float, str, bytes, list, tuple, dict, set, SymbolicString)
    )


def _literal_text(value: StackValue) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, SymbolicString):
        raw_name = value.name
        if len(raw_name) >= 2 and raw_name[0] == raw_name[-1] and raw_name[0] in {"'", '"'}:
            return raw_name[1:-1]
        return None
    if isinstance(value, SymbolicValue) and isinstance(value.value, str):
        return value.value
    return None


def _modeled_literal_import(name: str, state: VMState) -> SymbolicObject | None:
    """Return a modeled module object for safe literal dynamic imports."""
    if name != "os":
        return None
    addr = hash("os") & 0xFFFFFFFF
    module_val = SymbolicObject("os", addr, get_int_val(addr), {addr})
    path_addr = hash("os.path") & 0xFFFFFFFF
    path_module = SymbolicObject("os.path", path_addr, get_int_val(path_addr), {path_addr})
    state.store_heap(path_addr, {"__module_name__": "os.path"})
    state.store_heap(
        addr,
        {
            "__module_name__": "os",
            "environ": SymbolicDict(
                "os.environ",
                z3.Array("os.environ_arr", z3.StringSort(), z3.IntSort()),
                z3.Array("os.environ_keys", z3.StringSort(), z3.BoolSort()),
                z3.Int("os.environ_len"),
            ),
            "path": path_module,
        },
    )
    return module_val


class InputModel(FunctionModel):
    """Model for input()."""

    name = "input"
    qualname = "builtins.input"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) > 1 or kwargs:
            return _arity_type_error("input", "input() accepts at most one argument", state)
        result, constraint = SymbolicString.symbolic(f"input_{state.pc}")
        return ModelResult(value=result, constraints=[constraint], side_effects={"io": True})


class OpenModel(FunctionModel):
    """Model for open()."""

    name = "open"
    qualname = "builtins.open"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if _invalid_call_binding(
            args,
            kwargs,
            ("file", "mode", "buffering", "encoding", "errors", "newline", "closefd", "opener"),
            1,
        ):
            return _arity_type_error("open", "open() received invalid arguments", state)
        mode = args[1] if len(args) > 1 else kwargs.get("mode", "r")
        if _definite_non_text_argument(mode):
            return _arity_type_error("open", "open() mode must be a string", state)
        result, constraint = SymbolicValue.symbolic(f"file_{state.pc}")
        result.is_none = Z3_FALSE
        result.is_obj = Z3_TRUE
        result.affinity_type = "file"
        return ModelResult(value=result, constraints=[constraint], side_effects={"io": True})


class ExecModel(FunctionModel):
    """Model for exec() - code injection sink."""

    name = "exec"
    qualname = "builtins.exec"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if _invalid_call_binding(
            args,
            kwargs,
            ("source", "globals", "locals"),
            1,
            positional_only=frozenset({"source"}),
            keyword_only=frozenset({"closure"}),
        ):
            return _arity_type_error("exec", "exec() received invalid arguments", state)
        sink_severity = "info"
        code_arg: StackValue = args[0]
        if _definite_invalid_code_source(code_arg):
            return _arity_type_error(
                "exec", "exec() source must be a string, bytes, or code object", state
            )
        if isinstance(code_arg, (SymbolicString, SymbolicValue)):
            sink_severity = "critical"
        side_effects: dict[str, SideEffectValue] = {
            "sink_event": {
                "sink_type": "exec",
                "severity": sink_severity,
                "source": "builtins.exec",
            },
        }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class EvalModel(FunctionModel):
    """Model for eval() - code injection sink."""

    name = "eval"
    qualname = "builtins.eval"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if _invalid_call_binding(
            args,
            kwargs,
            ("source", "globals", "locals"),
            1,
            positional_only=frozenset({"source"}),
        ):
            return _arity_type_error("eval", "eval() received invalid arguments", state)
        sink_severity = "info"
        code_arg: StackValue = args[0]
        if _definite_invalid_code_source(code_arg):
            return _arity_type_error(
                "eval", "eval() source must be a string, bytes, or code object", state
            )
        if isinstance(code_arg, (SymbolicString, SymbolicValue)):
            sink_severity = "critical"
        side_effects: dict[str, SideEffectValue] = {
            "sink_event": {
                "sink_type": "eval",
                "severity": sink_severity,
                "source": "builtins.eval",
            },
        }
        result, constraint = SymbolicValue.symbolic(f"eval_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects=side_effects,
        )


class CompileModel(FunctionModel):
    """Model for compile()."""

    name = "compile"
    qualname = "builtins.compile"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if _invalid_call_binding(
            args,
            kwargs,
            ("source", "filename", "mode", "flags", "dont_inherit", "optimize"),
            3,
            keyword_only=frozenset({"_feature_version"}),
        ):
            return _arity_type_error("compile", "compile() received invalid arguments", state)
        source = args[0] if args else kwargs["source"]
        if _definite_invalid_code_source(source):
            return _arity_type_error(
                "compile", "compile() source must be a string, bytes, or AST object", state
            )
        filename = args[1] if len(args) > 1 else kwargs["filename"]
        mode = args[2] if len(args) > 2 else kwargs["mode"]
        if _definite_non_text_argument(filename, allow_bytes=True) or _definite_non_text_argument(
            mode
        ):
            return _arity_type_error(
                "compile", "compile() filename and mode have invalid types", state
            )
        if isinstance(mode, str) and mode not in {"exec", "eval", "single", "func_type"}:
            result, constraint = SymbolicValue.symbolic(f"compile_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=value_error_side_effect(
                    "builtins.compile", "compile() mode must be 'exec', 'eval' or 'single'"
                ),
            )
        sink_severity = (
            "critical" if isinstance(source, (SymbolicString, SymbolicValue)) else "info"
        )
        side_effects: dict[str, SideEffectValue] = {
            "sink_event": {
                "sink_type": "compile",
                "severity": sink_severity,
                "source": "builtins.compile",
            }
        }
        result, constraint = SymbolicValue.symbolic(f"code_{state.pc}")
        return ModelResult(value=result, constraints=[constraint], side_effects=side_effects)


class BreakpointModel(NoneResultFunctionModel):
    """Model for breakpoint()."""

    name = "breakpoint"
    qualname = "builtins.breakpoint"


class ImportModel(FunctionModel):
    """Model for __import__()."""

    name = "__import__"
    qualname = "builtins.__import__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if _invalid_call_binding(
            args,
            kwargs,
            ("name", "globals", "locals", "fromlist", "level"),
            1,
        ):
            return _arity_type_error("__import__", "__import__() received invalid arguments", state)
        name = args[0] if args else kwargs["name"]
        if name is None or isinstance(name, (int, float, bool, bytes, list, tuple, dict, set)):
            return _arity_type_error("__import__", "module name must be a string", state)
        if name == "":
            result, constraint = SymbolicValue.symbolic(f"import_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=value_error_side_effect("builtins.__import__", "Empty module name"),
            )
        level = args[4] if len(args) > 4 else kwargs.get("level", 0)
        if _definite_non_integer_level(level):
            return _arity_type_error("__import__", "__import__() level must be an integer", state)
        if isinstance(level, int) and not isinstance(level, bool) and level < 0:
            result, constraint = SymbolicValue.symbolic(f"import_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=value_error_side_effect("builtins.__import__", "level must be >= 0"),
            )
        literal_name = _literal_text(name)
        if literal_name is not None and level == 0:
            modeled_module = _modeled_literal_import(literal_name, state)
            if modeled_module is not None:
                return ModelResult(value=modeled_module)
        result, constraint = SymbolicValue.symbolic(f"import_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


__import__Model = ImportModel
