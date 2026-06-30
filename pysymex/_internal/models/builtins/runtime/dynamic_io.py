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

import ast
from typing import TYPE_CHECKING, cast

from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from collections.abc import MutableMapping

    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel, NoneResultModel
from pysymex._internal.models.contracts.results import (
    ModelDegradation,
    ModelDegradationKind,
    ModelResult,
    SideEffectValue,
)


def _model_degradation(
    name: str,
    owner: str,
    reason: str,
    *,
    kind: ModelDegradationKind = "unsupported",
) -> tuple[ModelDegradation, ...]:
    """Return one stable degradation record for an environment-facing builtin."""
    return (
        ModelDegradation(
            kind=kind,
            label=f"builtin_{name}_semantics_{kind}",
            owner=f"pysymex._internal.models.builtins.runtime.dynamic_io.{owner}",
            reason=reason,
        ),
    )


def _arity_type_error(source: str, message: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"{source}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=SideEffects.type_error(f"builtins.{source}", message),
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
        value,
        (float, str, bytes, list, tuple, dict, set, SymbolicString),
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
    from pysymex._internal.models.modules import materialize_module

    materialized = materialize_module(name, state, registered_only=True)
    if materialized is None:
        return None
    module, _ = materialized
    return module


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
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"io": True},
            degradations=_model_degradation(
                "open",
                "OpenModel",
                "filesystem outcomes and file object behavior are environment-dependent",
                kind="unknown",
            ),
        )


def _simple_exec_assignment_mutation(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    state: VMState,
) -> tuple[dict[str, object], list[z3.ExprRef | z3.BoolRef]] | None:
    """Return a precise namespace mutation for one simple literal ``exec`` assignment."""
    if not args:
        return None
    source = _literal_text(args[0])
    if source is None:
        return None
    target_name = _single_assignment_target(source)
    if target_name is None:
        return None
    namespace_arg = _exec_assignment_namespace(args, kwargs)
    if namespace_arg is None:
        return None
    original_dict = _runtime_dict(namespace_arg, state)
    if original_dict is None:
        return None
    value, constraints = _exec_assignment_value(source, original_dict, state)
    updated_dict = _dict_with_assignment(original_dict, target_name, value)
    return (
        {
            "operation": "exec_assignment",
            "original_dict": original_dict,
            "updated_dict": updated_dict,
        },
        constraints,
    )


def _single_assignment_target(source: str) -> str | None:
    """Return the assigned name for a single ``name = expr`` exec body."""
    try:
        module = ast.parse(source, mode="exec")
    except SyntaxError:
        return None
    if len(module.body) != 1:
        return None
    statement = module.body[0]
    if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
        return None
    target = statement.targets[0]
    if isinstance(target, ast.Name):
        return target.id
    return None


def _exec_assignment_namespace(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> StackValue | None:
    """Return the mapping CPython writes simple ``exec`` assignments into."""
    if "locals" in kwargs:
        return kwargs["locals"]
    if len(args) > 2:
        return args[2]
    if "globals" in kwargs:
        return kwargs["globals"]
    if len(args) > 1:
        return args[1]
    return None


def _runtime_dict(
    value: StackValue,
    state: VMState,
) -> MutableMapping[object, object] | SymbolicDict | None:
    """Return a concrete or modeled dictionary for an exec namespace argument."""
    if isinstance(value, dict | SymbolicDict):
        return cast("MutableMapping[object, object] | SymbolicDict", value)
    if isinstance(value, SymbolicObject):
        heap_value = state.load_heap(value.address, value)
        if isinstance(heap_value, dict | SymbolicDict):
            return cast("MutableMapping[object, object] | SymbolicDict", heap_value)
    return None


def _exec_assignment_value(
    source: str,
    namespace: MutableMapping[object, object] | SymbolicDict,
    state: VMState,
) -> tuple[StackValue, list[z3.ExprRef | z3.BoolRef]]:
    """Return a conservative value for the right-hand side of a simple assignment."""
    try:
        statement = ast.parse(source, mode="exec").body[0]
    except (SyntaxError, IndexError):
        return _unknown_exec_assignment_value(state)
    if not isinstance(statement, ast.Assign):
        return _unknown_exec_assignment_value(state)
    value = _evaluate_simple_exec_expr(statement.value, namespace)
    if value is not None:
        return value, []
    return _unknown_exec_assignment_value(state)


def _evaluate_simple_exec_expr(
    node: ast.AST,
    namespace: MutableMapping[object, object] | SymbolicDict,
) -> StackValue | None:
    """Evaluate tiny side-effect-free expressions used by exec namespace tests."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, str, bool)):
        return node.value
    if isinstance(node, ast.Name):
        return _namespace_value(namespace, node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
        left = _evaluate_simple_exec_expr(node.left, namespace)
        right = _evaluate_simple_exec_expr(node.right, namespace)
        if isinstance(left, int) and isinstance(right, int):
            return left + right if isinstance(node.op, ast.Add) else left - right
    return None


def _namespace_value(
    namespace: MutableMapping[object, object] | SymbolicDict,
    key: str,
) -> StackValue | None:
    """Return a retained namespace value when known."""
    if isinstance(namespace, SymbolicDict):
        found, value = namespace.concrete_value_for_key(key)
        return cast("StackValue | None", value) if found else None
    return cast("StackValue | None", namespace.get(key))


def _unknown_exec_assignment_value(
    state: VMState,
) -> tuple[SymbolicValue, list[z3.ExprRef | z3.BoolRef]]:
    """Return an unknown placeholder for an exec assignment RHS."""
    value, constraint = SymbolicValue.symbolic(f"exec_assignment_{state.pc}")
    return value, [constraint]


def _dict_with_assignment(
    original_dict: MutableMapping[object, object] | SymbolicDict,
    key: str,
    value: StackValue,
) -> dict[object, object] | SymbolicDict:
    """Return a namespace dictionary with one assignment applied."""
    if isinstance(original_dict, SymbolicDict):
        return original_dict.__setitem__(key, value)
    updated = dict(original_dict)
    updated[key] = value
    return updated


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
            positional_only=frozenset(("source",)),
            keyword_only=frozenset(("closure",)),
        ):
            return _arity_type_error("exec", "exec() received invalid arguments", state)
        sink_severity = "info"
        code_arg: StackValue = args[0]
        if _definite_invalid_code_source(code_arg):
            return _arity_type_error(
                "exec",
                "exec() source must be a string, bytes, or code object",
                state,
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
        constraints: list[z3.ExprRef | z3.BoolRef] = []
        assignment_mutation = _simple_exec_assignment_mutation(args, kwargs, state)
        if assignment_mutation is not None:
            side_effects["dict_mutation"] = cast("SideEffectValue", assignment_mutation[0])
            constraints.extend(assignment_mutation[1])
        return ModelResult(
            value=SymbolicNoneType(),
            constraints=constraints,
            side_effects=side_effects,
            degradations=_model_degradation(
                "exec",
                "ExecModel",
                "arbitrary executed code semantics are not fully interpreted by this model",
            ),
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
            positional_only=frozenset(("source",)),
        ):
            return _arity_type_error("eval", "eval() received invalid arguments", state)
        sink_severity = "info"
        code_arg: StackValue = args[0]
        if _definite_invalid_code_source(code_arg):
            return _arity_type_error(
                "eval",
                "eval() source must be a string, bytes, or code object",
                state,
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
            degradations=_model_degradation(
                "eval",
                "EvalModel",
                "arbitrary evaluated code semantics are represented by an unknown result",
            ),
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
            keyword_only=frozenset(("_feature_version",)),
        ):
            return _arity_type_error("compile", "compile() received invalid arguments", state)
        source = args[0] if args else kwargs["source"]
        if _definite_invalid_code_source(source):
            return _arity_type_error(
                "compile",
                "compile() source must be a string, bytes, or AST object",
                state,
            )
        filename = args[1] if len(args) > 1 else kwargs["filename"]
        mode = args[2] if len(args) > 2 else kwargs["mode"]
        if _definite_non_text_argument(filename, allow_bytes=True) or _definite_non_text_argument(
            mode,
        ):
            return _arity_type_error(
                "compile",
                "compile() filename and mode have invalid types",
                state,
            )
        if isinstance(mode, str) and mode not in {"exec", "eval", "single", "func_type"}:
            result, constraint = SymbolicValue.symbolic(f"compile_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.value_error(
                    "builtins.compile",
                    "compile() mode must be 'exec', 'eval' or 'single'",
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
            },
        }
        result, constraint = SymbolicValue.symbolic(f"code_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects=side_effects,
            degradations=_model_degradation(
                "compile",
                "CompileModel",
                "source compilation and syntax-error paths are not fully modeled",
                kind="unknown",
            ),
        )


class BreakpointModel(NoneResultModel):
    """Model for breakpoint() with explicit user-hook uncertainty."""

    name = "breakpoint"
    qualname = "builtins.breakpoint"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Abstract the configurable hook without executing host debugger behavior."""
        return ModelResult(
            value=SymbolicNoneType(),
            side_effects={"io": True},
            degradations=(
                ModelDegradation(
                    kind="unsupported",
                    label="builtin_breakpoint_hook_unsupported",
                    owner="pysymex._internal.models.builtins.runtime.dynamic_io.BreakpointModel",
                    reason="breakpoint() delegates to a configurable runtime hook",
                ),
            ),
        )


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
                side_effects=SideEffects.value_error("builtins.__import__", "Empty module name"),
            )
        level = args[4] if len(args) > 4 else kwargs.get("level", 0)
        if _definite_non_integer_level(level):
            return _arity_type_error("__import__", "__import__() level must be an integer", state)
        if isinstance(level, int) and not isinstance(level, bool) and level < 0:
            result, constraint = SymbolicValue.symbolic(f"import_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.value_error("builtins.__import__", "level must be >= 0"),
            )
        literal_name = _literal_text(name)
        if literal_name is not None and level == 0:
            modeled_module = _modeled_literal_import(literal_name, state)
            if modeled_module is not None:
                return ModelResult(
                    value=modeled_module,
                    degradations=_model_degradation(
                        "import",
                        "ImportModel",
                        "modeled imports omit arbitrary module initialization side effects",
                        kind="precision_loss",
                    ),
                )
        result, constraint = SymbolicValue.symbolic(f"import_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            degradations=_model_degradation(
                "import",
                "ImportModel",
                "module loading, initialization, and import failures are not modeled",
            ),
        )
