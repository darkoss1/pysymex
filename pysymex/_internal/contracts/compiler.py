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

"""Compile contract predicates to Z3 boolean formulas.

:class:`~pysymex._internal.contracts.compiler.ContractCompiler` traces callable predicates with Z3
operator overloading or parses string predicates via
:class:`~pysymex._internal.contracts.quantifiers.translator.ConditionTranslator`, using
:mod:`pysymex._internal.contracts.formula.cache` for string reuse. Does not run solver checks or
register decorators.
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING

import z3

from pysymex._internal.contracts.callable.safety import CallableSafety
from pysymex._internal.core.constants import Z3_ZERO
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from pysymex._internal.contracts.types import ContractPredicate

logger = get_logger(__name__)


class ContractCompiler:
    """Dual-mode contract compilation engine.

    Unifies the AST-based translation of string predicates and the symbolic
    tracing of callable predicates behind a single interface.

    Callable predicates are compiled via **symbolic tracing**: the predicate is
    invoked with Z3 symbolic variables, and Python operator overloading on Z3 AST
    objects directly constructs the Z3 boolean formula.

    String predicates are parsed into AST and translated to Z3 via
    :class:`~pysymex._internal.contracts.quantifiers.translator.ConditionTranslator`.
    """

    @staticmethod
    def compile_predicate(
        predicate: ContractPredicate,
        symbols: Mapping[str, z3.ExprRef],
    ) -> z3.BoolRef:
        """Compile a contract predicate to a Z3 boolean formula.

        Args:
            predicate: A callable (lambda/function) or a string expression.
            symbols: Mapping of parameter names to Z3 symbolic variables.

        Returns:
            A ``z3.BoolRef`` representing the compiled constraint.

        Raises:
            TypeError: If the predicate is of an unsupported type.
            ValueError: If compilation produces a malformed or unsupported formula.

        """
        if isinstance(predicate, str):
            return ContractCompiler._compile_string(predicate, symbols)
        if callable(predicate):
            return ContractCompiler.trace_callable(predicate, symbols)
        msg = f"Contract predicate must be a callable or string, got {type(predicate).__name__}"
        raise TypeError(
            msg,
        )

    @staticmethod
    def compile_expression(
        condition: str,
        symbols: Mapping[str, z3.ExprRef],
    ) -> z3.BoolRef:
        """Compile a string condition to a Z3 expression.

        Provides an entry point for string-based formulas queried outside the
        standard decorator cycle (e.g. ranking functions).

        Args:
            condition: A Python-style boolean expression string.
            symbols: Mapping of variable names to Z3 symbolic variables.

        Returns:
            A ``z3.BoolRef`` representing the compiled condition constraint.

        """
        return ContractCompiler._compile_string(condition, symbols)

    @staticmethod
    def trace_callable(
        predicate: Callable[..., z3.BoolRef | bool],
        symbols: Mapping[str, z3.ExprRef],
    ) -> z3.BoolRef:
        """Compile a callable predicate via symbolic tracing.

        Invokes the callable using active Z3 variables as positional arguments,
        utilizing Z3 operator overloading to build the symbolic AST directly.

        Args:
            predicate: A callable that returns a boolean or Z3 expression.
            symbols: Mapping of parameter names to active Z3 variable objects.

        Returns:
            A ``z3.BoolRef`` representing the traced predicate.

        Raises:
            ValueError: If the predicate parameters are unbound, if tracing
                raises an exception, or if the returned expression is invalid.

        Limitations:
            - Callable predicates are intentionally **not cached** to prevent
              unsoundness if the callable reads dynamic closure or module state.
            - Callable predicates are executed during tracing. They must be
              side-effect-free. Explicit Python bytecode mutations of host
              globals, closure cells, attributes, or subscripts are rejected
              before invocation. Arbitrary calls and imports inside predicate
              bytecode are also unsupported, except approved PySyMex symbolic
              combinators, because host calls can execute code while tracing.
            - Callable predicates with no bound symbolic parameters are unsupported.
              Use string predicates such as ``"True"`` or ``"False"`` for constants.
            - Callable predicates returning Python `bool` are unsupported because
              they may depend on host runtime state instead of symbolic evidence.
              Use a string predicate such as ``"True"`` for constants, or return
              a symbolic Z3 predicate.
            - Defaulted and keyword-only parameters follow normal Python call
              binding. Variadic ``*args`` and ``**kwargs`` predicates are
              unsupported because they do not map to a stable symbol table.
            - Real or floating-point arithmetic is unsupported.

        """
        try:
            sig = inspect.signature(predicate)
        except (ValueError, TypeError):
            args = list(symbols.values())
            kwargs = {}
            _traced_parameter_names = tuple(symbols.keys())
            _safe_default_parameter_names: tuple[str, ...] = ()
        else:
            (
                args,
                kwargs,
                _traced_parameter_names,
                _safe_default_parameter_names,
            ) = ContractCompiler._bound_callable_arguments(sig, symbols)

        if not _traced_parameter_names:
            msg = (
                "Callable contracts without bound symbolic parameters are unsupported; "
                "use a string predicate for constants"
            )
            raise ValueError(
                msg,
            )

        CallableSafety.reject_host_effects(
            predicate,
            safe_attribute_names=frozenset(_traced_parameter_names),
            safe_value_names=frozenset(_safe_default_parameter_names),
        )

        try:
            result = predicate(*args, **kwargs)
        except Exception as exc:
            msg = f"Contract predicate {predicate!r} could not be symbolically traced: {exc}"
            raise ValueError(
                msg,
            ) from exc

        if isinstance(result, bool):
            msg = (
                "Callable contracts returning Python bool are unsupported; use a string "
                "predicate for constants or return a symbolic Z3 predicate instead"
            )
            raise ValueError(
                msg,
            )
        formula = ContractCompiler.coerce_to_bool_ref(result, predicate)
        ContractCompiler._validate_supported_formula(formula)
        return formula

    @staticmethod
    def _bound_callable_arguments(
        signature: inspect.Signature,
        symbols: Mapping[str, z3.ExprRef],
    ) -> tuple[list[z3.ExprRef], dict[str, z3.ExprRef], tuple[str, ...], tuple[str, ...]]:
        """Return CPython-style callable predicate arguments for active symbols."""
        args: list[z3.ExprRef] = []
        kwargs: dict[str, z3.ExprRef] = {}
        traced_names: list[str] = []
        safe_default_names: list[str] = []
        for parameter in signature.parameters.values():
            if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
                msg = "Variadic callable contract parameters are unsupported"
                raise ValueError(msg)
            if parameter.kind is inspect.Parameter.VAR_KEYWORD:
                msg = "Variadic callable contract parameters are unsupported"
                raise ValueError(msg)

            if parameter.name not in symbols:
                if parameter.default is inspect.Parameter.empty:
                    msg = f"Unbound contract parameter: {parameter.name}"
                    raise ValueError(msg)
                if ContractCompiler._is_safe_callable_default(parameter.default):
                    safe_default_names.append(parameter.name)
                continue

            traced_names.append(parameter.name)
            if parameter.kind is inspect.Parameter.KEYWORD_ONLY:
                kwargs[parameter.name] = symbols[parameter.name]
            else:
                args.append(symbols[parameter.name])
        return args, kwargs, tuple(traced_names), tuple(safe_default_names)

    @staticmethod
    def _is_safe_callable_default(value: object) -> bool:
        """Return whether a callable predicate default cannot run host code."""
        return isinstance(value, (bool, int, float, str, bytes, type(None)))

    @staticmethod
    def _validate_supported_formula(
        formula: z3.BoolRef,
        *,
        allow_runtime_integer_terms: bool = False,
    ) -> None:
        """Assert that all operations in the formula are supported.

        Recursively traverses the Z3 AST to detect unsupported theories or
        division operations. String predicates pass through the AST translator
        first, so integer arithmetic terms that come only from runtime return
        expressions can be allowed without accepting unsupported source-level
        contract syntax.

        Args:
            formula: The Z3 formula to validate.
            allow_runtime_integer_terms: Whether integer division, modulo,
                remainder, and exponentiation terms already present in runtime
                expressions may be queried.

        Raises:
            ValueError: If the formula contains real/float sorts or division,
                modulo, remainder, or exponentiation operations.

        """
        unsupported_operations = {
            z3.Z3_OP_DIV: "division",
            z3.Z3_OP_IDIV: "integer division",
            z3.Z3_OP_REM: "remainder",
            z3.Z3_OP_MOD: "modulo",
            z3.Z3_OP_POWER: "exponentiation",
        }
        pending: list[z3.ExprRef] = [formula]
        while pending:
            expression = pending.pop()
            if expression.sort() == z3.RealSort() or isinstance(expression, z3.FPRef):
                msg = "Callable contract real or floating-point terms are unsupported"
                raise ValueError(msg)
            if not allow_runtime_integer_terms and z3.is_app(expression):
                operation = unsupported_operations.get(expression.decl().kind())
                if operation is not None:
                    msg = f"Callable contract {operation} terms are unsupported"
                    raise ValueError(msg)
            pending.extend(expression.children())

    @staticmethod
    def _compile_string(
        condition: str,
        symbols: Mapping[str, z3.ExprRef],
    ) -> z3.BoolRef:
        """Lower quantifiers and translate a string condition.

        Args:
            condition: The condition string.
            symbols: Mapping of variable names to Z3 variables.

        Returns:
            A compiled Z3 boolean expression.

        """
        from pysymex._internal.contracts.quantifiers.lowering import lower_condition_quantifiers

        formula = lower_condition_quantifiers(condition, dict(symbols))
        ContractCompiler._validate_supported_formula(formula, allow_runtime_integer_terms=True)
        return formula

    @staticmethod
    def coerce_to_bool_ref(
        result: z3.BoolRef | z3.ExprRef | bool | object,
        source: object,
    ) -> z3.BoolRef:
        """Coerce a tracing return value to a proper Z3 BoolRef.

        Args:
            result: The raw value returned by the traced callable.
            source: The callable source object, for error diagnostics.

        Returns:
            A ``z3.BoolRef`` representing the truth value.

        Raises:
            ValueError: If the type cannot be coerced.

        """
        if isinstance(result, z3.BoolRef):
            return result
        if isinstance(result, bool):
            return ConstraintValues.bool(result)
        if isinstance(result, z3.ArithRef):
            return result != Z3_ZERO
        msg = (
            f"Contract predicate {source!r} returned unsupported result type "
            f"{type(result).__name__}; expected z3.BoolRef, z3.ExprRef, or bool"
        )
        raise ValueError(
            msg,
        )
