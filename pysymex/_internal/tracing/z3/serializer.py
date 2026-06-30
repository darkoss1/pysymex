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

"""Crash-safe Z3 serializers for trace output."""

from __future__ import annotations

try:
    import z3
except ImportError:
    z3 = None


from typing import TYPE_CHECKING

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.logging.root import get_logger
from pysymex._internal.tracing.z3.protocols import (
    ABSTRACT_VAR_RE,
    MAX_EXPR_CHARS,
    UNSERIALIZABLE,
    ModelLike,
    NamespaceLike,
)

if TYPE_CHECKING:
    import re
    from collections.abc import Iterable

    from pysymex._internal.tracing.z3.registry import Z3SemanticRegistry

logger = get_logger(__name__)


class Z3Serializer:
    """Converts Z3 objects to human-readable strings for JSONL trace events."""

    def __init__(self, registry: Z3SemanticRegistry) -> None:
        """Initialize a Z3 trace serializer with a semantic name registry.

        Args:
            registry: The registry mapping internal Z3 declarations to variable names.

        """
        self._registry = registry

    def safe_sexpr(self, expr: object) -> str:
        """Convert a Z3 expression to a human-readable S-expression string."""
        if z3 is None:
            return repr(expr)[:MAX_EXPR_CHARS]
        try:
            if not isinstance(expr, z3.ExprRef):
                return repr(expr)[:MAX_EXPR_CHARS]
            try:
                simplified = simplify_expr(expr)
                raw = simplified.sexpr()
            except Exception:
                if logger.state.debug_enabled:
                    logger.debug(
                        "Failed to simplify Z3 expression for trace serialization",
                        exc_info=True,
                    )
                try:
                    raw = expr.sexpr()
                except Exception:
                    if logger.state.debug_enabled:
                        logger.debug("Failed to render Z3 expression sexpr", exc_info=True)
                    return repr(expr)[:MAX_EXPR_CHARS]
            truncated = raw[:MAX_EXPR_CHARS]
            return self.substitute_abstract_names(truncated)
        except Exception:
            if logger.state.debug_enabled:
                logger.debug("Failed to serialize Z3 expression", exc_info=True)
            try:
                return repr(expr)[:MAX_EXPR_CHARS]
            except Exception:
                return UNSERIALIZABLE

    def substitute_abstract_names(self, s: str) -> str:
        """Replace opaque Z3 internal identifiers with semantic names."""

        def _replace(match: re.Match[str]) -> str:
            """Replace."""
            token: str = match.group(0)

            semantic = self._registry.lookup(token)
            if semantic != token:
                return semantic

            for suffix_group in (match.group(1), match.group(2)):
                if suffix_group is not None:
                    alt = f"k!{suffix_group}"
                    alt_semantic = self._registry.lookup(alt)
                    if alt_semantic != alt:
                        return alt_semantic
            return token

        try:
            return ABSTRACT_VAR_RE.sub(_replace, s)
        except Exception:
            if logger.state.debug_enabled:
                logger.debug("Failed to substitute abstract Z3 names", exc_info=True)
            return s

    def constraints_to_smtlib(
        self,
        constraints: Iterable[object],
        causality: str = "",
    ) -> list[dict[str, str]]:
        """Serialise an iterable of Z3 boolean constraints to JSONL-safe dicts."""
        result: list[dict[str, str]] = []
        for c in constraints:
            try:
                result.append({"smtlib": self.safe_sexpr(c), "causality": causality})
            except Exception:
                if logger.state.debug_enabled:
                    logger.debug("Failed to serialize Z3 constraint", exc_info=True)
                result.append({"smtlib": UNSERIALIZABLE, "causality": causality})
        return result

    def serialize_model(self, model: object, max_vars: int = 30) -> dict[str, str]:
        """Serialise a Z3 satisfying model to a bounded name-to-value dict."""
        if z3 is None or model is None:
            return {}
        result: dict[str, str] = {}
        if not isinstance(model, ModelLike):
            return result
        try:
            decls = model.decls()
            for decl in decls[:max_vars]:
                try:
                    raw_name = decl.name()
                    semantic_name = self._registry.lookup(raw_name)
                    value_expr = model[decl]
                    value_str = self.safe_sexpr(value_expr)
                    result[semantic_name] = value_str
                except Exception:
                    if logger.state.debug_enabled:
                        logger.debug("Failed to serialize Z3 model declaration", exc_info=True)
                    continue
        except Exception:
            if logger.state.debug_enabled:
                logger.debug("Failed to enumerate Z3 model declarations", exc_info=True)
        return result

    def serialize_stack_value(self, val: object) -> str:
        """Serialise a single symbolic stack value to a string."""
        if val is None:
            return "None"
        try:
            for attr in ("expr", "_expr"):
                inner = getattr(val, attr, None)
                if inner is not None and z3 is not None and isinstance(inner, z3.ExprRef):
                    return self.safe_sexpr(inner)

            if z3 is not None and isinstance(val, z3.ExprRef):
                return self.safe_sexpr(val)

            r = repr(val)
            return r[:MAX_EXPR_CHARS]
        except Exception:
            if logger.state.debug_enabled:
                logger.debug("Failed to serialize stack value", exc_info=True)
            try:
                return type(val).__name__
            except Exception:
                return UNSERIALIZABLE

    def serialize_namespace(self, ns: object) -> dict[str, str]:
        """Serialise a variable namespace to strings."""
        out: dict[str, str] = {}
        if ns is None:
            return out
        if not isinstance(ns, NamespaceLike):
            return out
        try:
            for k, v in ns.items():
                try:
                    out[str(k)] = self.serialize_stack_value(v)
                except Exception:
                    if logger.state.debug_enabled:
                        logger.debug("Failed to serialize namespace item", exc_info=True)
                    out[str(k)] = UNSERIALIZABLE
        except Exception:
            if logger.state.debug_enabled:
                logger.debug("Failed to enumerate namespace for serialization", exc_info=True)
        return out
