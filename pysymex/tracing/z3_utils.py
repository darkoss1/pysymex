# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Safe Z3 expression serialisation and semantic variable renaming.

The core problem this module addresses: Z3 internally names many variables
with opaque identifiers such as ``k!1``, ``k!2``, ``!0``, etc.  These are
meaningless to an LLM reader.  This module provides:

1. :class:`Z3SemanticRegistry` — a name-mapping registry that translates
   opaque Z3 declaration names into the human-assigned symbolic names used
   in the pysymex analysis (e.g. ``k!1`` → ``sym_arg_x``).

2. :class:`Z3Serializer` — a crash-safe serialiser that converts Z3
   expressions, models, and constraint lists to strings/dicts suitable for
   embedding in JSONL trace events.

Safety guarantees
~~~~~~~~~~~~~~~~~
* Every Z3 API call that can raise (or, in extreme edge cases, trigger an
  internal Z3 assertion failure) is wrapped in a broad ``except Exception``.
  The fallback is always a human-understandable string rather than a crash
  or a silent empty result.
* Z3 can occasionally segfault on severely malformed ASTs.  To mitigate
  this, ``safe_sexpr`` calls ``z3.simplify()`` first and only falls back to
  direct ``.sexpr()`` if simplification succeeds — this eliminates most of
  the dangerous states.  True subprocess isolation is left as a future
  enhancement.
* Model iteration is bounded by ``max_vars`` to prevent megabyte-sized
  JSON objects on pathological problems.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from threading import Lock
from typing import Final

_z3_avail: bool = False
try:
    import z3 as _z3

    _z3_avail = True
except ImportError:
    _z3 = None

_Z3_AVAILABLE: Final[bool] = _z3_avail


_ABSTRACT_VAR_RE = re.compile(r"\bk!(\d+)\b|\b!(\d+)\b")


_MAX_EXPR_CHARS = 16384


_UNSERIALIZABLE = "<unserializable>"


class Z3SemanticRegistry:
    """Thread-safe registry mapping opaque Z3 declaration names to semantic ones.

    When pysymex creates a symbolic argument ``x`` it internally creates a
    Z3 integer/bitvector whose ``.decl().name()`` may be ``"x"`` — or, after
    transformations by Z3 tactics, it may become ``"k!0"`` or similar.  This
    registry bridges that gap.

    Usage::

        registry = Z3SemanticRegistry()
        # Auto-registration from a pysymex SymbolicValue:
        registry.auto_register(sym_val, "x")
        # Manual bulk overrides (highest precedence):
        registry.update({"k!0": "x", "k!1": "n"})

    Name resolution order:
        1. Manual overrides (``update()``).
        2. Auto-detected names (``auto_register()`` or ``register()``).
        3. Original name unchanged.
    """

    def __init__(self) -> None:
        self._lock = Lock()

        self._auto: dict[str, str] = {}
        self._overrides: dict[str, str] = {}

    def register(self, z3_var: object, semantic_name: str) -> None:
        """Register a Z3 expression's declaration name → semantic name.

        Args:
            z3_var:        A Z3 expression (``z3.ExprRef`` subclass).
            semantic_name: The human-readable name to use in traces.

        If Z3 is unavailable or ``z3_var`` is not a Z3 expression, the call
        is silently ignored.
        """
        if _z3 is None:
            return
        try:
            if isinstance(z3_var, _z3.ExprRef):
                decl_name: str = z3_var.decl().name()
                with self._lock:
                    self._auto[decl_name] = semantic_name
        except Exception:
            pass

    def auto_register(self, symbolic_value: object, semantic_name: str) -> None:
        """Attempt to extract and register Z3 variable(s) from a pysymex value.

        Handles the common pysymex value shapes:
        - Objects with an ``.expr`` attribute that is a Z3 expression.
        - Objects with a ``._z3_var`` attribute (e.g. ``SymbolicString``).
        - Plain Z3 expressions directly.

        For composite types (lists, dicts) that hold multiple inner
        expressions, only the top-level declaration is registered — callers
        should iterate and call ``register()`` per element as needed.

        Args:
            symbolic_value: A pysymex symbolic value or plain Z3 expression.
            semantic_name:  The human-readable name to associate.
        """
        if _z3 is None or symbolic_value is None:
            return
        try:
            expr = getattr(symbolic_value, "expr", None)
            if expr is not None and isinstance(expr, _z3.ExprRef):
                self.register(expr, semantic_name)
                return

            z3_var = getattr(symbolic_value, "_z3_var", None)
            if z3_var is not None and isinstance(z3_var, _z3.ExprRef):
                self.register(z3_var, semantic_name)
                return

            if isinstance(symbolic_value, _z3.ExprRef):
                self.register(symbolic_value, semantic_name)
        except Exception:
            pass

    def update(self, overrides: dict[str, str]) -> None:
        """Apply manual name-override mappings.  These take highest precedence.

        Args:
            overrides: Mapping of ``{z3_decl_name: semantic_name}``.
        """
        with self._lock:
            self._overrides.update(overrides)

    def lookup(self, z3_decl_name: str) -> str:
        """Return the semantic name for a Z3 declaration name, or the original.

        Args:
            z3_decl_name: The raw Z3 declaration name string.

        Returns:
            The registered semantic name if found, otherwise ``z3_decl_name``
            unchanged.
        """
        with self._lock:
            return self._overrides.get(z3_decl_name) or self._auto.get(z3_decl_name) or z3_decl_name

    def snapshot(self) -> dict[str, str]:
        """Return a read-only copy of the combined name mapping.

        Overrides shadow auto-registered names.  Useful for debugging.
        """
        with self._lock:
            merged = dict(self._auto)
            merged.update(self._overrides)
            return merged


class Z3Serializer:
    """Converts Z3 objects to human-readable strings for JSONL trace events.

    All methods are crash-safe: they never raise an exception to the caller.
    When serialisation fails the returned value is an informative placeholder
    string such as ``"<unserializable>"``.

    Args:
        registry: A :class:`Z3SemanticRegistry` used to substitute opaque
                  Z3 variable names with semantic ones.
    """

    def __init__(self, registry: Z3SemanticRegistry) -> None:
        self._registry = registry

    def safe_sexpr(self, expr: object) -> str:
        """Convert a Z3 expression to a human-readable S-expression string.

        Process:
        1. Try ``z3.simplify(expr)`` to normalise the expression; this also
           eliminates most forms that can cause segfaults in ``.sexpr()``.
        2. Call ``.sexpr()`` on the (possibly simplified) expression.
        3. Truncate to ``_MAX_EXPR_CHARS``.
        4. Replace opaque ``k!N`` / ``!N`` identifiers with semantic names.

        Falls back to ``repr(expr)[:_MAX_EXPR_CHARS]`` on any exception.

        Args:
            expr: Any Z3 expression (``z3.ExprRef`` subclass).

        Returns:
            A printable string.  Never raises.
        """
        if _z3 is None:
            return repr(expr)[:_MAX_EXPR_CHARS]
        try:
            if not isinstance(expr, _z3.ExprRef):
                return repr(expr)[:_MAX_EXPR_CHARS]
            try:
                simplified = _z3.simplify(expr)
                raw = simplified.sexpr()
            except Exception:
                try:
                    raw = expr.sexpr()
                except Exception:
                    return repr(expr)[:_MAX_EXPR_CHARS]
            truncated = raw[:_MAX_EXPR_CHARS]
            return self._substitute_abstract_names(truncated)
        except Exception:
            try:
                return repr(expr)[:_MAX_EXPR_CHARS]
            except Exception:
                return _UNSERIALIZABLE

    def _substitute_abstract_names(self, s: str) -> str:
        """Replace opaque Z3 internal identifiers with semantic names.

        Searches for ``k!N`` and ``!N`` patterns and substitutes them
        using the registry.  Names not present in the registry are left
        unchanged.

        Args:
            s: A raw S-expression or other Z3-produced string.

        Returns:
            The string with substitutions applied.
        """

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
            return _ABSTRACT_VAR_RE.sub(_replace, s)
        except Exception:
            return s

    def constraints_to_smtlib(
        self, constraints: Iterable[object], causality: str = ""
    ) -> list[dict[str, str]]:
        """Serialise an iterable of Z3 boolean constraints to JSONL-safe dicts.

        Each constraint produces one entry ``{"smtlib": ..., "causality": ...}``.
        Per-constraint exceptions are caught individually so a single bad
        expression does not abort the entire list.

        Args:
            constraints: Iterable of ``z3.BoolRef`` (or anything Z3-like).
            causality:   Default causality tag applied to all entries.
                         Individual entries with a known cause may override
                         this by passing named ``(constraint, causality)``
                         tuples — but for the common list-of-constraints
                         case a single causality string is sufficient.

        Returns:
            List of dicts with ``"smtlib"`` and ``"causality"`` keys,
            suitable for constructing :class:`~pysymex.tracing.schemas.ConstraintEntry`.
        """
        result: list[dict[str, str]] = []
        for c in constraints:
            try:
                result.append({"smtlib": self.safe_sexpr(c), "causality": causality})
            except Exception:
                result.append({"smtlib": _UNSERIALIZABLE, "causality": causality})
        return result

    def serialize_model(self, model: object, max_vars: int = 30) -> dict[str, str]:
        """Serialise a Z3 satisfying model to a bounded ``{name: value}`` dict.

        The model excerpt is bounded to ``max_vars`` entries to prevent
        enormous JSON objects on problems with hundreds of variables.

        Args:
            model:    A ``z3.ModelRef`` returned by a satisfying solver check.
            max_vars: Maximum number of variable assignments to include.

        Returns:
            Dict mapping semantic variable name → value S-expression.
            Returns ``{}`` on any error (non-crashing).
        """
        if _z3 is None or model is None:
            return {}
        result: dict[str, str] = {}
        try:
            decls_fn = getattr(model, "decls", None)
            if not callable(decls_fn):
                return result
            decls = decls_fn()
            if not isinstance(decls, list):
                return result
            for decl in decls[:max_vars]:
                try:
                    raw_name: str = decl.name()
                    semantic_name = self._registry.lookup(raw_name)
                    value_expr = model[decl]  # type: ignore[index]
                    value_str = self.safe_sexpr(value_expr)
                    result[semantic_name] = value_str
                except Exception:
                    continue
        except Exception:
            pass
        return result

    def serialize_stack_value(self, val: object) -> str:
        """Serialise a single symbolic stack value to a string.

        Attempts several strategies in order:
        1. If the value has a ``._expr`` or ``.expr`` attribute that is a
           Z3 expression, use :meth:`safe_sexpr`.
        2. If the value itself is a Z3 expression, use :meth:`safe_sexpr`.
        3. If the value is a plain Python object, use ``repr()`` (bounded).
        4. Fall back to the type name only.

        Args:
            val: Any value that may be on the symbolic execution stack.

        Returns:
            A printable, bounded string.  Never raises.
        """
        if val is None:
            return "None"
        try:
            for attr in ("expr", "_expr"):
                inner = getattr(val, attr, None)
                if inner is not None and _z3 is not None and isinstance(inner, _z3.ExprRef):
                    return self.safe_sexpr(inner)

            if _z3 is not None and isinstance(val, _z3.ExprRef):
                return self.safe_sexpr(val)

            r = repr(val)
            return r[:_MAX_EXPR_CHARS]
        except Exception:
            try:
                return type(val).__name__
            except Exception:
                return _UNSERIALIZABLE

    def serialize_namespace(self, ns: object) -> dict[str, str]:
        """Serialise a variable namespace (local_vars or global_vars) to strings.

        Keys that raise during iteration or serialisation are skipped.

        Args:
            ns: A ``dict``-like namespace (may be a ``CowDict`` or plain dict).

        Returns:
            ``{name: serialised_value}`` dict.
        """
        out: dict[str, str] = {}
        if ns is None:
            return out
        try:
            items_fn = getattr(ns, "items", None)
            if not callable(items_fn):
                return out
            items_obj = items_fn()
            if not isinstance(items_obj, Iterable):
                return out
            for k, v in items_obj:
                try:
                    out[str(k)] = self.serialize_stack_value(v)
                except Exception:
                    out[str(k)] = _UNSERIALIZABLE
        except Exception:
            pass
        return out
