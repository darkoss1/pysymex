"""HavocValue — precision-preserving value for unmodeled function calls.

When the symbolic executor encounters a call to an **unmodeled** function
(e.g. ``requests.get``, ``asyncio.run``), it pushes a ``HavocValue`` onto the
symbolic stack. ``HavocValue`` is a genuine :class:`SymbolicValue` subclass
backed by fresh, unconstrained Z3 variables.

This means:

* **Arithmetic / comparison** works exactly like a normal symbolic value —
  ``HavocValue / 0`` still triggers ``DivisionByZeroDetector``.
* **Branching** forks correctly — ``if havoc_val: ...`` creates two feasible
  paths because ``could_be_truthy()`` is a real Z3 expression.
* **Taint labels** propagate — if the unmodeled function received tainted
  arguments, the returned ``HavocValue`` carries their union.
* **Structural operations** (attribute access, calls, subscripts) produce
  *new* ``HavocValue`` instances so downstream code doesn't crash.

Detectors run their normal Z3 checks; issues whose counterexample involves
havoc variables are confidence-degraded in the false-positive filter (not
blindly suppressed).

.. versionadded:: 0.2.0-alpha
"""

from __future__ import annotations

from dataclasses import dataclass, field

import z3

from pysymex.core.types import Z3_FALSE, SymbolicValue


@dataclass(slots=True)
class HavocValue(SymbolicValue):
    """A :class:`SymbolicValue` produced by an unmodeled built-in/call.

    Internally it is a perfectly normal symbolic value (fresh Z3 variables,
    unconstrained int/bool type tag).  The only extra bookkeeping is a
    boolean marker (``_is_havoc``) that downstream code can inspect when it
    needs to know *why* the value has no concrete provenance.

    Create instances via the :meth:`havoc` factory, **not** the constructor.
    """

    _is_havoc: bool = field(default=True, init=False, repr=False, compare=False)
    _attributes: dict[str, tuple[HavocValue, z3.BoolRef]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    @staticmethod
    def havoc(
        name: str,
        *,
        taint_labels: frozenset[str] | set[str] | None = None,
    ) -> tuple[HavocValue, z3.BoolRef]:
        """Create a fresh havoc value with its own Z3 variables.

        Parameters
        ----------
        name:
            Debugging / variable-naming prefix (e.g. ``"havoc_call@42"``).
        taint_labels:
            Taint labels to attach (typically the union of all argument taints
            passed to the unmodeled function).

        Returns
        -------
        (HavocValue, type_constraint)
            A tuple mirroring :meth:`SymbolicValue.symbolic`.
        """
        z3_int = z3.Int(f"{name}_int")
        z3_bool = z3.Bool(f"{name}_bool")
        is_int = z3.Bool(f"{name}_is_int")
        is_bool = z3.Bool(f"{name}_is_bool")
        is_path = z3.Bool(f"{name}_is_path")

        type_constraint = z3.And(
            z3.Or(is_int, is_bool, is_path),
            z3.Not(z3.And(is_int, is_bool)),
            z3.Not(z3.And(is_int, is_path)),
            z3.Not(z3.And(is_bool, is_path)),
        )

        val = HavocValue(
            z3_int=z3_int,
            is_int=is_int,
            z3_bool=z3_bool,
            is_bool=is_bool,
            _name=name,
            is_path=is_path,
            is_none=Z3_FALSE,
            taint_labels=frozenset(taint_labels) if taint_labels is not None else None,
        )
        return val, type_constraint

    def __repr__(self) -> str:
        return f"HavocValue({self._name})"


def is_havoc(value: object) -> bool:
    """Return ``True`` if *value* is a :class:`HavocValue`."""
    return isinstance(value, HavocValue)


def has_havoc(*values: object) -> bool:
    """Return ``True`` if **any** of *values* is a :class:`HavocValue`."""
    return any(isinstance(v, HavocValue) for v in values)


def union_taint(values: list[object] | tuple[object, ...]) -> frozenset[str] | None:
    """Compute the union of ``taint_labels`` across *values*.

    Returns ``None`` when no value carries taint (the common case).
    """
    merged: set[str] | None = None
    for v in values:
        labels = getattr(v, "taint_labels", None)
        if labels:
            if merged is None:
                merged = set(labels)
            else:
                merged.update(labels)
    return frozenset(merged) if merged is not None else None
