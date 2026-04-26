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
* **Structural operations** (attribute access, calls, subscripts) produce
  *new* ``HavocValue`` instances so downstream code doesn't crash.

Detectors run their normal Z3 checks; issues whose counterexample involves
havoc variables are confidence-degraded in the false-positive filter (not
blindly suppressed).

.. versionadded:: 0.2.0-alpha
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeGuard

import z3

from pysymex.core.types.scalars import SymbolicValue


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
    _attributes: dict[str, tuple[HavocValue, z3.BoolRef]] = field(  # type: ignore[assignment]  # default_factory=dict returns dict, not dict[str, tuple[...]]
        default_factory=dict, init=False, repr=False, compare=False
    )

    @staticmethod
    def havoc(
        name: str,
    ) -> tuple[HavocValue, z3.BoolRef]:
        """Create a fresh havoc value with its own Z3 variables.

        Parameters
        ----------
        name:
            Debugging / variable-naming prefix (e.g. ``"havoc_call@42"``).

        Returns
        -------
        (HavocValue, type_constraint)
            A tuple mirroring :meth:`SymbolicValue.symbolic`.
        """
        z3_int = z3.Int(f"{name}_int")
        z3_bool = z3.Bool(f"{name}_bool")
        z3_float = z3.FP(f"{name}_float", z3.Float64())
        z3_str = z3.String(f"{name}_str")
        z3_addr = z3.Int(f"{name}_addr")

        is_int = z3.Bool(f"{name}_is_int")
        is_bool = z3.Bool(f"{name}_is_bool")
        is_str = z3.Bool(f"{name}_is_str")
        is_path = z3.Bool(f"{name}_is_path")
        is_obj = z3.Bool(f"{name}_is_obj")
        is_none = z3.Bool(f"{name}_is_none")
        is_float = z3.Bool(f"{name}_is_float")

        is_list = z3.Bool(f"{name}_is_list")
        is_dict = z3.Bool(f"{name}_is_dict")

        type_vars = [is_int, is_bool, is_str, is_path, is_obj, is_none, is_float, is_list, is_dict]
        at_least_one = z3.Or(*type_vars)
        at_most_one: list[z3.BoolRef] = []
        for i in range(len(type_vars)):
            for j in range(i + 1, len(type_vars)):
                at_most_one.append(z3.Not(z3.And(type_vars[i], type_vars[j])))

        type_constraint = z3.And(at_least_one, *at_most_one)

        val = HavocValue(
            z3_int=z3_int,
            is_int=is_int,
            z3_bool=z3_bool,
            is_bool=is_bool,
            z3_float=z3_float,
            is_float=is_float,
            z3_str=z3_str,
            is_str=is_str,
            z3_addr=z3_addr,
            is_obj=is_obj,
            is_path=is_path,
            is_none=is_none,
            is_list=is_list,
            is_dict=is_dict,
            _name=name,
        )
        return val, type_constraint

    def __getitem__(self, key: object) -> tuple[HavocValue, z3.BoolRef]:
        """Subscripting a HavocValue produces a new HavocValue."""
        name = f"{self._name}[{getattr(key, 'name', str(key))}]"
        return HavocValue.havoc(name)

    def __getattr__(self, name: str) -> tuple[HavocValue, z3.BoolRef]:
        """Accessing attribute on a HavocValue produces a new HavocValue."""
        if name.startswith("_"):
            raise AttributeError(name)
        full_name = f"{self._name}.{name}"
        return HavocValue.havoc(full_name)

    def __call__(self, *args: object, **kwargs: object) -> tuple[HavocValue, z3.BoolRef]:
        """Calling a HavocValue produces a new HavocValue."""
        full_name = f"{self._name}()"
        return HavocValue.havoc(full_name)

    def __repr__(self) -> str:
        return f"HavocValue({self._name})"

    def get_cached_attributes(self) -> dict[str, tuple[HavocValue, z3.BoolRef]]:
        """Return the attribute cache used for lazy havoc attribute materialization."""
        return self._attributes


def is_havoc(value: object) -> TypeGuard[HavocValue]:
    """Return ``True`` if *value* is a :class:`HavocValue`."""
    return isinstance(value, HavocValue)


def has_havoc(*values: object) -> bool:
    """Return ``True`` if **any** of *values* is a :class:`HavocValue`."""
    return any(isinstance(v, HavocValue) for v in values)
