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

"""Quantifier support package for contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .core import (
        ConditionTranslator as ConditionTranslator,
        QuantifierInstantiator as QuantifierInstantiator,
        QuantifierParser as QuantifierParser,
        QuantifierVerifier as QuantifierVerifier,
        exists as exists,
        exists_unique as exists_unique,
        extract_quantifiers as extract_quantifiers,
        forall as forall,
        parse_condition_to_z3 as parse_condition_to_z3,
        replace_quantifiers_with_z3 as replace_quantifiers_with_z3,
    )
    from .types import (
        BoundSpec as BoundSpec,
        Quantifier as Quantifier,
        QuantifierKind as QuantifierKind,
        QuantifierVar as QuantifierVar,
    )

_EXPORTS: dict[str, tuple[str, str]] = {
    "ConditionTranslator": (".core", "ConditionTranslator"),
    "QuantifierInstantiator": (".core", "QuantifierInstantiator"),
    "QuantifierParser": (".core", "QuantifierParser"),
    "QuantifierVerifier": (".core", "QuantifierVerifier"),
    "exists": (".core", "exists"),
    "exists_unique": (".core", "exists_unique"),
    "extract_quantifiers": (".core", "extract_quantifiers"),
    "forall": (".core", "forall"),
    "parse_condition_to_z3": (".core", "parse_condition_to_z3"),
    "replace_quantifiers_with_z3": (".core", "replace_quantifiers_with_z3"),
    "BoundSpec": (".types", "BoundSpec"),
    "Quantifier": (".types", "Quantifier"),
    "QuantifierKind": (".types", "QuantifierKind"),
    "QuantifierVar": (".types", "QuantifierVar"),
}


def __getattr__(name: str) -> object:
    """Lazy-load quantifier components."""
    if name in _EXPORTS:
        from importlib import import_module

        module_path, attr_name = _EXPORTS[name]
        module = import_module(module_path, __package__)
        return getattr(module, attr_name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "ConditionTranslator",
    "QuantifierInstantiator",
    "QuantifierParser",
    "QuantifierVerifier",
    "exists",
    "exists_unique",
    "extract_quantifiers",
    "forall",
    "parse_condition_to_z3",
    "replace_quantifiers_with_z3",
    "BoundSpec",
    "Quantifier",
    "QuantifierKind",
    "QuantifierVar",
]
