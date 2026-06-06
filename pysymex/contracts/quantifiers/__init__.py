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

"""Parse, translate, instantiate, and verify quantified contract conditions.

Supports ``forall``, ``exists``, and ``exists_unique`` in string predicates and
factory helpers. Used from :mod:`pysymex.contracts.compiler` and exposed on the
public :mod:`pysymex.contracts` namespace.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .extraction import (
        extract_quantifiers,
        replace_quantifiers_with_z3,
    )
    from .factories import exists, exists_unique, forall
    from .instantiation import QuantifierInstantiator
    from .lowering import (
        ConcreteRange,
        QuantifierLoweringError,
        QuantifierLoweringPolicy,
        find_quantifier_occurrences,
        lower_condition_quantifiers,
        lower_quantifier,
    )
    from .parser import QuantifierParser
    from .translator import (
        ConditionTranslator,
        parse_condition_to_z3,
    )
    from .types import (
        BoundSpec,
        Quantifier,
        QuantifierKind,
        QuantifierVar,
    )
    from .verification import QuantifierVerifier

_EXPORTS: dict[str, tuple[str, str]] = {
    "ConditionTranslator": (".translator", "ConditionTranslator"),
    "ConcreteRange": (".lowering", "ConcreteRange"),
    "QuantifierLoweringError": (".lowering", "QuantifierLoweringError"),
    "QuantifierLoweringPolicy": (".lowering", "QuantifierLoweringPolicy"),
    "QuantifierInstantiator": (".instantiation", "QuantifierInstantiator"),
    "QuantifierParser": (".parser", "QuantifierParser"),
    "QuantifierVerifier": (".verification", "QuantifierVerifier"),
    "exists": (".factories", "exists"),
    "exists_unique": (".factories", "exists_unique"),
    "extract_quantifiers": (".extraction", "extract_quantifiers"),
    "find_quantifier_occurrences": (".lowering", "find_quantifier_occurrences"),
    "forall": (".factories", "forall"),
    "lower_condition_quantifiers": (".lowering", "lower_condition_quantifiers"),
    "lower_quantifier": (".lowering", "lower_quantifier"),
    "parse_condition_to_z3": (".translator", "parse_condition_to_z3"),
    "replace_quantifiers_with_z3": (".extraction", "replace_quantifiers_with_z3"),
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
    "ConcreteRange",
    "QuantifierLoweringError",
    "QuantifierLoweringPolicy",
    "QuantifierInstantiator",
    "QuantifierParser",
    "QuantifierVerifier",
    "exists",
    "exists_unique",
    "extract_quantifiers",
    "find_quantifier_occurrences",
    "forall",
    "lower_condition_quantifiers",
    "lower_quantifier",
    "parse_condition_to_z3",
    "replace_quantifiers_with_z3",
    "BoundSpec",
    "Quantifier",
    "QuantifierKind",
    "QuantifierVar",
]
