"""Contract support for PySpectre.
Provides:
- Quantifier support (forall, exists) for specifications
- Z3-based symbolic verification of quantified formulas
"""

from pyspectre.contracts.quantifiers import (
    BoundSpec,
    ConditionTranslator,
    Quantifier,
    QuantifierInstantiator,
    QuantifierKind,
    QuantifierParser,
    QuantifierVar,
    QuantifierVerifier,
    exists,
    exists_unique,
    extract_quantifiers,
    forall,
    parse_condition_to_z3,
    replace_quantifiers_with_z3,
)

__all__ = [
    "QuantifierKind",
    "QuantifierVar",
    "BoundSpec",
    "Quantifier",
    "QuantifierParser",
    "extract_quantifiers",
    "parse_condition_to_z3",
    "forall",
    "exists",
    "exists_unique",
    "QuantifierInstantiator",
    "QuantifierVerifier",
    "ConditionTranslator",
    "replace_quantifiers_with_z3",
]
