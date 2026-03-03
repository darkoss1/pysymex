"""
Quantifier Support for pysymex.
Phase 21: Express "for all" and "exists" in contracts.
Provides:
- forall(var, range, condition) - Universal quantification
- exists(var, range, condition) - Existential quantification
- Z3 quantifier encoding
- Quantifier instantiation heuristics
"""

from pysymex.contracts.quantifiers_core import ConditionTranslator as ConditionTranslator

from pysymex.contracts.quantifiers_core import QuantifierInstantiator as QuantifierInstantiator

from pysymex.contracts.quantifiers_core import QuantifierParser as QuantifierParser

from pysymex.contracts.quantifiers_core import QuantifierVerifier as QuantifierVerifier

from pysymex.contracts.quantifiers_core import exists as exists

from pysymex.contracts.quantifiers_core import exists_unique as exists_unique

from pysymex.contracts.quantifiers_core import extract_quantifiers as extract_quantifiers

from pysymex.contracts.quantifiers_core import forall as forall

from pysymex.contracts.quantifiers_core import parse_condition_to_z3 as parse_condition_to_z3

from pysymex.contracts.quantifiers_core import (
    replace_quantifiers_with_z3 as replace_quantifiers_with_z3,
)

from pysymex.contracts.quantifiers_types import BoundSpec as BoundSpec

from pysymex.contracts.quantifiers_types import Quantifier as Quantifier

from pysymex.contracts.quantifiers_types import QuantifierKind as QuantifierKind

from pysymex.contracts.quantifiers_types import QuantifierVar as QuantifierVar

__all__ = [
    "QuantifierKind",
    "QuantifierVar",
    "BoundSpec",
    "Quantifier",
    "QuantifierParser",
    "parse_condition_to_z3",
    "ConditionTranslator",
    "forall",
    "exists",
    "exists_unique",
    "QuantifierInstantiator",
    "QuantifierVerifier",
    "extract_quantifiers",
    "replace_quantifiers_with_z3",
]
