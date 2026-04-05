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

"""
Quantifier Support for pysymex.
Phase 21: Express "for all" and "exists" in contracts.
Provides:
- forall(var, range, condition) - Universal quantification
- exists(var, range, condition) - Existential quantification
- Z3 quantifier encoding
- Quantifier instantiation heuristics
"""

from pysymex.contracts.quantifiers_core import (
    ConditionTranslator as ConditionTranslator,
)
from pysymex.contracts.quantifiers_core import (
    QuantifierInstantiator as QuantifierInstantiator,
)
from pysymex.contracts.quantifiers_core import QuantifierParser as QuantifierParser
from pysymex.contracts.quantifiers_core import (
    QuantifierVerifier as QuantifierVerifier,
)
from pysymex.contracts.quantifiers_core import exists as exists
from pysymex.contracts.quantifiers_core import exists_unique as exists_unique
from pysymex.contracts.quantifiers_core import (
    extract_quantifiers as extract_quantifiers,
)
from pysymex.contracts.quantifiers_core import forall as forall
from pysymex.contracts.quantifiers_core import (
    parse_condition_to_z3 as parse_condition_to_z3,
)
from pysymex.contracts.quantifiers_core import (
    replace_quantifiers_with_z3 as replace_quantifiers_with_z3,
)
from pysymex.contracts.quantifiers_types import BoundSpec as BoundSpec
from pysymex.contracts.quantifiers_types import Quantifier as Quantifier
from pysymex.contracts.quantifiers_types import QuantifierKind as QuantifierKind
from pysymex.contracts.quantifiers_types import QuantifierVar as QuantifierVar

__all__ = [
    "BoundSpec",
    "ConditionTranslator",
    "Quantifier",
    "QuantifierInstantiator",
    "QuantifierKind",
    "QuantifierParser",
    "QuantifierVar",
    "QuantifierVerifier",
    "exists",
    "exists_unique",
    "extract_quantifiers",
    "forall",
    "parse_condition_to_z3",
    "replace_quantifiers_with_z3",
]
