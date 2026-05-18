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

"""Contract support for pysymex.

Provides the complete contract verification subsystem:

**Decorators**::

    from pysymex.contracts import requires, ensures, invariant, assumes, assigns, pure
    from pysymex.contracts import And_, Or_, Not_, Implies_

**Types**::

    from pysymex.contracts import Contract, ContractKind, FunctionContract
    from pysymex.contracts import ContractViolation, VerificationResult, Severity

**Compiler & Verifier**::

    from pysymex.contracts import ContractCompiler, ContractVerifier

**Quantifiers** (unchanged)::

    from pysymex.contracts import forall, exists, exists_unique

Lazy-loaded: quantifier symbols are resolved on first access via ``__getattr__``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._lazy import lazy_getattr

from pysymex.contracts.compiler import And_, ContractCompiler, Implies_, Not_, Or_
from pysymex.contracts.decorators import (
    assigns,
    assumes,
    ensures,
    function_contracts,
    get_function_contract,
    invariant,
    loop_invariant,
    pure,
    requires,
)
from pysymex.contracts.types import (
    Contract,
    ContractKind,
    ContractPredicate,
    ContractViolation,
    EffectKind,
    FunctionContract,
    InjectionPoint,
    Severity,
    VerificationResult,
)

if TYPE_CHECKING:
    from pysymex.contracts.verifier import ContractVerifier, VerificationReport
    from pysymex.contracts.quantifiers import (
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


_QUANTIFIER_EXPORTS: dict[str, tuple[str, str]] = {
    "BoundSpec": ("pysymex.contracts.quantifiers", "BoundSpec"),
    "ConditionTranslator": ("pysymex.contracts.quantifiers", "ConditionTranslator"),
    "Quantifier": ("pysymex.contracts.quantifiers", "Quantifier"),
    "QuantifierInstantiator": ("pysymex.contracts.quantifiers", "QuantifierInstantiator"),
    "QuantifierKind": ("pysymex.contracts.quantifiers", "QuantifierKind"),
    "QuantifierParser": ("pysymex.contracts.quantifiers", "QuantifierParser"),
    "QuantifierVar": ("pysymex.contracts.quantifiers", "QuantifierVar"),
    "QuantifierVerifier": ("pysymex.contracts.quantifiers", "QuantifierVerifier"),
    "exists": ("pysymex.contracts.quantifiers", "exists"),
    "exists_unique": ("pysymex.contracts.quantifiers", "exists_unique"),
    "extract_quantifiers": ("pysymex.contracts.quantifiers", "extract_quantifiers"),
    "forall": ("pysymex.contracts.quantifiers", "forall"),
    "parse_condition_to_z3": ("pysymex.contracts.quantifiers", "parse_condition_to_z3"),
    "replace_quantifiers_with_z3": (
        "pysymex.contracts.quantifiers",
        "replace_quantifiers_with_z3",
    ),
    "ContractVerifier": ("pysymex.contracts.verifier", "ContractVerifier"),
    "VerificationReport": ("pysymex.contracts.verifier", "VerificationReport"),
}


def __getattr__(name: str) -> object:
    """Lazy-load quantifier symbols on first access."""
    return lazy_getattr(name, __name__, _QUANTIFIER_EXPORTS, globals())


def __dir__() -> list[str]:
    """List all exported names, including lazy ones."""
    return list(__all__)


__all__: list[str] = [
    "And_",
    "BoundSpec",
    "ConditionTranslator",
    "Contract",
    "ContractCompiler",
    "ContractKind",
    "ContractPredicate",
    "ContractVerifier",
    "ContractViolation",
    "EffectKind",
    "FunctionContract",
    "Implies_",
    "InjectionPoint",
    "Not_",
    "Or_",
    "Quantifier",
    "QuantifierInstantiator",
    "QuantifierKind",
    "QuantifierParser",
    "QuantifierVar",
    "QuantifierVerifier",
    "Severity",
    "VerificationReport",
    "VerificationResult",
    "assigns",
    "assumes",
    "ensures",
    "exists",
    "exists_unique",
    "extract_quantifiers",
    "forall",
    "function_contracts",
    "get_function_contract",
    "invariant",
    "loop_invariant",
    "parse_condition_to_z3",
    "pure",
    "replace_quantifiers_with_z3",
    "requires",
]
