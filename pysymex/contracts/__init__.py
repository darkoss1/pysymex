"""Contract support for pysymex.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.

Provides:
- Quantifier support (forall, exists) for specifications
- Z3-based symbolic verification of quantified formulas
"""

from __future__ import annotations

from importlib import import_module

_EXPORTS: dict[str, tuple[str, str]] = {
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
    "replace_quantifiers_with_z3": ("pysymex.contracts.quantifiers", "replace_quantifiers_with_z3"),
}


def __getattr__(name: str) -> object:
    """Getattr."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pysymex.contracts' has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Dir."""
    return list(_EXPORTS.keys())


__all__: list[str] = [
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
