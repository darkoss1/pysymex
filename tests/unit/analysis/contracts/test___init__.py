"""Test exports of pysymex.contracts."""

import pysymex.contracts as c


def test_has_exports() -> None:
    """Test that contract types are exported."""
    exports = [
        "And",
        "Contract",
        "ContractKind",
        "ContractSeverity",
        "ContractViolation",
        "FunctionContract",
        "Implies",
        "Not",
        "Or",
        "VerificationResult",
        "assigns",
        "assumes",
        "ensures",
        "exists",
        "unique",
        "forall",
        "invariant",
        "loop",
        "pure",
        "requires",
    ]
    for export in exports:
        assert hasattr(c, export)

    assert not hasattr(c, "function_contracts")
    assert not hasattr(c, "ContractRegistry.get")
