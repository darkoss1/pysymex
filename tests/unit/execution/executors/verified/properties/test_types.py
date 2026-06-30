from pysymex._internal.execution.executors.verified.properties.types import (
    ProofReason,
    ProofStatus,
    PropertyKind,
    PropertyProof,
    PropertySpec,
)
from pysymex._internal.execution.executors.verified.properties.types import (
    ProofReason as ExportedProofReason,
)


class TestPropertyKind:
    """Test suite for pysymex._internal.execution.executors.verified.properties.types.PropertyKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert PropertyKind.BOUNDED.name == "BOUNDED"


class TestProofStatus:
    """Test suite for pysymex._internal.execution.executors.verified.properties.types.ProofStatus."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ProofStatus.PROVEN.name == "PROVEN"


class TestProofReason:
    """Test suite for pysymex._internal.execution.executors.verified.properties.types.ProofReason."""

    def test_initialization(self) -> None:
        """Proof reasons are exported as part of the property proof contract."""
        assert ProofReason.SOLVER_UNKNOWN.name == "SOLVER_UNKNOWN"
        assert ExportedProofReason is ProofReason


class TestPropertySpec:
    """Test suite for pysymex._internal.execution.executors.verified.properties.types.PropertySpec."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        s = PropertySpec(PropertyKind.BOUNDED, "prop")
        assert s.name == "prop"


class TestPropertyProof:
    """Test suite for pysymex._internal.execution.executors.verified.properties.types.PropertyProof."""

    def test_is_proven(self) -> None:
        """Test is_proven behavior."""
        p = PropertyProof(PropertySpec(PropertyKind.BOUNDED, "p"), ProofStatus.PROVEN)
        assert p.is_proven is True

    def test_is_disproven(self) -> None:
        """Test is_disproven behavior."""
        p = PropertyProof(PropertySpec(PropertyKind.BOUNDED, "p"), ProofStatus.DISPROVEN)
        assert p.is_disproven is True

    def test_format(self) -> None:
        """Test format behavior."""
        p = PropertyProof(PropertySpec(PropertyKind.BOUNDED, "p"), ProofStatus.PROVEN)
        assert "[OK] p: PROVEN" in p.format()

    def test_format_uses_ascii_status_labels(self) -> None:
        """Property diagnostics should render deterministically in plain terminals."""
        expected = {
            ProofStatus.PROVEN: "[OK]",
            ProofStatus.DISPROVEN: "[FAIL]",
            ProofStatus.UNKNOWN: "[UNKNOWN]",
            ProofStatus.TIMEOUT: "[TIMEOUT]",
            ProofStatus.CONDITIONAL: "[CONDITIONAL]",
        }

        for status, prefix in expected.items():
            proof = PropertyProof(PropertySpec(PropertyKind.BOUNDED, "p"), status)
            formatted = proof.format()
            assert formatted.startswith(prefix)
            assert formatted.isascii()

    def test_format_includes_reason_when_present(self) -> None:
        """Unknown proof diagnostics include machine-readable reason names."""
        proof = PropertyProof(
            PropertySpec(PropertyKind.BOUNDED, "p"),
            ProofStatus.UNKNOWN,
            reason=ProofReason.SOLVER_UNKNOWN,
        )

        formatted = proof.format()

        assert "Reason: SOLVER_UNKNOWN" in formatted
        assert formatted.isascii()
