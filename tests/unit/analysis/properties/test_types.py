import pytest
import z3
from pysymex.analysis.properties.types import PropertyKind, ProofStatus, PropertySpec, PropertyProof


class TestPropertyKind:
    """Test suite for pysymex.analysis.properties.types.PropertyKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert PropertyKind.COMMUTATIVITY.name == "COMMUTATIVITY"


class TestProofStatus:
    """Test suite for pysymex.analysis.properties.types.ProofStatus."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ProofStatus.PROVEN.name == "PROVEN"


class TestPropertySpec:
    """Test suite for pysymex.analysis.properties.types.PropertySpec."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        s = PropertySpec(PropertyKind.COMMUTATIVITY, "prop")
        assert s.name == "prop"


class TestPropertyProof:
    """Test suite for pysymex.analysis.properties.types.PropertyProof."""

    def test_is_proven(self) -> None:
        """Test is_proven behavior."""
        p = PropertyProof(PropertySpec(PropertyKind.COMMUTATIVITY, "p"), ProofStatus.PROVEN)
        assert p.is_proven is True

    def test_is_disproven(self) -> None:
        """Test is_disproven behavior."""
        p = PropertyProof(PropertySpec(PropertyKind.COMMUTATIVITY, "p"), ProofStatus.DISPROVEN)
        assert p.is_disproven is True

    def test_format(self) -> None:
        """Test format behavior."""
        p = PropertyProof(PropertySpec(PropertyKind.COMMUTATIVITY, "p"), ProofStatus.PROVEN)
        assert "✓ p: PROVEN" in p.format()
