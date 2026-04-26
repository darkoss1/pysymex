import pytest
from pysymex.analysis.resources.types import (
    ResourceKind,
    ResourceState,
    ResourceIssueKind,
    ResourceIssue,
    StateTransition,
)


class TestResourceKind:
    """Test suite for pysymex.analysis.resources.types.ResourceKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ResourceKind.FILE.name == "FILE"


class TestResourceState:
    """Test suite for pysymex.analysis.resources.types.ResourceState."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ResourceState.OPEN.name == "OPEN"


class TestResourceIssueKind:
    """Test suite for pysymex.analysis.resources.types.ResourceIssueKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ResourceIssueKind.RESOURCE_LEAK.name == "RESOURCE_LEAK"


class TestResourceIssue:
    """Test suite for pysymex.analysis.resources.types.ResourceIssue."""

    def test_format(self) -> None:
        """Test format behavior."""
        issue = ResourceIssue(
            kind=ResourceIssueKind.RESOURCE_LEAK,
            message="Leaked",
            resource_name="my_res",
            line_number=10,
            current_state=ResourceState.OPEN,
        )
        fmt = issue.format()
        assert "[RESOURCE_LEAK] at line 10 (my_res) [state: OPEN]: Leaked" in fmt


class TestStateTransition:
    """Test suite for pysymex.analysis.resources.types.StateTransition."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        st = StateTransition(ResourceState.UNINITIALIZED, ResourceState.OPEN, "open")
        assert st.from_state == ResourceState.UNINITIALIZED
        assert st.to_state == ResourceState.OPEN
        assert st.action == "open"
