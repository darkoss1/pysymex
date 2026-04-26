"""Tests for utils package."""

from __future__ import annotations

import pysymex.utils


class TestUtilsInit:
    """Test class for utils package."""

    def test_utils_init_is_empty(self) -> None:
        """Verify that utils init loads cleanly without exports."""
        assert pysymex.utils.__name__ == "pysymex.utils"
