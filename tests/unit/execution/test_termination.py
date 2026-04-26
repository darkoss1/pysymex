from __future__ import annotations

import pytest
import z3

from pysymex.execution.termination import (
    RankingFunction,
    TerminationAnalyzer,
    TerminationProof,
    TerminationStatus,
)


class TestTerminationStatus:
    """Test suite for pysymex.execution.termination.TerminationStatus."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        names = {item.name for item in TerminationStatus}

        assert "TERMINATES" in names
        assert "NON_TERMINATING" in names
        assert "UNKNOWN" in names
        assert "BOUNDED" in names


class TestRankingFunction:
    """Test suite for pysymex.execution.termination.RankingFunction."""

    def test_compile(self) -> None:
        """Test compile behavior."""
        x = z3.Int("x")
        ranking = RankingFunction(name="r", expression="x")

        compiled = ranking.compile({"x": x})

        assert str(compiled) == "x"
        assert ranking.z3_expr is not None


class TestTerminationProof:
    """Test suite for pysymex.execution.termination.TerminationProof."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        proof = TerminationProof(
            status=TerminationStatus.TERMINATES,
            ranking_function=RankingFunction(name="r", expression="x"),
            message="ok",
        )

        assert proof.status is TerminationStatus.TERMINATES
        assert proof.ranking_function is not None
        assert proof.message == "ok"


class TestTerminationAnalyzer:
    """Test suite for pysymex.execution.termination.TerminationAnalyzer."""

    def test_check_termination(self) -> None:
        """Test check_termination behavior."""
        x = z3.Int("x")
        analyzer = TerminationAnalyzer(timeout_ms=1000)

        proven = analyzer.check_termination(
            loop_condition=x > 0,
            loop_body_effect={"x": x - 1},
            symbols={"x": x},
        )

        assert proven.status is TerminationStatus.TERMINATES
        assert proven.ranking_function is not None

        non_decreasing = RankingFunction(name="bad", expression="x")
        unknown = analyzer.check_termination(
            loop_condition=x > 0,
            loop_body_effect={"x": x + 1},
            symbols={"x": x},
            ranking=non_decreasing,
        )

        assert unknown.status is TerminationStatus.UNKNOWN
        assert "decreasing" in unknown.message.lower()
