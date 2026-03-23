import pytest
import asyncio
from pysymex import analyze
from pysymex.analysis.detectors import IssueKind

@pytest.mark.xfail(
    strict=False,
    reason="Coroutine body exploration is currently incomplete for async def with await",
)
def test_async_e2e():
    async def async_div(x):
        # A simple async function that might div by zero
        await asyncio.sleep(0)  # Yield control to ensure it behaves as a coroutine
        return 10 / x

    result = analyze(async_div, {"x": "int"}, timeout=10.0, max_paths=200)
    
    # Needs to detect the division by zero even though it's an async def
    issues = result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)
    assert len(issues) > 0, "Should detect division by zero inside async function"
    ce = issues[0].get_counterexample()
    assert ce["x"] == 0, "Counterexample should resolve correctly"
