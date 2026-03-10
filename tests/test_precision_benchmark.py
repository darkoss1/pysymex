"""Precision benchmark for pysymex.

Measures detection precision on a controlled corpus:
- True positives: known bugs that should be detected
- False positives: clean code that should not be flagged


Marked with @pytest.mark.slow so it doesn't run in every CI pass.
"""

import os
import tempfile
import textwrap

import pytest

from pysymex.analysis.pipeline import Scanner, ScannerConfig

# ---------------------------------------------------------------------------
# Known-buggy code (each snippet should produce at least one finding)
# ---------------------------------------------------------------------------

KNOWN_BUGS: dict[str, str] = {
    "division_by_zero": textwrap.dedent("""\
        def divide(x):
            return 10 / 0
    """),
    "unused_variable": textwrap.dedent("""\
        def compute():
            unused = 42
            return 1
    """),
    "dead_store": textwrap.dedent("""\
        def overwrite():
            x = 1
            x = 2
            return x
    """),
    "unreachable_code": textwrap.dedent("""\
        def dead():
            return 1
            print("unreachable")
    """),
    "bare_except": textwrap.dedent("""\
        def risky():
            try:
                return 1 / 0
            except:
                pass
    """),
    "broad_except_silenced": textwrap.dedent("""\
        def silenced():
            try:
                x = int("not a number")
            except Exception:
                pass
    """),
}

# ---------------------------------------------------------------------------
# Known-clean code (should NOT produce findings)
# ---------------------------------------------------------------------------

KNOWN_CLEAN: dict[str, str] = {
    "simple_function": textwrap.dedent("""\
        def add(a, b):
            return a + b
    """),
    "class_with_methods": textwrap.dedent("""\
        class Foo:
            def __init__(self, x):
                self.x = x
            def get(self):
                return self.x
    """),
    "dataclass_fields": textwrap.dedent("""\
        from dataclasses import dataclass
        @dataclass
        class Config:
            name: str = "default"
            count: int = 0
    """),
    "loop_variable": textwrap.dedent("""\
        def process(items):
            total = 0
            for item in items:
                total += item
            return total
    """),
    "conditional_return": textwrap.dedent("""\
        def classify(x):
            if x > 0:
                return "positive"
            else:
                return "negative"
    """),
    "dunder_variables": textwrap.dedent("""\
        __all__ = ["main"]
        __version__ = "1.0"
        def main():
            return 0
    """),
}


def _scan_source(scanner: Scanner, source: str, name: str) -> list:
    """Write *source* to a temp file, scan it, return unsuppressed issues."""
    fd, path = tempfile.mkstemp(suffix=".py", prefix=f"bench_{name}_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(source)
        issues = scanner.scan_file(path)
        return [i for i in issues if not i.is_suppressed()]
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestPrecisionBenchmark:
    """Precision benchmark."""

    def _make_scanner(self) -> Scanner:
        return Scanner(
            ScannerConfig(
                suppress_likely_false_positives=True,
                verbose=False,
            )
        )

    def test_precision_above_threshold(self):
        """Precision (TP / (TP + FP)) must exceed 20%."""
        scanner = self._make_scanner()

        tp = 0
        for name, source in KNOWN_BUGS.items():
            active = _scan_source(scanner, source, name)
            if active:
                tp += 1

        fp = 0
        for name, source in KNOWN_CLEAN.items():
            active = _scan_source(scanner, source, name)
            fp += len(active)

        total = tp + fp
        precision = tp / total if total > 0 else 0.0
        assert precision > 0.20, (
            f"Precision {precision:.1%} is below 20% target. "
            f"TP={tp} (of {len(KNOWN_BUGS)} buggy snippets), FP={fp}"
        )

    def test_known_bugs_detected(self):
        """At least half the known bugs should be detected."""
        scanner = self._make_scanner()
        detected = 0
        for name, source in KNOWN_BUGS.items():
            active = _scan_source(scanner, source, name)
            if active:
                detected += 1
        assert (
            detected >= len(KNOWN_BUGS) // 2
        ), f"Only {detected}/{len(KNOWN_BUGS)} known bugs detected"

    def test_clean_code_low_fp(self):
        """Clean code should produce very few false positives."""
        scanner = self._make_scanner()
        total_fp = 0
        for name, source in KNOWN_CLEAN.items():
            active = _scan_source(scanner, source, name)
            total_fp += len(active)
        assert total_fp < len(
            KNOWN_CLEAN
        ), f"Too many FPs in clean code: {total_fp} (should be < {len(KNOWN_CLEAN)})"
