#!/usr/bin/env python3
# PySyMex: Python Symbolic Execution & Formal Verification
# Copyright (C) 2026 PySyMex Team
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

"""
Tests for Z3 Formal Verification Prover

Tests that the prover correctly:
1. Detects crashes that CAN happen
2. Proves code that CANNOT crash is safe
3. Handles all Python guard patterns
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from pysymex.analysis.solver import (
    Z3_AVAILABLE,
    BugType,
    verify_file,
    verify_function,
)

pytestmark = pytest.mark.skipif(not Z3_AVAILABLE, reason="Z3 not available")


class TestDivisionByZero:
    """Test division by zero detection and proofs."""

    def test_unguarded_division_crashes(self):
        def f(a, b):
            return a / b

        results = verify_function(f)
        assert len(results) >= 1
        assert any(r.can_crash for r in results)
        assert any(r.counterexample and r.counterexample.get("b") == "0" for r in results)

    def test_unguarded_modulo_crashes(self):
        def f(a, b):
            return a % b

        results = verify_function(f)
        assert any(r.can_crash for r in results)

    def test_unguarded_floor_div_crashes(self):
        def f(a, b):
            return a // b

        results = verify_function(f)
        assert any(r.can_crash for r in results)

    def test_division_by_constant_is_safe(self):
        def f(a):
            return a / 2

        results = verify_function(f)
        assert all(r.proven_safe for r in results)


class TestGuardPatterns:
    """Test that guards are correctly recognized."""

    def test_equality_guard_safe(self):
        """if b == 0: return; a/b is safe"""

        def f(a, b):
            if b == 0:
                return 0
            return a / b

        results = verify_function(f)
        assert all(r.proven_safe for r in results)

    def test_inequality_guard_safe(self):
        """if b != 0: a/b is safe"""

        def f(a, b):
            if b != 0:
                return a / b
            return 0

        results = verify_function(f)
        assert all(r.proven_safe for r in results)

    def test_truthiness_guard_safe(self):
        """if b: a/b is safe"""

        def f(a, b):
            if b:
                return a / b
            return 0

        results = verify_function(f)
        assert all(r.proven_safe for r in results)

    def test_not_truthiness_guard_safe(self):
        """if not b: return; a/b is safe"""

        def f(a, b):
            if not b:
                return 0
            return a / b

        results = verify_function(f)
        assert all(r.proven_safe for r in results)

    def test_greater_than_guard_safe(self):
        """if b > 0: a/b is safe"""

        def f(a, b):
            if b > 0:
                return a / b
            return 0

        results = verify_function(f)
        assert all(r.proven_safe for r in results)

    def test_less_than_guard_safe(self):
        """if b < 0: a/b is safe"""

        def f(a, b):
            if b < 0:
                return a / b
            return 0

        results = verify_function(f)
        assert all(r.proven_safe for r in results)

    def test_greater_equal_guard_safe(self):
        """if b >= 1: a/b is safe"""

        def f(a, b):
            if b >= 1:
                return a / b
            return 0

        results = verify_function(f)
        assert all(r.proven_safe for r in results)


class TestComplexControlFlow:
    """Test complex control flow patterns."""

    def test_early_return_safe(self):
        def f(a, b):
            if b == 0:
                return None
            result = a / b
            return result

        results = verify_function(f)
        assert all(r.proven_safe for r in results)

    def test_exception_guard_safe(self):
        def f(a, b):
            if b == 0:
                raise ValueError()
            return a / b

        results = verify_function(f)
        assert all(r.proven_safe for r in results)

    def test_nested_guards_accumulate(self):
        def f(a, b, c):
            if a > 0:
                if b > 0:
                    if c == 0:
                        return 0
                    return a / c
            return 0

        results = verify_function(f)
        assert all(r.proven_safe for r in results)
        # Should track multiple constraints
        assert all(len(r.crash.path_constraints) >= 2 for r in results)

    def test_multiple_divisions_same_guard(self):
        def f(a, b):
            if b == 0:
                return 0
            x = a / b
            y = (a + 1) / b
            return x + y

        results = verify_function(f)
        assert all(r.proven_safe for r in results)


class TestProofResults:
    """Test proof result accuracy."""

    def test_sat_status_for_crash(self):
        def f(a, b):
            return a / b

        results = verify_function(f)
        assert results[0].z3_status == "sat"

    def test_unsat_status_for_safe(self):
        def f(a, b):
            if b == 0:
                return 0
            return a / b

        results = verify_function(f)
        assert all(r.z3_status == "unsat" for r in results)

    def test_counterexample_provided(self):
        def f(a, b):
            return a / b

        results = verify_function(f)
        assert results[0].counterexample is not None
        assert "b" in results[0].counterexample

    def test_bug_type_correct(self):
        def f(a, b):
            return a / b

        results = verify_function(f)
        assert results[0].crash.bug_type == BugType.DIVISION_BY_ZERO


class TestEdgeCases:
    """Test edge cases."""

    def test_no_params(self):
        def f():
            return 42

        results = verify_function(f)
        assert len(results) == 0

    def test_no_division(self):
        def f(a, b):
            return a + b

        results = verify_function(f)
        assert len(results) == 0

    def test_division_by_one(self):
        def f(a):
            return a / 1

        results = verify_function(f)
        assert all(r.proven_safe for r in results)


class TestFileVerification:
    """Test file-level verification."""

    def test_verify_file_finds_bugs(self, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text("""
def unsafe(a, b):
    return a / b

def safe(a, b):
    if b == 0:
        return 0
    return a / b
""")

        results = verify_file(str(test_file))

        # Should find bugs in unsafe function
        assert "unsafe" in results
        assert any(r.can_crash for r in results["unsafe"])

        # Safe function should not be in results (no bugs to report)
        # Or if present, should have no crashes
        if "safe" in results:
            assert all(r.proven_safe for r in results["safe"])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
