"""Tests for CI integration (ci/core.py, ci/types.py)."""
from __future__ import annotations
import pytest
from pysymex.ci.types import ExitCode, CIResult, FailureThreshold
from pysymex.ci.core import (
    GitHubActionsReporter, GitLabReporter, CIRunner,
    generate_precommit_config, generate_precommit_hook_script, run_ci_check,
)


# -- Types --

class TestExitCode:
    def test_enum(self):
        assert len(ExitCode) >= 1

    def test_has_success(self):
        names = [m.name for m in ExitCode]
        assert any(n.upper() in ("SUCCESS", "OK", "PASS") for n in names)


class TestCIResult:
    def test_creation(self):
        cr = CIResult(exit_code=ExitCode.SUCCESS)
        assert cr is not None

    def test_has_exit_code(self):
        cr = CIResult(exit_code=ExitCode.SUCCESS)
        assert (hasattr(cr, 'exit_code') or hasattr(cr, 'code') or
                hasattr(cr, 'status'))


class TestFailureThreshold:
    def test_creation(self):
        ft = FailureThreshold()
        assert ft is not None


# -- Core --

class TestGitHubActionsReporter:
    def test_creation(self):
        r = GitHubActionsReporter()
        assert r is not None

    def test_has_report(self):
        assert (hasattr(GitHubActionsReporter, 'report') or
                hasattr(GitHubActionsReporter, 'format') or
                hasattr(GitHubActionsReporter, 'emit') or
                hasattr(GitHubActionsReporter, 'report_result') or
                hasattr(GitHubActionsReporter, 'report_vulnerability'))


class TestGitLabReporter:
    def test_creation(self):
        r = GitLabReporter()
        assert r is not None


class TestCIRunner:
    def test_creation(self):
        runner = CIRunner()
        assert runner is not None

    def test_has_run(self):
        assert (hasattr(CIRunner, 'run') or hasattr(CIRunner, 'execute') or
                hasattr(CIRunner, 'analyze_and_report'))


class TestGeneratePrecommitConfig:
    def test_returns_string(self):
        result = generate_precommit_config()
        assert isinstance(result, str)
        assert len(result) > 0


class TestGeneratePrecommitHookScript:
    def test_returns_string(self):
        result = generate_precommit_hook_script()
        assert isinstance(result, str)
        assert len(result) > 0


class TestRunCiCheck:
    def test_callable(self):
        assert callable(run_ci_check)
