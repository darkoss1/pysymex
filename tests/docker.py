"""Parallel Docker test runner for pysymex across multiple Python versions.

This script runs pytest in parallel across Docker containers for Python 3.11, 3.12, and 3.13,
providing stable, reliable test execution with comprehensive result reporting.

Usage:
    python tests/docker.py [pytest_args...]

Example:
    python tests/docker.py -v tests/unit/
    python tests/docker.py -k "test_analyze"
    python tests/docker.py --update-wsl
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.docker.core import DockerTestRunner


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run pysymex tests in parallel across Docker containers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tests/docker.py                    # Run all tests
  python tests/docker.py -- -v tests/unit/  # Run unit tests with verbose output
  python tests/docker.py -- -k test_analyze # Run tests matching pattern
        """,
    )
    parser.add_argument(
        "pytest_args",
        nargs="*",
        default=[],
        help="Additional arguments to pass to pytest (use -- to separate)",
    )
    parser.add_argument(
        "--update-wsl",
        action="store_true",
        help=(
            "On Windows, prompt before WSL repair when Docker Desktop is blocked. "
            "May run 'wsl --update', winget WSL upgrade, and Docker Desktop restart."
        ),
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Answer yes to maintenance prompts enabled by --update-wsl.",
    )

    args, unknown = parser.parse_known_args()
    pytest_args = args.pytest_args + unknown

    runner = DockerTestRunner(
        pytest_args,
        prompt_wsl_update=args.update_wsl,
        assume_yes=args.yes,
    )
    results = runner.run_all_tests()
    return runner.print_results(results)


if __name__ == "__main__":
    sys.exit(main())
