import argparse

import pysymex.cli.parser


def test_create_parser() -> None:
    """Test create_parser behavior."""
    parser = pysymex.cli.parser.create_parser()
    assert isinstance(parser, argparse.ArgumentParser)


def test_scan_parser_default_timeout_is_bounded_for_stress_scans() -> None:
    """Default symbolic scans should not spend 30 seconds per function before reporting."""
    parser = pysymex.cli.parser.create_parser()
    args = parser.parse_args(["scan", "target.py"])

    assert args.timeout == 5


def test_verify_parser_exposes_shared_report_options() -> None:
    """Verify should expose the same report shape controls as scan-like commands."""
    parser = pysymex.cli.parser.create_parser()
    args = parser.parse_args(["verify", "target.py", "--format", "json", "-o", "report.json"])

    assert args.format == "json"
    assert args.output == "report.json"
