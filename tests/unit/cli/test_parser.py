import argparse
import pysymex.cli.parser

def test_create_parser() -> None:
    """Test create_parser behavior."""
    parser = pysymex.cli.parser.create_parser()
    assert isinstance(parser, argparse.ArgumentParser)
