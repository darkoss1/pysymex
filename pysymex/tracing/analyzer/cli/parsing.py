# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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

"""Argument parsing helpers for the trace analyzer CLI."""

from __future__ import annotations

import argparse

from pysymex.logger import get_logger

logger = get_logger(__name__)


def parse_seq_range(value: str) -> tuple[int, int]:
    """Parse seq range."""
    parts = value.split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("seq-range must be in the form START:END (e.g. 100:500)")
    try:
        return int(parts[0]), int(parts[1])
    except ValueError as exc:
        logger.debug("Invalid trace analyzer seq range: %s", value, exc_info=True)
        raise argparse.ArgumentTypeError(f"seq-range values must be integers: {exc}") from exc


def parse_pc_range(value: str) -> tuple[int, int]:
    """Parse pc range."""
    parts = value.split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("pc-range must be in the form START:END (e.g. 0:200)")
    try:
        return int(parts[0]), int(parts[1])
    except ValueError as exc:
        logger.debug("Invalid trace analyzer pc range: %s", value, exc_info=True)
        raise argparse.ArgumentTypeError(f"pc-range values must be integers: {exc}") from exc


def parse_path_id_list(value: str) -> list[int]:
    """Parse path id list."""
    try:
        return [int(x.strip()) for x in value.split(",") if x.strip()]
    except ValueError as exc:
        logger.debug("Invalid trace analyzer path-id list: %s", value, exc_info=True)
        raise argparse.ArgumentTypeError(
            f"path-id-list must be comma-separated integers: {exc}"
        ) from exc


def parse_confidence_range(value: str) -> tuple[float, float]:
    """Parse confidence range."""
    parts = value.split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("confidence must be in the form MIN:MAX (e.g. 0.8:1.0)")
    try:
        return float(parts[0]), float(parts[1])
    except ValueError as exc:
        logger.debug("Invalid trace analyzer confidence range: %s", value, exc_info=True)
        raise argparse.ArgumentTypeError(f"confidence values must be floats: {exc}") from exc


__all__ = [
    "parse_confidence_range",
    "parse_path_id_list",
    "parse_pc_range",
    "parse_seq_range",
]
