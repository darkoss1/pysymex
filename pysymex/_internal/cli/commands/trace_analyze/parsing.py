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

from pysymex._internal.cli.commands.validation import non_negative_float, non_negative_int
from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)


def parse_seq_range(value: str) -> tuple[int, int]:
    """Parse seq range."""
    parts = value.split(":")
    if len(parts) != 2:
        msg = "seq-range must be in the form START:END (e.g. 100:500)"
        raise argparse.ArgumentTypeError(msg)
    try:
        start = non_negative_int(parts[0])
        end = non_negative_int(parts[1])
    except argparse.ArgumentTypeError as exc:
        logger.debug("Invalid trace analyzer seq range: %s", value, exc_info=True)
        msg = f"seq-range values must be non-negative integers: {exc}"
        raise argparse.ArgumentTypeError(
            msg,
        ) from exc
    if start > end:
        msg = "seq-range START must be less than or equal to END"
        raise argparse.ArgumentTypeError(msg)
    return start, end


def parse_pc_range(value: str) -> tuple[int, int]:
    """Parse pc range."""
    parts = value.split(":")
    if len(parts) != 2:
        msg = "pc-range must be in the form START:END (e.g. 0:200)"
        raise argparse.ArgumentTypeError(msg)
    try:
        start = non_negative_int(parts[0])
        end = non_negative_int(parts[1])
    except argparse.ArgumentTypeError as exc:
        logger.debug("Invalid trace analyzer pc range: %s", value, exc_info=True)
        msg = f"pc-range values must be non-negative integers: {exc}"
        raise argparse.ArgumentTypeError(
            msg,
        ) from exc
    if start > end:
        msg = "pc-range START must be less than or equal to END"
        raise argparse.ArgumentTypeError(msg)
    return start, end


def parse_path_id_list(value: str) -> list[int]:
    """Parse path id list."""
    try:
        path_ids = [non_negative_int(x.strip()) for x in value.split(",") if x.strip()]
    except argparse.ArgumentTypeError as exc:
        logger.debug("Invalid trace analyzer path-id list: %s", value, exc_info=True)
        msg = f"path-id-list must be comma-separated non-negative integers: {exc}"
        raise argparse.ArgumentTypeError(
            msg,
        ) from exc
    if not path_ids:
        msg = "path-id-list must include at least one path id"
        raise argparse.ArgumentTypeError(msg)
    return path_ids


def parse_confidence_range(value: str) -> tuple[float, float]:
    """Parse confidence range."""
    parts = value.split(":")
    if len(parts) != 2:
        msg = "confidence must be in the form MIN:MAX (e.g. 0.8:1.0)"
        raise argparse.ArgumentTypeError(msg)
    try:
        start = non_negative_float(parts[0])
        end = non_negative_float(parts[1])
    except argparse.ArgumentTypeError as exc:
        logger.debug("Invalid trace analyzer confidence range: %s", value, exc_info=True)
        msg = f"confidence values must be numbers from 0.0 to 1.0: {exc}"
        raise argparse.ArgumentTypeError(
            msg,
        ) from exc
    if start > 1.0 or end > 1.0:
        msg = "confidence values must be between 0.0 and 1.0"
        raise argparse.ArgumentTypeError(msg)
    if start > end:
        msg = "confidence MIN must be less than or equal to MAX"
        raise argparse.ArgumentTypeError(msg)
    return start, end
