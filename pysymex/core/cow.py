"""Backward-compatibility shim — renamed to copy_on_write.py."""

from pysymex.core.copy_on_write import (
    CowDict,
    CowSet,
    ConstraintChain,
)

__all__ = ["CowDict", "CowSet", "ConstraintChain"]
