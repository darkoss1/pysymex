"""Backward-compatibility shim — renamed to copy_on_write.py."""

from pysymex.core.copy_on_write import (
    ConstraintChain,
    CowDict,
    CowSet,
)

__all__ = ["ConstraintChain", "CowDict", "CowSet"]
