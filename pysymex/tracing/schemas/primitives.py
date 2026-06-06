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

"""Primitive trace schema models and typed default factories."""

from __future__ import annotations

from typing import TypeAlias

from pydantic import BaseModel, ConfigDict, Field


class ConstraintEntry(BaseModel):
    """A single path constraint enriched with its causal origin."""

    model_config = ConfigDict(frozen=True)

    smtlib: str
    causality: str


def new_string_list() -> list[str]:
    """Create an empty list of strings."""
    return []


def new_string_dict() -> dict[str, str]:
    """Create an empty ``dict[str, str]`` mapping."""
    return {}


class StackDiff(BaseModel):
    """Net change to the symbolic stack after one instruction."""

    model_config = ConfigDict(frozen=True)

    popped: int = Field(default=0, ge=0)
    pushed: list[str] = Field(default_factory=new_string_list)


class VarDiff(BaseModel):
    """Net change to the variable namespace after one instruction."""

    model_config = ConfigDict(frozen=True)

    modified: dict[str, str] = Field(default_factory=new_string_dict)
    added: dict[str, str] = Field(default_factory=new_string_dict)
    removed: list[str] = Field(default_factory=new_string_list)


ConfigScalar: TypeAlias = str | int | float | bool | None


def new_config_scalar_dict() -> dict[str, ConfigScalar]:
    """Create an empty config snapshot map with scalar values."""
    return {}


def new_constraint_list() -> list[ConstraintEntry]:
    """Typed factory for ConstraintEntry list fields.

    A named factory (vs. ``default_factory=list``) lets pyright strict mode
    resolve the element type as ``ConstraintEntry`` instead of ``Unknown``.
    """
    return []


__all__ = [
    "ConstraintEntry",
    "StackDiff",
    "VarDiff",
    "ConfigScalar",
    "new_config_scalar_dict",
    "new_constraint_list",
    "new_string_dict",
    "new_string_list",
]
