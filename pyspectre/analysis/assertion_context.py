"""Assertion Context Analyzer for PySpectre.

This module provides deeper analysis of assertion-related issues to
determine whether they are intentional security/validation checks
or potentially accidental bugs.

v0.3.0-alpha: Initial implementation
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


class ContextType(Enum):
    """Type of code context surrounding an assertion."""

    PRODUCTION_CHECK = auto()
    CONFIG_GUARD = auto()
    INPUT_VALIDATION = auto()
    TYPE_GUARD = auto()
    NULL_GUARD = auto()
    PERMISSION_CHECK = auto()
    INVARIANT = auto()
    BOUNDARY_CHECK = auto()
    UNKNOWN = auto()


@dataclass
class AssertionAnalysis:
    """Analysis result for an assertion."""

    context_type: ContextType
    is_intentional: bool
    function_purpose: str | None = None
    related_condition: str | None = None
    confidence: float = 0.5


VALIDATION_FUNCTION_PATTERNS = re.compile(
    r"^(validate|sanitize|check|verify|ensure|require|assert_|guard_)",
    re.IGNORECASE,
)

SECURITY_FUNCTION_PATTERNS = re.compile(
    r"^(auth|authorize|permission|access|security|protect|restrict|deny|allow)",
    re.IGNORECASE,
)

PRODUCTION_PATTERNS = [
    re.compile(r"\bPRODUCTION\b", re.IGNORECASE),
    re.compile(r"\bPROD\b"),
    re.compile(r"\bDEBUG\b"),
    re.compile(r"\bDEVELOPMENT\b", re.IGNORECASE),
    re.compile(r"\bSTAGING\b", re.IGNORECASE),
    re.compile(r"\bTESTING\b"),
    re.compile(r"os\.environ\.get\(['\"]ENV", re.IGNORECASE),
    re.compile(r"config\.(production|debug|development)", re.IGNORECASE),
]

CONFIG_PATTERNS = [
    re.compile(r"\bconfig\.", re.IGNORECASE),
    re.compile(r"\bsettings\.", re.IGNORECASE),
    re.compile(r"\boptions\.", re.IGNORECASE),
    re.compile(r"\bOPTIONS\b"),
    re.compile(r"\.required\b"),
    re.compile(r"\.strict\b"),
    re.compile(r"\.enabled\b"),
]

RAISE_PATTERNS = {
    "ValueError": ContextType.INPUT_VALIDATION,
    "TypeError": ContextType.TYPE_GUARD,
    "RuntimeError": ContextType.PRODUCTION_CHECK,
    "AssertionError": ContextType.INVARIANT,
    "PermissionError": ContextType.PERMISSION_CHECK,
    "PermissionDenied": ContextType.PERMISSION_CHECK,
    "AuthenticationError": ContextType.PERMISSION_CHECK,
    "AuthorizationError": ContextType.PERMISSION_CHECK,
    "ValidationError": ContextType.INPUT_VALIDATION,
}


def analyze_function_name(name: str | None) -> tuple[ContextType, float]:
    """Analyze function name to determine assertion context.

    Args:
        name: Function name to analyze

    Returns:
        Tuple of (ContextType, confidence)
    """
    if not name:
        return ContextType.UNKNOWN, 0.3

    if VALIDATION_FUNCTION_PATTERNS.match(name):
        return ContextType.INPUT_VALIDATION, 0.9

    if SECURITY_FUNCTION_PATTERNS.match(name):
        return ContextType.PERMISSION_CHECK, 0.9

    name_lower = name.lower()

    if any(word in name_lower for word in ["init", "setup", "configure", "load"]):
        return ContextType.INVARIANT, 0.7

    if any(word in name_lower for word in ["parse", "convert", "process"]):
        return ContextType.INPUT_VALIDATION, 0.6

    return ContextType.UNKNOWN, 0.3


def analyze_source_context(
    source_code: str,
    line_number: int | None = None,
) -> tuple[ContextType, float]:
    """Analyze source code context around an assertion.

    Args:
        source_code: Source code to analyze
        line_number: Optional specific line to focus on

    Returns:
        Tuple of (ContextType, confidence)
    """
    for pattern in PRODUCTION_PATTERNS:
        if pattern.search(source_code):
            return ContextType.PRODUCTION_CHECK, 0.85

    for pattern in CONFIG_PATTERNS:
        if pattern.search(source_code):
            return ContextType.CONFIG_GUARD, 0.8

    for exc_name, context_type in RAISE_PATTERNS.items():
        if f"raise {exc_name}" in source_code:
            return context_type, 0.75

    if "isinstance(" in source_code:
        return ContextType.TYPE_GUARD, 0.7

    if " is None" in source_code or " is not None" in source_code:
        return ContextType.NULL_GUARD, 0.7

    return ContextType.UNKNOWN, 0.3


def analyze_assertion(
    message: str,
    function_name: str | None = None,
    source_code: str | None = None,
    line_number: int | None = None,
) -> AssertionAnalysis:
    """Perform comprehensive analysis of an assertion.

    Args:
        message: The assertion error message
        function_name: Name of the function containing the assertion
        source_code: Optional source code context
        line_number: Optional line number of the assertion

    Returns:
        AssertionAnalysis with context and intentionality determination
    """
    context_type, confidence = analyze_function_name(function_name)

    if source_code:
        src_context, src_confidence = analyze_source_context(source_code, line_number)
        if src_confidence > confidence:
            context_type = src_context
            confidence = src_confidence

    message_lower = message.lower()

    if any(word in message_lower for word in ["required", "mandatory", "must"]):
        if context_type == ContextType.UNKNOWN:
            context_type = ContextType.INPUT_VALIDATION
            confidence = max(confidence, 0.6)

    if any(word in message_lower for word in ["permission", "access", "unauthorized"]):
        context_type = ContextType.PERMISSION_CHECK
        confidence = max(confidence, 0.8)

    is_intentional = context_type != ContextType.UNKNOWN and confidence > 0.5

    return AssertionAnalysis(
        context_type=context_type,
        is_intentional=is_intentional,
        function_purpose=_infer_function_purpose(function_name),
        related_condition=None,
        confidence=confidence,
    )


def _infer_function_purpose(name: str | None) -> str | None:
    """Infer the purpose of a function from its name."""
    if not name:
        return None

    name_lower = name.lower()

    if VALIDATION_FUNCTION_PATTERNS.match(name):
        return "Input validation"

    if SECURITY_FUNCTION_PATTERNS.match(name):
        return "Security/authorization check"

    if "init" in name_lower or "setup" in name_lower:
        return "Initialization"

    if "parse" in name_lower or "process" in name_lower:
        return "Data processing"

    return None


def is_intentional_assertion(
    message: str,
    function_name: str | None = None,
    source_code: str | None = None,
) -> bool:
    """Quick check if an assertion appears to be intentional.

    Args:
        message: The assertion error message
        function_name: Name of the function
        source_code: Optional source context

    Returns:
        True if the assertion appears intentional
    """
    analysis = analyze_assertion(message, function_name, source_code)
    return analysis.is_intentional
