"""Reporting module for pysymex.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.
"""

from __future__ import annotations

from importlib import import_module

_EXPORTS: dict[str, tuple[str, str]] = {
    "Formatter": ("pysymex.reporting.formatters", "Formatter"),
    "HTMLFormatter": ("pysymex.reporting.formatters", "HTMLFormatter"),
    "JSONFormatter": ("pysymex.reporting.formatters", "JSONFormatter"),
    "MarkdownFormatter": ("pysymex.reporting.formatters", "MarkdownFormatter"),
    "TextFormatter": ("pysymex.reporting.formatters", "TextFormatter"),
    "format_result": ("pysymex.reporting.formatters", "format_result"),
    "AnalysisReport": ("pysymex.reporting.html_report", "AnalysisReport"),
    "IssueReport": ("pysymex.reporting.html_report", "IssueReport"),
    "create_report_from_result": ("pysymex.reporting.html_report", "create_report_from_result"),
    "generate_html_report": ("pysymex.reporting.html_report", "generate_html_report"),
    "save_html_report": ("pysymex.reporting.html_report", "save_html_report"),
    "SECURITY_RULES": ("pysymex.reporting.sarif", "SECURITY_RULES"),
    "SARIFGenerator": ("pysymex.reporting.sarif", "SARIFGenerator"),
    "SARIFLog": ("pysymex.reporting.sarif", "SARIFLog"),
    "SARIFResult": ("pysymex.reporting.sarif", "SARIFResult"),
    "generate_sarif": ("pysymex.reporting.sarif", "generate_sarif"),
}


def __getattr__(name: str) -> object:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pysymex.reporting' has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return list(_EXPORTS.keys())


__all__: list[str] = [
    "SECURITY_RULES",
    "AnalysisReport",
    "Formatter",
    "HTMLFormatter",
    "IssueReport",
    "JSONFormatter",
    "MarkdownFormatter",
    "SARIFGenerator",
    "SARIFLog",
    "SARIFResult",
    "TextFormatter",
    "create_report_from_result",
    "format_result",
    "generate_html_report",
    "generate_sarif",
    "save_html_report",
]
