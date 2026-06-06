"""Hundred-case symbolic-execution corpus model and factory."""

from __future__ import annotations

import textwrap
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from pysymex.analysis.detectors import IssueKind


@dataclass(frozen=True, slots=True)
class CorpusCase:
    name: str
    source: str
    symbolic_args: Mapping[str, str]
    expected_issue_kinds: frozenset[IssueKind] = frozenset()

    @property
    def expects_clean_run(self) -> bool:
        return not self.expected_issue_kinds


_ANNOTATIONS: Mapping[str, str] = {
    "bool": "bool",
    "dict": "dict[str, int]",
    "float": "float",
    "int": "int",
    "list": "list[int]",
    "none": "object",
    "nullable": "object",
    "object": "object",
    "str": "str",
}


def make_case(
    name: str,
    symbolic_args: Mapping[str, str],
    body: str,
    *,
    expected_issue_kinds: Iterable[IssueKind] = (),
) -> CorpusCase:
    params = ", ".join(
        f"{arg_name}: {_ANNOTATIONS.get(arg_type, 'object')}"
        for arg_name, arg_type in symbolic_args.items()
    )
    normalized_body = textwrap.dedent(body).strip()
    source = f"def {name}({params}) -> object:\n{textwrap.indent(normalized_body, '    ')}\n"
    return CorpusCase(
        name=name,
        source=source,
        symbolic_args=dict(symbolic_args),
        expected_issue_kinds=frozenset(expected_issue_kinds),
    )
