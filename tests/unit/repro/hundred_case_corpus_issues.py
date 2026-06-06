"""Buggy hundred-case symbolic-execution corpus generators."""

from __future__ import annotations

from pysymex.analysis.detectors import IssueKind

from tests.unit.repro.hundred_case_corpus_model import CorpusCase, make_case


def division_issue_cases() -> list[CorpusCase]:
    return [
        make_case(
            f"bug_floor_division_zero_{index}",
            {"x": "int"},
            f"""
            if x == {index}:
                return 100 // (x - {index})
            return 1
            """,
            expected_issue_kinds=[IssueKind.DIVISION_BY_ZERO],
        )
        for index in range(12)
    ]


def modulo_and_true_division_issue_cases() -> list[CorpusCase]:
    cases: list[CorpusCase] = []
    for index in range(4):
        cases.append(
            make_case(
                f"bug_modulo_zero_{index}",
                {"x": "int"},
                f"""
                if x == {index}:
                    return 100 % (x - {index})
                return 1
                """,
                expected_issue_kinds=[IssueKind.MODULO_BY_ZERO],
            )
        )
    for index in range(4):
        cases.append(
            make_case(
                f"bug_true_division_zero_{index}",
                {"x": "int"},
                f"""
                if x == {index}:
                    return 100.0 / (x - {index})
                return 1.0
                """,
                expected_issue_kinds=[IssueKind.DIVISION_BY_ZERO],
            )
        )
    return cases


def positive_index_issue_cases() -> list[CorpusCase]:
    return [
        make_case(
            f"bug_positive_index_{index}",
            {"i": "int"},
            f"""
            values = [1, 2, 3]
            if i >= {index + 3}:
                return values[i - {index}]
            return values[0]
            """,
            expected_issue_kinds=[IssueKind.INDEX_ERROR],
        )
        for index in range(10)
    ]


def negative_index_issue_cases() -> list[CorpusCase]:
    return [
        make_case(
            f"bug_negative_index_{index}",
            {"i": "int"},
            f"""
            values = [1, 2, 3]
            if i < {-index - 3}:
                return values[i + {index}]
            return values[0]
            """,
            expected_issue_kinds=[IssueKind.INDEX_ERROR],
        )
        for index in range(5)
    ]


def key_issue_cases() -> list[CorpusCase]:
    return [
        make_case(
            f"bug_missing_dict_key_{index}",
            {"flag": "int"},
            f"""
            values = {{"present": {index}}}
            if flag == {index}:
                return values["missing_{index}"]
            return values["present"]
            """,
            expected_issue_kinds=[IssueKind.KEY_ERROR],
        )
        for index in range(8)
    ]


def none_issue_cases() -> list[CorpusCase]:
    cases: list[CorpusCase] = []
    for index in range(2):
        cases.append(
            make_case(
                f"bug_none_attribute_{index}",
                {"flag": "int"},
                f"""
                value = None
                if flag == {index}:
                    return value.missing
                return 0
                """,
                expected_issue_kinds=[IssueKind.NULL_DEREFERENCE],
            )
        )
    for index in range(2):
        cases.append(
            make_case(
                f"bug_none_subscript_{index}",
                {"flag": "int"},
                f"""
                value = None
                if flag == {index}:
                    return value[0]
                return 0
                """,
                expected_issue_kinds=[IssueKind.NULL_DEREFERENCE],
            )
        )
    return cases


def type_issue_cases() -> list[CorpusCase]:
    return [
        make_case(
            "bug_int_plus_string",
            {"x": "int"},
            """
            if x > 0:
                return x + "suffix"
            return x
            """,
            expected_issue_kinds=[IssueKind.TYPE_ERROR],
        ),
        make_case(
            "bug_string_minus_int",
            {"x": "int"},
            """
            if x > 0:
                return "prefix" - x
            return x
            """,
            expected_issue_kinds=[IssueKind.TYPE_ERROR],
        ),
    ]


def assertion_issue_cases() -> list[CorpusCase]:
    return [
        make_case(
            "bug_explicit_assertion",
            {"x": "int"},
            """
            if x == 13:
                raise AssertionError("hundred-case assertion")
            return x
            """,
            expected_issue_kinds=[IssueKind.ASSERTION_ERROR],
        )
    ]
