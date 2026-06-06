"""Clean hundred-case symbolic-execution corpus generators."""

from __future__ import annotations

from tests.unit.repro.hundred_case_corpus_model import CorpusCase, make_case


def clean_nonzero_division_cases() -> list[CorpusCase]:
    return [
        make_case(
            f"clean_nonzero_division_{index}",
            {"x": "int"},
            f"""
            if x == {index}:
                return 100 // (x - {index} + 1)
            return 1
            """,
        )
        for index in range(10)
    ]


def clean_guarded_list_cases() -> list[CorpusCase]:
    return [
        make_case(
            f"clean_guarded_list_index_{index}",
            {"i": "int"},
            f"""
            values = [{index}, {index + 1}, {index + 2}]
            if i >= 0 and i < 3:
                return values[i]
            return values[0]
            """,
        )
        for index in range(10)
    ]


def clean_dict_cases() -> list[CorpusCase]:
    return [
        make_case(
            f"clean_dict_get_default_{index}",
            {"flag": "int"},
            f"""
            values = {{"present": {index}}}
            if flag > {index}:
                return values.get("missing", {index})
            return values["present"]
            """,
        )
        for index in range(10)
    ]


def clean_arithmetic_branch_cases() -> list[CorpusCase]:
    return [
        make_case(
            f"clean_arithmetic_branch_{index}",
            {"x": "int", "y": "int"},
            f"""
            if x > {index} and y < {index + 5}:
                return (x + y) - {index}
            return (x - y) + {index}
            """,
        )
        for index in range(10)
    ]


def clean_fixed_loop_cases() -> list[CorpusCase]:
    return [
        make_case(
            f"clean_fixed_loop_{index}",
            {"x": "int"},
            f"""
            total = 0
            for value in range({index % 4 + 1}):
                total += value
            if x > {index}:
                return total + x
            return total - x
            """,
        )
        for index in range(10)
    ]
