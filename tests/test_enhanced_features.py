import pytest

from pysymex.analysis.type_inference import PyType, TypeKind

from pysymex.reporting.sarif import generate_sarif


def test_pytype_enhancements():
    t = PyType(kind=TypeKind.LIST, length=10)

    assert t.length == 10

    t = PyType(kind=TypeKind.DICT, known_keys={"a": PyType.int_type()})

    assert "a" in t.known_keys

    assert t.known_keys["a"].kind == TypeKind.INT

    t = PyType(kind=TypeKind.INT, value_constraints={"min": 0, "max": 100})

    assert t.value_constraints["min"] == 0

    t1 = PyType(kind=TypeKind.INT, length=5)

    t2 = PyType(kind=TypeKind.INT, length=5)

    t3 = PyType(kind=TypeKind.INT, length=10)

    assert t1 == t2

    assert t1 != t3

    assert hash(t1) == hash(t2)

    assert hash(t1) != hash(t3)


def test_sarif_generation():
    issues = [
        {
            "kind": "DIVISION_BY_ZERO",
            "severity": "ERROR",
            "file": "test.py",
            "line": 10,
            "message": "Division by zero",
            "confidence": 1.0,
        },
        {
            "kind": "UNUSED_VARIABLE",
            "severity": "warning",
            "file": "test.py",
            "line": 5,
            "message": "Unused var",
            "confidence": 0.9,
        },
    ]

    sarif_log = generate_sarif(issues=issues)

    sarif_json = sarif_log.to_json()

    assert "SVM010" in sarif_json

    assert "SVM013" in sarif_json

    assert "test.py" in sarif_json

    assert '"startLine": 10' in sarif_json

    assert '"startLine": 5' in sarif_json


if __name__ == "__main__":
    test_pytype_enhancements()

    test_sarif_generation()

    print("All tests passed!")
