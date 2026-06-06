from pysymex.analysis.domains.strings.analyzer import StringAnalyzer
from pysymex.analysis.domains.strings.security import PathTraversalAnalyzer, SQLInjectionAnalyzer
from pysymex.analysis.domains.strings.types import StringWarningKind


def test_sql_injection_analyzer_warns_on_dynamic_execute_fstring() -> None:
    analyzer = SQLInjectionAnalyzer()

    warnings = analyzer.analyze_source(
        "def find_user(cursor, name):\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
        "db.py",
    )

    assert len(warnings) == 1
    assert warnings[0].kind == StringWarningKind.SQL_INJECTION
    assert warnings[0].file == "db.py"
    assert warnings[0].line == 2
    assert warnings[0].severity == "error"


def test_sql_injection_analyzer_accepts_parameterized_query() -> None:
    analyzer = SQLInjectionAnalyzer()

    warnings = analyzer.analyze_source(
        "def find_user(cursor, name):\n"
        "    cursor.execute('SELECT * FROM users WHERE name = ?', (name,))\n"
    )

    assert warnings == []


def test_path_traversal_analyzer_warns_on_dynamic_parent_directory_open() -> None:
    analyzer = PathTraversalAnalyzer()

    warnings = analyzer.analyze_source(
        'def read_file(name):\n    return open(f"../uploads/{name}").read()\n',
        "files.py",
    )

    assert len(warnings) == 1
    assert warnings[0].kind == StringWarningKind.PATH_TRAVERSAL
    assert warnings[0].file == "files.py"
    assert warnings[0].line == 2
    assert warnings[0].severity == "error"


def test_string_analyzer_includes_security_warnings() -> None:
    analyzer = StringAnalyzer()

    warnings = analyzer.analyze_source(
        'def read_file(name):\n    return open(f"../uploads/{name}").read()\n'
    )

    assert any(warning.kind == StringWarningKind.PATH_TRAVERSAL for warning in warnings)


def test_security_analyzers_return_empty_on_syntax_error() -> None:
    assert SQLInjectionAnalyzer().analyze_source("def broken(:") == []
    assert PathTraversalAnalyzer().analyze_source("def broken(:") == []
