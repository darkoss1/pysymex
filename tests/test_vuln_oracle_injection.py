from pysymex import analyze
from pysymex.analysis.detectors import IssueKind

def test_command_injection_oracle():
    def bug_cmd(x):
        import os
        os.system("echo " + x)
        
    def safe_cmd():
        import os
        os.system("echo hello")
        
    res_bug = analyze(bug_cmd, {"x": "str"})
    issue_bug = res_bug.get_issues_by_kind(IssueKind.COMMAND_INJECTION)
    assert len(issue_bug) > 0, "Should detect command injection when input is symbolic"

    res_safe = analyze(safe_cmd, {})
    issue_safe = res_safe.get_issues_by_kind(IssueKind.COMMAND_INJECTION)
    assert len(issue_safe) == 0, "Should not false positive on exactly concrete commands"

def test_path_traversal_oracle():
    def bug_path(filename):
        with open("/var/log/" + filename, "r") as f:
            return f.read()
            
    res_bug = analyze(bug_path, {"filename": "str"})
    issue_bug = res_bug.get_issues_by_kind(IssueKind.PATH_TRAVERSAL)
    assert len(issue_bug) > 0, "Should detect path traversal strictly"
