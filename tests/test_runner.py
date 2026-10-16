import sys
import pytest
from marsadix.core.runner import (ToolError, ToolNotFound, parse_json_lines,
                                  run_tool)

PY = sys.executable


def test_run_ok():
    r = run_tool([PY, "-c", "print('hi')"])
    assert r.ok and r.stdout.strip() == "hi"


def test_nonzero_exit_no_check():
    r = run_tool([PY, "-c", "import sys; sys.exit(3)"])
    assert r.returncode == 3 and not r.ok


def test_check_raises():
    with pytest.raises(ToolError):
        run_tool([PY, "-c", "import sys; sys.exit(1)"], check=True)


def test_timeout():
    r = run_tool([PY, "-c", "import time; time.sleep(5)"], timeout=1)
    assert r.timed_out and not r.ok


def test_missing_tool():
    with pytest.raises(ToolNotFound):
        run_tool(["definitely-not-a-real-tool-xyz"])


def test_stdin():
    r = run_tool([PY, "-c", "import sys; print(sys.stdin.read().upper())"], input_text="abc")
    assert r.stdout.strip() == "ABC"


def test_no_shell_injection():
    # ';' must be passed as a literal argument, not interpreted by a shell
    r = run_tool([PY, "-c", "import sys; print(sys.argv[1])", "a; echo pwned"])
    assert r.stdout.strip() == "a; echo pwned"


def test_parse_json_lines():
    text = '{"a":1}\nnot json\n{"b":2}\n{broken\n'
    assert parse_json_lines(text) == [{"a": 1}, {"b": 2}]
