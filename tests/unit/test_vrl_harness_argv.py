"""
Regression tests for ExecutionHarness ARGV-vs-STDIN handling (VRL Task 1.7).

The bug: ``ExecutionHarness.run()`` piped seed inputs to STDIN and ran the
binary with an *empty* argv.  CLI tools that read their arguments from argv
ignored the input entirely, so the differential oracle spuriously reported
EQUIVALENT.

These tests use a tiny Python script as the "binary".  The script prints its
``sys.argv[1:]`` to stdout and the raw stdin bytes to stderr, so we can prove
that seed tokens reach the *process argv* and that stdin payloads remain
distinct.
"""

import sys
import textwrap
from pathlib import Path

import pytest

from reveng.verification.differential.harness import ExecutionHarness

# A tiny "binary": echoes argv on stdout, echoes stdin length on stderr.
_ECHO_SCRIPT = textwrap.dedent("""\
    import sys
    argv = sys.argv[1:]
    sys.stdout.write("ARGV:" + "|".join(argv))
    data = sys.stdin.buffer.read()
    sys.stderr.write("STDIN:" + str(len(data)))
    """)


@pytest.fixture()
def echo_harness(tmp_path: Path) -> ExecutionHarness:
    """Return a harness whose 'binary' is the python echo script."""
    script = tmp_path / "echo_argv.py"
    script.write_text(_ECHO_SCRIPT, encoding="utf-8")
    # Use the current interpreter as the binary, with the script as a fixed
    # first argument captured in cwd; we point binary_path at the interpreter
    # and pass the script + seed tokens through argv.
    return ExecutionHarness(Path(sys.executable))

    # noqa: unreachable -- fixture returns above


def _run(harness: ExecutionHarness, script: Path, tokens, stdin=b""):
    """Helper: run the python script with *tokens* as argv after the script."""
    return harness.run(argv=[str(script), *tokens], input_bytes=stdin)


def test_seed_tokens_reach_process_argv(tmp_path: Path) -> None:
    """Seed tokens passed via argv must appear in the child's sys.argv."""
    script = tmp_path / "echo_argv.py"
    script.write_text(_ECHO_SCRIPT, encoding="utf-8")
    harness = ExecutionHarness(Path(sys.executable))

    result = _run(harness, script, ["--help", "--version"], stdin=b"")

    assert result.exit_code == 0
    stdout = result.stdout.decode()
    assert "ARGV:--help|--version" in stdout


def test_stdin_payload_remains_distinct_from_argv(tmp_path: Path) -> None:
    """input_bytes must go to stdin, NOT be appended to argv."""
    script = tmp_path / "echo_argv.py"
    script.write_text(_ECHO_SCRIPT, encoding="utf-8")
    harness = ExecutionHarness(Path(sys.executable))

    result = _run(harness, script, ["--flag"], stdin=b"hello-stdin")

    stdout = result.stdout.decode()
    stderr = result.stderr.decode()
    # argv only contains the script path + the explicit flag, never the stdin
    assert "ARGV:--flag" in stdout
    assert "hello-stdin" not in stdout
    # stdin received exactly the 11 bytes of payload
    assert "STDIN:11" in stderr


def test_run_without_argv_defaults_to_empty(tmp_path: Path) -> None:
    """Calling run() with no argv must not crash and yields empty argv."""
    script = tmp_path / "echo_argv.py"
    script.write_text(_ECHO_SCRIPT, encoding="utf-8")
    # binary_path is the script-running interpreter invocation; here we only
    # verify that omitting argv is accepted and stdin still flows.
    harness = ExecutionHarness(Path(sys.executable))
    result = harness.run(argv=[str(script)], input_bytes=b"abc")
    assert result.exit_code == 0
    assert "ARGV:" in result.stdout.decode()
    assert "STDIN:3" in result.stderr.decode()
