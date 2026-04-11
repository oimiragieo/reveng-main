"""
Unit tests for ClaudeCodeCLIAnalyzer.

All tests mock ``subprocess.run`` — no real ``claude`` CLI invocation is
made. These tests verify the contract expected by
``reveng.verification.refinement.refiner`` (``analyze(prompt) -> object
with .content``) and the error-handling paths documented in
``claude_cli_analyzer.py``.

Run with:
    cd C:/dev/projects/reveng-main && \
        python -m pytest tests/unit/test_claude_cli_analyzer.py -xvs
"""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from reveng.agents.ai.ai_analyzer_enhanced import get_analyzer
from reveng.agents.ai.claude_cli_analyzer import ClaudeCLIResult, ClaudeCodeCLIAnalyzer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_completed(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> MagicMock:
    """Return a fake ``subprocess.CompletedProcess``-like object."""
    completed = MagicMock()
    completed.stdout = stdout
    completed.stderr = stderr
    completed.returncode = returncode
    return completed


def _success_envelope(
    result: str = "refined source code here",
    input_tokens: int = 123,
    output_tokens: int = 456,
    cost: float = 0.00123,
) -> str:
    return json.dumps(
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "result": result,
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            },
            "total_cost_usd": cost,
            "session_id": "test-session",
        }
    )


# ---------------------------------------------------------------------------
# Test 1: successful call returns the refined source
# ---------------------------------------------------------------------------


def test_analyze_returns_refined_source_on_success():
    analyzer = ClaudeCodeCLIAnalyzer()
    stdout = _success_envelope(result="int main(void) { return 42; }")

    with patch(
        "reveng.agents.ai.claude_cli_analyzer.subprocess.run",
        return_value=_make_completed(stdout=stdout),
    ) as mock_run:
        result = analyzer.analyze("please refine this C code")

    assert isinstance(result, ClaudeCLIResult)
    assert result.content == "int main(void) { return 42; }"
    assert mock_run.called


# ---------------------------------------------------------------------------
# Test 2: is_error=True in JSON raises RuntimeError
# ---------------------------------------------------------------------------


def test_analyze_raises_when_is_error_true():
    analyzer = ClaudeCodeCLIAnalyzer()
    envelope = json.dumps(
        {
            "is_error": True,
            "error": "context length exceeded",
            "result": "context length exceeded",
        }
    )

    with patch(
        "reveng.agents.ai.claude_cli_analyzer.subprocess.run",
        return_value=_make_completed(stdout=envelope),
    ):
        with pytest.raises(RuntimeError, match="is_error=true"):
            analyzer.analyze("prompt")


# ---------------------------------------------------------------------------
# Test 3: non-zero returncode raises RuntimeError
# ---------------------------------------------------------------------------


def test_analyze_raises_on_nonzero_returncode():
    analyzer = ClaudeCodeCLIAnalyzer()

    with patch(
        "reveng.agents.ai.claude_cli_analyzer.subprocess.run",
        return_value=_make_completed(
            stdout="",
            stderr="claude: not authenticated",
            returncode=1,
        ),
    ):
        with pytest.raises(RuntimeError, match="exited with code 1"):
            analyzer.analyze("prompt")


# ---------------------------------------------------------------------------
# Test 4: subprocess.TimeoutExpired raises RuntimeError
# ---------------------------------------------------------------------------


def test_analyze_raises_on_timeout():
    analyzer = ClaudeCodeCLIAnalyzer(timeout_seconds=5)

    with patch(
        "reveng.agents.ai.claude_cli_analyzer.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="claude", timeout=5),
    ):
        with pytest.raises(RuntimeError, match="timed out after 5s"):
            analyzer.analyze("prompt")


# ---------------------------------------------------------------------------
# Test 5: result field is extracted correctly from JSON envelope
# ---------------------------------------------------------------------------


def test_analyze_extracts_result_and_usage_fields():
    analyzer = ClaudeCodeCLIAnalyzer()
    stdout = _success_envelope(
        result="// refined\nint f(void){return 1;}",
        input_tokens=111,
        output_tokens=222,
        cost=0.042,
    )

    with patch(
        "reveng.agents.ai.claude_cli_analyzer.subprocess.run",
        return_value=_make_completed(stdout=stdout),
    ):
        result = analyzer.analyze("prompt")

    assert result.content == "// refined\nint f(void){return 1;}"
    assert result.usage.input_tokens == 111
    assert result.usage.output_tokens == 222
    assert result.tokens_used == 333
    assert result.cost_usd == 0.042


# ---------------------------------------------------------------------------
# Test 6: get_analyzer("claude-cli") returns ClaudeCodeCLIAnalyzer
# ---------------------------------------------------------------------------


def test_get_analyzer_claude_cli_returns_cli_analyzer():
    instance = get_analyzer("claude-cli")
    assert isinstance(instance, ClaudeCodeCLIAnalyzer)


# ---------------------------------------------------------------------------
# Test 7: get_analyzer("claude-code") alias also works
# ---------------------------------------------------------------------------


def test_get_analyzer_claude_code_alias_works():
    instance_hyphen = get_analyzer("claude-code")
    instance_under = get_analyzer("claude_code")
    assert isinstance(instance_hyphen, ClaudeCodeCLIAnalyzer)
    assert isinstance(instance_under, ClaudeCodeCLIAnalyzer)


# ---------------------------------------------------------------------------
# Test 8: subprocess is invoked with shell=False (security requirement)
# ---------------------------------------------------------------------------


def test_analyze_invokes_subprocess_with_shell_false():
    analyzer = ClaudeCodeCLIAnalyzer()
    stdout = _success_envelope()

    with patch(
        "reveng.agents.ai.claude_cli_analyzer.subprocess.run",
        return_value=_make_completed(stdout=stdout),
    ) as mock_run:
        analyzer.analyze("some prompt")

    assert mock_run.call_count == 1
    _args, kwargs = mock_run.call_args
    assert kwargs.get("shell") is False
    assert kwargs.get("capture_output") is True
    assert kwargs.get("text") is True
    # First positional arg should be a list (argv), not a string
    argv = mock_run.call_args.args[0]
    assert isinstance(argv, list)
    # On Windows the .CMD shim is wrapped: ["cmd", "/c", "<path>/claude.CMD", ...]
    # On other platforms argv[0] is the direct claude path.
    assert any("claude" in a.lower() for a in argv)  # full path resolved via shutil.which
    assert "--bare" in argv
    assert "-p" in argv
    # The prompt must be the final element
    assert argv[-1] == "some prompt"
