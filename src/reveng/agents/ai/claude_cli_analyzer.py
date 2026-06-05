"""
LLM provider that calls the Claude Code CLI (``claude -p``) as a subprocess.

Uses the existing Claude Code OAuth subscription session — no
``ANTHROPIC_API_KEY`` required. This is a drop-in provider for the VRL
iterative refinement loop, which expects an object with an
``analyze(prompt: str)`` method returning a result object with a
``.content`` attribute (and optional ``.usage`` / ``.tokens_used``).

The refiner interface contract (see ``reveng.verification.refinement.refiner``
and ``refiner._count_tokens``):

    result = analyzer.analyze(prompt)        # str -> Result-like
    text   = result.content                  # str
    tokens = result.usage.input_tokens +\
             result.usage.output_tokens      # optional
    # or result.tokens_used                  # optional fallback

This module implements that contract via a subprocess.run call to the
``claude`` CLI in headless / bare mode so that no hooks, MCP servers,
CLAUDE.md, or memory files are injected into the prompt.
"""

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Headless invocation flags (source: headless-ai-cli/tools/major/claude.md)
# ---------------------------------------------------------------------------

_CLAUDE_CMD = [
    "claude",
    "--output-format",
    "json",
    "--model",
    "sonnet",
    "--permission-mode",
    "bypassPermissions",
    # NOTE: --bare was removed. In claude-code v2, --bare triggers D9()=true which
    # makes s7() return null unconditionally, bypassing ALL credential loading
    # (OAuth, CLAUDE_CODE_OAUTH_TOKEN, and API key env vars). The result is always
    # "Not logged in" regardless of ~/.claude/.credentials.json content.
    # Isolation is achieved instead via:
    #   --no-session-persistence  (no session state written/read)
    #   CLAUDE_CODE_DISABLE_CLAUDE_MDS=1  (env var, set in analyze(), skips CLAUDE.md)
    "--no-session-persistence",
    "--max-turns",
    "1",  # single-turn only — no agentic loops
    "-p",  # prompt follows as next arg
]

_TIMEOUT_SECONDS = 120


# ---------------------------------------------------------------------------
# Result objects (duck-typed to satisfy refiner._count_tokens)
# ---------------------------------------------------------------------------


@dataclass
class _Usage:
    """Lightweight usage object exposing ``input_tokens`` / ``output_tokens``."""

    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class ClaudeCLIResult:
    """
    Result of a single ``claude -p`` invocation.

    Shape contract:
      - ``content``: the text of Claude's response (or ``result`` field from JSON)
      - ``usage``: optional object with ``input_tokens`` / ``output_tokens``
      - ``tokens_used``: optional flat token count (fallback path)
      - ``cost_usd``: optional cost in USD (from ``total_cost_usd`` field)
      - ``raw``: the parsed JSON envelope for debugging
    """

    content: str
    usage: _Usage = field(default_factory=_Usage)
    tokens_used: int = 0
    cost_usd: float = 0.0
    raw: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# The analyzer
# ---------------------------------------------------------------------------


class ClaudeCodeCLIAnalyzer:
    """
    OAuth-based LLM provider that shells out to the ``claude`` CLI.

    Intended as a drop-in ``analyzer`` for the VRL IterativeRefiner. The
    refiner only calls ``analyzer.analyze(prompt)`` and reads
    ``result.content``, so only that interface is implemented here.

    This class exists specifically to bypass the ``ANTHROPIC_API_KEY``
    requirement of ``AnthropicAnalyzer`` — it uses the existing Claude
    Code OAuth subscription session instead.
    """

    def __init__(
        self,
        timeout_seconds: int = _TIMEOUT_SECONDS,
        cmd: Optional[list] = None,
    ) -> None:
        """
        Initialize the analyzer.

        Args:
            timeout_seconds:
                Per-call subprocess timeout. Defaults to 120 s.
            cmd:
                Optional override of the base command list. Primarily for
                tests. Must NOT include the prompt argument itself — the
                prompt is appended per-call.
        """
        self.timeout_seconds = timeout_seconds
        self._cmd = list(cmd) if cmd is not None else list(_CLAUDE_CMD)
        # Deviation DR-1: resolve `claude` to its full path so subprocess.run
        # with shell=False works on Windows where `claude` is a .CMD shim.
        if self._cmd and self._cmd[0] == "claude":
            resolved = shutil.which("claude")
            if resolved:
                self._cmd[0] = resolved
        # Windows: .CMD/.BAT shims cannot be directly exec'd with shell=False
        if os.name == "nt" and self._cmd and self._cmd[0].lower().endswith((".cmd", ".bat")):
            self._cmd = ["cmd", "/c"] + self._cmd
        logger.info(
            "ClaudeCodeCLIAnalyzer ready: timeout=%ds cmd=%s",
            self.timeout_seconds,
            " ".join(self._cmd),
        )

    # ------------------------------------------------------------------
    # Public interface — matches what refiner.py calls
    # ------------------------------------------------------------------

    def analyze(self, prompt: str) -> ClaudeCLIResult:
        """
        Send ``prompt`` to the ``claude`` CLI and return a structured result.

        Args:
            prompt: The full prompt text (C source + divergence info, as
                    assembled by ``build_refinement_prompt``).

        Returns:
            A ``ClaudeCLIResult`` exposing ``.content`` (str), ``.usage``,
            ``.tokens_used``, and ``.cost_usd``.

        Raises:
            RuntimeError:
                When the CLI exits non-zero, times out, returns malformed
                JSON, or returns an error envelope (``is_error == True``).
        """
        argv = self._cmd + [prompt]

        # Inject CLAUDE_CODE_DISABLE_CLAUDE_MDS=1 so the subprocess does not
        # load CLAUDE.md files from the working directory or parent dirs.
        # This replaces the context-isolation previously provided by --bare
        # (which was removed because it also disables credential loading in v2).
        env = os.environ.copy()
        env["CLAUDE_CODE_DISABLE_CLAUDE_MDS"] = "1"

        try:
            completed = subprocess.run(  # noqa: S603  (shell=False, argv list)
                argv,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            msg = (
                f"claude CLI timed out after {self.timeout_seconds}s "
                f"(prompt length={len(prompt)})"
            )
            logger.error(msg)
            raise RuntimeError(msg) from exc
        except FileNotFoundError as exc:
            msg = (
                "claude CLI binary not found on PATH. Install Claude Code "
                "and ensure `claude` is executable from the shell."
            )
            logger.error(msg)
            raise RuntimeError(msg) from exc

        if completed.returncode != 0:
            msg = (
                f"claude CLI exited with code {completed.returncode}: "
                f"{(completed.stderr or '').strip()[:500]}"
            )
            logger.error(msg)
            raise RuntimeError(msg)

        stdout = completed.stdout or ""
        try:
            envelope = json.loads(stdout)
        except json.JSONDecodeError as exc:
            msg = f"claude CLI returned non-JSON stdout: " f"{stdout[:300]!r} (err={exc})"
            logger.error(msg)
            raise RuntimeError(msg) from exc

        if not isinstance(envelope, dict):
            msg = f"claude CLI JSON was not an object: {type(envelope).__name__}"
            logger.error(msg)
            raise RuntimeError(msg)

        if envelope.get("is_error") is True:
            err_msg = envelope.get("error") or envelope.get("result") or "unknown error"
            msg = f"claude CLI reported is_error=true: {err_msg}"
            logger.error(msg)
            raise RuntimeError(msg)

        result_text = envelope.get("result")
        if not isinstance(result_text, str):
            msg = (
                f"claude CLI JSON missing 'result' string field " f"(keys={list(envelope.keys())})"
            )
            logger.error(msg)
            raise RuntimeError(msg)

        # ------- token / cost telemetry (best-effort) -------
        usage_raw = envelope.get("usage") or {}
        input_tokens = int(usage_raw.get("input_tokens", 0) or 0)
        output_tokens = int(usage_raw.get("output_tokens", 0) or 0)
        total_tokens = input_tokens + output_tokens

        cost_usd = float(envelope.get("total_cost_usd", 0.0) or 0.0)
        if cost_usd:
            logger.info(
                "claude CLI call: tokens_in=%d tokens_out=%d cost_usd=%.4f",
                input_tokens,
                output_tokens,
                cost_usd,
            )
        else:
            logger.debug(
                "claude CLI call: tokens_in=%d tokens_out=%d",
                input_tokens,
                output_tokens,
            )

        return ClaudeCLIResult(
            content=result_text,
            usage=_Usage(input_tokens=input_tokens, output_tokens=output_tokens),
            tokens_used=total_tokens,
            cost_usd=cost_usd,
            raw=envelope,
        )
