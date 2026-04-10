"""
Subprocess-based execution harness for differential binary testing.

Runs a binary with provided stdin bytes and captures stdout / stderr /
exit-code within a wall-clock deadline.  All process spawning uses
``shell=False`` to prevent shell injection (see SE-03 in project safety rules).
"""

import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExecutionResult:
    """Captured result from running a binary once."""

    stdout: bytes
    stderr: bytes
    exit_code: int
    elapsed_seconds: float
    timed_out: bool

    def __repr__(self) -> str:
        return (
            f"ExecutionResult("
            f"exit_code={self.exit_code}, "
            f"timed_out={self.timed_out}, "
            f"stdout_len={len(self.stdout)}, "
            f"elapsed={self.elapsed_seconds:.3f}s)"
        )


class HarnessError(RuntimeError):
    """Raised when the harness cannot launch the target binary."""


class ExecutionHarness:
    """
    Thin subprocess wrapper that runs a binary with stdin input.

    Parameters
    ----------
    binary_path:
        Absolute (or PATH-resolvable) path to the executable.
    timeout_seconds:
        Wall-clock deadline per invocation.  Defaults to 5 seconds.
    env:
        Optional environment variable override dict.  ``None`` inherits the
        current process environment.
    cwd:
        Working directory for the child process.  ``None`` inherits the
        current working directory.
    """

    def __init__(
        self,
        binary_path: Path,
        timeout_seconds: float = 5.0,
        env: Optional[dict] = None,
        cwd: Optional[Path] = None,
    ) -> None:
        self._binary_path = Path(binary_path)
        self._timeout = timeout_seconds
        self._env = env
        self._cwd = cwd

    @property
    def binary_path(self) -> Path:
        return self._binary_path

    @property
    def timeout_seconds(self) -> float:
        return self._timeout

    def run(self, input_bytes: bytes) -> ExecutionResult:
        """
        Execute the binary with *input_bytes* on stdin.

        Returns an :class:`ExecutionResult`.  Never raises on normal
        execution failures (non-zero exit, timeout) — those are encoded in
        the result.  *Does* raise :class:`HarnessError` when the binary
        cannot be launched (missing file, bad permissions).

        Parameters
        ----------
        input_bytes:
            Raw bytes written to the child process stdin.
        """
        t0 = time.monotonic()

        try:
            proc = subprocess.run(
                [str(self._binary_path)],
                input=input_bytes,
                capture_output=True,
                timeout=self._timeout,
                shell=False,  # NEVER shell=True (security rule)
                env=self._env,
                cwd=self._cwd,
            )
            elapsed = time.monotonic() - t0
            return ExecutionResult(
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
                elapsed_seconds=elapsed,
                timed_out=False,
            )

        except subprocess.TimeoutExpired as exc:
            elapsed = time.monotonic() - t0
            logger.debug("Binary %s timed out after %.1fs", self._binary_path, elapsed)
            # Drain whatever partial output is available
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            return ExecutionResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=-1,
                elapsed_seconds=elapsed,
                timed_out=True,
            )

        except FileNotFoundError:
            raise HarnessError(
                f"Binary not found: {self._binary_path!s}. "
                "Ensure the path points to an executable file."
            )

        except PermissionError:
            raise HarnessError(
                f"Permission denied launching: {self._binary_path!s}. "
                "Check file permissions (chmod +x) before running the harness."
            )
