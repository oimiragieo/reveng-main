"""
Unit tests for reveng.verification.refinement.compile_adapter.

All subprocess calls are mocked — no real compilation occurs.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest

from reveng.verification.refinement.compile_adapter import make_compile_fn

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SIMPLE_SOURCE = "#include <stdio.h>\nint main(void) { return 0; }\n"


def _md5_hash(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()


def _successful_run() -> MagicMock:
    """Return a mock CompletedProcess that signals success."""
    result = MagicMock(spec=subprocess.CompletedProcess)
    result.returncode = 0
    result.stderr = b""
    return result


def _output_path_from_cmd(cmd) -> Path:
    """Extract the compiler's intended output binary path from *cmd*."""
    if "-o" in cmd:
        return Path(cmd[cmd.index("-o") + 1])
    for token in cmd:
        if token.startswith("/Fe"):  # MSVC
            return Path(token[len("/Fe") :])
    raise AssertionError(f"No output path found in compiler cmd: {cmd}")


def _compile_ok(cmd, **kwargs) -> MagicMock:
    """
    side_effect mimicking a real successful compiler invocation.

    A real compiler writes the output binary to disk; the compile_adapter now
    asserts that the artifact exists after returncode==0 (freshness guard), so
    the mock must create the file to faithfully emulate success.
    """
    out = _output_path_from_cmd(cmd)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"\x7fELF-mock-binary")
    return _successful_run()


def _failed_run(stderr: bytes = b"compilation failed") -> MagicMock:
    result = MagicMock(spec=subprocess.CompletedProcess)
    result.returncode = 1
    result.stderr = stderr
    return result


# ---------------------------------------------------------------------------
# Test 1 — make_compile_fn returns a callable
# ---------------------------------------------------------------------------


def test_make_compile_fn_returns_callable():
    fn = make_compile_fn()
    assert callable(fn), "make_compile_fn() must return a callable"


# ---------------------------------------------------------------------------
# Test 2 — calling the fn writes the .c file and invokes a compiler
# ---------------------------------------------------------------------------


def test_compile_fn_writes_source_file_and_calls_compiler(tmp_path):
    with patch("subprocess.run", side_effect=_compile_ok) as mock_run:
        fn = make_compile_fn(workspace_dir=tmp_path)
        binary = fn(_SIMPLE_SOURCE)

        # subprocess.run should have been called at least once
        assert mock_run.called, "subprocess.run was not called"

        # The source file should exist on disk
        short_hash = _md5_hash(_SIMPLE_SOURCE)[:8]
        src_file = tmp_path / f"vrl_source_{short_hash}.c"
        assert src_file.exists(), f"Expected source file {src_file} was not created"

        # The returned path should point to the expected binary
        suffix = ".exe" if sys.platform == "win32" else ""
        expected_binary = tmp_path / f"vrl_binary_{short_hash}{suffix}"
        assert binary == expected_binary


# ---------------------------------------------------------------------------
# Test 3 — returns a Path to the binary
# ---------------------------------------------------------------------------


def test_compile_fn_returns_path_object(tmp_path):
    with patch("subprocess.run", side_effect=_compile_ok):
        fn = make_compile_fn(workspace_dir=tmp_path)
        result = fn(_SIMPLE_SOURCE)
        assert isinstance(result, Path), f"Expected Path, got {type(result)}"


# ---------------------------------------------------------------------------
# Test 4 — filename determinism: same source → same filename
# ---------------------------------------------------------------------------


def test_compile_fn_same_source_same_filename(tmp_path):
    with patch("subprocess.run", side_effect=_compile_ok):
        fn = make_compile_fn(workspace_dir=tmp_path)
        path_a = fn(_SIMPLE_SOURCE)
        path_b = fn(_SIMPLE_SOURCE)
        assert path_a == path_b, "Same source must yield identical binary path"


# ---------------------------------------------------------------------------
# Test 5 — filename determinism: different source → different filename
# ---------------------------------------------------------------------------


def test_compile_fn_different_source_different_filename(tmp_path):
    other_source = "#include <stdlib.h>\nint main(void) { return 1; }\n"
    with patch("subprocess.run", side_effect=_compile_ok):
        fn = make_compile_fn(workspace_dir=tmp_path)
        path_a = fn(_SIMPLE_SOURCE)
        path_b = fn(other_source)
        assert path_a != path_b, "Different sources must yield different binary paths"


# ---------------------------------------------------------------------------
# Test 6 — workspace_dir=None uses system temp directory
# ---------------------------------------------------------------------------


def test_compile_fn_uses_system_temp_when_workspace_dir_is_none():
    import tempfile

    with patch("subprocess.run", side_effect=_compile_ok):
        fn = make_compile_fn(workspace_dir=None)
        result = fn(_SIMPLE_SOURCE)

        # The parent directory should be the system temp dir
        assert result.parent == Path(
            tempfile.gettempdir()
        ), f"Expected parent {Path(tempfile.gettempdir())}, got {result.parent}"


# ---------------------------------------------------------------------------
# Test 7 — workspace_dir=specific_path uses that directory
# ---------------------------------------------------------------------------


def test_compile_fn_uses_given_workspace_dir(tmp_path):
    custom_dir = tmp_path / "my_workspace"
    with patch("subprocess.run", side_effect=_compile_ok):
        fn = make_compile_fn(workspace_dir=custom_dir)
        result = fn(_SIMPLE_SOURCE)
        assert result.parent == custom_dir, f"Expected parent {custom_dir}, got {result.parent}"


# ---------------------------------------------------------------------------
# Test 8 — SmartCompiler (subprocess) exception propagates unchanged
# ---------------------------------------------------------------------------


def test_compile_fn_propagates_runtime_error_when_all_compilers_fail(tmp_path):
    # All compilers return non-zero
    with patch("subprocess.run", return_value=_failed_run(b"fatal error")):
        fn = make_compile_fn(workspace_dir=tmp_path)
        with pytest.raises(RuntimeError, match="All compilers failed"):
            fn(_SIMPLE_SOURCE)


# ---------------------------------------------------------------------------
# Test 9 — binary path has .exe suffix on Windows (mock sys.platform)
# ---------------------------------------------------------------------------


def test_compile_fn_binary_has_exe_suffix_on_windows(tmp_path):
    with patch("subprocess.run", side_effect=_compile_ok):
        with patch("reveng.verification.refinement.compile_adapter.sys") as mock_sys:
            mock_sys.platform = "win32"
            fn = make_compile_fn(workspace_dir=tmp_path)
            result = fn(_SIMPLE_SOURCE)
            assert result.suffix == ".exe", f"Expected .exe suffix on win32, got {result.suffix}"


# ---------------------------------------------------------------------------
# Test 10 — source file content matches what was passed in
# ---------------------------------------------------------------------------


def test_compile_fn_source_file_content_matches_input(tmp_path):
    with patch("subprocess.run", side_effect=_compile_ok):
        fn = make_compile_fn(workspace_dir=tmp_path)
        fn(_SIMPLE_SOURCE)

        short_hash = _md5_hash(_SIMPLE_SOURCE)[:8]
        src_file = tmp_path / f"vrl_source_{short_hash}.c"
        written = src_file.read_text(encoding="utf-8")
        assert written == _SIMPLE_SOURCE, "Source file content must exactly match input"


# ---------------------------------------------------------------------------
# Test 11 — fallback: gcc not found, clang succeeds
# ---------------------------------------------------------------------------


def test_compile_fn_falls_back_to_clang_when_gcc_not_found(tmp_path):
    def side_effect(cmd, **kwargs):
        compiler = cmd[0]
        if compiler == "gcc":
            raise FileNotFoundError("gcc not found")
        # clang succeeds — emulate a real compiler by writing the artifact.
        return _compile_ok(cmd, **kwargs)

    with patch("subprocess.run", side_effect=side_effect) as mock_run:
        fn = make_compile_fn(workspace_dir=tmp_path)
        result = fn(_SIMPLE_SOURCE)

        # Verify clang was called
        calls = mock_run.call_args_list
        compilers_tried = [c.args[0][0] if c.args else c.kwargs["cmd"][0] for c in calls]
        assert "clang" in compilers_tried, "Expected clang to be tried in fallback"
        assert isinstance(result, Path)


# ---------------------------------------------------------------------------
# Test 12 — workspace_dir is created if it does not exist
# ---------------------------------------------------------------------------


def test_compile_fn_creates_workspace_dir_if_missing(tmp_path):
    new_dir = tmp_path / "does" / "not" / "exist"
    assert not new_dir.exists(), "Precondition: directory must not exist yet"
    with patch("subprocess.run", side_effect=_compile_ok):
        fn = make_compile_fn(workspace_dir=new_dir)
        fn(_SIMPLE_SOURCE)
    assert new_dir.exists(), "make_compile_fn must create workspace_dir if missing"
