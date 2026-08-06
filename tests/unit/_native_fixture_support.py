"""Helpers for native micro-CLI fixture tests."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
NATIVE_ROOT = REPO_ROOT / "test_samples" / "native"


def locate_fixture(name: str) -> Tuple[Optional[Path], Optional[str]]:
    """Return (binary_path, None) or (None, skip_reason)."""
    if name == "hello_c":
        path = NATIVE_ROOT / "hello_c" / "build" / "hello_c"
    elif name == "hello_go":
        path = NATIVE_ROOT / "hello_go" / "build" / "hello_go"
    else:
        return None, f"unknown fixture {name}"
    if path.is_file():
        return path, None
    return None, "run: make -C test_samples/native"


def emit_skip_marker(name: str, reason: str) -> str:
    marker = f"NATIVE_FIXTURE_SKIPPED: {name} reason={reason}"
    print(marker)
    return marker
