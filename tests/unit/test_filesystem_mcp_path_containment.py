"""Regression tests for FilesystemMCPServer path containment.

Guards against the prefix-bypass vulnerability where a sibling directory
sharing the root's string prefix (e.g. ``<root>_secret``) passed the
``str(full_path).startswith(str(root_path))`` containment check.
"""

import pytest

from reveng.agent_sdk.mcp.servers.filesystem import FilesystemMCPServer


def test_sibling_prefix_path_is_rejected(tmp_path):
    """A path resolving to ``<root>_secret/...`` must be rejected."""
    root = tmp_path / "root"
    root.mkdir()
    sibling = tmp_path / "root_secret"
    sibling.mkdir()
    (sibling / "x").write_text("secret")

    server = FilesystemMCPServer(root_path=str(root))

    with pytest.raises(ValueError):
        server._resolve_path("../root_secret/x")


def test_path_inside_root_is_accepted(tmp_path):
    """A path inside the root directory must be accepted."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "inside.txt").write_text("ok")

    server = FilesystemMCPServer(root_path=str(root))

    resolved = server._resolve_path("inside.txt")
    assert resolved == (root / "inside.txt").resolve()
