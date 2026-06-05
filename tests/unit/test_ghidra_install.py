"""Tests for installing the Ghidra binary distribution."""

from __future__ import annotations

import importlib.util
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER_PATH = REPO_ROOT / "scripts" / "install_ghidra.py"
SERVER_PATH = REPO_ROOT / "external" / "ghidra-server" / "ghidra_http_server.py"


def _load_module(name: str, path: Path):
    assert path.exists(), f"Expected module at {path}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.pop(name, None)
    spec.loader.exec_module(module)
    return module


def test_install_ghidra_is_idempotent_for_existing_install(tmp_path: Path):
    installer = _load_module("test_install_ghidra_existing", INSTALLER_PATH)
    install_root = tmp_path / installer.DEFAULT_DIST_NAME
    headless = install_root / "support" / installer.get_headless_script_name()
    headless.parent.mkdir(parents=True)
    headless.write_text("echo ready\n", encoding="utf-8")

    calls: list[tuple[str, Path]] = []

    def _unexpected(*args, **kwargs):
        calls.append(("called", tmp_path))
        raise AssertionError("Download/extract should not run for an existing install")

    installer.download_with_progress = _unexpected
    installer.extract_archive = _unexpected

    result = installer.install_ghidra(
        dist_root=tmp_path,
        install_root=install_root,
        archive_path=tmp_path / "ghidra.zip",
    )

    assert result == install_root
    assert calls == []


def test_install_ghidra_extracts_downloaded_distribution(tmp_path: Path):
    installer = _load_module("test_install_ghidra_extract", INSTALLER_PATH)
    dist_root = tmp_path / "external" / "ghidra-dist"
    archive_path = dist_root / "ghidra.zip"

    def _fake_download(url: str, destination: Path):
        destination.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(destination, "w") as archive:
            archive.writestr(
                f"{installer.DEFAULT_DIST_NAME}/support/{installer.get_headless_script_name()}",
                "echo ready\n",
            )
        installer.EXPECTED_SHA256 = installer.calculate_sha256(destination)
        return destination

    installer.download_with_progress = _fake_download

    result = installer.install_ghidra(
        dist_root=dist_root,
        install_root=dist_root / installer.DEFAULT_DIST_NAME,
        archive_path=archive_path,
    )

    assert result == dist_root / installer.DEFAULT_DIST_NAME
    assert (result / "support" / installer.get_headless_script_name()).exists()


def test_verify_archive_checksum_accepts_expected_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    installer = _load_module("test_install_ghidra_checksum_ok", INSTALLER_PATH)
    archive_path = tmp_path / "ghidra.zip"
    archive_path.write_bytes(b"checksum ok")

    updates: list[bytes] = []

    class _FakeHash:
        def update(self, chunk: bytes) -> None:
            updates.append(chunk)

        def hexdigest(self) -> str:
            return installer.EXPECTED_SHA256

    monkeypatch.setattr(installer.hashlib, "sha256", lambda: _FakeHash())

    assert installer.verify_archive_checksum(archive_path) == archive_path
    assert archive_path.exists()
    assert updates == [b"checksum ok"]


def test_verify_archive_checksum_removes_archive_on_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    installer = _load_module("test_install_ghidra_checksum_bad", INSTALLER_PATH)
    archive_path = tmp_path / "ghidra.zip"
    archive_path.write_bytes(b"checksum bad")

    class _FakeHash:
        def update(self, chunk: bytes) -> None:
            return None

        def hexdigest(self) -> str:
            return "0" * 64

    monkeypatch.setattr(installer.hashlib, "sha256", lambda: _FakeHash())

    with pytest.raises(ValueError, match="Checksum verification failed"):
        installer.verify_archive_checksum(archive_path)

    assert not archive_path.exists()


def test_resolve_ghidra_path_prefers_binary_distribution(tmp_path: Path):
    server = _load_module("test_ghidra_http_server_prefers_dist", SERVER_PATH)
    external_root = tmp_path / "external"
    dist_root = external_root / "ghidra-dist" / server.DEFAULT_GHIDRA_DIST_NAME
    legacy_root = external_root / "ghidra"

    (dist_root / "support").mkdir(parents=True)
    (legacy_root / "support").mkdir(parents=True)
    (dist_root / "support" / server.get_headless_script_name()).write_text("", encoding="utf-8")
    (legacy_root / "support" / server.get_headless_script_name()).write_text("", encoding="utf-8")

    assert server.resolve_ghidra_path(external_root) == dist_root


def test_resolve_ghidra_path_falls_back_to_legacy_source_tree(tmp_path: Path):
    server = _load_module("test_ghidra_http_server_legacy", SERVER_PATH)
    external_root = tmp_path / "external"
    legacy_root = external_root / "ghidra"
    (legacy_root / "support").mkdir(parents=True)
    (legacy_root / "support" / server.get_headless_script_name()).write_text("", encoding="utf-8")

    assert server.resolve_ghidra_path(external_root) == legacy_root
