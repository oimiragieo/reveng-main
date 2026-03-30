from __future__ import annotations

import asyncio
from types import SimpleNamespace

from reveng import recompile_command


def test_console_safe_text_replaces_unencodable_characters(monkeypatch):
    monkeypatch.setattr(recompile_command.sys, "stdout", SimpleNamespace(encoding="cp1252"))

    assert recompile_command._console_safe_text("📝 Generated Source Files:") == "? Generated Source Files:"


def test_run_recompile_command_forwards_ghidra_timeout(monkeypatch):
    captured = {}

    async def fake_recompile_command(**kwargs):
        captured.update(kwargs)
        return 0

    def fake_asyncio_run(coroutine):
        try:
            coroutine.send(None)
        except StopIteration as exc:
            return exc.value
        raise AssertionError("Coroutine did not finish synchronously")

    monkeypatch.setattr(recompile_command, "recompile_command", fake_recompile_command)
    monkeypatch.setattr(asyncio, "run", fake_asyncio_run)

    result = recompile_command.run_recompile_command(
        binary_path="C:\\demo\\sample.exe",
        ghidra_timeout=777,
    )

    assert result == 0
    assert captured["ghidra_timeout"] == 777
