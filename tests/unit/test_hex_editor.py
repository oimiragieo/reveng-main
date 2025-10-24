"""Unit tests for the refactored HexEditor module."""

from pathlib import Path

from reveng.tools.hex_editor import EmbeddedBinary, EntropyRegion, HexEditor, HexView


def _create_binary(tmp_path: Path, content: bytes) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(content)
    return path


def test_open_binary_returns_hex_view(tmp_path: Path):
    binary = _create_binary(tmp_path, b"MZ" + b"\x00" * 10)
    editor = HexEditor()

    view = editor.open_binary(str(binary))

    assert isinstance(view, HexView)
    assert view.length == len(view.data)
    assert view.data.startswith(b"MZ")


def test_search_pattern_finds_offsets(tmp_path: Path):
    data = b"MZ" + b"pattern" + b"\x00" * 10 + b"pattern"
    binary = _create_binary(tmp_path, data)
    editor = HexEditor()
    view = editor.open_binary(str(binary))

    offsets = editor.search_pattern(b"pattern", view)

    assert offsets == [2, 19]


def test_extract_region_bounds_checked(tmp_path: Path):
    binary = _create_binary(tmp_path, b"HEADER" + b"data" + b"TAIL")
    editor = HexEditor()
    view = editor.open_binary(str(binary))

    region = editor.extract_region(6, 4, view)
    assert region == b"data"

    empty = editor.extract_region(100, 10, view)
    assert empty == b""


def test_entropy_analysis_returns_regions(tmp_path: Path):
    binary = _create_binary(tmp_path, b"\x00" * 2048 + b"\xff" * 2048)
    editor = HexEditor()
    view = editor.open_binary(str(binary))

    regions = editor.analyze_entropy_regions(view)

    assert all(isinstance(region, EntropyRegion) for region in regions)


def test_find_embedded_executables_identifies_pe(tmp_path: Path):
    binary = _create_binary(tmp_path, b"MZ" + b"\x00" * 60 + b"PE\x00\x00")
    editor = HexEditor()
    view = editor.open_binary(str(binary))

    embedded = editor.find_embedded_executables(view)

    assert isinstance(embedded, list)
    if embedded:
        assert isinstance(embedded[0], EmbeddedBinary)


def test_extract_strings_advanced(tmp_path: Path):
    binary = _create_binary(tmp_path, b"MZ" + b"hello\x00" + b"world\x00")
    editor = HexEditor()
    view = editor.open_binary(str(binary))

    strings = editor.extract_strings_advanced(view, min_length=5)

    assert any("hello" in s for s in strings)
    assert "world" in strings
