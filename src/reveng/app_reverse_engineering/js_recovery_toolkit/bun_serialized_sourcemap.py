"""Decode Bun ``SerializedSourceMap`` blobs (standalone compile sourcemaps).

Layout (oven-sh/bun ``sourcemap::SerializedSourceMap``)::

    Header { source_files_count: u32, map_bytes_length: u32 }
    source_files_count × StringPointer  — file names
    source_files_count × StringPointer  — zstd-compressed source contents
    map_bytes_length bytes              — InternalSourceMap blob
    string payload bytes referenced by StringPointers

``StringPointer`` is ``{ offset: u32, length: u32 }`` into the same blob.

When Claude/npm SEAs ship with ``sourcemap_size == 0``, this path is inert —
that is measured, not assumed. Hermetic fixtures prove the decoder.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_HEADER_FMT = "<II"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)
_PTR_FMT = "<II"
_PTR_SIZE = struct.calcsize(_PTR_FMT)


@dataclass
class BunSerializedSourceMap:
    source_files_count: int
    map_bytes_length: int
    sources: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    decode_ok: bool = False

    def to_serializable(self) -> dict:
        return {
            "schema_version": "1.0",
            "result_type": "bun_serialized_sourcemap",
            "source_files_count": self.source_files_count,
            "map_bytes_length": self.map_bytes_length,
            "recovered_file_count": len(self.sources),
            "paths": sorted(self.sources.keys()),
            "decode_ok": self.decode_ok,
            "notes": list(self.notes),
            "decoded_exe_claim": False,
        }


def _read_ptr(blob: bytes, offset: int) -> Tuple[int, int]:
    off, length = struct.unpack_from(_PTR_FMT, blob, offset)
    return int(off), int(length)


def _slice(blob: bytes, offset: int, length: int) -> Optional[bytes]:
    if offset < 0 or length < 0 or offset + length > len(blob):
        return None
    return blob[offset : offset + length]


def _zstd_decompress(payload: bytes) -> Optional[bytes]:
    try:
        import zstandard
    except ImportError:
        return None
    try:
        dctx = zstandard.ZstdDecompressor()
        # Cap output to avoid bombs from malicious claimed sizes
        return dctx.decompress(payload, max_output_size=64 * 1024 * 1024)
    except Exception:
        try:
            import zstandard

            dctx = zstandard.ZstdDecompressor()
            with dctx.stream_reader(payload) as reader:
                return reader.read(64 * 1024 * 1024)
        except Exception:
            return None


def parse_serialized_sourcemap(blob: bytes) -> BunSerializedSourceMap:
    """Parse a Bun SerializedSourceMap blob; decompress zstd sourcesContent."""
    out = BunSerializedSourceMap(source_files_count=0, map_bytes_length=0)
    if len(blob) < _HEADER_SIZE:
        out.notes.append("blob_too_short")
        return out
    count, map_len = struct.unpack_from(_HEADER_FMT, blob, 0)
    out.source_files_count = count
    out.map_bytes_length = map_len
    if count == 0:
        out.notes.append("empty_source_files")
        out.decode_ok = True
        return out
    table_bytes = count * _PTR_SIZE * 2
    if _HEADER_SIZE + table_bytes + map_len > len(blob):
        out.notes.append("header_table_overflow")
        return out

    name_base = _HEADER_SIZE
    content_base = _HEADER_SIZE + count * _PTR_SIZE
    for i in range(count):
        noff, nlen = _read_ptr(blob, name_base + i * _PTR_SIZE)
        coff, clen = _read_ptr(blob, content_base + i * _PTR_SIZE)
        name_raw = _slice(blob, noff, nlen)
        if name_raw is None:
            out.notes.append(f"bad_name_ptr:{i}")
            continue
        name = name_raw.decode("utf-8", errors="replace").rstrip("\x00")
        compressed = _slice(blob, coff, clen)
        if compressed is None:
            out.notes.append(f"bad_content_ptr:{i}")
            continue
        if not compressed:
            out.sources[name] = ""
            continue
        plain = _zstd_decompress(compressed)
        if plain is None:
            out.notes.append(f"zstd_fail:{i}")
            continue
        out.sources[name] = plain.decode("utf-8", errors="replace")
    out.decode_ok = len(out.sources) > 0 or count == 0
    if out.decode_ok:
        out.notes.append("serialized_sourcemap_ok")
    return out


def build_serialized_sourcemap_fixture(sources: Dict[str, str]) -> bytes:
    """Build a minimal SerializedSourceMap blob for hermetic tests."""
    import zstandard

    names = list(sources.keys())
    n = len(names)
    cctx = zstandard.ZstdCompressor(level=3)
    compressed = [cctx.compress(sources[name].encode("utf-8")) for name in names]
    name_bytes = [name.encode("utf-8") for name in names]

    map_bytes_length = 8  # dummy InternalSourceMap placeholder
    header = struct.pack(_HEADER_FMT, n, map_bytes_length)
    # Pointers then dummy map then payloads
    ptr_table_size = n * _PTR_SIZE * 2
    payload_start = _HEADER_SIZE + ptr_table_size + map_bytes_length
    ptrs = bytearray()
    payloads = bytearray()
    cursor = payload_start
    # name pointers
    name_ptrs: List[Tuple[int, int]] = []
    for nb in name_bytes:
        name_ptrs.append((cursor, len(nb)))
        payloads.extend(nb)
        cursor += len(nb)
    content_ptrs: List[Tuple[int, int]] = []
    for cb in compressed:
        content_ptrs.append((cursor, len(cb)))
        payloads.extend(cb)
        cursor += len(cb)
    for off, length in name_ptrs:
        ptrs.extend(struct.pack(_PTR_FMT, off, length))
    for off, length in content_ptrs:
        ptrs.extend(struct.pack(_PTR_FMT, off, length))
    dummy_map = b"\x00" * map_bytes_length
    return bytes(header + ptrs + dummy_map + payloads)


def materialize_serialized_sources(parsed: BunSerializedSourceMap, output_dir: Path) -> int:
    """Write recovered sources under output_dir; return files written."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for raw_path, body in parsed.sources.items():
        rel = raw_path.replace("\\", "/")
        if "src/" in rel:
            rel = rel[rel.index("src/") :]
        rel = rel.lstrip("/")
        if not rel or ".." in rel.split("/"):
            continue
        dest = output_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(body, encoding="utf-8")
        written += 1
    return written
