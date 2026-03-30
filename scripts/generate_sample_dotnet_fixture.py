from __future__ import annotations

import struct
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = REPO_ROOT / "test_samples" / "sample_dotnet.dll"


def build_dotnet_pe() -> bytes:
    dos_header = bytearray(0x80)
    dos_header[:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

    optional_header = bytearray(0xE0)
    optional_header[0:2] = struct.pack("<H", 0x10B)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[20:24] = struct.pack("<I", 0x1000)
    optional_header[24:28] = struct.pack("<I", 0x2000)
    optional_header[28:32] = struct.pack("<I", 0x400000)
    optional_header[32:36] = struct.pack("<I", 0x1000)
    optional_header[36:40] = struct.pack("<I", 0x200)
    optional_header[56:60] = struct.pack("<I", 0x2000)
    optional_header[60:64] = struct.pack("<I", 0x200)
    optional_header[68:70] = struct.pack("<H", 3)
    optional_header[92:96] = struct.pack("<I", 16)
    com_descriptor_offset = 96 + (8 * 14)
    optional_header[com_descriptor_offset : com_descriptor_offset + 8] = struct.pack(
        "<II", 0x1100, 0x48
    )

    pe_header = bytearray()
    pe_header.extend(b"PE\x00\x00")
    pe_header.extend(struct.pack("<H", 0x14C))
    pe_header.extend(struct.pack("<H", 1))
    pe_header.extend(struct.pack("<I", 0))
    pe_header.extend(struct.pack("<I", 0))
    pe_header.extend(struct.pack("<I", 0))
    pe_header.extend(struct.pack("<H", 0xE0))
    pe_header.extend(struct.pack("<H", 0x010F))
    pe_header.extend(optional_header)

    section_header = bytearray(40)
    section_header[:8] = b".text\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 0x200)
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", 0x200)
    section_header[20:24] = struct.pack("<I", 0x200)
    section_header[36:40] = struct.pack("<I", 0x60000020)

    headers = bytes(dos_header) + bytes(pe_header) + bytes(section_header)
    headers = headers.ljust(0x200, b"\x00")
    return headers + (b"\x00" * 0x200)


def main() -> int:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_bytes(build_dotnet_pe())
    print(f"Wrote fixture to: {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
