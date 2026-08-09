from __future__ import annotations

import json
import struct
import subprocess
from pathlib import Path

import pytest

from reveng.tools.anti_analysis.bun_extractor import (
    BunExecutableExtractor,
    BunSourcemapProvenance,
    PEHandoffSignal,
    PEInstructionPreview,
    PEStartupTarget,
    PETLSCallback,
    build_bun_equivalence_validation_summary,
    build_bun_report_severity_summary,
    build_bun_runtime_escalation_summary,
    run_bun_sea_workflow,
)
from reveng.tools.anti_analysis.packer_detector import PackerDetector
from reveng.tools.anti_analysis.universal_unpacker import UniversalUnpacker


def _path_endswith(path: str | None, suffix: str) -> bool:
    """OS-agnostic suffix check for recovered filesystem / virtual paths."""
    if path is None:
        return False
    return Path(path).as_posix().endswith(Path(suffix).as_posix())


def _build_pe_with_bun_section(
    section_data: bytes, tls_callback_offsets: list[int] | None = None
) -> bytes:
    dos_header = bytearray(0x80)
    dos_header[:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

    image_base = 0x400000
    optional_header = bytearray(0xE0)
    optional_header[0:2] = struct.pack("<H", 0x10B)  # PE32
    optional_header[16:20] = struct.pack("<I", 0x1000)  # AddressOfEntryPoint
    optional_header[20:24] = struct.pack("<I", 0x1000)  # BaseOfCode
    optional_header[24:28] = struct.pack("<I", 0x2000)  # BaseOfData
    optional_header[28:32] = struct.pack("<I", image_base)  # ImageBase
    optional_header[32:36] = struct.pack("<I", 0x1000)  # SectionAlignment
    optional_header[36:40] = struct.pack("<I", 0x200)  # FileAlignment
    optional_header[56:60] = struct.pack("<I", 0x2000)  # SizeOfImage
    optional_header[60:64] = struct.pack("<I", 0x200)  # SizeOfHeaders
    optional_header[68:70] = struct.pack("<H", 3)  # Subsystem (CUI)
    optional_header[92:96] = struct.pack("<I", 16)  # NumberOfRvaAndSizes

    if tls_callback_offsets:
        section_blob = bytearray(section_data)
        tls_directory_offset = 0x80
        callbacks_table_offset = 0xC0
        callback_table_rva = 0x1000 + callbacks_table_offset
        section_blob.extend(
            b"\x00"
            * max(
                0,
                callbacks_table_offset + (len(tls_callback_offsets) + 1) * 4 - len(section_blob),
            )
        )
        struct.pack_into(
            "<IIIIII",
            section_blob,
            tls_directory_offset,
            0,
            0,
            0,
            image_base + callback_table_rva,
            0,
            0,
        )
        for index, callback_offset in enumerate(tls_callback_offsets):
            struct.pack_into(
                "<I",
                section_blob,
                callbacks_table_offset + index * 4,
                image_base + 0x1000 + callback_offset,
            )
        struct.pack_into(
            "<II",
            optional_header,
            96 + 8 * 9,
            0x1000 + tls_directory_offset,
            24,
        )
        section_data = bytes(section_blob)

    pe_header = bytearray()
    pe_header.extend(b"PE\x00\x00")
    pe_header.extend(struct.pack("<H", 0x14C))  # IMAGE_FILE_MACHINE_I386
    pe_header.extend(struct.pack("<H", 1))  # NumberOfSections
    pe_header.extend(struct.pack("<I", 0))  # TimeDateStamp
    pe_header.extend(struct.pack("<I", 0))  # PointerToSymbolTable
    pe_header.extend(struct.pack("<I", 0))  # NumberOfSymbols
    pe_header.extend(struct.pack("<H", 0xE0))  # SizeOfOptionalHeader
    pe_header.extend(struct.pack("<H", 0x010F))  # Characteristics
    pe_header.extend(optional_header)

    pointer_to_raw_data = 0x200
    raw_size = ((len(section_data) + 0x1FF) // 0x200) * 0x200
    section_header = bytearray(40)
    section_header[:8] = b".bun\x00\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", len(section_data))  # VirtualSize
    section_header[12:16] = struct.pack("<I", 0x1000)  # VirtualAddress
    section_header[16:20] = struct.pack("<I", raw_size)  # SizeOfRawData
    section_header[20:24] = struct.pack("<I", pointer_to_raw_data)  # PointerToRawData
    section_header[36:40] = struct.pack("<I", 0x40000040)

    headers = bytes(dos_header) + bytes(pe_header) + bytes(section_header)
    headers = headers.ljust(pointer_to_raw_data, b"\x00")
    return headers + section_data.ljust(raw_size, b"\x00")


def _build_pe64_with_bun_section(section_data: bytes) -> bytes:
    dos_header = bytearray(0x80)
    dos_header[:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

    image_base = 0x140000000
    optional_header = bytearray(0xF0)
    optional_header[0:2] = struct.pack("<H", 0x20B)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[20:24] = struct.pack("<I", 0x1000)
    optional_header[24:32] = struct.pack("<Q", image_base)
    optional_header[32:36] = struct.pack("<I", 0x1000)
    optional_header[36:40] = struct.pack("<I", 0x200)
    optional_header[56:60] = struct.pack("<I", 0x2000)
    optional_header[60:64] = struct.pack("<I", 0x200)
    optional_header[68:70] = struct.pack("<H", 3)
    optional_header[108:112] = struct.pack("<I", 16)

    pe_header = bytearray()
    pe_header.extend(b"PE\x00\x00")
    pe_header.extend(struct.pack("<H", 0x8664))
    pe_header.extend(struct.pack("<H", 1))
    pe_header.extend(struct.pack("<I", 0))
    pe_header.extend(struct.pack("<I", 0))
    pe_header.extend(struct.pack("<I", 0))
    pe_header.extend(struct.pack("<H", 0xF0))
    pe_header.extend(struct.pack("<H", 0x022F))
    pe_header.extend(optional_header)

    pointer_to_raw_data = 0x200
    raw_size = ((len(section_data) + 0x1FF) // 0x200) * 0x200
    section_header = bytearray(40)
    section_header[:8] = b".bun\x00\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", len(section_data))
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", raw_size)
    section_header[20:24] = struct.pack("<I", pointer_to_raw_data)
    section_header[36:40] = struct.pack("<I", 0x60000020)

    headers = bytes(dos_header) + bytes(pe_header) + bytes(section_header)
    headers = headers.ljust(pointer_to_raw_data, b"\x00")
    return headers + section_data.ljust(raw_size, b"\x00")


def _write_bun_fixture(tmp_path: Path) -> Path:
    blob = bytearray()

    def _add_string(data: bytes) -> tuple[int, int]:
        offset = len(blob)
        blob.extend(data)
        blob.append(0)
        return offset, len(data)

    js_bundle = (
        b"// @bun\n" b"console.log('hello from bun');\n" b"//# sourceMappingURL=index.js.map\n"
    )
    package_json = b'{"name":"demo"}'
    sourcemap_blob = b"serialized-sourcemap"

    name1 = _add_string(b"B:/~BUN/root/src/index.js")
    contents1 = _add_string(js_bundle)
    sourcemap1 = _add_string(sourcemap_blob)
    name2 = _add_string(b"B:/~BUN/root/package.json")
    contents2 = _add_string(package_json)
    compile_argv = _add_string(b"--compile")

    modules_offset = len(blob)
    blob.extend(
        struct.pack(
            "<IIIIIIIIIIII4B",
            name1[0],
            name1[1],
            contents1[0],
            contents1[1],
            sourcemap1[0],
            sourcemap1[1],
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            1,
            0,
            0,
        )
    )
    blob.extend(
        struct.pack(
            "<IIIIIIIIIIII4B",
            name2[0],
            name2[1],
            contents2[0],
            contents2[1],
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            6,
            0,
            0,
        )
    )
    modules_length = 2 * 52
    byte_count = len(blob)
    blob.extend(
        struct.pack(
            "<QIIIIII",
            byte_count,
            modules_offset,
            modules_length,
            0,
            compile_argv[0],
            compile_argv[1],
            0,
        )
    )
    blob.extend(b"\n---- Bun! ----\n")

    bundle_blob = struct.pack("<I", len(blob)) + blob
    binary_path = tmp_path / "sample_bun.exe"
    binary_path.write_bytes(_build_pe_with_bun_section(bundle_blob))
    return binary_path


def _write_bun_short_record_fixture(tmp_path: Path) -> Path:
    virtual_path = b"B:/~BUN/root/droid.exe"
    raw_bytes = virtual_path + b"\x00" + b"// @bun\n" + b"console.log('short bun payload');\n"
    fake_module_record = struct.pack(
        "<IIIIIIII4B",
        0,
        22,
        23,
        len(raw_bytes) - 23,
        0,
        0,
        0,
        0,
        0,
        1,
        1,
        1,
    )
    byte_count = len(raw_bytes) + len(fake_module_record)
    blob = bytearray(raw_bytes)
    modules_offset = len(blob)
    blob.extend(fake_module_record)
    blob.extend(
        struct.pack(
            "<QIIIIII",
            byte_count,
            modules_offset,
            len(fake_module_record),
            0,
            byte_count - 1,
            0,
            121,
        )
    )
    blob.extend(b"\n---- Bun! ----\n")

    bundle_blob = struct.pack("<I", len(blob)) + blob
    binary_path = tmp_path / "sample_bun_short.exe"
    binary_path.write_bytes(_build_pe_with_bun_section(bundle_blob))
    return binary_path


def _write_bun_extended_short_record_fixture(tmp_path: Path) -> Path:
    virtual_path = b"B:/~BUN/root/app.js"
    raw_bytes = (
        virtual_path + b"\x00" + b"// @bun\n" + b"console.log('extended short bun payload');\n"
    )
    fake_module_record = struct.pack(
        "<IIIIIIIII4B",
        0,
        len(virtual_path),
        len(virtual_path) + 1,
        len(raw_bytes) - (len(virtual_path) + 1),
        0,
        0,
        0,
        0,
        0,
        1,
        1,
        0,
        0,
    )
    byte_count = len(raw_bytes) + len(fake_module_record)
    blob = bytearray(raw_bytes)
    modules_offset = len(blob)
    blob.extend(fake_module_record)
    blob.extend(
        struct.pack(
            "<QIIIIII",
            byte_count,
            modules_offset,
            len(fake_module_record),
            0,
            byte_count - 1,
            0,
            121,
        )
    )
    blob.extend(b"\n---- Bun! ----\n")

    bundle_blob = struct.pack("<I", len(blob)) + blob
    binary_path = tmp_path / "sample_bun_extended_short.exe"
    binary_path.write_bytes(_build_pe_with_bun_section(bundle_blob))
    return binary_path


def _write_bun_fallback_fixture(tmp_path: Path) -> Path:
    js_bundle = b"// @bun\n" b"console.log('fallback bun payload');\n" b"B:/~BUN/root/droid.exe\n"
    fake_module_record = b"\x00" * 35
    byte_count = len(js_bundle) + len(fake_module_record)
    blob = bytearray(js_bundle)
    modules_offset = len(blob)
    blob.extend(fake_module_record)
    blob.extend(
        struct.pack(
            "<QIIIIII",
            byte_count,
            modules_offset,
            len(fake_module_record),
            0,
            byte_count - 1,
            0,
            121,
        )
    )
    blob.extend(b"\n---- Bun! ----\n")

    bundle_blob = struct.pack("<I", len(blob)) + blob
    binary_path = tmp_path / "sample_bun_fallback.exe"
    binary_path.write_bytes(_build_pe_with_bun_section(bundle_blob))
    return binary_path


def _write_bun_fallback_fixture_with_inline_sourcemap(tmp_path: Path) -> Path:
    inline_sourcemap = (
        "data:application/json;base64,"
        "eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZHJvaWQuZXhlIiwic291cmNlcyI6WyJkcm9pZC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiIn0="
    )
    js_bundle = (
        b"// @bun\n"
        b"console.log('fallback bun payload');\n"
        + f"//# sourceMappingURL={inline_sourcemap}\n".encode("utf-8")
        + b"B:/~BUN/root/droid.exe\n"
    )
    fake_module_record = b"\x00" * 35
    byte_count = len(js_bundle) + len(fake_module_record)
    blob = bytearray(js_bundle)
    modules_offset = len(blob)
    blob.extend(fake_module_record)
    blob.extend(
        struct.pack(
            "<QIIIIII",
            byte_count,
            modules_offset,
            len(fake_module_record),
            0,
            byte_count - 1,
            0,
            121,
        )
    )
    blob.extend(b"\n---- Bun! ----\n")

    bundle_blob = struct.pack("<I", len(blob)) + blob
    binary_path = tmp_path / "sample_bun_fallback_sourcemap.exe"
    binary_path.write_bytes(_build_pe_with_bun_section(bundle_blob))
    return binary_path


def _write_bun_fallback_fixture_with_external_sourcemap(tmp_path: Path) -> Path:
    sourcemap_json = (
        b'{"version":3,"file":"droid.exe","sources":["droid.ts"],"names":[],"mappings":""}'
    )
    js_bundle = (
        b"// @bun\n"
        b"console.log('fallback bun payload');\n"
        b"//# sourceMappingURL=droid.exe.map\n"
        + (b"\x00" * 8)
        + b"B:/~BUN/root/droid.exe.map\x00"
        + sourcemap_json
        + b"\x00"
        + b"B:/~BUN/root/droid.exe\n"
    )
    fake_module_record = b"\x00" * 35
    byte_count = len(js_bundle) + len(fake_module_record)
    blob = bytearray(js_bundle)
    modules_offset = len(blob)
    blob.extend(fake_module_record)
    blob.extend(
        struct.pack(
            "<QIIIIII",
            byte_count,
            modules_offset,
            len(fake_module_record),
            0,
            byte_count - 1,
            0,
            121,
        )
    )
    blob.extend(b"\n---- Bun! ----\n")

    bundle_blob = struct.pack("<I", len(blob)) + blob
    binary_path = tmp_path / "sample_bun_fallback_external_sourcemap.exe"
    binary_path.write_bytes(_build_pe_with_bun_section(bundle_blob))
    return binary_path


def _write_bun_fallback_fixture_with_supporting_json(tmp_path: Path) -> Path:
    package_json = b'{"name":"fallback-demo","type":"module"}'
    tsconfig_json = b'{"compilerOptions":{"module":"esnext"}}'
    js_bundle = (
        b"// @bun\n"
        b"console.log('fallback bun payload');\n"
        + (b"\x00" * 4)
        + b"B:/~BUN/root/package.json\x00"
        + package_json
        + b"\x00\x00"
        + b"B:/~BUN/root/tsconfig.json\x00"
        + tsconfig_json
        + b"\x00"
        + b"B:/~BUN/root/droid.exe\n"
    )
    fake_module_record = b"\x00" * 35
    byte_count = len(js_bundle) + len(fake_module_record)
    blob = bytearray(js_bundle)
    modules_offset = len(blob)
    blob.extend(fake_module_record)
    blob.extend(
        struct.pack(
            "<QIIIIII",
            byte_count,
            modules_offset,
            len(fake_module_record),
            0,
            byte_count - 1,
            0,
            121,
        )
    )
    blob.extend(b"\n---- Bun! ----\n")

    bundle_blob = struct.pack("<I", len(blob)) + blob
    binary_path = tmp_path / "sample_bun_fallback_supporting_json.exe"
    binary_path.write_bytes(_build_pe_with_bun_section(bundle_blob))
    return binary_path


def _write_bun_fallback_fixture_with_supporting_text(tmp_path: Path) -> Path:
    env_text = b"API_BASE=https://example.test\nFEATURE_FLAG=true\n"
    config_text = b"export const config = { mode: 'demo' };\n"
    js_bundle = (
        b"// @bun\n"
        b"console.log('fallback bun payload');\n"
        + (b"\x00" * 4)
        + b"B:/~BUN/root/.env\x00"
        + env_text
        + b"\x00\x00"
        + b"B:/~BUN/root/config.ts\x00"
        + config_text
        + b"\x00"
        + b"B:/~BUN/root/droid.exe\n"
    )
    fake_module_record = b"\x00" * 35
    byte_count = len(js_bundle) + len(fake_module_record)
    blob = bytearray(js_bundle)
    modules_offset = len(blob)
    blob.extend(fake_module_record)
    blob.extend(
        struct.pack(
            "<QIIIIII",
            byte_count,
            modules_offset,
            len(fake_module_record),
            0,
            byte_count - 1,
            0,
            121,
        )
    )
    blob.extend(b"\n---- Bun! ----\n")

    bundle_blob = struct.pack("<I", len(blob)) + blob
    binary_path = tmp_path / "sample_bun_fallback_supporting_text.exe"
    binary_path.write_bytes(_build_pe_with_bun_section(bundle_blob))
    return binary_path


def _write_bun_fallback_fixture_with_supporting_wasm(tmp_path: Path) -> Path:
    wasm_blob = b"\x00asm\x01\x00\x00\x00\x01\x04\x01\x60\x00\x00"
    js_bundle = (
        b"// @bun\n"
        b"console.log('fallback bun payload');\n"
        + (b"\x00" * 4)
        + b"B:/~BUN/root/module.wasm\x00"
        + wasm_blob
        + b"\x00\x00"
        + b"B:/~BUN/root/droid.exe\n"
    )
    fake_module_record = b"\x00" * 35
    byte_count = len(js_bundle) + len(fake_module_record)
    blob = bytearray(js_bundle)
    modules_offset = len(blob)
    blob.extend(fake_module_record)
    blob.extend(
        struct.pack(
            "<QIIIIII",
            byte_count,
            modules_offset,
            len(fake_module_record),
            0,
            byte_count - 1,
            0,
            121,
        )
    )
    blob.extend(b"\n---- Bun! ----\n")

    bundle_blob = struct.pack("<I", len(blob)) + blob
    binary_path = tmp_path / "sample_bun_fallback_supporting_wasm.exe"
    binary_path.write_bytes(_build_pe_with_bun_section(bundle_blob))
    return binary_path


def _write_bun_fallback_fixture_with_supporting_web_and_config(tmp_path: Path) -> Path:
    css_text = b"body { color: #fff; background: #111; }\n"
    html_text = b"<!doctype html><html><body><div id='app'></div></body></html>\n"
    yaml_text = b"name: fallback-demo\nmode: demo\n"
    toml_text = b"[install]\nproduction = true\n"
    js_bundle = (
        b"// @bun\n"
        b"console.log('fallback bun payload');\n"
        + (b"\x00" * 4)
        + b"B:/~BUN/root/styles.css\x00"
        + css_text
        + b"\x00\x00"
        + b"B:/~BUN/root/index.html\x00"
        + html_text
        + b"\x00\x00"
        + b"B:/~BUN/root/app.yaml\x00"
        + yaml_text
        + b"\x00\x00"
        + b"B:/~BUN/root/bunfig.toml\x00"
        + toml_text
        + b"\x00"
        + b"B:/~BUN/root/droid.exe\n"
    )
    fake_module_record = b"\x00" * 35
    byte_count = len(js_bundle) + len(fake_module_record)
    blob = bytearray(js_bundle)
    modules_offset = len(blob)
    blob.extend(fake_module_record)
    blob.extend(
        struct.pack(
            "<QIIIIII",
            byte_count,
            modules_offset,
            len(fake_module_record),
            0,
            byte_count - 1,
            0,
            121,
        )
    )
    blob.extend(b"\n---- Bun! ----\n")

    bundle_blob = struct.pack("<I", len(blob)) + blob
    binary_path = tmp_path / "sample_bun_fallback_supporting_web_and_config.exe"
    binary_path.write_bytes(_build_pe_with_bun_section(bundle_blob))
    return binary_path


def _write_bun_fallback_fixture_with_invalid_offsets(tmp_path: Path) -> Path:
    js_bundle = (
        b"// @bun\n" b"console.log('invalid offsets fallback');\n" b"B:/~BUN/root/droid.exe\n"
    )
    fake_module_record = b"\x01" * 19
    byte_count = len(js_bundle) + len(fake_module_record)
    blob = bytearray(js_bundle)
    modules_offset = len(blob)
    blob.extend(fake_module_record)
    blob.extend(
        struct.pack(
            "<QIIIIII",
            byte_count + 4096,
            modules_offset,
            len(fake_module_record),
            0,
            byte_count - 1,
            0,
            121,
        )
    )
    blob.extend(b"\n---- Bun! ----\n")

    bundle_blob = struct.pack("<I", len(blob)) + blob
    binary_path = tmp_path / "sample_bun_invalid_offsets.exe"
    binary_path.write_bytes(_build_pe_with_bun_section(bundle_blob))
    return binary_path


def _write_bun_fallback_fixture_with_sparse_mixed_paths(tmp_path: Path) -> Path:
    package_json = b'{"name":"sparse-demo","type":"module"}'
    env_text = b"MODE=prod\nAPI_BASE=https://example.test\n"
    js_bundle = (
        b"// @bun\n"
        b"console.log('sparse mixed fallback payload');\n"
        + b"/$bunfs/root/package.json\x00"
        + package_json
        + b"\x00\x00"
        + b"/$bunfs/root/.env\x00"
        + env_text
        + b"\x00\x00"
        + b"/$bunfs/root/src/main.ts\n"
    )
    fake_module_record = b"\x00" * 35
    byte_count = len(js_bundle) + len(fake_module_record)
    blob = bytearray(js_bundle)
    modules_offset = len(blob)
    blob.extend(fake_module_record)
    blob.extend(
        struct.pack(
            "<QIIIIII",
            byte_count,
            modules_offset,
            len(fake_module_record),
            0,
            byte_count - 1,
            0,
            121,
        )
    )
    blob.extend(b"\n---- Bun! ----\n")

    bundle_blob = struct.pack("<I", len(blob)) + blob
    binary_path = tmp_path / "sample_bun_sparse_mixed_paths.exe"
    binary_path.write_bytes(_build_pe_with_bun_section(bundle_blob))
    return binary_path


def _fixture_matrix_cases():
    return [
        (
            "module_graph_full",
            _write_bun_fixture,
            {
                "detect": {"section_name": ".bun", "container": "pe"},
                "recovery": {"mode": "module_graph", "module_layout": "full"},
                "manifest": {"module_count": 2},
            },
        ),
        (
            "module_graph_short",
            _write_bun_short_record_fixture,
            {
                "detect": {"section_name": ".bun", "container": "pe"},
                "recovery": {"mode": "module_graph", "module_layout": "short"},
                "manifest": {"module_count": 1},
            },
        ),
        (
            "module_graph_short_extended",
            _write_bun_extended_short_record_fixture,
            {
                "detect": {"section_name": ".bun", "container": "pe"},
                "recovery": {"mode": "module_graph", "module_layout": "short_ext"},
                "manifest": {"module_count": 1},
            },
        ),
        (
            "path_scan_primary_source",
            _write_bun_fallback_fixture,
            {
                "detect": {"section_name": ".bun", "container": "pe"},
                "recovery": {"mode": "path_scan", "module_layout": None},
                "manifest": {"discovered_path_count": 1, "primary_suffix": "root/droid.exe"},
            },
        ),
        (
            "path_scan_external_sourcemap",
            _write_bun_fallback_fixture_with_external_sourcemap,
            {
                "detect": {"section_name": ".bun", "container": "pe"},
                "recovery": {"mode": "path_scan", "module_layout": None},
                "manifest": {"sourcemap_suffix": "root/droid.exe.map"},
            },
        ),
        (
            "path_scan_supporting_wasm",
            _write_bun_fallback_fixture_with_supporting_wasm,
            {
                "detect": {"section_name": ".bun", "container": "pe"},
                "recovery": {"mode": "path_scan", "module_layout": None},
                "manifest": {"supporting_suffix": "root/module.wasm"},
            },
        ),
        (
            "path_scan_supporting_web_and_config",
            _write_bun_fallback_fixture_with_supporting_web_and_config,
            {
                "detect": {"section_name": ".bun", "container": "pe"},
                "recovery": {"mode": "path_scan", "module_layout": None},
                "manifest": {"supporting_suffix": "root/styles.css"},
            },
        ),
        (
            "path_scan_invalid_offsets",
            _write_bun_fallback_fixture_with_invalid_offsets,
            {
                "detect": {"section_name": ".bun", "container": "pe"},
                "recovery": {"mode": "path_scan", "module_layout": None},
                "manifest": {"discovered_path_count": 1, "primary_suffix": "root/droid.exe"},
            },
        ),
        (
            "path_scan_sparse_mixed_paths",
            _write_bun_fallback_fixture_with_sparse_mixed_paths,
            {
                "detect": {"section_name": ".bun", "container": "pe"},
                "recovery": {"mode": "path_scan", "module_layout": None},
                "manifest": {
                    "discovered_path_count": 3,
                    "primary_suffix": "root/src/main.ts",
                    "supporting_suffix": "root/package.json",
                },
            },
        ),
    ]


def test_bun_extractor_detects_bun_pe_section(tmp_path: Path):
    binary_path = _write_bun_fixture(tmp_path)

    info = BunExecutableExtractor().detect(str(binary_path))

    assert info.is_bun_executable is True
    assert info.container == "pe"
    assert info.section_name == ".bun"
    assert info.javascript_start_offset is not None
    assert any(".bun" in indicator for indicator in info.indicators)


@pytest.mark.parametrize(
    ("case_name", "builder", "expected"),
    _fixture_matrix_cases(),
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_bun_fixture_matrix_characterization(tmp_path: Path, case_name: str, builder, expected):
    binary_path = builder(tmp_path)
    output_dir = tmp_path / f"{case_name}_out"
    extractor = BunExecutableExtractor()

    info = extractor.detect(str(binary_path))
    recovery = extractor.recover_virtual_files(str(binary_path), str(output_dir))

    assert info.is_bun_executable is True
    assert info.section_name == expected["detect"]["section_name"]
    assert info.container == expected["detect"]["container"]
    assert recovery.success is True
    assert recovery.recovery_mode == expected["recovery"]["mode"]
    if expected["recovery"]["module_layout"] is not None:
        assert recovery.graph is not None
        assert recovery.graph.module_layout == expected["recovery"]["module_layout"]

    manifest = json.loads(Path(recovery.manifest_path).read_text(encoding="utf-8"))
    if "module_count" in expected["manifest"]:
        assert manifest["module_count"] == expected["manifest"]["module_count"]
    if "discovered_path_count" in expected["manifest"]:
        assert manifest["discovered_path_count"] == expected["manifest"]["discovered_path_count"]
    if "primary_suffix" in expected["manifest"]:
        assert _path_endswith(
            manifest["artifacts"]["primary_source_path"],
            expected["manifest"]["primary_suffix"],
        )
    if "sourcemap_suffix" in expected["manifest"]:
        assert _path_endswith(
            manifest["artifacts"]["recovered_sourcemap_path"],
            expected["manifest"]["sourcemap_suffix"],
        )
    if "supporting_suffix" in expected["manifest"]:
        assert any(
            _path_endswith(path, expected["manifest"]["supporting_suffix"])
            for path in manifest["artifacts"]["recovered_supporting_artifacts"]
        )


def test_bun_extractor_summarizes_native_pe_stub(tmp_path: Path):
    binary_path = _write_bun_fixture(tmp_path)

    summary = BunExecutableExtractor().analyze_pe_stub(str(binary_path))

    assert summary is not None
    assert summary.container == "pe"
    assert summary.machine == "0x014c"
    assert ".bun" in summary.section_names
    assert summary.entry_point_rva == 0x1000
    assert summary.entry_point_section == ".bun"
    assert isinstance(summary.entry_point_preview, list)
    assert summary.tls_directory_rva is None
    assert summary.tls_callback_vas == []
    assert summary.tls_callbacks == []
    assert summary.import_dlls == []
    assert summary.imported_functions == []
    assert summary.startup_classification == "mixed_or_unknown"
    assert "Embedded Bun payload section present" in summary.indicators


def test_bun_extractor_resolves_tls_callback_metadata(tmp_path: Path):
    bundle_blob = struct.pack("<I", 8) + b"// @bun\n"
    binary_path = tmp_path / "sample_bun_tls.exe"
    binary_path.write_bytes(
        _build_pe_with_bun_section(bundle_blob, tls_callback_offsets=[0x180, 0x1C0])
    )

    summary = BunExecutableExtractor().analyze_pe_stub(str(binary_path))

    assert summary is not None
    assert summary.tls_directory_rva == 0x1080
    assert summary.tls_callback_vas == [0x401180, 0x4011C0]
    assert [callback.rva for callback in summary.tls_callbacks] == [0x1180, 0x11C0]
    assert all(callback.section_name == ".bun" for callback in summary.tls_callbacks)
    assert "TLS callbacks present: 2" in summary.indicators


def test_bun_extractor_includes_instruction_previews(tmp_path: Path):
    section_blob = bytearray(b"\xe8\x1b\x00\x00\x00\xe9\x36\x00\x00\x00\xc3")
    section_blob.extend(b"\x00" * (0x20 - len(section_blob)))
    section_blob.extend(b"\x31\xc0\xc3")
    section_blob.extend(b"\x00" * (0x40 - len(section_blob)))
    section_blob.extend(b"\x83\xf8\x01\xc3")
    section_blob.extend(b"\x00" * (0x180 - len(section_blob)))
    section_blob.extend(b"\x31\xc0\xc3")
    section_blob.extend(b"\x00" * (0x1C0 - len(section_blob)))
    section_blob.extend(b"\x83\xfa\x03\xc3")
    binary_path = tmp_path / "sample_bun_preview.exe"
    binary_path.write_bytes(
        _build_pe_with_bun_section(bytes(section_blob), tls_callback_offsets=[0x180, 0x1C0])
    )

    summary = BunExecutableExtractor().analyze_pe_stub(str(binary_path))

    assert summary is not None
    assert summary.entry_point_preview
    assert summary.entry_point_preview[0].mnemonic == "call"
    assert summary.entry_point_preview[0].target_address == 0x401020
    assert summary.entry_point_preview[0].target_rva == 0x1020
    assert summary.entry_point_preview[0].target_section == ".bun"
    assert summary.entry_point_preview[1].mnemonic == "jmp"
    assert summary.entry_point_preview[1].target_address == 0x401040
    assert summary.startup_classification == "mixed_or_unknown"
    assert [target.source for target in summary.startup_targets[:2]] == ["entrypoint", "entrypoint"]
    assert summary.startup_targets[0].target_address == 0x401020
    assert summary.startup_targets[0].target_preview[0].mnemonic == "xor"
    assert len(summary.tls_callbacks) == 2
    assert summary.tls_callbacks[0].instruction_preview[0].mnemonic == "xor"
    assert summary.tls_callbacks[1].instruction_preview[0].mnemonic == "cmp"


def test_bun_extractor_classifies_runtime_bootstrap_profile():
    extractor = BunExecutableExtractor()
    entry_preview = [
        PEInstructionPreview(0x140001000, "sub", "rsp, 0x28", None, None, None, None, None, None),
        PEInstructionPreview(
            0x140001004, "call", "0x140001020", 0x140001020, 0x1020, ".text", None, None, None
        ),
        PEInstructionPreview(0x140001009, "add", "rsp, 0x28", None, None, None, None, None, None),
        PEInstructionPreview(
            0x14000100D, "jmp", "0x140001040", 0x140001040, 0x1040, ".text", None, None, None
        ),
    ]
    tls_callbacks = [
        PETLSCallback(0x140001180, 0x1180, ".text", 0x380, []),
        PETLSCallback(0x1400011C0, 0x11C0, ".text", 0x3C0, []),
    ]

    classification, reasons = extractor._classify_startup_profile(
        entry_point_section=".text",
        entry_point_preview=entry_preview,
        tls_callbacks=tls_callbacks,
        suspicious_imports=["LoadLibraryA"],
    )

    assert classification == "runtime_bootstrap_likely"
    assert any("TLS callbacks are present" in reason for reason in reasons)


def test_bun_extractor_collects_startup_targets():
    extractor = BunExecutableExtractor()
    data = b""
    pe_header = {
        "image_base": 0x140000000,
        "sections": [],
        "pe_magic": 0x20B,
    }
    entry_preview = [
        PEInstructionPreview(0x140001000, "sub", "rsp, 0x28", None, None, None, None, None, None),
        PEInstructionPreview(
            0x140001004, "call", "0x140001020", 0x140001020, 0x1020, ".text", None, None, None
        ),
        PEInstructionPreview(
            0x14000100D, "jmp", "0x140001040", 0x140001040, 0x1040, ".text", None, None, None
        ),
    ]
    tls_callbacks = [
        PETLSCallback(
            0x140001180,
            0x1180,
            ".text",
            0x380,
            [
                PEInstructionPreview(
                    0x140001180,
                    "call",
                    "0x140001220",
                    0x140001220,
                    0x1220,
                    ".text",
                    None,
                    None,
                    None,
                )
            ],
        )
    ]

    targets = extractor._collect_startup_targets(data, pe_header, {}, entry_preview, tls_callbacks)

    assert [target.source for target in targets] == [
        "entrypoint",
        "entrypoint",
        "tls_callback[0]",
    ]
    assert targets[0].symbolic_label == "text_rva_00001020"
    assert targets[1].symbolic_label == "text_rva_00001040"
    assert targets[2].symbolic_label == "text_rva_00001220"
    assert targets[2].target_address == 0x140001220
    assert targets[0].target_preview == []


def test_bun_extractor_collects_indirect_import_startup_targets():
    extractor = BunExecutableExtractor()
    data = b""
    pe_header = {
        "image_base": 0x140000000,
        "sections": [],
        "pe_magic": 0x20B,
    }
    entry_preview = [
        PEInstructionPreview(
            0x140001000,
            "call",
            "qword ptr [rip + 0x18]",
            None,
            None,
            None,
            "KERNEL32.dll!LoadLibraryA",
            0x14000101E,
            ".idata",
        )
    ]

    targets = extractor._collect_startup_targets(data, pe_header, {}, entry_preview, [])

    assert len(targets) == 1
    assert targets[0].target_address == 0x14000101E
    assert targets[0].target_rva == 0x101E
    assert targets[0].target_section == ".idata"
    assert targets[0].symbolic_label == "kernel32_dll_loadlibrarya"
    assert targets[0].target_resolution == "import_iat"
    assert targets[0].import_target == "KERNEL32.dll!LoadLibraryA"
    assert targets[0].target_preview == []


def test_bun_extractor_builds_symbolic_label_without_section():
    extractor = BunExecutableExtractor()

    label = extractor._build_startup_symbolic_label(
        PEStartupTarget(
            source="entrypoint",
            instruction_address=0x140001000,
            instruction_mnemonic="call",
            target_address=0x140001234,
            target_rva=None,
            target_section=None,
            symbolic_label="",
            target_resolution="direct",
            import_target=None,
            target_preview=[],
        )
    )

    assert label == "va_0000000140001234"


def test_bun_extractor_builds_bounded_startup_graph():
    extractor = BunExecutableExtractor()
    pe_header = {
        "image_base": 0x140000000,
        "sections": [],
        "pe_magic": 0x20B,
    }
    entry_preview = [
        PEInstructionPreview(
            0x140001000, "call", "0x140001020", 0x140001020, 0x1020, ".text", None, None, None
        )
    ]
    tls_callbacks = [PETLSCallback(0x140001180, 0x1180, ".text", 0x380, [])]
    startup_targets = [
        PEStartupTarget(
            source="entrypoint",
            instruction_address=0x140001000,
            instruction_mnemonic="call",
            target_address=0x140001020,
            target_rva=0x1020,
            target_section=".text",
            symbolic_label="text_rva_00001020",
            target_resolution="direct",
            import_target=None,
            target_preview=[
                PEInstructionPreview(
                    0x140001020,
                    "call",
                    "0x140001060",
                    0x140001060,
                    0x1060,
                    ".text",
                    None,
                    None,
                    None,
                ),
                PEInstructionPreview(
                    0x140001025,
                    "call",
                    "qword ptr [rip + 0x18]",
                    None,
                    None,
                    None,
                    "KERNEL32.dll!GetProcAddress",
                    0x140002000,
                    ".idata",
                ),
            ],
        )
    ]

    graph = extractor._build_startup_graph(pe_header, entry_preview, tls_callbacks, startup_targets)

    assert graph.roots == ["entrypoint", "tls_callback[0]"]
    assert graph.truncated is False
    assert {node.label for node in graph.nodes} >= {
        "entrypoint",
        "tls_callback[0]",
        "text_rva_00001020",
        "text_rva_00001060",
        "kernel32_dll_getprocaddress",
    }
    assert any(
        edge.source_label == "entrypoint" and edge.target_label == "text_rva_00001020"
        for edge in graph.edges
    )
    assert any(
        edge.source_label == "text_rva_00001020"
        and edge.target_label == "text_rva_00001060"
        and edge.depth == 2
        for edge in graph.edges
    )
    assert any(
        edge.source_label == "text_rva_00001020"
        and edge.target_label == "kernel32_dll_getprocaddress"
        and edge.target_resolution == "import_iat"
        for edge in graph.edges
    )


def test_bun_extractor_detects_bun_handoff_signals(tmp_path: Path):
    binary_path = _write_bun_fixture(tmp_path)

    summary = BunExecutableExtractor().analyze_pe_stub(str(binary_path))

    assert summary is not None
    signal_kinds = {signal.kind for signal in summary.handoff_signals}
    assert "embedded_bun_section" in signal_kinds
    assert "bun_bundle_trailer" in signal_kinds
    assert "bun_virtual_path_marker" in signal_kinds
    assert "bundled_javascript_marker" in signal_kinds


def test_bun_extractor_collects_cross_references(tmp_path: Path):
    binary_path = _write_bun_fixture(tmp_path)

    summary = BunExecutableExtractor().analyze_pe_stub(str(binary_path))

    assert summary is not None
    cross_reference_kinds = {reference.kind for reference in summary.cross_references}
    assert "bun_virtual_path" in cross_reference_kinds
    assert "source_map_marker" in cross_reference_kinds
    assert "compile_argv" in cross_reference_kinds


def test_bun_extractor_builds_runtime_readiness_surface():
    extractor = BunExecutableExtractor()
    pe_header = {
        "image_base": 0x140000000,
        "entry_point_rva": 0x1000,
        "sections": [
            {
                "name": ".text",
                "virtual_size": 0x400,
                "virtual_address": 0x1000,
                "raw_size": 0x400,
                "raw_address": 0x200,
            },
            {
                "name": ".bun",
                "virtual_size": 0x400,
                "virtual_address": 0x2000,
                "raw_size": 0x400,
                "raw_address": 0x600,
            },
        ],
    }
    tls_callbacks = [PETLSCallback(0x140001180, 0x1180, ".text", 0x380, [])]
    startup_targets = [
        PEStartupTarget(
            source="entrypoint",
            instruction_address=0x140001004,
            instruction_mnemonic="call",
            target_address=0x140002020,
            target_rva=0x2020,
            target_section=".bun",
            symbolic_label="bun_rva_00002020",
            target_resolution="direct",
            import_target=None,
            target_preview=[],
        ),
        PEStartupTarget(
            source="entrypoint",
            instruction_address=0x140001020,
            instruction_mnemonic="call",
            target_address=0x140002100,
            target_rva=0x2100,
            target_section=".idata",
            symbolic_label="kernel32_dll_getprocaddress",
            target_resolution="import_iat",
            import_target="KERNEL32.dll!GetProcAddress",
            target_preview=[],
        ),
    ]
    startup_graph = extractor._build_startup_graph(pe_header, [], tls_callbacks, startup_targets)
    handoff_signals = []

    readiness = extractor._build_runtime_readiness(
        pe_header=pe_header,
        entry_point_section=".text",
        tls_callbacks=tls_callbacks,
        startup_targets=startup_targets,
        startup_graph=startup_graph,
        handoff_signals=handoff_signals,
    )

    breakpoint_labels = {point.label for point in readiness.breakpoints}
    dump_labels = {point.label for point in readiness.dump_points}
    assert "entrypoint" in breakpoint_labels
    assert "tls_callback[0]" in breakpoint_labels
    assert "bun_rva_00002020" in breakpoint_labels
    assert "callsite_kernel32_dll_getprocaddress" in breakpoint_labels
    assert "bun_rva_00002020" in dump_labels
    assert any("TLS callbacks" in note for note in readiness.notes)


def test_bun_extractor_builds_dump_guidance():
    extractor = BunExecutableExtractor()
    readiness = extractor._build_runtime_readiness(
        pe_header={"image_base": 0x140000000, "entry_point_rva": 0x1000, "sections": []},
        entry_point_section=".text",
        tls_callbacks=[],
        startup_targets=[
            PEStartupTarget(
                source="entrypoint",
                instruction_address=0x140001004,
                instruction_mnemonic="call",
                target_address=0x140002020,
                target_rva=0x2020,
                target_section=".bun",
                symbolic_label="bun_rva_00002020",
                target_resolution="direct",
                import_target=None,
                target_preview=[],
            ),
            PEStartupTarget(
                source="entrypoint",
                instruction_address=0x140001020,
                instruction_mnemonic="call",
                target_address=0x140002100,
                target_rva=0x2100,
                target_section=".idata",
                symbolic_label="kernel32_dll_getprocaddress",
                target_resolution="import_iat",
                import_target="KERNEL32.dll!GetProcAddress",
                target_preview=[],
            ),
        ],
        startup_graph=extractor._build_startup_graph(
            {
                "image_base": 0x140000000,
                "entry_point_rva": 0x1000,
                "sections": [
                    {
                        "name": ".bun",
                        "virtual_size": 0x400,
                        "virtual_address": 0x2000,
                        "raw_size": 0x400,
                        "raw_address": 0x600,
                    }
                ],
            },
            [],
            [],
            [
                PEStartupTarget(
                    source="entrypoint",
                    instruction_address=0x140001004,
                    instruction_mnemonic="call",
                    target_address=0x140002020,
                    target_rva=0x2020,
                    target_section=".bun",
                    symbolic_label="bun_rva_00002020",
                    target_resolution="direct",
                    import_target=None,
                    target_preview=[],
                )
            ],
        ),
        handoff_signals=[
            PEHandoffSignal(
                "embedded_bun_section", "section_table", "Embedded Bun section", "high"
            ),
        ],
    )
    guidance = extractor._build_dump_guidance(
        startup_classification="runtime_bootstrap_likely",
        suspicious_imports=["GetProcAddress", "VirtualProtect"],
        runtime_readiness=readiness,
        handoff_signals=[
            PEHandoffSignal(
                "embedded_bun_section", "section_table", "Embedded Bun section", "high"
            ),
        ],
    )

    action_kinds = {action.kind for action in guidance.actions}
    assert guidance.recommended is True
    assert "memory_dump" in action_kinds
    assert "import_reconstruction" in action_kinds


def test_bun_extractor_recommends_postprocessing_hooks():
    extractor = BunExecutableExtractor()
    hooks = extractor._recommend_postprocessing_hooks(
        source_text='var x=require("ws");\nfunction n(a,b){return a+b}\n//# sourceMappingURL=app.js.map\n',
        runtime_features=["bun_import_meta_require"],
        shims_applied=["import.meta.require replacement"],
        sourcemap_provenance=BunSourcemapProvenance(
            origin="referenced_virtual_path",
            byte_size=128,
            sha256="abc",
            parse_status="valid_json",
            file_field="app.js",
            source_count=2,
            file_matches_source_name=True,
        ),
    )

    tool_names = [hook["tool"] for hook in hooks]
    assert tool_names[0] == "tsmap-extract"
    assert "recover-source" in tool_names
    assert "webcrack" in tool_names
    assert "bundle-breaker" in tool_names
    assert "wakaru" in tool_names
    assert "restringer" in tool_names
    by_tool = {hook["tool"]: hook for hook in hooks}
    assert by_tool["tsmap-extract"]["category"] == "sourcemap_reconstruction"
    assert "tsmap-extract" in by_tool["tsmap-extract"]["command_template"]
    assert by_tool["webcrack"]["category"] == "debundling"
    assert "webcrack" in by_tool["webcrack"]["command_template"]
    assert by_tool["bundle-breaker"]["category"] == "debundling"
    assert by_tool["wakaru"]["category"] == "readability_normalization"
    assert by_tool["restringer"]["category"] == "deobfuscation"


def test_bun_extractor_includes_rip_relative_preview_hints(tmp_path: Path):
    section_blob = bytearray(b"\x48\x8b\x05\x19\x00\x00\x00\xc3")
    section_blob.extend(b"\x00" * (0x20 - len(section_blob)))
    section_blob.extend(struct.pack("<Q", 0x1122334455667788))
    binary_path = tmp_path / "sample_bun_preview64.exe"
    binary_path.write_bytes(_build_pe64_with_bun_section(bytes(section_blob)))

    summary = BunExecutableExtractor().analyze_pe_stub(str(binary_path))

    assert summary is not None
    assert summary.machine == "0x8664"
    assert summary.entry_point_preview[0].mnemonic == "mov"
    assert summary.entry_point_preview[0].rip_relative_address == 0x140001020
    assert summary.entry_point_preview[0].rip_relative_section == ".bun"
    assert summary.entry_point_preview[0].import_target is None


def test_bun_extractor_extracts_javascript_from_pe_bundle(tmp_path: Path):
    binary_path = _write_bun_fixture(tmp_path)
    output_path = tmp_path / "extracted.js"

    result = BunExecutableExtractor().extract_javascript(str(binary_path), str(output_path))

    assert result.success is True
    assert result.output_path == str(output_path)
    assert output_path.exists()
    extracted = output_path.read_text(encoding="utf-8")
    assert extracted.startswith("// @bun")
    assert "console.log('hello from bun');" in extracted
    assert "\x00" not in extracted


def test_bun_extractor_parses_module_graph_and_recovers_virtual_files(tmp_path: Path):
    binary_path = _write_bun_fixture(tmp_path)
    output_dir = tmp_path / "bunfs"
    extractor = BunExecutableExtractor()

    graph = extractor.parse_module_graph(str(binary_path))
    recovery = extractor.recover_virtual_files(str(binary_path), str(output_dir))

    assert graph is not None
    assert graph.compile_exec_argv == "--compile"
    assert len(graph.modules) == 2
    assert graph.modules[0].virtual_path == "B:/~BUN/root/src/index.js"
    assert _path_endswith(graph.modules[0].recovered_path, "root/src/index.js")
    assert recovery.success is True
    assert recovery.manifest_path is not None
    manifest = json.loads(Path(recovery.manifest_path).read_text(encoding="utf-8"))
    assert manifest["modules"][0]["sourcemap_provenance"]["origin"] == "module_graph_embedded"
    assert manifest["modules"][0]["sourcemap_provenance"]["parse_status"] == "non_json_payload"
    assert (output_dir / "root" / "src" / "index.js").exists()
    assert (output_dir / "root" / "src" / "index.js.bunmap").exists()
    assert (output_dir / "root" / "package.json").exists()


def test_bun_extractor_parses_short_module_graph_layout(tmp_path: Path):
    binary_path = _write_bun_short_record_fixture(tmp_path)
    output_dir = tmp_path / "bunfs_short"
    extractor = BunExecutableExtractor()

    graph = extractor.parse_module_graph(str(binary_path))
    recovery = extractor.recover_virtual_files(str(binary_path), str(output_dir))

    assert graph is not None
    assert graph.module_layout == "short"
    assert len(graph.modules) == 1
    assert graph.modules[0].virtual_path == "B:/~BUN/root/droid.exe"
    assert graph.modules[0].content_offset == 23
    assert recovery.success is True
    assert recovery.recovery_mode == "module_graph"
    assert (output_dir / "root" / "droid.exe").exists()
    assert "short bun payload" in (output_dir / "root" / "droid.exe").read_text(encoding="utf-8")


def test_bun_extractor_parses_extended_short_module_graph_layout(tmp_path: Path):
    binary_path = _write_bun_extended_short_record_fixture(tmp_path)
    output_dir = tmp_path / "bunfs_short_ext"
    extractor = BunExecutableExtractor()

    graph = extractor.parse_module_graph(str(binary_path))
    recovery = extractor.recover_virtual_files(str(binary_path), str(output_dir))

    assert graph is not None
    assert graph.module_layout == "short_ext"
    assert len(graph.modules) == 1
    assert graph.modules[0].virtual_path == "B:/~BUN/root/app.js"
    assert graph.modules[0].content_offset == 20
    assert recovery.success is True
    assert recovery.recovery_mode == "module_graph"
    assert (output_dir / "root" / "app.js").exists()
    assert "extended short bun payload" in (output_dir / "root" / "app.js").read_text(
        encoding="utf-8"
    )


def test_bun_extractor_recovers_metadata_when_module_graph_layout_is_unknown(tmp_path: Path):
    binary_path = _write_bun_fallback_fixture(tmp_path)
    output_dir = tmp_path / "bunfs_fallback"
    extractor = BunExecutableExtractor()

    graph = extractor.parse_module_graph(str(binary_path))
    recovery = extractor.recover_virtual_files(str(binary_path), str(output_dir))

    assert graph is None
    assert recovery.success is True
    assert recovery.recovery_mode == "path_scan"
    assert recovery.manifest_path is not None
    manifest = json.loads(Path(recovery.manifest_path).read_text(encoding="utf-8"))
    assert manifest["recovery_mode"] == "path_scan"
    assert manifest["offsets"]["modules_length"] == 35
    assert manifest["discovered_path_count"] == 1
    assert manifest["discovered_paths"][0]["virtual_path"] == "B:/~BUN/root/droid.exe"
    assert _path_endswith(manifest["artifacts"]["primary_source_path"], "root/droid.exe")
    assert (output_dir / "root" / "droid.exe").exists()
    assert "fallback bun payload" in (output_dir / "root" / "droid.exe").read_text(encoding="utf-8")
    assert (output_dir / "bundle_tail.bin").exists()
    assert (output_dir / "module_records.bin").exists()
    assert (output_dir / "discovered_paths.txt").exists()


def test_bun_extractor_recovers_inline_sourcemap_during_path_scan_fallback(tmp_path: Path):
    binary_path = _write_bun_fallback_fixture_with_inline_sourcemap(tmp_path)
    output_dir = tmp_path / "bunfs_fallback_sourcemap"
    extractor = BunExecutableExtractor()

    recovery = extractor.recover_virtual_files(str(binary_path), str(output_dir))

    assert recovery.success is True
    assert recovery.recovery_mode == "path_scan"
    manifest = json.loads(Path(recovery.manifest_path).read_text(encoding="utf-8"))
    assert _path_endswith(manifest["artifacts"]["primary_source_path"], "root/droid.exe")
    assert _path_endswith(
        manifest["artifacts"]["recovered_sourcemap_path"], "root/droid.exe.bunmap"
    )
    assert manifest["artifacts"]["recovered_sourcemap_provenance"]["origin"] == "inline_data_url"
    assert manifest["artifacts"]["recovered_sourcemap_provenance"]["parse_status"] == "valid_json"
    assert (
        manifest["artifacts"]["recovered_sourcemap_provenance"]["file_matches_source_name"] is True
    )
    sourcemap = json.loads((output_dir / "root" / "droid.exe.bunmap").read_text(encoding="utf-8"))
    assert sourcemap["version"] == 3
    assert sourcemap["file"] == "droid.exe"


def test_bun_extractor_recovers_external_sourcemap_during_path_scan_fallback(tmp_path: Path):
    binary_path = _write_bun_fallback_fixture_with_external_sourcemap(tmp_path)
    output_dir = tmp_path / "bunfs_fallback_external_sourcemap"
    extractor = BunExecutableExtractor()

    recovery = extractor.recover_virtual_files(str(binary_path), str(output_dir))

    assert recovery.success is True
    assert recovery.recovery_mode == "path_scan"
    manifest = json.loads(Path(recovery.manifest_path).read_text(encoding="utf-8"))
    assert _path_endswith(manifest["artifacts"]["primary_source_path"], "root/droid.exe")
    assert _path_endswith(manifest["artifacts"]["recovered_sourcemap_path"], "root/droid.exe.map")
    assert (
        manifest["artifacts"]["recovered_sourcemap_provenance"]["origin"]
        == "referenced_virtual_path"
    )
    assert manifest["artifacts"]["recovered_sourcemap_provenance"]["parse_status"] == "valid_json"
    assert (
        manifest["artifacts"]["recovered_sourcemap_provenance"]["file_matches_source_name"] is True
    )
    sourcemap = json.loads((output_dir / "root" / "droid.exe.map").read_text(encoding="utf-8"))
    assert sourcemap["version"] == 3
    assert sourcemap["sources"] == ["droid.ts"]


def test_bun_extractor_recovers_supporting_json_artifacts_during_path_scan_fallback(tmp_path: Path):
    binary_path = _write_bun_fallback_fixture_with_supporting_json(tmp_path)
    output_dir = tmp_path / "bunfs_fallback_supporting_json"
    extractor = BunExecutableExtractor()

    recovery = extractor.recover_virtual_files(str(binary_path), str(output_dir))

    assert recovery.success is True
    assert recovery.recovery_mode == "path_scan"
    manifest = json.loads(Path(recovery.manifest_path).read_text(encoding="utf-8"))
    supporting = manifest["artifacts"]["recovered_supporting_artifacts"]
    assert any(_path_endswith(path, "root/package.json") for path in supporting)
    assert any(_path_endswith(path, "root/tsconfig.json") for path in supporting)
    package_json = json.loads((output_dir / "root" / "package.json").read_text(encoding="utf-8"))
    assert package_json["name"] == "fallback-demo"
    tsconfig = json.loads((output_dir / "root" / "tsconfig.json").read_text(encoding="utf-8"))
    assert tsconfig["compilerOptions"]["module"] == "esnext"


def test_bun_extractor_recovers_supporting_text_artifacts_during_path_scan_fallback(tmp_path: Path):
    binary_path = _write_bun_fallback_fixture_with_supporting_text(tmp_path)
    output_dir = tmp_path / "bunfs_fallback_supporting_text"
    extractor = BunExecutableExtractor()

    recovery = extractor.recover_virtual_files(str(binary_path), str(output_dir))

    assert recovery.success is True
    assert recovery.recovery_mode == "path_scan"
    manifest = json.loads(Path(recovery.manifest_path).read_text(encoding="utf-8"))
    supporting = manifest["artifacts"]["recovered_supporting_artifacts"]
    assert any(_path_endswith(path, "root/.env") for path in supporting)
    assert any(_path_endswith(path, "root/config.ts") for path in supporting)
    env_text = (output_dir / "root" / ".env").read_text(encoding="utf-8")
    assert "API_BASE=https://example.test" in env_text
    config_text = (output_dir / "root" / "config.ts").read_text(encoding="utf-8")
    assert "export const config" in config_text


def test_bun_extractor_recovers_supporting_wasm_artifact_during_path_scan_fallback(tmp_path: Path):
    binary_path = _write_bun_fallback_fixture_with_supporting_wasm(tmp_path)
    output_dir = tmp_path / "bunfs_fallback_supporting_wasm"
    extractor = BunExecutableExtractor()

    recovery = extractor.recover_virtual_files(str(binary_path), str(output_dir))

    assert recovery.success is True
    assert recovery.recovery_mode == "path_scan"
    manifest = json.loads(Path(recovery.manifest_path).read_text(encoding="utf-8"))
    supporting = manifest["artifacts"]["recovered_supporting_artifacts"]
    assert any(_path_endswith(path, "root/module.wasm") for path in supporting)
    wasm_bytes = (output_dir / "root" / "module.wasm").read_bytes()
    assert wasm_bytes.startswith(b"\x00asm\x01\x00\x00\x00")


def test_bun_extractor_recovers_supporting_web_and_config_artifacts_during_path_scan_fallback(
    tmp_path: Path,
):
    binary_path = _write_bun_fallback_fixture_with_supporting_web_and_config(tmp_path)
    output_dir = tmp_path / "bunfs_fallback_supporting_web_and_config"
    extractor = BunExecutableExtractor()

    recovery = extractor.recover_virtual_files(str(binary_path), str(output_dir))

    assert recovery.success is True
    assert recovery.recovery_mode == "path_scan"
    manifest = json.loads(Path(recovery.manifest_path).read_text(encoding="utf-8"))
    supporting = manifest["artifacts"]["recovered_supporting_artifacts"]
    assert any(_path_endswith(path, "root/styles.css") for path in supporting)
    assert any(_path_endswith(path, "root/index.html") for path in supporting)
    assert any(_path_endswith(path, "root/app.yaml") for path in supporting)
    assert any(_path_endswith(path, "root/bunfig.toml") for path in supporting)
    assert "background: #111" in (output_dir / "root" / "styles.css").read_text(encoding="utf-8")
    assert (
        "<!doctype html>"
        in (output_dir / "root" / "index.html").read_text(encoding="utf-8").lower()
    )
    assert "name: fallback-demo" in (output_dir / "root" / "app.yaml").read_text(encoding="utf-8")
    assert "[install]" in (output_dir / "root" / "bunfig.toml").read_text(encoding="utf-8")


def test_bun_extractor_recovers_metadata_with_invalid_offsets_path_scan(tmp_path: Path):
    binary_path = _write_bun_fallback_fixture_with_invalid_offsets(tmp_path)
    output_dir = tmp_path / "bunfs_invalid_offsets"
    extractor = BunExecutableExtractor()

    graph = extractor.parse_module_graph(str(binary_path))
    recovery = extractor.recover_virtual_files(str(binary_path), str(output_dir))

    assert graph is None
    assert recovery.success is True
    manifest = json.loads(Path(recovery.manifest_path).read_text(encoding="utf-8"))
    assert manifest["recovery_mode"] == "path_scan"
    assert manifest["offsets"] is None
    assert manifest["artifacts"]["module_records_path"] is None
    assert _path_endswith(manifest["artifacts"]["primary_source_path"], "root/droid.exe")
    assert "invalid offsets fallback" in (output_dir / "root" / "droid.exe").read_text(
        encoding="utf-8"
    )


def test_bun_extractor_prefers_code_path_for_sparse_mixed_path_scan(tmp_path: Path):
    binary_path = _write_bun_fallback_fixture_with_sparse_mixed_paths(tmp_path)
    output_dir = tmp_path / "bunfs_sparse_mixed"
    extractor = BunExecutableExtractor()

    recovery = extractor.recover_virtual_files(str(binary_path), str(output_dir))

    assert recovery.success is True
    manifest = json.loads(Path(recovery.manifest_path).read_text(encoding="utf-8"))
    assert manifest["recovery_mode"] == "path_scan"
    assert manifest["discovered_path_count"] == 3
    assert _path_endswith(manifest["artifacts"]["primary_source_path"], "root/src/main.ts")
    supporting = manifest["artifacts"]["recovered_supporting_artifacts"]
    assert any(_path_endswith(path, "root/package.json") for path in supporting)
    assert any(_path_endswith(path, "root/.env") for path in supporting)
    assert "sparse mixed fallback payload" in (output_dir / "root" / "src" / "main.ts").read_text(
        encoding="utf-8"
    )
    package_json = json.loads((output_dir / "root" / "package.json").read_text(encoding="utf-8"))
    assert package_json["name"] == "sparse-demo"
    env_text = (output_dir / "root" / ".env").read_text(encoding="utf-8")
    assert "MODE=prod" in env_text


def test_bun_extractor_normalizes_recovered_project_workspace(tmp_path: Path):
    source_path = tmp_path / "droid.exe"
    source_path.write_text(
        (
            "// @bun\n"
            'import { dlopen, FFIType, ptr } from "bun:ffi";\n'
            'import WebSocket from "ws";\n'
            'import signer from "@aws-sdk/signature-v4a/client";\n'
            'const fs = import.meta.require("fs");\n'
            'const noisy = `require("iconv-lite")`;\n'
            "await Promise.resolve();\n"
            "console.log(WebSocket, signer, fs, noisy);\n"
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "normalized"

    result = BunExecutableExtractor().normalize_project(str(source_path), str(output_dir))

    assert result.success is True
    assert result.entrypoint_path is not None
    assert result.sea_entrypoint_path is not None
    assert result.sea_config_path is not None
    assert result.package_json_path is not None
    assert result.manifest_path is not None
    assert result.inferred_dependencies == ["ws", "@aws-sdk/signature-v4a"]
    assert "bun_import_meta_require" in result.runtime_features
    assert "await_usage" in result.runtime_features
    assert "import.meta.require replacement" in result.shims_applied
    assert "bun:ffi replacement" in result.shims_applied
    assert any(
        check["check"] == "dependency_import_sanity" and check["severity"] == "warning"
        for check in result.semantic_checks
    )
    assert any(
        check["check"] == "bun_require_shim" and check["severity"] == "info"
        for check in result.semantic_checks
    )

    normalized_source = Path(result.entrypoint_path).read_text(encoding="utf-8")
    assert normalized_source.startswith('// @bun\nimport { createRequire } from "module";\n')
    assert 'import { dlopen, FFIType, ptr } from "./reveng-bun-ffi-shim.mjs";' in normalized_source
    assert 'import { createRequire } from "module";' in normalized_source
    assert 'import WebSocket from "ws";' in normalized_source
    assert 'createRequire(import.meta.url)("fs")' in normalized_source
    bun_ffi_shim = Path(result.output_dir) / "reveng-bun-ffi-shim.mjs"
    assert bun_ffi_shim.exists()
    assert 'export const dlopen = unsupported("dlopen");' in bun_ffi_shim.read_text(
        encoding="utf-8"
    )

    package_json = json.loads(Path(result.package_json_path).read_text(encoding="utf-8"))
    assert package_json["type"] == "module"
    assert package_json["scripts"]["start"] == "node ./droid.mjs"
    assert package_json["dependencies"] == {"ws": "*", "@aws-sdk/signature-v4a": "*"}
    assert package_json["reveng"]["inferred_dependencies"] == ["ws", "@aws-sdk/signature-v4a"]
    assert package_json["reveng"]["dependency_analysis"]["required_packages"] == [
        "ws",
        "@aws-sdk/signature-v4a",
    ]
    assert package_json["reveng"]["dependency_analysis"]["builtin_modules"] == ["fs"]
    assert package_json["reveng"]["dependency_analysis"]["ignored_package_strings"] == [
        "iconv-lite"
    ]
    assert package_json["reveng"]["sea_entrypoint_path"].endswith("sea-entry.cjs")
    assert package_json["reveng"]["sea_config_path"].endswith("sea-config.json")
    assert package_json["reveng"]["sea_companion_files"] == ["droid.mjs", "reveng-bun-ffi-shim.mjs"]
    assert (
        package_json["reveng"]["suggested_install_command"]
        == "npm install ws @aws-sdk/signature-v4a"
    )
    assert (
        package_json["reveng"]["suggested_postject_install_command"]
        == "npm install --save-dev postject"
    )
    assert any(
        "ignored embedded package-name strings" in warning
        for warning in package_json["reveng"]["warnings"]
    )
    assert any(
        "built-in modules were detected" in warning
        for warning in package_json["reveng"]["warnings"]
    )
    assert any(
        check["check"] == "dependency_import_sanity"
        for check in package_json["reveng"]["semantic_checks"]
    )
    assert any(
        hook["tool"] == "webcrack" for hook in package_json["reveng"]["postprocessing_hooks"]
    )
    assert any(
        hook["tool"] == "bundle-breaker" for hook in package_json["reveng"]["postprocessing_hooks"]
    )
    assert any(
        "command_template" in hook for hook in package_json["reveng"]["postprocessing_hooks"]
    )
    assert any(
        hook["tool"] == "webcrack" for hook in package_json["reveng"]["postprocessing_hooks"]
    )

    manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
    assert manifest["entrypoint_path"].endswith("droid.mjs")
    assert manifest["sea_entrypoint_path"].endswith("sea-entry.cjs")
    assert manifest["sea_config_path"].endswith("sea-config.json")
    assert manifest["inferred_dependencies"] == ["ws", "@aws-sdk/signature-v4a"]
    assert manifest["dependency_analysis"]["required_packages"] == ["ws", "@aws-sdk/signature-v4a"]
    assert manifest["dependency_analysis"]["builtin_modules"] == ["fs"]
    assert manifest["dependency_analysis"]["ignored_package_strings"] == ["iconv-lite"]
    assert manifest["sea_companion_files"] == ["droid.mjs", "reveng-bun-ffi-shim.mjs"]
    assert any(check["check"] == "bun_require_shim" for check in manifest["semantic_checks"])
    assert any(hook["tool"] == "webcrack" for hook in manifest["postprocessing_hooks"])
    assert any(hook["tool"] == "restringer" for hook in manifest["postprocessing_hooks"])
    assert all(
        "category" in hook and "command_template" in hook
        for hook in manifest["postprocessing_hooks"]
    )

    sea_entry = Path(result.sea_entrypoint_path).read_text(encoding="utf-8")
    assert 'sea = require("node:sea");' in sea_entry
    assert "const runtimeRoot = resolveRuntimeRoot();" in sea_entry
    assert 'await import(pathToFileURL(path.join(runtimeRoot, "droid.mjs")).href);' in sea_entry


def test_bun_extractor_builds_node_sea_from_normalized_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source_path = tmp_path / "droid.exe"
    source_path.write_text(
        '// @bun\nimport WebSocket from "ws";\nconst fs = import.meta.require("fs");\n',
        encoding="utf-8",
    )
    normalized = BunExecutableExtractor().normalize_project(
        str(source_path), str(tmp_path / "normalized")
    )
    assert normalized.success is True
    assert normalized.sea_config_path is not None

    fake_node = tmp_path / "node.exe"
    fake_node.write_bytes(b"node")

    def fake_run(command, cwd, capture_output, text, check):
        if command[1] == "install":
            ws_package = Path(cwd, "node_modules", "ws", "package.json")
            ws_package.parent.mkdir(parents=True, exist_ok=True)
            ws_package.write_text('{"name":"ws"}', encoding="utf-8")
        if "--experimental-sea-config" in command:
            Path(cwd, "sea-prep.blob").write_bytes(b"blob")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(
        "reveng.tools.anti_analysis.bun_extractor.shutil.which", lambda _: str(fake_node)
    )
    monkeypatch.setattr(
        "reveng.tools.anti_analysis.bun_extractor.subprocess.run",
        fake_run,
    )

    result = BunExecutableExtractor().build_node_sea(str(tmp_path / "normalized"))

    assert result.success is True
    assert result.output_path is not None
    assert result.sea_blob_path is not None
    assert Path(result.output_path).exists()
    assert Path(result.sea_blob_path).exists()
    assert result.verification is not None
    assert result.verification["status"] in {"pass", "pass_with_warnings"}
    assert any(check["check"] == "sea_blob_generated" for check in result.verification["checks"])
    assert any(
        check["check"] == "dependency_manifest_alignment" for check in result.verification["checks"]
    )
    assert any(
        check["check"] == "sea_asset_bundle_coverage" for check in result.verification["checks"]
    )
    assert any(check["check"] == "standalone_copy_probe" for check in result.verification["checks"])
    assert any("install ws postject --silent" in command for command in result.commands_run)
    assert any("--experimental-sea-config" in command for command in result.commands_run)
    sea_config = json.loads(Path(normalized.sea_config_path).read_text(encoding="utf-8"))
    assert sea_config["assets"]["droid.mjs"] == "droid.mjs"
    assert sea_config["assets"]["package.json"] == "package.json"
    assert sea_config["assets"]["node_modules/ws/package.json"] == "node_modules/ws/package.json"


def test_bun_extractor_builds_node_sea_from_relative_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.chdir(tmp_path)
    Path("droid.exe").write_text(
        '// @bun\nimport WebSocket from "ws";\nconst fs = import.meta.require("fs");\n',
        encoding="utf-8",
    )
    normalized = BunExecutableExtractor().normalize_project("droid.exe", "normalized")
    assert normalized.success is True

    fake_node = tmp_path / "node.exe"
    fake_node.write_bytes(b"node")

    def fake_run(command, cwd, capture_output, text, check):
        if command[1] == "install":
            ws_package = Path(cwd, "node_modules", "ws", "package.json")
            ws_package.parent.mkdir(parents=True, exist_ok=True)
            ws_package.write_text('{"name":"ws"}', encoding="utf-8")
        if "--experimental-sea-config" in command:
            assert command[-1] == "sea-config.json"
            Path(cwd, "sea-prep.blob").write_bytes(b"blob")
        if "NODE_SEA_BLOB" in command:
            blob_index = command.index("NODE_SEA_BLOB")
            assert Path(command[blob_index - 1]).is_absolute()
            assert Path(command[blob_index + 1]).is_absolute()
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(
        "reveng.tools.anti_analysis.bun_extractor.shutil.which", lambda _: str(fake_node)
    )
    monkeypatch.setattr(
        "reveng.tools.anti_analysis.bun_extractor.subprocess.run",
        fake_run,
    )

    result = BunExecutableExtractor().build_node_sea("normalized")

    assert result.success is True
    assert result.output_path == str(Path("normalized") / "bun-sea.exe")
    assert result.sea_blob_path == str(Path("normalized") / "sea-prep.blob")
    sea_config = json.loads(Path("normalized", "sea-config.json").read_text(encoding="utf-8"))
    assert sea_config["assets"]["droid.mjs"] == "droid.mjs"


def test_bun_differential_validation_tracks_expected_rewrites(tmp_path: Path):
    source_path = tmp_path / "droid.exe"
    source_path.write_text(
        (
            "// @bun\n"
            'import { dlopen } from "bun:ffi";\n'
            'import WebSocket from "ws";\n'
            'const fs = import.meta.require("fs");\n'
            "await Promise.resolve();\n"
        ),
        encoding="utf-8",
    )
    extractor = BunExecutableExtractor()
    normalized = extractor.normalize_project(str(source_path), str(tmp_path / "normalized"))

    differential = extractor._build_differential_validation(str(source_path), normalized)

    assert differential["status"] == "pass"
    assert differential["content_changed"] is True
    assert "await_usage" in differential["preserved_runtime_features"]
    assert any(
        check["check"] == "dependency_runtime_parity" and check["status"] == "pass"
        for check in differential["checks"]
    )
    assert any(
        check["check"] == "bun_require_rewrite_coverage" and check["status"] == "pass"
        for check in differential["checks"]
    )
    assert any(
        check["check"] == "bun_ffi_rewrite_coverage" and check["status"] == "pass"
        for check in differential["checks"]
    )
    assert "bun:ffi -> ./reveng-bun-ffi-shim.mjs" in differential["expected_rewrites"]
    assert (
        differential["artifacts"]["canonical_input"]["sha256"]
        != differential["artifacts"]["normalized_entrypoint"]["sha256"]
    )


def test_bun_extractor_rewrites_minified_bun_ffi_imports(tmp_path: Path):
    source_path = tmp_path / "minified.exe"
    source_path.write_text(
        (
            "// @bun\n"
            'import{dlopen as load,FFIType as ffiType,ptr}from"bun:ffi";'
            "console.log(load, ffiType, ptr);\n"
        ),
        encoding="utf-8",
    )

    result = BunExecutableExtractor().normalize_project(
        str(source_path), str(tmp_path / "normalized")
    )

    assert result.success is True
    assert "bun:ffi replacement" in result.shims_applied
    normalized_source = Path(result.entrypoint_path).read_text(encoding="utf-8")
    assert 'import{dlopen as load,FFIType as ffiType,ptr}from"./reveng-bun-ffi-shim.mjs";' in (
        normalized_source
    )
    assert (Path(result.output_dir) / "reveng-bun-ffi-shim.mjs").exists()


def test_bun_extractor_bootstraps_bun_global_usage(tmp_path: Path):
    source_path = tmp_path / "bun-global.exe"
    source_path.write_text(
        (
            "// @bun\n"
            "var {$: runner} = globalThis.Bun;\n"
            "const selfPath = Bun.fileURLToPath(import.meta.url);\n"
            "console.log(runner, selfPath);\n"
        ),
        encoding="utf-8",
    )

    result = BunExecutableExtractor().normalize_project(
        str(source_path), str(tmp_path / "normalized")
    )

    assert result.success is True
    assert "bun global bootstrap" in result.shims_applied
    normalized_source = Path(result.entrypoint_path).read_text(encoding="utf-8")
    assert normalized_source.startswith('// @bun\nimport "./reveng-bun-global-shim.mjs";\n')
    bun_global_shim = Path(result.output_dir) / "reveng-bun-global-shim.mjs"
    assert bun_global_shim.exists()
    assert "globalThis.Bun = bunShim;" in bun_global_shim.read_text(encoding="utf-8")


def test_bun_differential_validation_tracks_bun_global_bootstrap(tmp_path: Path):
    source_path = tmp_path / "bun-global-diff.exe"
    source_path.write_text(
        (
            "// @bun\n"
            "const selfPath = Bun.fileURLToPath(import.meta.url);\n"
            "console.log(selfPath);\n"
        ),
        encoding="utf-8",
    )

    extractor = BunExecutableExtractor()
    normalized = extractor.normalize_project(str(source_path), str(tmp_path / "normalized"))
    differential = extractor._build_differential_validation(str(source_path), normalized)

    assert differential["status"] == "pass"
    assert any(
        check["check"] == "bun_global_bootstrap_coverage" and check["status"] == "pass"
        for check in differential["checks"]
    )
    assert (
        "Bun global bootstrap -> ./reveng-bun-global-shim.mjs" in differential["expected_rewrites"]
    )


def test_bun_sea_workflow_reports_differential_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    binary_path = _write_bun_fixture(tmp_path)
    fake_node = tmp_path / "node.exe"
    fake_node.write_bytes(b"node")

    def fake_run(command, cwd, capture_output, text, check):
        if "--experimental-sea-config" in command:
            Path(cwd, "sea-prep.blob").write_bytes(b"blob")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(
        "reveng.tools.anti_analysis.bun_extractor.shutil.which", lambda _: str(fake_node)
    )
    monkeypatch.setattr(
        "reveng.tools.anti_analysis.bun_extractor.subprocess.run",
        fake_run,
    )

    workflow = run_bun_sea_workflow(str(binary_path), output_dir=str(tmp_path / "workflow_out"))

    assert workflow.status == "success"
    assert workflow.differential_validation is not None
    assert workflow.differential_validation["status"] == "pass"
    assert workflow.report_data is not None
    assert workflow.report_data["differential_validation"]["status"] == "pass"
    assert any(
        check["check"] == "runtime_feature_continuity"
        for check in workflow.differential_validation["checks"]
    )


def test_bun_sea_workflow_reports_runtime_escalation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    binary_path = _write_bun_fixture(tmp_path)
    fake_node = tmp_path / "node.exe"
    fake_node.write_bytes(b"node")

    def fake_run(command, cwd, capture_output, text, check):
        if "--experimental-sea-config" in command:
            Path(cwd, "sea-prep.blob").write_bytes(b"blob")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(
        "reveng.tools.anti_analysis.bun_extractor.shutil.which", lambda _: str(fake_node)
    )
    monkeypatch.setattr(
        "reveng.tools.anti_analysis.bun_extractor.subprocess.run",
        fake_run,
    )

    workflow = run_bun_sea_workflow(str(binary_path), output_dir=str(tmp_path / "workflow_out"))

    assert workflow.report_data is not None
    assert workflow.report_data["runtime_escalation"]["dimension"] == "runtime_escalation"
    assert workflow.report_data["runtime_escalation"]["recommended"] is True
    assert any(
        step["kind"] == "set_breakpoints"
        for step in workflow.report_data["runtime_escalation"]["next_steps"]
    )


def test_bun_sea_workflow_reports_equivalence_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    binary_path = _write_bun_fixture(tmp_path)
    fake_node = tmp_path / "node.exe"
    fake_node.write_bytes(b"node")

    def fake_run(command, cwd, capture_output, text, check):
        if "--experimental-sea-config" in command:
            Path(cwd, "sea-prep.blob").write_bytes(b"blob")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(
        "reveng.tools.anti_analysis.bun_extractor.shutil.which", lambda _: str(fake_node)
    )
    monkeypatch.setattr(
        "reveng.tools.anti_analysis.bun_extractor.subprocess.run",
        fake_run,
    )

    workflow = run_bun_sea_workflow(str(binary_path), output_dir=str(tmp_path / "workflow_out"))

    assert workflow.report_data is not None
    assert workflow.report_data["equivalence_validation"]["dimension"] == "equivalence_validation"
    assert (
        workflow.report_data["equivalence_validation"]["equivalence_level"]
        == "structural_candidate"
    )
    assert any(
        step["kind"] == "characterization_smoke_test"
        for step in workflow.report_data["equivalence_validation"]["recommended_validations"]
    )


def test_bun_report_severity_summary_rolls_up_attention_factors(tmp_path: Path):
    source_path = tmp_path / "severity.js"
    source_path.write_text(
        (
            "// @bun\n"
            'import WebSocket from "ws";\n'
            'const fs = import.meta.require("fs");\n'
            "await Promise.resolve();\n"
        ),
        encoding="utf-8",
    )
    normalization = BunExecutableExtractor().normalize_project(
        str(source_path), str(tmp_path / "normalized")
    )

    summary = build_bun_report_severity_summary(
        normalization=normalization,
        differential_validation={
            "status": "fail",
            "checks": [
                {
                    "check": "runtime_feature_continuity",
                    "severity": "error",
                    "status": "fail",
                    "message": "Normalization dropped a preserved runtime feature",
                }
            ],
        },
        verification={
            "status": "pass_with_warnings",
            "checks": [
                {
                    "check": "bun_marker_continuity",
                    "severity": "warning",
                    "status": "warn",
                    "message": "Bun header continuity is degraded",
                }
            ],
        },
    )

    assert summary["dimension"] == "reconstruction_risk"
    assert summary["level"] == "high"
    assert summary["score"] > 0
    assert any(factor["source"] == "differential_validation" for factor in summary["factors"])
    assert any(factor["source"] == "sea_build_verification" for factor in summary["factors"])


def test_bun_equivalence_validation_summary_reports_semantic_candidate():
    summary = build_bun_equivalence_validation_summary(
        differential_validation={
            "status": "pass",
            "content_changed": True,
            "expected_rewrites": ["import.meta.require -> createRequire(import.meta.url)"],
            "missing_runtime_features": [],
            "added_runtime_features": [],
            "checks": [
                {"check": "dependency_runtime_parity", "status": "pass"},
                {"check": "runtime_feature_continuity", "status": "pass"},
            ],
        },
        verification={
            "status": "pass",
            "checks": [
                {"check": "output_binary_generated", "status": "pass"},
                {"check": "dependency_manifest_alignment", "status": "pass"},
            ],
        },
    )

    assert summary["dimension"] == "equivalence_validation"
    assert summary["status"] == "candidate"
    assert summary["equivalence_level"] == "semantic_candidate"
    assert summary["confidence"] == "medium"
    assert summary["evidence"]["content_changed"] is True
    assert summary["recommended_validations"][0]["kind"] == "characterization_smoke_test"


def test_bun_equivalence_validation_summary_reports_divergence():
    summary = build_bun_equivalence_validation_summary(
        differential_validation={
            "status": "fail",
            "content_changed": True,
            "expected_rewrites": [],
            "missing_runtime_features": ["await_usage"],
            "added_runtime_features": [],
            "checks": [
                {
                    "check": "runtime_feature_continuity",
                    "status": "fail",
                    "message": "Normalization dropped preserved runtime features",
                }
            ],
        },
        verification={
            "status": "pass_with_warnings",
            "checks": [
                {
                    "check": "bun_marker_continuity",
                    "status": "warn",
                    "message": "Bun header continuity is degraded",
                }
            ],
        },
    )

    assert summary["status"] == "divergent"
    assert summary["equivalence_level"] == "not_equivalent"
    assert summary["confidence"] == "high"
    assert any(step["kind"] == "runtime_compare" for step in summary["recommended_validations"])


def test_bun_runtime_escalation_summary_prioritizes_runtime_steps():
    extractor = BunExecutableExtractor()
    readiness = extractor._build_runtime_readiness(
        pe_header={"image_base": 0x140000000, "entry_point_rva": 0x1000, "sections": []},
        entry_point_section=".text",
        tls_callbacks=[],
        startup_targets=[
            PEStartupTarget(
                source="entrypoint",
                instruction_address=0x140001004,
                instruction_mnemonic="call",
                target_address=0x140002020,
                target_rva=0x2020,
                target_section=".bun",
                symbolic_label="bun_rva_00002020",
                target_resolution="direct",
                import_target=None,
                target_preview=[],
            ),
            PEStartupTarget(
                source="entrypoint",
                instruction_address=0x140001020,
                instruction_mnemonic="call",
                target_address=0x140002100,
                target_rva=0x2100,
                target_section=".idata",
                symbolic_label="kernel32_dll_getprocaddress",
                target_resolution="import_iat",
                import_target="KERNEL32.dll!GetProcAddress",
                target_preview=[],
            ),
        ],
        startup_graph=extractor._build_startup_graph(
            {
                "image_base": 0x140000000,
                "entry_point_rva": 0x1000,
                "sections": [
                    {
                        "name": ".bun",
                        "virtual_size": 0x400,
                        "virtual_address": 0x2000,
                        "raw_size": 0x400,
                        "raw_address": 0x600,
                    }
                ],
            },
            [],
            [],
            [
                PEStartupTarget(
                    source="entrypoint",
                    instruction_address=0x140001004,
                    instruction_mnemonic="call",
                    target_address=0x140002020,
                    target_rva=0x2020,
                    target_section=".bun",
                    symbolic_label="bun_rva_00002020",
                    target_resolution="direct",
                    import_target=None,
                    target_preview=[],
                )
            ],
        ),
        handoff_signals=[
            PEHandoffSignal(
                "embedded_bun_section", "section_table", "Embedded Bun section", "high"
            ),
        ],
    )
    native_stub = extractor.analyze_pe_stub
    del native_stub
    summary = build_bun_runtime_escalation_summary(
        native_stub=type(
            "NativeStub",
            (),
            {
                "startup_classification": "runtime_bootstrap_likely",
                "runtime_readiness": readiness,
                "dump_guidance": extractor._build_dump_guidance(
                    startup_classification="runtime_bootstrap_likely",
                    suspicious_imports=["GetProcAddress", "VirtualProtect"],
                    runtime_readiness=readiness,
                    handoff_signals=[
                        PEHandoffSignal(
                            "embedded_bun_section",
                            "section_table",
                            "Embedded Bun section",
                            "high",
                        )
                    ],
                ),
                "startup_graph": type("StartupGraph", (), {"truncated": True})(),
            },
        )(),
        report_severity={"level": "high", "score": 75},
        differential_validation={"status": "warn"},
        verification={"status": "pass_with_warnings"},
    )

    assert summary["dimension"] == "runtime_escalation"
    assert summary["recommended"] is True
    assert summary["status"] == "runtime_dump_recommended"
    assert summary["evidence"]["dump_guidance_recommended"] is True
    assert summary["evidence"]["breakpoint_count"] >= 1
    step_kinds = [step["kind"] for step in summary["next_steps"]]
    assert step_kinds[:3] == [
        "set_breakpoints",
        "capture_memory_dump",
        "reconstruct_imports",
    ]


def test_bun_extractor_analyzes_dependency_roles():
    analysis = BunExecutableExtractor()._analyze_dependencies(
        (
            'import WebSocket from "ws";\n'
            'const fs = import.meta.require("node:fs");\n'
            'const noisy = `require("iconv-lite")`;\n'
            'const alsoNoisy = "chalk";\n'
        )
    )

    assert analysis.required_packages == ["ws"]
    assert analysis.builtin_modules == ["fs"]
    assert analysis.ignored_package_strings == ["iconv-lite"]


def test_bun_extractor_tracks_aliased_create_require_dependencies():
    analysis = BunExecutableExtractor()._analyze_dependencies(
        (
            'import { createRequire } from "module";\n'
            "var O$ = createRequire(import.meta.url);\n"
            'const ac = O$("abort-controller");\n'
        )
    )

    assert analysis.required_packages == ["abort-controller"]


def test_bun_extractor_ignores_embedded_manifest_and_diff_noise_in_dependency_analysis():
    analysis = BunExecutableExtractor()._analyze_dependencies(
        (
            'import WebSocket from "ws";\n'
            "```diff\n"
            "--- a/src/services/blog-post/BlogPostService.ts\n"
            "+++ b/src/services/blog-post/BlogPostService.ts\n"
            "@@ -45,3 +45,6 @@ import { logInfo } from '@factory/logging';\n"
            "```\n"
            'const packageMeta = "dependencies:{\\"@factory/logging\\":\\"^0.1.0\\",\\"@factory/runtime\\":\\"^0.1.0\\"}";\n'
        )
    )

    assert analysis.required_packages == ["ws"]


def test_packer_detector_identifies_bun_executable(tmp_path: Path):
    binary_path = _write_bun_fixture(tmp_path)

    info = PackerDetector().detect(str(binary_path))

    assert info.packed is True
    assert info.packer_name == "Bun"
    assert info.unpacking_method == "specialized"
    assert any("bun" in indicator.lower() for indicator in info.indicators)


def test_universal_unpacker_extracts_bun_javascript(tmp_path: Path):
    binary_path = _write_bun_fixture(tmp_path)
    output_path = tmp_path / "bundle.js"

    result = UniversalUnpacker().unpack(str(binary_path), str(output_path), method="auto")

    assert result.success is True
    assert result.method_used == "bun"
    assert result.unpacked_path == str(output_path)
    assert output_path.exists()
    assert "hello from bun" in output_path.read_text(encoding="utf-8")
    assert result.artifacts is not None
    assert any(
        str(output_path.with_name("bundle_bunfs")) in artifact for artifact in result.artifacts
    )


def test_probe_standalone_output_cleans_up_temp_dir(tmp_path: Path, monkeypatch):
    """Regression: _probe_standalone_output must not leak its mkdtemp probe dir."""
    import tempfile as _tempfile

    from reveng.tools.anti_analysis import bun_extractor as _bun_module

    output_exe = tmp_path / "standalone.exe"
    output_exe.write_bytes(b"not a real executable")

    created_dirs: list[Path] = []
    real_mkdtemp = _tempfile.mkdtemp

    def _tracking_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        if kwargs.get("prefix", "").startswith("reveng_bun_sea_probe_") or (
            args and str(args[0]).startswith("reveng_bun_sea_probe_")
        ):
            created_dirs.append(Path(path))
        return path

    monkeypatch.setattr(_bun_module.tempfile, "mkdtemp", _tracking_mkdtemp)

    extractor = BunExecutableExtractor()
    result = extractor._probe_standalone_output(output_exe)

    assert isinstance(result, dict)
    assert created_dirs, "expected _probe_standalone_output to create a probe temp dir"
    for probe_dir in created_dirs:
        assert not probe_dir.exists(), f"probe temp dir leaked: {probe_dir}"
