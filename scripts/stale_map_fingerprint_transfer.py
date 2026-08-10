#!/usr/bin/env python3
"""Operator helper: stale-map fingerprint transfer (Wave 5 Tier A).

Writes JSON under --output-dir. Does not claim exe decode.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from reveng.app_reverse_engineering.js_stale_map_transfer import (  # noqa: E402
    build_index_from_sourcemap,
    scan_bundle,
)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--map", required=True, type=Path, help="Stale .map or .map.json with sourcesContent"
    )
    p.add_argument("--bundle", required=True, type=Path, help="Target JS bundle to scan")
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument("--salt", default="reveng-wave5-stale-map-v1")
    args = p.parse_args()

    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    index = build_index_from_sourcemap(args.map, salt=args.salt)
    (out / "fingerprint_index.json").write_text(
        json.dumps(index.to_serializable(), indent=2) + "\n", encoding="utf-8"
    )
    result = scan_bundle(index, args.bundle.read_text(encoding="utf-8", errors="replace"))
    payload = result.to_serializable()
    (out / "fingerprint_transfer.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "first_party_confirmed_count": payload["metrics"]["first_party_confirmed_count"],
                "decoded_exe_claim": payload["decoded_exe_claim"],
                "llm_used": payload["llm_used"],
                "output_dir": str(out),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
