#!/usr/bin/env python3
"""
REVENG Cleanup Script
====================

Removes legacy/duplicate files and keeps only production-ready code.

Categories:
- Legacy docs (superseded by newer versions)
- Duplicate documentation
- Old tool versions (v1, broken versions)
- Empty/unused directories
"""

import shutil
from pathlib import Path

# Files to remove (legacy/duplicate documentation)
FILES_TO_REMOVE = [
    # Superseded by IMPLEMENTATION_COMPLETE.md
    "BLOCKERS_RESOLVED.md",
    "FIXES_VERIFIED.md",
    "INTEGRATION_COMPLETE.md",
    "CLEANUP_COMPLETE.md",

    # Superseded by README.md and IMPLEMENTATION_COMPLETE.md
    "BUGFIX_SUMMARY.md",
    "CRITICAL_BUGFIXES.md",
    "EXECUTIVE_SUMMARY.md",
    "IMPROVEMENTS_IMPLEMENTED.md",
    "IMPROVEMENT_ROADMAP.md",
    "QUICK_START_IMPROVEMENTS.md",
    "INDEX.md",

    # Legacy files
    "AI_AGENT_INSTRUCTIONS.md",

    # Old versions (keep only _fixed and _v2 versions)
    "tools/human_readable_converter.py",  # Use _fixed version
    "tools/binary_reassembler.py",  # Use _v2 version
]

# Folders to check and potentially remove if empty
FOLDERS_TO_CHECK = [
    "ai_recompiler_analysis_droid",
    "deobfuscated_app",
]

def main():
    root = Path(".")
    removed_count = 0

    print("REVENG Cleanup - Removing Legacy Files")
    print("=" * 60)
    print()

    # Remove files
    for file_path in FILES_TO_REMOVE:
        full_path = root / file_path
        if full_path.exists():
            print(f"Removing: {file_path}")
            full_path.unlink()
            removed_count += 1
        else:
            print(f"Skip (not found): {file_path}")

    print()
    print(f"Removed {removed_count} files")
    print()

    # Check folders
    print("Checking folders...")
    for folder_path in FOLDERS_TO_CHECK:
        full_path = root / folder_path
        if full_path.exists() and full_path.is_dir():
            # Count files
            files = list(full_path.rglob("*"))
            file_count = sum(1 for f in files if f.is_file())

            if file_count <= 2:  # Only README or similar
                print(f"  {folder_path}: {file_count} files (consider manual review)")
            else:
                print(f"  {folder_path}: {file_count} files (keeping)")

    print()
    print("Cleanup complete!")
    print()
    print("Kept files:")
    print("  - README.md (main documentation)")
    print("  - CLAUDE.md (AI assistant guide)")
    print("  - IMPLEMENTATION_COMPLETE.md (complete implementation report)")
    print("  - PROJECT_STRUCTURE.md (project layout)")
    print("  - tools/*_fixed.py and *_v2.py (production versions)")

if __name__ == "__main__":
    main()
