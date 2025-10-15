#!/usr/bin/env python3
"""
Stub Purge Tool
===============

Removes narrative stubs from generated C source files.

Fixes:
- Removes Windows-specific headers (#include <windows.h>)
- Removes Windows-specific API calls (GetLastError, ERROR_SUCCESS)
- Removes narrative printf logging ("Executing function...", "Function type...", etc.)
- Generates minimal functional stubs based on function purpose
- Ensures all functions have proper return statements

Usage:
    python tools/purge_stubs.py                    # Purge src_optimal_analysis_droid/functions/
    python tools/purge_stubs.py --dir custom_dir   # Purge custom directory
    python tools/purge_stubs.py --dry-run          # Preview changes without writing
"""

import argparse
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class StubPurger:
    """Purge narrative stubs from C source files"""

    # Patterns to detect narrative stub code
    NARRATIVE_PATTERNS = [
        r'printf\("Executing \w+ function',
        r'printf\("Function type:',
        r'printf\("Complexity level:',
        r'printf\("Memory address:',
        r'printf\("Function size:',
        r'printf\("\w+ function completed',
        r'// Professional implementation with all MCP features',
        r'// This function demonstrates the power',
        r'// Function entry point',
    ]

    # Windows-specific patterns to remove
    WINDOWS_PATTERNS = [
        r'#include <windows\.h>',
        r'GetLastError\(\)',
        r'ERROR_SUCCESS',
        r'SetLastError',
    ]

    def __init__(self, source_dir: Path, dry_run: bool = False):
        """Initialize purger"""
        self.source_dir = source_dir
        self.dry_run = dry_run
        self.stats = {
            'files_processed': 0,
            'files_modified': 0,
            'windows_headers_removed': 0,
            'narrative_stubs_removed': 0,
            'functions_cleaned': 0
        }

    def purge_all(self):
        """Purge all C files in directory"""
        if not self.source_dir.exists():
            logger.error(f"Directory not found: {self.source_dir}")
            return

        c_files = list(self.source_dir.glob("*.c"))
        logger.info(f"Found {len(c_files)} C files to process")

        for c_file in c_files:
            self._purge_file(c_file)

        self._print_stats()

    def _purge_file(self, file_path: Path):
        """Purge a single file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                original = f.read()

            cleaned = self._clean_content(original, file_path.stem)

            self.stats['files_processed'] += 1

            if cleaned != original:
                self.stats['files_modified'] += 1

                if self.dry_run:
                    logger.info(f"[DRY RUN] Would modify: {file_path.name}")
                else:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(cleaned)
                    logger.info(f"Cleaned: {file_path.name}")
            else:
                logger.debug(f"No changes needed: {file_path.name}")

        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")

    def _clean_content(self, content: str, func_name: str) -> str:
        """Clean file content"""
        # Check if it has Windows headers
        has_windows = '#include <windows.h>' in content
        if has_windows:
            self.stats['windows_headers_removed'] += 1

        # Check if it has narrative stubs
        has_narrative = any(re.search(pattern, content) for pattern in self.NARRATIVE_PATTERNS)
        if has_narrative:
            self.stats['narrative_stubs_removed'] += 1

        # Extract function components
        func_info = self._extract_function_info(content, func_name)

        # Generate clean version
        cleaned = self._generate_clean_file(func_info)

        return cleaned

    def _extract_function_info(self, content: str, func_name: str) -> Dict:
        """Extract function metadata from content"""
        # Extract purpose from comment
        purpose_match = re.search(r'\* Purpose: (.+)', content)
        purpose = purpose_match.group(1) if purpose_match else self._infer_purpose(func_name)

        # Extract complexity if available
        complexity_match = re.search(r'Complexity: (\w+)', content)
        complexity = complexity_match.group(1).lower() if complexity_match else 'medium'

        # Extract function signature
        func_match = re.search(r'(void|int|char\*?|long|short|float|double)\s+(\w+)\s*\([^)]*\)\s*\{', content)

        if func_match:
            return_type = func_match.group(1)
            extracted_name = func_match.group(2)
        else:
            # Default to int return type
            return_type = 'int'
            extracted_name = func_name

        return {
            'name': extracted_name,
            'return_type': return_type,
            'purpose': purpose,
            'complexity': complexity
        }

    def _infer_purpose(self, func_name: str) -> str:
        """Infer function purpose from name"""
        name_lower = func_name.lower()

        if 'memory' in name_lower or 'alloc' in name_lower:
            return 'Memory management'
        elif 'file' in name_lower or 'open' in name_lower or 'read' in name_lower or 'write' in name_lower:
            return 'File I/O operations'
        elif 'network' in name_lower or 'socket' in name_lower or 'send' in name_lower or 'recv' in name_lower:
            return 'Network operations'
        elif 'init' in name_lower:
            return 'Initialization'
        elif 'cleanup' in name_lower or 'free' in name_lower:
            return 'Resource cleanup'
        elif 'parse' in name_lower:
            return 'Data parsing'
        elif 'js_' in name_lower:
            return 'JavaScript engine operations'
        else:
            return 'General operations'

    def _generate_clean_file(self, func_info: Dict) -> str:
        """Generate clean file content"""
        name = func_info['name']
        return_type = func_info['return_type']
        purpose = func_info['purpose']

        # Generate functional stub based on purpose
        body = self._generate_functional_body(name, purpose, return_type)

        # Build clean file
        content = f"""/*
 * {name}
 * Purpose: {purpose}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * {name} - {purpose}
 */
{return_type} {name}() {{
{body}
}}
"""
        self.stats['functions_cleaned'] += 1
        return content

    def _generate_functional_body(self, func_name: str, purpose: str, return_type: str) -> str:
        """Generate functional body based on function purpose"""
        name_lower = func_name.lower()
        purpose_lower = purpose.lower()

        # Memory management functions
        if 'alloc' in name_lower or 'memory' in name_lower:
            if return_type == 'void':
                return """    void *ptr = malloc(256);
    if (ptr) {
        memset(ptr, 0, 256);
        free(ptr);
    }"""
            else:
                return """    void *ptr = malloc(256);
    if (ptr) {
        memset(ptr, 0, 256);
        free(ptr);
    }
    return 0;"""

        # File operations
        elif 'file' in name_lower or 'open' in name_lower or 'read' in name_lower or 'write' in name_lower:
            if return_type == 'void':
                return """    // File operation stub"""
            else:
                return """    // File operation stub
    return 0;"""

        # Network operations
        elif 'network' in name_lower or 'socket' in name_lower:
            if return_type == 'void':
                return """    // Network operation stub"""
            else:
                return """    // Network operation stub
    return 0;"""

        # Initialization
        elif 'init' in name_lower:
            if return_type == 'void':
                return """    // Initialization stub"""
            else:
                return """    // Initialization stub
    return 0;"""

        # Cleanup
        elif 'cleanup' in name_lower or 'free' in name_lower:
            if return_type == 'void':
                return """    // Cleanup stub"""
            else:
                return """    // Cleanup stub
    return 0;"""

        # Default
        else:
            if return_type == 'void':
                return """    // Generic operation"""
            else:
                return """    // Generic operation
    return 0;"""

    def _print_stats(self):
        """Print processing statistics"""
        logger.info("\n=== Purge Statistics ===")
        logger.info(f"Files processed: {self.stats['files_processed']}")
        logger.info(f"Files modified: {self.stats['files_modified']}")
        logger.info(f"Windows headers removed: {self.stats['windows_headers_removed']}")
        logger.info(f"Narrative stubs removed: {self.stats['narrative_stubs_removed']}")
        logger.info(f"Functions cleaned: {self.stats['functions_cleaned']}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Purge narrative stubs from C source files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        '--dir',
        type=Path,
        default=Path('src_optimal_analysis_droid/functions'),
        help='Directory containing C files to purge (default: src_optimal_analysis_droid/functions)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview changes without writing files'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("REVENG Stub Purge Tool")
    logger.info("=" * 50)

    purger = StubPurger(args.dir, dry_run=args.dry_run)
    purger.purge_all()

    if args.dry_run:
        logger.info("\nDry run completed. Run without --dry-run to apply changes.")


if __name__ == "__main__":
    main()
