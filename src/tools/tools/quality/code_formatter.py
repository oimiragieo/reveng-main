#!/usr/bin/env python3
"""
Code Formatter Tool
===================

This tool formats generated code using industry-standard formatters:
- C/C++ code formatting with clang-format
- Python code formatting with black
- Static analysis with cppcheck

Author: Enhancement
Version: 1.0
"""

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('code_formatter.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class CodeFormatter:
    """
    Code Formatter Tool

    Formats generated code using:
    - clang-format for C/C++
    - black for Python
    - cppcheck for C/C++ static analysis
    """

    def __init__(self):
        """Initialize the code formatter"""
        self.has_clang_format = self._check_tool("clang-format")
        self.has_cppcheck = self._check_tool("cppcheck")
        self.has_black = self._check_tool("black")

        logger.info("Code Formatter initialized")
        logger.info(f"clang-format available: {self.has_clang_format}")
        logger.info(f"cppcheck available: {self.has_cppcheck}")
        logger.info(f"black available: {self.has_black}")

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        return shutil.which(tool_name) is not None

    def format_c_code(self, file_path: Path) -> Tuple[bool, str]:
        """Format C/C++ code using clang-format"""
        if not self.has_clang_format:
            logger.warning("clang-format not available, skipping C code formatting")
            return False, "clang-format not available"

        try:
            # Run clang-format
            result = subprocess.run(
                ["clang-format", "-i", "-style=file", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                logger.info(f"Formatted C code: {file_path}")
                return True, "Success"
            else:
                logger.error(f"clang-format failed: {result.stderr}")
                return False, result.stderr

        except subprocess.TimeoutExpired:
            logger.error(f"clang-format timeout for {file_path}")
            return False, "Timeout"
        except Exception as e:
            logger.error(f"Error formatting {file_path}: {e}")
            return False, str(e)

    def analyze_c_code(self, file_path: Path) -> Dict[str, List[str]]:
        """Analyze C/C++ code with cppcheck"""
        if not self.has_cppcheck:
            logger.warning("cppcheck not available, skipping static analysis")
            return {"warnings": [], "errors": []}

        try:
            # Run cppcheck
            result = subprocess.run(
                [
                    "cppcheck",
                    "--enable=all",
                    "--suppress=missingIncludeSystem",
                    "--suppress=unusedFunction",
                    "--template={severity}:{file}:{line}:{message}",
                    str(file_path)
                ],
                capture_output=True,
                text=True,
                timeout=60
            )

            # Parse output
            warnings = []
            errors = []

            for line in result.stderr.split('\n'):
                if line.strip():
                    if line.startswith('error:'):
                        errors.append(line)
                    elif line.startswith('warning:') or line.startswith('style:'):
                        warnings.append(line)

            if errors:
                logger.warning(f"cppcheck found {len(errors)} errors in {file_path}")
            if warnings:
                logger.info(f"cppcheck found {len(warnings)} warnings in {file_path}")

            return {"warnings": warnings, "errors": errors}

        except subprocess.TimeoutExpired:
            logger.error(f"cppcheck timeout for {file_path}")
            return {"warnings": [], "errors": ["Timeout"]}
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
            return {"warnings": [], "errors": [str(e)]}

    def format_python_code(self, file_path: Path) -> Tuple[bool, str]:
        """Format Python code using black"""
        if not self.has_black:
            logger.warning("black not available, skipping Python formatting")
            return False, "black not available"

        try:
            # Run black
            result = subprocess.run(
                ["black", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                logger.info(f"Formatted Python code: {file_path}")
                return True, "Success"
            else:
                logger.error(f"black failed: {result.stderr}")
                return False, result.stderr

        except subprocess.TimeoutExpired:
            logger.error(f"black timeout for {file_path}")
            return False, "Timeout"
        except Exception as e:
            logger.error(f"Error formatting {file_path}: {e}")
            return False, str(e)

    def format_directory(self, directory: Path, file_pattern: str = "*.c") -> Dict[str, any]:
        """Format all files in a directory"""
        logger.info(f"Formatting directory: {directory} (pattern: {file_pattern})")

        if not directory.exists():
            logger.error(f"Directory not found: {directory}")
            return {"success": False, "error": "Directory not found"}

        # Find all matching files
        files = list(directory.rglob(file_pattern))
        logger.info(f"Found {len(files)} files to format")

        results = {
            "total": len(files),
            "formatted": 0,
            "failed": 0,
            "analysis": {"warnings": 0, "errors": 0},
            "files": {}
        }

        for file_path in files:
            # Format based on file type
            if file_pattern.endswith('.c') or file_pattern.endswith('.cpp') or file_pattern.endswith('.h'):
                success, message = self.format_c_code(file_path)

                if success:
                    results["formatted"] += 1

                    # Run static analysis
                    analysis = self.analyze_c_code(file_path)
                    results["analysis"]["warnings"] += len(analysis["warnings"])
                    results["analysis"]["errors"] += len(analysis["errors"])
                    results["files"][str(file_path)] = {
                        "formatted": True,
                        "analysis": analysis
                    }
                else:
                    results["failed"] += 1
                    results["files"][str(file_path)] = {
                        "formatted": False,
                        "error": message
                    }

            elif file_pattern.endswith('.py'):
                success, message = self.format_python_code(file_path)

                if success:
                    results["formatted"] += 1
                    results["files"][str(file_path)] = {"formatted": True}
                else:
                    results["failed"] += 1
                    results["files"][str(file_path)] = {
                        "formatted": False,
                        "error": message
                    }

        logger.info(f"Formatting complete: {results['formatted']} formatted, {results['failed']} failed")
        logger.info(f"Static analysis: {results['analysis']['warnings']} warnings, {results['analysis']['errors']} errors")

        return results


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='Format generated code')
    parser.add_argument('directory', help='Directory to format')
    parser.add_argument('--pattern', default='*.c', help='File pattern to match (default: *.c)')
    args = parser.parse_args()

    # Create formatter
    formatter = CodeFormatter()

    # Format directory
    results = formatter.format_directory(Path(args.directory), args.pattern)

    # Print summary
    print(f"\nFormatting Summary:")
    print(f"  Total files: {results['total']}")
    print(f"  Formatted: {results['formatted']}")
    print(f"  Failed: {results['failed']}")
    print(f"  Warnings: {results['analysis']['warnings']}")
    print(f"  Errors: {results['analysis']['errors']}")


if __name__ == "__main__":
    main()