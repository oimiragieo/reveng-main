#!/usr/bin/env python3
"""
REVENG Toolchain Checker
========================

Detects required compilers, assemblers, and libraries for binary reassembly.

Checks for:
- C Compilers: MSVC (cl.exe), MinGW (gcc), clang, gcc
- Python Libraries: lief, keystone-engine, capstone
- Optional: Ghidra, MCP servers

Provides actionable installation commands when tools are missing.

Usage:
    python tools/check_toolchain.py              # Check all requirements
    python tools/check_toolchain.py --fix        # Show installation commands
    python tools/check_toolchain.py --json       # Output JSON format
"""

import argparse
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY or Windows)"""
        cls.GREEN = cls.YELLOW = cls.RED = cls.BLUE = cls.BOLD = cls.END = ''


class ToolchainChecker:
    """Check for required REVENG toolchain components"""

    def __init__(self, enable_colors: bool = True):
        """Initialize checker"""
        self.system = platform.system().lower()
        self.results = {
            'compilers': {},
            'python_packages': {},
            'optional': {},
            'summary': {}
        }

        if not enable_colors or not sys.stdout.isatty():
            Colors.disable()

    def check_all(self) -> Dict:
        """Check all toolchain components"""
        print(f"{Colors.BOLD}REVENG Toolchain Check{Colors.END}")
        print("=" * 60)
        print(f"Platform: {platform.system()} {platform.release()}")
        print(f"Architecture: {platform.machine()}")
        print()

        # Check compilers
        print(f"{Colors.BOLD}1. C Compilers{Colors.END}")
        self._check_compilers()
        print()

        # Check Python packages
        print(f"{Colors.BOLD}2. Python Packages{Colors.END}")
        self._check_python_packages()
        print()

        # Check optional tools
        print(f"{Colors.BOLD}3. Optional Tools{Colors.END}")
        self._check_optional()
        print()

        # Generate summary
        self._generate_summary()
        self._print_summary()

        return self.results

    def _check_compilers(self):
        """Check for C compilers"""
        compilers = []

        if self.system == 'windows':
            compilers = [
                ('cl', 'MSVC (Visual Studio)'),
                ('gcc', 'MinGW GCC'),
                ('clang', 'Clang/LLVM')
            ]
        else:
            compilers = [
                ('gcc', 'GCC'),
                ('clang', 'Clang/LLVM'),
                ('cc', 'System C Compiler')
            ]

        for cmd, name in compilers:
            result = self._check_command(cmd, get_version=True)
            self.results['compilers'][name] = result
            self._print_result(name, result)

    def _check_python_packages(self):
        """Check for required Python packages"""
        packages = [
            ('lief', 'LIEF (Binary modification)'),
            ('keystone', 'Keystone (Assembler)'),
            ('capstone', 'Capstone (Disassembler)')
        ]

        for module, name in packages:
            result = self._check_python_module(module)
            self.results['python_packages'][name] = result
            self._print_result(name, result)

    def _check_optional(self):
        """Check for optional tools"""
        # Check Ghidra
        ghidra_result = self._check_ghidra()
        self.results['optional']['Ghidra'] = ghidra_result
        self._print_result('Ghidra', ghidra_result)

    def _check_command(self, cmd: str, get_version: bool = False) -> Dict:
        """Check if command is available"""
        path = shutil.which(cmd)

        if path:
            version = None
            if get_version:
                version = self._get_version(cmd)

            return {
                'available': True,
                'path': path,
                'version': version
            }
        else:
            return {
                'available': False,
                'path': None,
                'version': None
            }

    def _get_version(self, cmd: str) -> Optional[str]:
        """Get version of command"""
        version_flags = ['--version', '-v', '/version']

        for flag in version_flags:
            try:
                result = subprocess.run(
                    [cmd, flag],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    # Extract first line
                    return result.stdout.split('\n')[0][:80]
            except:
                continue

        return None

    def _check_python_module(self, module: str) -> Dict:
        """Check if Python module is installed"""
        try:
            __import__(module)
            # Get version if available
            try:
                mod = __import__(module)
                version = getattr(mod, '__version__', 'installed')
            except:
                version = 'installed'

            return {
                'available': True,
                'version': version
            }
        except ImportError:
            return {
                'available': False,
                'version': None
            }

    def _check_ghidra(self) -> Dict:
        """Check for Ghidra installation"""
        # Common Ghidra paths
        ghidra_paths = []

        if self.system == 'windows':
            ghidra_paths = [
                Path(r'C:\ghidra'),
                Path(r'C:\Program Files\ghidra'),
                Path.home() / 'ghidra'
            ]
        else:
            ghidra_paths = [
                Path('/opt/ghidra'),
                Path('/usr/local/ghidra'),
                Path.home() / 'ghidra'
            ]

        for path in ghidra_paths:
            if path.exists():
                return {
                    'available': True,
                    'path': str(path)
                }

        return {
            'available': False,
            'path': None
        }

    def _print_result(self, name: str, result: Dict):
        """Print check result"""
        if result['available']:
            status = f"{Colors.GREEN}[OK]{Colors.END}"
            version = result.get('version', '')
            version_str = f" ({version})" if version else ""
            print(f"  {status} {name}{version_str}")
        else:
            status = f"{Colors.RED}[MISSING]{Colors.END}"
            print(f"  {status} {name}")

    def _generate_summary(self):
        """Generate summary statistics"""
        total_compilers = len(self.results['compilers'])
        available_compilers = sum(1 for r in self.results['compilers'].values() if r['available'])

        total_packages = len(self.results['python_packages'])
        available_packages = sum(1 for r in self.results['python_packages'].values() if r['available'])

        total_optional = len(self.results['optional'])
        available_optional = sum(1 for r in self.results['optional'].values() if r['available'])

        self.results['summary'] = {
            'compilers': {
                'total': total_compilers,
                'available': available_compilers,
                'missing': total_compilers - available_compilers
            },
            'python_packages': {
                'total': total_packages,
                'available': available_packages,
                'missing': total_packages - available_packages
            },
            'optional': {
                'total': total_optional,
                'available': available_optional,
                'missing': total_optional - available_optional
            },
            'ready': available_compilers > 0 and available_packages == total_packages
        }

    def _print_summary(self):
        """Print summary"""
        summary = self.results['summary']

        print(f"{Colors.BOLD}Summary{Colors.END}")
        print("-" * 60)
        print(f"Compilers: {summary['compilers']['available']}/{summary['compilers']['total']} available")
        print(f"Python Packages: {summary['python_packages']['available']}/{summary['python_packages']['total']} available")
        print(f"Optional Tools: {summary['optional']['available']}/{summary['optional']['total']} available")
        print()

        if summary['ready']:
            print(f"{Colors.GREEN}{Colors.BOLD}[OK] Toolchain ready for reassembly{Colors.END}")
        else:
            print(f"{Colors.YELLOW}{Colors.BOLD}[WARNING] Missing required components{Colors.END}")

    def show_fix_instructions(self):
        """Show installation instructions for missing components"""
        missing_compilers = [name for name, result in self.results['compilers'].items() if not result['available']]
        missing_packages = [name for name, result in self.results['python_packages'].items() if not result['available']]

        if not missing_compilers and not missing_packages:
            print(f"{Colors.GREEN}All required components are installed!{Colors.END}")
            return

        print()
        print(f"{Colors.BOLD}Installation Instructions{Colors.END}")
        print("=" * 60)

        if missing_packages:
            print(f"\n{Colors.BOLD}Install Python Packages:{Colors.END}")
            print(f"{Colors.BLUE}pip install lief keystone-engine capstone{Colors.END}")

        if missing_compilers:
            print(f"\n{Colors.BOLD}Install C Compiler:{Colors.END}")
            if self.system == 'windows':
                print(f"{Colors.BLUE}# Option 1: Visual Studio Build Tools{Colors.END}")
                print("Download from: https://visualstudio.microsoft.com/downloads/")
                print()
                print(f"{Colors.BLUE}# Option 2: MinGW via Chocolatey{Colors.END}")
                print("choco install mingw")
                print()
                print(f"{Colors.BLUE}# Option 3: LLVM/Clang{Colors.END}")
                print("choco install llvm")
            elif self.system == 'linux':
                print(f"{Colors.BLUE}# Debian/Ubuntu:{Colors.END}")
                print("sudo apt-get install build-essential gcc clang")
                print()
                print(f"{Colors.BLUE}# Fedora/RHEL:{Colors.END}")
                print("sudo dnf install gcc gcc-c++ clang")
            elif self.system == 'darwin':
                print(f"{Colors.BLUE}# Install Xcode Command Line Tools:{Colors.END}")
                print("xcode-select --install")

        print()
        print(f"{Colors.YELLOW}After installing, run: python tools/check_toolchain.py{Colors.END}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Check REVENG toolchain requirements',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        '--fix',
        action='store_true',
        help='Show installation instructions for missing components'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )

    args = parser.parse_args()

    checker = ToolchainChecker(enable_colors=not args.no_color)
    results = checker.check_all()

    if args.fix:
        checker.show_fix_instructions()

    if args.json:
        print()
        print(json.dumps(results, indent=2))

    # Exit code based on readiness
    sys.exit(0 if results['summary']['ready'] else 1)


if __name__ == "__main__":
    main()
