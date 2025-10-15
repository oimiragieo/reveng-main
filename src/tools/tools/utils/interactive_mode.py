#!/usr/bin/env python3
"""
REVENG Interactive Mode
========================

Interactive shell for reverse engineering workflows:
- Explore analysis results
- Query functions, strings, imports
- Run individual pipeline steps
- Customize analysis parameters
- Export results in real-time

Provides REPL-style interface for advanced users.
"""

import cmd
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
import subprocess

logger = logging.getLogger(__name__)


class REVENGShell(cmd.Cmd):
    """Interactive REVENG shell"""

    intro = """
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   REVENG Interactive Mode                                             ║
║   Reverse Engineering Toolkit                                         ║
║                                                                       ║
║   Type 'help' or '?' to list commands.                                ║
║   Type 'tutorial' for a quick start guide.                            ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
"""

    prompt = 'reveng> '

    def __init__(self):
        """Initialize REVENG shell"""
        super().__init__()
        self.binary_path = None
        self.analysis_folder = None
        self.analysis_data = {}
        self.current_function = None

    # ===== Binary Management =====

    def do_load(self, arg):
        """
        Load a binary for analysis.

        Usage: load <binary_path>
        Example: load droid.exe
        """
        if not arg:
            print("Error: Please specify a binary path")
            print("Usage: load <binary_path>")
            return

        binary_path = Path(arg)
        if not binary_path.exists():
            print(f"Error: Binary not found: {binary_path}")
            return

        self.binary_path = binary_path
        self.analysis_folder = Path(f"analysis_{binary_path.stem}")

        print(f"Loaded binary: {self.binary_path}")
        print(f"Analysis folder: {self.analysis_folder}")

        # Load existing analysis if available
        if self.analysis_folder.exists():
            self._load_analysis()
            print(f"Loaded existing analysis ({len(self.analysis_data.get('functions', []))} functions)")

    def do_analyze(self, arg):
        """
        Run full REVENG analysis pipeline.

        Usage: analyze [--steps=1,2,3]
        Example: analyze
        Example: analyze --steps=1,2,5
        """
        if not self.binary_path:
            print("Error: No binary loaded. Use 'load <binary>' first")
            return

        print(f"Running analysis on {self.binary_path}...")

        try:
            result = subprocess.run(
                [sys.executable, "reveng_analyzer.py", str(self.binary_path)],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                print("✓ Analysis complete!")
                self._load_analysis()
            else:
                print(f"✗ Analysis failed: {result.stderr}")

        except Exception as e:
            print(f"Error: {e}")

    def do_status(self, arg):
        """
        Show current analysis status.

        Usage: status
        """
        if not self.binary_path:
            print("No binary loaded")
            return

        print("=" * 70)
        print("ANALYSIS STATUS")
        print("=" * 70)
        print(f"Binary: {self.binary_path}")
        print(f"Analysis folder: {self.analysis_folder}")
        print()

        if self.analysis_data:
            print(f"Functions: {len(self.analysis_data.get('functions', []))}")
            print(f"Strings: {len(self.analysis_data.get('strings', []))}")
            print(f"Imports: {len(self.analysis_data.get('imports', []))}")
        else:
            print("No analysis data loaded")

        print("=" * 70)

    # ===== Function Queries =====

    def do_functions(self, arg):
        """
        List all functions.

        Usage: functions [filter]
        Example: functions
        Example: functions alloc
        """
        functions = self.analysis_data.get('functions', [])

        if not functions:
            print("No functions found. Run 'analyze' first.")
            return

        # Apply filter
        if arg:
            functions = [f for f in functions if arg.lower() in f.get('name', '').lower()]

        print(f"Functions ({len(functions)}):")
        print("-" * 70)

        for i, func in enumerate(functions[:50], 1):
            name = func.get('name', 'unknown')
            addr = func.get('address', '???')
            print(f"{i:3d}. {name:40s} @ {addr}")

        if len(functions) > 50:
            print(f"... and {len(functions) - 50} more")

    def do_function(self, arg):
        """
        Show details for a specific function.

        Usage: function <name>
        Example: function malloc_wrapper
        """
        if not arg:
            print("Usage: function <name>")
            return

        functions = self.analysis_data.get('functions', [])
        matches = [f for f in functions if arg.lower() in f.get('name', '').lower()]

        if not matches:
            print(f"Function not found: {arg}")
            return

        if len(matches) > 1:
            print(f"Multiple matches found ({len(matches)}):")
            for i, func in enumerate(matches[:10], 1):
                print(f"{i}. {func.get('name')}")
            print("Please be more specific")
            return

        func = matches[0]
        self.current_function = func

        print("=" * 70)
        print(f"Function: {func.get('name')}")
        print("=" * 70)
        print(f"Address: {func.get('address')}")
        print(f"Return type: {func.get('return_type', 'unknown')}")
        print(f"Parameters: {len(func.get('parameters', []))}")
        print(f"Purpose: {func.get('purpose', 'N/A')}")
        print(f"Complexity: {func.get('complexity', 'unknown')}")
        print("=" * 70)

    def do_strings(self, arg):
        """
        List all strings.

        Usage: strings [filter]
        Example: strings
        Example: strings error
        """
        strings = self.analysis_data.get('strings', [])

        if not strings:
            print("No strings found. Run 'analyze' first.")
            return

        # Apply filter
        if arg:
            strings = [s for s in strings if arg.lower() in s.lower()]

        print(f"Strings ({len(strings)}):")
        print("-" * 70)

        for i, string in enumerate(strings[:50], 1):
            print(f"{i:3d}. {string}")

        if len(strings) > 50:
            print(f"... and {len(strings) - 50} more")

    def do_imports(self, arg):
        """
        List imported functions.

        Usage: imports [filter]
        Example: imports
        Example: imports socket
        """
        imports = self.analysis_data.get('imports', [])

        if not imports:
            print("No imports found. Run 'analyze' first.")
            return

        # Apply filter
        if arg:
            imports = [i for i in imports if arg.lower() in i.lower()]

        print(f"Imports ({len(imports)}):")
        print("-" * 70)

        for i, imp in enumerate(imports[:50], 1):
            print(f"{i:3d}. {imp}")

        if len(imports) > 50:
            print(f"... and {len(imports) - 50} more")

    # ===== Analysis Tools =====

    def do_complexity(self, arg):
        """
        Analyze function complexity.

        Usage: complexity [output_dir]
        Example: complexity
        """
        if not self.analysis_folder:
            print("Error: No analysis loaded")
            return

        # Look for generated code
        code_dirs = [
            Path("human_readable_code"),
            Path(f"src_optimal_analysis_{self.binary_path.stem}")
        ]

        code_dir = None
        for d in code_dirs:
            if d.exists():
                code_dir = d
                break

        if not code_dir:
            print("Error: No generated code found")
            return

        print(f"Analyzing complexity in {code_dir}...")

        try:
            result = subprocess.run(
                [sys.executable, "tools/complexity_scorer.py", str(code_dir)],
                capture_output=True,
                text=True
            )

            print(result.stdout)

            if result.returncode == 0:
                print("✓ Complexity report: complexity_report.json")

        except Exception as e:
            print(f"Error: {e}")

    def do_validate(self, arg):
        """
        Validate rebuilt binary.

        Usage: validate <rebuilt_binary>
        Example: validate human_readable_code/droid.exe
        """
        if not arg:
            print("Usage: validate <rebuilt_binary>")
            return

        if not self.binary_path:
            print("Error: No original binary loaded")
            return

        rebuilt_path = Path(arg)
        if not rebuilt_path.exists():
            print(f"Error: Rebuilt binary not found: {rebuilt_path}")
            return

        print(f"Validating {rebuilt_path} against {self.binary_path}...")

        try:
            from tools.binary_validator import BinaryValidator

            validator = BinaryValidator()
            report = validator.validate_rebuild(self.binary_path, rebuilt_path)

            verdict = report['verdict']
            print()
            print(f"Valid: {verdict['valid']}")
            print(f"Confidence: {verdict['confidence']:.2f}")

            if verdict.get('warnings'):
                print(f"Warnings: {len(verdict['warnings'])}")

            if verdict.get('errors'):
                print(f"Errors: {len(verdict['errors'])}")

            validator.save_report(report, Path("validation_report.json"))
            print("✓ Full report: validation_report.json")

        except ImportError:
            print("Error: binary_validator not available")
        except Exception as e:
            print(f"Error: {e}")

    def do_diff(self, arg):
        """
        Compare original vs rebuilt binary.

        Usage: diff <rebuilt_binary>
        Example: diff human_readable_code/droid.exe
        """
        if not arg:
            print("Usage: diff <rebuilt_binary>")
            return

        if not self.binary_path:
            print("Error: No original binary loaded")
            return

        rebuilt_path = Path(arg)
        if not rebuilt_path.exists():
            print(f"Error: Rebuilt binary not found: {rebuilt_path}")
            return

        print(f"Comparing binaries...")

        try:
            from tools.binary_diff import BinaryDiff

            differ = BinaryDiff()
            report = differ.compare(self.binary_path, rebuilt_path)

            differ.print_summary(report)
            differ.save_report(report, Path("binary_diff_report.json"))

            print("✓ Full report: binary_diff_report.json")

        except ImportError:
            print("Error: binary_diff not available")
        except Exception as e:
            print(f"Error: {e}")

    def do_export(self, arg):
        """
        Export analysis to other tool formats.

        Usage: export <format> [output_path]
        Formats: ida, ghidra, r2, binja, json, all

        Example: export ida ida_import.py
        Example: export all exports/
        """
        if not arg:
            print("Usage: export <format> [output_path]")
            print("Formats: ida, ghidra, r2, binja, json, all")
            return

        if not self.analysis_folder:
            print("Error: No analysis loaded")
            return

        parts = arg.split()
        format_name = parts[0].lower()
        output_path = Path(parts[1]) if len(parts) > 1 else None

        try:
            from tools.export_formats import ExportFormats

            exporter = ExportFormats(self.analysis_folder)

            if format_name == 'all':
                output_dir = output_path or self.analysis_folder / "exports"
                results = exporter.export_all(output_dir)

                print("Export Results:")
                for fmt, success in results.items():
                    status = "✓" if success else "✗"
                    print(f"  {status} {fmt}")

            elif format_name == 'ida':
                output = output_path or Path("reveng_import_ida.py")
                if exporter.export_ida_python(output):
                    print(f"✓ IDA script: {output}")

            elif format_name == 'ghidra':
                output = output_path or Path("reveng_import_ghidra.py")
                if exporter.export_ghidra_script(output):
                    print(f"✓ Ghidra script: {output}")

            elif format_name in ['r2', 'radare2']:
                output = output_path or Path("reveng_import.r2")
                if exporter.export_radare2_script(output):
                    print(f"✓ Radare2 script: {output}")

            elif format_name in ['binja', 'binaryninja']:
                output = output_path or Path("reveng_import_binja.py")
                if exporter.export_binary_ninja_script(output):
                    print(f"✓ Binary Ninja script: {output}")

            elif format_name == 'json':
                output = output_path or Path("reveng_export.json")
                if exporter.export_json(output):
                    print(f"✓ JSON export: {output}")

            else:
                print(f"Unknown format: {format_name}")
                print("Available: ida, ghidra, r2, binja, json, all")

        except ImportError:
            print("Error: export_formats not available")
        except Exception as e:
            print(f"Error: {e}")

    # ===== Utilities =====

    def do_tutorial(self, arg):
        """Show interactive mode tutorial."""
        print("""
╔═══════════════════════════════════════════════════════════════════════╗
║                        REVENG TUTORIAL                                ║
╚═══════════════════════════════════════════════════════════════════════╝

1. Load a binary:
   reveng> load droid.exe

2. Run analysis:
   reveng> analyze

3. Explore results:
   reveng> functions        # List all functions
   reveng> function malloc  # Show function details
   reveng> strings error    # Search strings

4. Advanced analysis:
   reveng> complexity       # Analyze code complexity
   reveng> validate rebuilt.exe  # Validate rebuilt binary
   reveng> diff rebuilt.exe      # Compare binaries

5. Export results:
   reveng> export ida       # Export to IDA Pro
   reveng> export all       # Export to all formats

6. Get help:
   reveng> help             # List all commands
   reveng> help <command>   # Show command help

7. Exit:
   reveng> exit
        """)

    def do_clear(self, arg):
        """Clear the screen."""
        import os
        os.system('cls' if os.name == 'nt' else 'clear')

    def do_exit(self, arg):
        """Exit REVENG interactive mode."""
        print("Goodbye!")
        return True

    def do_quit(self, arg):
        """Exit REVENG interactive mode."""
        return self.do_exit(arg)

    def do_EOF(self, arg):
        """Exit on EOF (Ctrl+D)."""
        print()
        return self.do_exit(arg)

    # ===== Helper Methods =====

    def _load_analysis(self):
        """Load analysis data from folder"""
        self.analysis_data = {}

        # Load analysis report
        report_path = self.analysis_folder / "universal_analysis_report.json"
        if report_path.exists():
            with open(report_path, 'r', encoding='utf-8') as f:
                self.analysis_data['report'] = json.load(f)

        # Load specifications
        specs_path = Path("SPECS")
        if specs_path.exists():
            functions = []
            for spec_file in specs_path.glob("*.json"):
                with open(spec_file, 'r', encoding='utf-8') as f:
                    spec = json.load(f)
                    if 'functions' in spec:
                        functions.extend(spec['functions'])

            self.analysis_data['functions'] = functions


# Main entry point
def main():
    """Run REVENG interactive shell"""
    shell = REVENGShell()
    shell.cmdloop()


if __name__ == "__main__":
    main()
