"""
Binary analysis tool - integrates REVENG binary analysis capabilities.
"""

from typing import Any, Dict
import asyncio

from ..base import BaseTool, ToolResult


class BinaryAnalysisTool(BaseTool):
    """
    Analyze binary files for security vulnerabilities and malware.

    This tool integrates REVENG's binary analysis capabilities including:
    - Decompilation (Ghidra)
    - AI-enhanced code analysis (Gemini)
    - Vulnerability detection
    - Malware classification
    """

    name = "analyze_binary"
    description = """Analyze a binary file (EXE, DLL, ELF, etc.) for security issues.

This tool performs comprehensive binary analysis including:
- Decompilation to source code
- Vulnerability detection (buffer overflows, use-after-free, etc.)
- Malware classification and threat scoring
- Function and API analysis
- Security recommendations

Use this when you need to:
- Analyze unknown executables
- Find security vulnerabilities
- Reverse engineer binary functionality
- Detect malware or suspicious behavior

The analysis takes 10-60 seconds depending on binary size."""

    input_schema = {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to the binary file to analyze"
            },
            "quick_mode": {
                "type": "boolean",
                "description": "Quick analysis (faster but less detailed). Default: false",
                "default": False
            }
        },
        "required": ["path"]
    }

    async def execute(self, args: Dict[str, Any]) -> ToolResult:
        """Execute binary analysis."""
        path = args["path"]
        quick_mode = args.get("quick_mode", False)

        try:
            # Import REVENG analyzer
            from reveng.analyzer import REVENGAnalyzer

            analyzer = REVENGAnalyzer()

            # Run analysis (async)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                analyzer.analyze,
                path
            )

            # Format result
            analysis_text = self._format_analysis(result, path, quick_mode)

            return ToolResult.success_result(
                analysis_text,
                binary_path=path,
                quick_mode=quick_mode,
            )

        except ImportError:
            return ToolResult.error_result(
                "REVENG analyzer not available. Install REVENG core components."
            )
        except FileNotFoundError:
            return ToolResult.error_result(
                f"Binary file not found: {path}"
            )
        except Exception as e:
            return ToolResult.error_result(
                f"Analysis failed: {str(e)}"
            )

    def _format_analysis(self, result: Any, path: str, quick_mode: bool) -> str:
        """Format analysis result as text."""
        output = [
            f"Binary Analysis: {path}",
            "=" * 70,
            "",
        ]

        if hasattr(result, 'vulnerabilities'):
            output.append(f"Vulnerabilities: {len(result.vulnerabilities)}")
            if result.vulnerabilities:
                output.append("")
                for i, vuln in enumerate(result.vulnerabilities[:5], 1):
                    output.append(f"  {i}. {vuln.type}: {vuln.description}")
                if len(result.vulnerabilities) > 5:
                    output.append(f"  ... and {len(result.vulnerabilities) - 5} more")

        if hasattr(result, 'threat_score'):
            output.append(f"\nThreat Score: {result.threat_score}/100")

        if hasattr(result, 'file_type'):
            output.append(f"File Type: {result.file_type}")

        if not quick_mode and hasattr(result, 'functions'):
            output.append(f"\nFunctions Analyzed: {len(result.functions)}")

        output.append("")
        output.append("Analysis complete. Use 'reveng analyze' CLI for full details.")

        return "\n".join(output)
