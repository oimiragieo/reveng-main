"""
JavaScript deobfuscation tool - integrates REVENG JS deobfuscation capabilities.
"""

from typing import Any, Dict

from ..base import BaseTool, ToolResult


class JSDeobfuscationTool(BaseTool):
    """
    Deobfuscate JavaScript code (minified, obfuscated, packed).

    This tool integrates REVENG's JavaScript deobfuscation pipeline including:
    - Webpack/Browserify unbundling
    - obfuscator.io reversal
    - ML-based variable renaming
    - Malware detection
    """

    name = "deobfuscate_javascript"
    description = """Deobfuscate JavaScript code to make it human-readable.

This tool performs comprehensive JavaScript deobfuscation including:
- Unpacking eval-based obfuscation
- Unbundling Webpack/Browserify bundles
- Reversing obfuscator.io obfuscation
- ML-based variable renaming
- Malware detection (cryptominers, keyloggers, etc.)
- Beautiful formatting with Prettier

Use this when you need to:
- Reverse engineer obfuscated JavaScript
- Analyze suspicious scripts
- Understand minified production code
- Detect malicious JavaScript

The deobfuscation takes 5-30 seconds depending on code size."""

    input_schema = {
        "type": "object",
        "properties": {
            "code": {
                "type": "string",
                "description": "JavaScript code to deobfuscate (or path to file)",
            },
            "use_ml": {
                "type": "boolean",
                "description": "Use ML variable renaming (better quality). Default: true",
                "default": True,
            },
            "detect_malware": {
                "type": "boolean",
                "description": "Check for malicious patterns. Default: true",
                "default": True,
            },
        },
        "required": ["code"],
    }

    async def execute(self, args: Dict[str, Any]) -> ToolResult:
        """Execute JavaScript deobfuscation."""
        code_or_path = args["code"]
        use_ml = args.get("use_ml", True)
        detect_malware = args.get("detect_malware", True)

        try:
            # Check if it's a file path
            from pathlib import Path

            if Path(code_or_path).is_file():
                with open(code_or_path, "r") as f:
                    code = f.read()
                source = code_or_path
            else:
                code = code_or_path
                source = "inline code"

            # Import deobfuscator
            from reveng.javascript.deobfuscator import JavaScriptDeobfuscator

            deob = JavaScriptDeobfuscator(use_ml=use_ml, use_llm=False)

            # Run deobfuscation (async)
            result = await deob.deobfuscate(code)

            # Malware detection if requested
            malware_info = ""
            if detect_malware:
                from reveng.javascript.malware_detector import MalwareDetector

                detector = MalwareDetector()
                malware_result = detector.analyze(result.deobfuscated_code)

                if malware_result.is_malicious:
                    malware_info = (
                        f"\n⚠️  MALWARE DETECTED (score: {malware_result.threat_score:.1%})\n"
                    )
                    malware_info += f"Threats: {len(malware_result.indicators)}\n"
                    for ind in malware_result.indicators[:3]:
                        malware_info += f"  - {ind.category.value}: {ind.description}\n"

            # Format result
            output = [
                f"JavaScript Deobfuscation: {source}",
                "=" * 70,
                f"Confidence: {result.confidence:.1%}",
                f"Obfuscation types: {[t.value for t in result.obfuscation_types]}",
                f"Execution time: {result.execution_time:.2f}s",
                malware_info,
                "",
                "Deobfuscated Code:",
                "-" * 70,
                result.deobfuscated_code[:1000],  # First 1000 chars
            ]

            if len(result.deobfuscated_code) > 1000:
                output.append(f"\n... ({len(result.deobfuscated_code)} total characters)")

            return ToolResult.success_result(
                "\n".join(output),
                confidence=result.confidence,
                execution_time=result.execution_time,
                malware_detected=malware_result.is_malicious if detect_malware else False,
            )

        except ImportError:
            return ToolResult.error_result(
                "JavaScript deobfuscator not available. Install REVENG JS module."
            )
        except Exception as e:
            return ToolResult.error_result(f"Deobfuscation failed: {str(e)}")
