"""
REVENG MCP Server
=================

Provides REVENG binary analysis and JavaScript deobfuscation via MCP.
"""

import asyncio
from typing import Any, Dict, List

from ..server import MCPServer, MCPTool


class REVENGMCPServer(MCPServer):
    """
    REVENG MCP Server.

    Exposes REVENG capabilities as MCP tools:
    - Binary analysis and decompilation
    - JavaScript deobfuscation
    - Malware detection
    - Vulnerability scanning

    Example:
        ```python
        server = REVENGMCPServer()
        await server.start(StdioTransport())
        ```
    """

    def __init__(self):
        super().__init__("reveng-mcp", "1.0.0")

        # Register REVENG tools
        self.register_tool(
            MCPTool(
                name="analyze_binary",
                description="Analyze a binary file (EXE, DLL, ELF, etc.)",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to binary file"},
                        "quick_mode": {"type": "boolean", "description": "Use quick analysis mode"},
                    },
                    "required": ["path"],
                },
                handler=self.analyze_binary,
            )
        )

        self.register_tool(
            MCPTool(
                name="deobfuscate_js",
                description="Deobfuscate JavaScript code",
                input_schema={
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Obfuscated JavaScript code"},
                        "use_ml": {"type": "boolean", "description": "Use ML for renaming"},
                        "detect_malware": {
                            "type": "boolean",
                            "description": "Run malware detection",
                        },
                    },
                    "required": ["code"],
                },
                handler=self.deobfuscate_js,
            )
        )

        self.register_tool(
            MCPTool(
                name="detect_malware",
                description="Detect malware in code or binary",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to file"},
                        "type": {"type": "string", "enum": ["binary", "javascript"]},
                    },
                    "required": ["path", "type"],
                },
                handler=self.detect_malware,
            )
        )

    async def analyze_binary(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a binary file"""
        try:
            from reveng.analyzer import REVENGAnalyzer

            path = args["path"]
            quick_mode = args.get("quick_mode", False)

            analyzer = REVENGAnalyzer()

            # Run analysis in executor to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, analyzer.analyze, path)

            # Format results
            text = f"Binary Analysis: {path}\n"
            text += "=" * 70 + "\n\n"

            if hasattr(result, "file_type"):
                text += f"File Type: {result.file_type}\n"
            if hasattr(result, "architecture"):
                text += f"Architecture: {result.architecture}\n"
            if hasattr(result, "vulnerabilities"):
                text += f"\nVulnerabilities Found: {len(result.vulnerabilities)}\n"
                for vuln in result.vulnerabilities[:10]:
                    text += f"  • {vuln}\n"
            if hasattr(result, "decompiled_code"):
                text += f"\nDecompiled Code:\n{result.decompiled_code[:1000]}\n"

            return {
                "content": [{"type": "text", "text": text}],
                "analysis": {
                    "file_type": getattr(result, "file_type", "unknown"),
                    "vulnerabilities": getattr(result, "vulnerabilities", []),
                },
            }

        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Error analyzing binary: {str(e)}"}],
                "error": str(e),
            }

    async def deobfuscate_js(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Deobfuscate JavaScript code"""
        try:
            from reveng.javascript.deobfuscator import JavaScriptDeobfuscator

            code = args["code"]
            use_ml = args.get("use_ml", True)
            detect_malware = args.get("detect_malware", True)

            deob = JavaScriptDeobfuscator(use_ml=use_ml, use_llm=False)
            result = await deob.deobfuscate(code)

            text = "JavaScript Deobfuscation Results\n"
            text += "=" * 70 + "\n\n"
            text += f"Confidence: {result.confidence}%\n"
            text += f"Obfuscation Types: {', '.join(result.obfuscation_types)}\n\n"
            text += "Deobfuscated Code:\n"
            text += "-" * 70 + "\n"
            text += result.deobfuscated_code[:2000]

            response = {
                "content": [{"type": "text", "text": text}],
                "deobfuscated_code": result.deobfuscated_code,
                "confidence": result.confidence,
                "obfuscation_types": result.obfuscation_types,
            }

            # Add malware detection if requested
            if detect_malware:
                from reveng.javascript.malware_detector import MalwareDetector

                detector = MalwareDetector()
                malware_result = detector.analyze(result.deobfuscated_code)

                response["malware_score"] = malware_result.threat_score
                response["is_malicious"] = malware_result.is_malicious

                if malware_result.is_malicious:
                    text += f"\n\n⚠️  MALWARE DETECTED (score: {malware_result.threat_score}/100)\n"
                    text += "Indicators:\n"
                    for indicator in malware_result.indicators[:5]:
                        text += f"  • {indicator}\n"

            return response

        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Error deobfuscating JavaScript: {str(e)}"}],
                "error": str(e),
            }

    async def detect_malware(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Detect malware in file"""
        try:
            path = args["path"]
            file_type = args["type"]

            if file_type == "javascript":
                from reveng.javascript.malware_detector import MalwareDetector

                # Read file
                with open(path, "r") as f:
                    code = f.read()

                detector = MalwareDetector()
                result = detector.analyze(code)

                text = f"Malware Analysis: {path}\n"
                text += "=" * 70 + "\n\n"
                text += f"Threat Score: {result.threat_score}/100\n"
                text += f"Is Malicious: {'YES ⚠️' if result.is_malicious else 'NO ✓'}\n\n"

                if result.indicators:
                    text += "Indicators:\n"
                    for indicator in result.indicators:
                        text += f"  • {indicator}\n"

                return {
                    "content": [{"type": "text", "text": text}],
                    "threat_score": result.threat_score,
                    "is_malicious": result.is_malicious,
                    "indicators": result.indicators,
                }

            else:
                # Binary malware detection
                # TODO: Implement binary malware detection
                return {
                    "content": [
                        {"type": "text", "text": "Binary malware detection not yet implemented"}
                    ]
                }

        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Error detecting malware: {str(e)}"}],
                "error": str(e),
            }

    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """Read a resource (not implemented)"""
        return {"uri": uri, "mimeType": "text/plain", "text": "Resources not supported"}

    async def get_prompt(self, name: str, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get a prompt (not implemented)"""
        return []


# Main entry point
if __name__ == "__main__":
    import sys

    from ..transports import StdioTransport

    async def main():
        server = REVENGMCPServer()
        transport = StdioTransport()
        await server.start(transport)

    asyncio.run(main())
