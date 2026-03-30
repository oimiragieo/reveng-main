"""
REVENG MCP Server
=================

Provides REVENG binary analysis and JavaScript deobfuscation via MCP.
"""

import asyncio
from pathlib import Path
from typing import Any, Dict, List

from ....app_reverse_engineering import (
    AppCorpusEntry,
    create_default_framework,
    run_app_corpus,
    select_app_corpus_entries,
)
from ....result_contracts import build_mcp_tool_response, make_evidence_item
from ..server import MCPServer, MCPTool

try:
    from scripts.run_app_reverse_engineering_corpus import load_app_corpus_config
except Exception:  # pragma: no cover - script import fallback
    load_app_corpus_config = None


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

        self.register_tool(
            MCPTool(
                name="reverse_engineer_app",
                description="Generate a normalized app reverse-engineering contract and SPECS library",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to app entry file or package",
                        },
                        "language": {
                            "type": "string",
                            "description": "Adapter language or auto",
                            "enum": ["auto", "javascript", "jvm", "python", "dotnet"],
                        },
                        "output_dir": {
                            "type": "string",
                            "description": "Directory for analysis output",
                        },
                    },
                    "required": ["path"],
                },
                handler=self.reverse_engineer_app,
            )
        )

        self.register_tool(
            MCPTool(
                name="run_app_corpus",
                description="Run the manifest-driven app reverse-engineering corpus and return the rollup report",
                input_schema={
                    "type": "object",
                    "properties": {
                        "config_path": {
                            "type": "string",
                            "description": "Optional corpus config path",
                        },
                        "entry_names": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of corpus entry names to run",
                        },
                        "output_dir": {
                            "type": "string",
                            "description": "Optional corpus output directory",
                        },
                    },
                },
                handler=self.run_app_corpus,
            )
        )

    async def analyze_binary(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a binary file"""
        try:
            from reveng.analyzer import REVENGAnalyzer

            path = args["path"]
            quick_mode = args.get("quick_mode", False)

            analyzer = REVENGAnalyzer(binary_path=path, check_ollama=not quick_mode)

            # Run analysis in executor to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, analyzer.analyze_binary)

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

            analysis_payload = result if isinstance(result, dict) else {}
            return build_mcp_tool_response(
                tool_name="analyze_binary",
                text=text,
                payload={
                    "analysis": {
                        "file_type": analysis_payload.get("binary", {}).get("type", "unknown"),
                        "vulnerabilities": analysis_payload.get("errors", []),
                    },
                    "analysis_result": analysis_payload,
                },
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "binary_input",
                            path=path,
                            trace_id=f"mcp:analyze:{path}",
                            evidence_kind="input_binary",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "artifacts": [],
                    "stages": [
                        "mcp_tool_execution",
                        "binary_analysis",
                        "result_contract_serialization",
                    ],
                    "references": [],
                    "tools": ["analyze_binary", "reveng_analyzer"],
                },
            )

        except Exception as e:
            return build_mcp_tool_response(
                tool_name="analyze_binary",
                text=f"Error analyzing binary: {str(e)}",
                payload={},
                status="error",
                error=str(e),
            )

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

            return build_mcp_tool_response(
                tool_name="deobfuscate_js",
                text=text,
                payload=response,
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "javascript_input",
                            trace_id="mcp:deobfuscate:code",
                            evidence_kind="input_script",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "artifacts": [
                        make_evidence_item(
                            "deobfuscated_javascript",
                            trace_id="mcp:deobfuscate:output",
                            evidence_kind="generated_source",
                            confidence=float(result.confidence) / 100.0,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "stages": [
                        "mcp_tool_execution",
                        "javascript_deobfuscation",
                        "result_contract_serialization",
                    ],
                    "references": [],
                    "tools": ["deobfuscate_js", "javascript_deobfuscator"],
                },
            )

        except Exception as e:
            return build_mcp_tool_response(
                tool_name="deobfuscate_js",
                text=f"Error deobfuscating JavaScript: {str(e)}",
                payload={},
                status="error",
                error=str(e),
            )

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

                return build_mcp_tool_response(
                    tool_name="detect_malware",
                    text=text,
                    payload={
                        "threat_score": result.threat_score,
                        "is_malicious": result.is_malicious,
                        "indicators": result.indicators,
                    },
                    provenance={
                        "inputs": [
                            make_evidence_item(
                                "javascript_input",
                                path=path,
                                trace_id=f"mcp:malware:{path}",
                                evidence_kind="input_script",
                                confidence=1.0,
                                source_result_type="mcp_tool_result",
                            )
                        ],
                        "artifacts": [],
                        "stages": [
                            "mcp_tool_execution",
                            "javascript_malware_detection",
                            "result_contract_serialization",
                        ],
                        "references": [],
                        "tools": ["detect_malware", "javascript_malware_detector"],
                    },
                )

            else:
                # Binary malware detection
                # TODO: Implement binary malware detection
                return build_mcp_tool_response(
                    tool_name="detect_malware",
                    text="Binary malware detection not yet implemented",
                    payload={},
                )

        except Exception as e:
            return build_mcp_tool_response(
                tool_name="detect_malware",
                text=f"Error detecting malware: {str(e)}",
                payload={},
                status="error",
                error=str(e),
            )

    async def reverse_engineer_app(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Run the shared app reverse-engineering workflow through MCP."""
        try:
            path = Path(args["path"]).expanduser().resolve()
            language = str(args.get("language") or "auto")
            output_dir = str(
                Path(args.get("output_dir") or (Path.cwd() / f"analysis_{path.stem}"))
                .expanduser()
                .resolve()
            )

            framework = create_default_framework()
            result = await framework.reverse_engineer(
                str(path),
                output_dir,
                language=language,
            )

            text = (
                f"App reverse engineering completed for {path.name}\n"
                + "=" * 70
                + "\n\n"
                + f"Language: {result.language}\n"
                + f"Adapter: {result.adapter_name}\n"
                + f"Validation: {result.validation_grade}\n"
                + f"Recovered sources: {result.source_count}\n"
                + f"Analysis summary: {result.analysis_file}\n"
            )
            provenance = dict(result.provenance)
            provenance["stages"] = ["mcp_tool_execution"] + list(provenance.get("stages", []))
            provenance["tools"] = ["reverse_engineer_app"] + list(provenance.get("tools", []))

            return build_mcp_tool_response(
                tool_name="reverse_engineer_app",
                text=text,
                payload={
                    "language": result.language,
                    "analysis_file": str(result.analysis_file),
                    "app_result": result.metadata,
                },
                provenance=provenance,
            )
        except Exception as e:
            return build_mcp_tool_response(
                tool_name="reverse_engineer_app",
                text=f"Error reverse engineering app: {str(e)}",
                payload={},
                status="error",
                error=str(e),
            )

    async def run_app_corpus(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Run the manifest-driven app reverse-engineering corpus through MCP."""
        try:
            if load_app_corpus_config is None:
                raise RuntimeError("App corpus loader is not available")

            config_path = args.get("config_path")
            config = (
                load_app_corpus_config(Path(config_path).expanduser().resolve())
                if config_path
                else load_app_corpus_config()
            )
            corpus_entries = [AppCorpusEntry(**entry) for entry in config.get("entries", [])]
            corpus_entries = select_app_corpus_entries(corpus_entries, args.get("entry_names"))
            output_dir = str(
                Path(
                    args.get("output_dir")
                    or (Path.cwd() / "reports" / "app_reverse_engineering_corpus")
                )
                .expanduser()
                .resolve()
            )
            report = await run_app_corpus(corpus_entries, output_dir)
            text = (
                "App corpus execution completed\n"
                + "=" * 70
                + "\n\n"
                + f"Matrix status: {report['summary']['matrix_status']}\n"
                + f"Completed entries: {report['summary']['completed_entries']}\n"
                + f"Failed entries: {report['summary']['failed_entries']}\n"
            )
            return build_mcp_tool_response(
                tool_name="run_app_corpus",
                text=text,
                payload={"corpus_report": report},
                provenance={
                    "inputs": [],
                    "artifacts": [],
                    "stages": [
                        "mcp_tool_execution",
                        "app_corpus_execution",
                        "result_contract_serialization",
                    ],
                    "references": [],
                    "tools": ["run_app_corpus"],
                },
            )
        except Exception as e:
            return build_mcp_tool_response(
                tool_name="run_app_corpus",
                text=f"Error running app corpus: {str(e)}",
                payload={},
                status="error",
                error=str(e),
            )

    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """Read a resource (not implemented)"""
        return {"uri": uri, "mimeType": "text/plain", "text": "Resources not supported"}

    async def get_prompt(self, name: str, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get a prompt (not implemented)"""
        return []


# Main entry point
if __name__ == "__main__":
    from ..transports import StdioTransport

    async def main():
        server = REVENGMCPServer()
        transport = StdioTransport()
        await server.start(transport)

    asyncio.run(main())
