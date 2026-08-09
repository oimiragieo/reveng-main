"""
REVENG Enterprise MCP Server
============================

Preview MCP server exposing REVENG capabilities to AI agents.

Maturity follows docs/support_matrix.json — exploit generation is experimental;
native Ghidra paths are limited. Do not treat this surface as GA.

Features:
- Specialized reverse engineering tools (capability-graded)
- Resource providers for analysis results
- Prompt templates for common workflows
- Enterprise controls (rate limiting, audit logging) when configured
- Explicit unsupported/could_not_measure responses for unwired knobs

Example:
    ```python
    server = REVENGEnterpriseServer()
    await server.start(StdioTransport())
    ```

Author: REVENG Development Team
Version: 4.0.0
License: MIT
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, cast

import requests

from ....ai.angr_cfg_preprocessor import AngrCFGPreprocessor, CFGExtractionError
from ....app_reverse_engineering import (
    AppCorpusEntry,
    create_default_framework,
    run_app_corpus,
    select_app_corpus_entries,
)
from ....core.result_contracts import (
    RESULT_SCHEMA_VERSION,
    build_mcp_resource_result,
    build_mcp_tool_response,
    make_evidence_item,
    make_trace_reference,
)
from ....integrations.ghidra.ghidra_engine import GhidraEngine
from ....tools.anti_analysis.bun_extractor import run_bun_sea_workflow
from ..server import MCPPrompt, MCPResource, MCPServer, MCPTool

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

try:
    from scripts.run_app_reverse_engineering_corpus import load_app_corpus_config
except Exception:  # pragma: no cover - script import fallback
    load_app_corpus_config = None

OLLAMA_CHAT_HOST = "http://localhost:11434"
OLLAMA_CHAT_ENDPOINT = f"{OLLAMA_CHAT_HOST}/api/chat"
OLLAMA_CHAT_MODEL = "qwen2.5-coder:32b-instruct"
OLLAMA_CHAT_TIMEOUT_SECONDS = 90


class AuditLogger:
    """Enterprise audit logging for MCP operations"""

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or Path.home() / ".reveng" / "audit_logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.current_log = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.jsonl"

    def log_event(
        self,
        event_type: str,
        tool_name: str,
        args: Dict[str, Any],
        result: str,
        duration_ms: float,
        error: Optional[str] = None,
    ):
        """Log audit event"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "tool_name": tool_name,
            "args_hash": hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()[:16],
            "result": result,
            "duration_ms": duration_ms,
            "error": error,
        }

        with open(self.current_log, "a") as f:
            f.write(json.dumps(event) + "\n")

        logger.info(f"Audit: {event_type} - {tool_name} - {result} ({duration_ms:.2f}ms)")


class RateLimiter:
    """Simple token bucket rate limiter"""

    def __init__(self, tokens_per_second: float = 10.0, bucket_size: int = 20):
        self.tokens_per_second = tokens_per_second
        self.bucket_size = bucket_size
        self.tokens: float = float(bucket_size)
        self.last_update = time.time()

    async def acquire(self) -> bool:
        """Try to acquire a token"""
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.bucket_size, self.tokens + elapsed * self.tokens_per_second)
        self.last_update = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class OllamaRepairEngine:
    """Minimal LLM adapter that matches the recompilation engine's expectations."""

    def __init__(
        self,
        model: str = "qwen2.5-coder:32b-instruct",
        host: str = "http://localhost:11434",
        timeout: int = 90,
        temperature: float = 0.1,
    ):
        self.model = model
        self.host = host
        self.timeout = timeout
        self.temperature = temperature

        try:
            import ollama as ollama_module
        except ImportError:
            self.ollama = None
            self.client = None
        else:
            self.ollama = ollama_module
            self.client = (
                ollama_module.Client(host=host) if hasattr(ollama_module, "Client") else None
            )

    def is_available(self) -> bool:
        """Return True when the Ollama Python package is available."""
        return self.ollama is not None

    async def _generate_async(self, prompt: str) -> str:
        """Generate text using the configured Ollama model."""
        if not self.is_available():
            raise RuntimeError("ollama Python package is not available")

        response = await asyncio.wait_for(
            asyncio.to_thread(self._chat, prompt),
            timeout=self.timeout,
        )
        content = self._extract_message_content(response)
        if not content.strip():
            raise RuntimeError("Ollama returned an empty response")
        return content

    def _chat(self, prompt: str) -> Any:
        """Send a single prompt to Ollama."""
        messages = [
            {
                "role": "system",
                "content": (
                    "You are an expert reverse engineer repairing C code so it becomes "
                    "valid, compilable, and faithful to the original binary structure."
                ),
            },
            {"role": "user", "content": prompt},
        ]
        options = {"temperature": self.temperature}

        if self.client is not None:
            return self.client.chat(model=self.model, messages=messages, options=options)

        ollama_module = self.ollama
        if ollama_module is None:
            raise RuntimeError("ollama Python package is not available")

        return ollama_module.chat(model=self.model, messages=messages, options=options)

    def _extract_message_content(self, response: Any) -> str:
        """Extract a text message from Ollama's response object."""
        if isinstance(response, dict):
            message = response.get("message", {})
            if isinstance(message, dict):
                return str(message.get("content", ""))
            return str(response.get("response", ""))

        message = getattr(response, "message", None)
        if isinstance(message, dict):
            return str(message.get("content", ""))

        content = getattr(message, "content", None)
        if content is not None:
            return str(content)

        return str(getattr(response, "response", ""))


class REVENGEnterpriseServer(MCPServer):
    """
    Enterprise-grade REVENG MCP Server.

    Exposes comprehensive REVENG capabilities as MCP tools, resources, and prompts
    for AI-powered binary analysis and reverse engineering workflows.

    Capabilities:
    - Binary Analysis: Decompile, analyze, and recompile binaries
    - Security: Vulnerability detection and exploit generation
    - JavaScript: Deobfuscation and malware detection
    - AI Queries: Natural language interface to analysis results
    - Diffing: Semantic binary comparison
    - Classification: Malware and threat intelligence

    Example:
        ```python
        server = REVENGEnterpriseServer()
        await server.start(StdioTransport())
        ```
    """

    _TOOL_RISK_POLICIES: Dict[str, Dict[str, Any]] = {
        "analyze_binary": {"risk_level": "moderate", "requires_policy_acknowledgement": False},
        "decompile_binary": {"risk_level": "moderate", "requires_policy_acknowledgement": False},
        "recompile_binary": {"risk_level": "high", "requires_policy_acknowledgement": False},
        "diff_binaries": {"risk_level": "moderate", "requires_policy_acknowledgement": False},
        "scan_yara": {"risk_level": "moderate", "requires_policy_acknowledgement": False},
        "analyze_memory_dump": {"risk_level": "high", "requires_policy_acknowledgement": False},
        "find_vulnerabilities": {
            "risk_level": "moderate",
            "requires_policy_acknowledgement": False,
        },
        "generate_exploit": {"risk_level": "high", "requires_policy_acknowledgement": True},
        "classify_malware": {"risk_level": "moderate", "requires_policy_acknowledgement": False},
        "deobfuscate_javascript": {
            "risk_level": "moderate",
            "requires_policy_acknowledgement": False,
        },
        "detect_js_malware": {"risk_level": "moderate", "requires_policy_acknowledgement": False},
        "ask_ai_about_binary": {"risk_level": "moderate", "requires_policy_acknowledgement": False},
        "ai_code_reconstruction": {"risk_level": "high", "requires_policy_acknowledgement": False},
        "get_analysis_report": {"risk_level": "low", "requires_policy_acknowledgement": False},
        "list_recent_analyses": {"risk_level": "low", "requires_policy_acknowledgement": False},
        "reverse_engineer_app": {"risk_level": "low", "requires_policy_acknowledgement": False},
        "run_app_corpus": {"risk_level": "low", "requires_policy_acknowledgement": False},
    }

    # Wave 2 explicit denylist — MCP spec hints (not every risk_level=high).
    _MCP_HINT_DENYLIST: Dict[str, Dict[str, bool]] = {
        "generate_exploit": {
            "destructiveHint": True,
            "readOnlyHint": False,
            "openWorldHint": True,
        },
        "recompile_binary": {
            "destructiveHint": True,
            "readOnlyHint": False,
            "openWorldHint": True,
        },
    }

    def __init__(self, enable_rate_limiting: bool = True, enable_audit_log: bool = True):
        super().__init__("reveng-enterprise", "4.0.0")

        # Enterprise features
        self.audit_logger = AuditLogger() if enable_audit_log else None
        self.rate_limiter = RateLimiter(tokens_per_second=5.0) if enable_rate_limiting else None
        ollama_chat_config = self._resolve_ollama_chat_config()
        self.ollama_chat_host = ollama_chat_config["host"]
        self.ollama_chat_endpoint = ollama_chat_config["endpoint"]
        self.ollama_chat_model = ollama_chat_config["model"]
        self.ollama_chat_timeout_seconds = ollama_chat_config["timeout_seconds"]

        # Analysis results cache
        self.results_cache: Dict[str, Any] = {}
        self.cache_dir = Path.home() / ".reveng" / "mcp_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ghidra_engine = GhidraEngine(fail_fast=False)

        # Register all tools
        self._register_binary_tools()
        self._register_forensics_tools()
        self._register_security_tools()
        self._register_javascript_tools()
        self._register_ai_tools()
        self._register_utility_tools()

        # Register resources
        self._register_resources()

        # Register prompts
        self._register_prompts()
        self._apply_tool_policies()

        logger.info("REVENG Enterprise MCP Server initialized")

    def _resolve_ollama_chat_config(self) -> Dict[str, Any]:
        """Resolve MCP-local Ollama routing from config and environment."""
        host = OLLAMA_CHAT_HOST
        model = OLLAMA_CHAT_MODEL
        timeout_seconds = OLLAMA_CHAT_TIMEOUT_SECONDS

        try:
            from ....tools.config.config_manager import ConfigManager

            ai_config = ConfigManager().get_ai_config()
        except Exception:
            ai_config = None
        else:
            if ai_config.provider in {"ollama", "local"}:
                host = ai_config.ollama_host or host
                if ai_config.ollama_model and ai_config.ollama_model != "auto":
                    model = ai_config.ollama_model
                timeout_seconds = int(ai_config.ollama_timeout or timeout_seconds)

        host = os.environ.get(
            "REVENG_MCP_OLLAMA_HOST",
            os.environ.get("OLLAMA_HOST", host),
        )
        model = os.environ.get(
            "REVENG_MCP_OLLAMA_MODEL",
            os.environ.get("OLLAMA_MODEL", model),
        )
        timeout_raw = os.environ.get(
            "REVENG_MCP_OLLAMA_TIMEOUT",
            os.environ.get("OLLAMA_TIMEOUT", str(timeout_seconds)),
        )
        try:
            timeout_seconds = max(1, int(timeout_raw))
        except ValueError:
            timeout_seconds = OLLAMA_CHAT_TIMEOUT_SECONDS

        normalized_host = host.rstrip("/")
        return {
            "host": normalized_host,
            "endpoint": f"{normalized_host}/api/chat",
            "model": model,
            "timeout_seconds": timeout_seconds,
        }

    def _apply_tool_policies(self) -> None:
        """Apply enterprise risk annotations and input gates to registered tools."""
        for tool_name, tool in self.tools.items():
            policy = self._TOOL_RISK_POLICIES.get(
                tool_name,
                {"risk_level": "moderate", "requires_policy_acknowledgement": False},
            )
            annotations: Dict[str, Any] = {
                "risk_level": policy["risk_level"],
                "requires_policy_acknowledgement": policy["requires_policy_acknowledgement"],
                "least_privilege_reviewed": True,
            }
            mcp_hints = self._MCP_HINT_DENYLIST.get(tool_name)
            if mcp_hints:
                annotations.update(mcp_hints)
            tool.annotations = annotations
            if policy["requires_policy_acknowledgement"]:
                properties = tool.input_schema.setdefault("properties", {})
                properties.setdefault(
                    "policy_acknowledged",
                    {
                        "type": "boolean",
                        "description": (
                            "Explicit acknowledgement that this high-risk tool may generate "
                            "sensitive outputs or perform privileged analysis steps."
                        ),
                    },
                )

    def _build_policy_denied_response(self, tool_name: str, reason: str) -> Dict[str, Any]:
        """Build a policy denial response with explicit provenance."""
        return build_mcp_tool_response(
            tool_name=tool_name,
            text=(
                f"Policy denied `{tool_name}`. "
                "This tool requires explicit `policy_acknowledged: true`."
            ),
            payload={},
            status="error",
            error=reason,
            provenance={
                "inputs": [],
                "artifacts": [],
                "stages": [
                    "mcp_tool_execution",
                    "enterprise_policy_gate",
                    "result_contract_serialization",
                ],
                "references": [
                    make_trace_reference(
                        "blocked_by_policy",
                        tool_name,
                        trace_id=f"enterprise:mcp:policy:{tool_name}",
                        confidence=1.0,
                    )
                ],
                "tools": [tool_name, "enterprise_policy_gate"],
            },
        )

    def _validate_tool_policy(
        self, tool_name: str, args: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Validate policy requirements for a tool invocation."""
        policy = self._TOOL_RISK_POLICIES.get(tool_name)
        if not policy or not policy.get("requires_policy_acknowledgement"):
            return None
        if args.get("policy_acknowledged") is True:
            return None
        return self._build_policy_denied_response(tool_name, "policy_acknowledgement_required")

    @staticmethod
    def _hash_text(value: str) -> str:
        """Return a stable SHA-256 hash for provenance metadata."""
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _build_ollama_provenance_metadata(
        self,
        *,
        prompt_text: str,
        context_text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build traceable metadata for Ollama-backed MCP outputs."""
        metadata: Dict[str, Any] = {
            "prompt_sha256": self._hash_text(prompt_text),
            "model_host": self.ollama_chat_host,
            "model_endpoint": self.ollama_chat_endpoint,
        }
        if context_text is not None:
            metadata["context_sha256"] = self._hash_text(context_text)
        return metadata

    # ==================================================================================
    # BINARY ANALYSIS TOOLS
    # ==================================================================================

    def _register_binary_tools(self):
        """Register binary analysis and decompilation tools"""

        self.register_tool(
            MCPTool(
                name="analyze_binary",
                description="Comprehensive binary analysis with AI-powered decompilation and reconstruction",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to binary file (PE, ELF, Mach-O, JAR, .NET, etc.)",
                        },
                        "quick_mode": {
                            "type": "boolean",
                            "description": "Skip Ollama preflight check (faster startup; analysis steps unchanged)",
                        },
                        "enable_ai": {
                            "type": "boolean",
                            "description": "Use AI-powered code reconstruction (Gemini/Claude)",
                        },
                        "find_vulnerabilities": {
                            "type": "boolean",
                            "description": "Scan for vulnerabilities during analysis",
                        },
                    },
                    "required": ["path"],
                },
                handler=self.analyze_binary,
            )
        )

        self.register_tool(
            MCPTool(
                name="decompile_binary",
                description="Decompile binary to source using Ghidra (AI enhancement unsupported in this MCP path)",
                input_schema={
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Path to binary file",
                        },
                        "output_path": {
                            "type": "string",
                            "description": "Output path for decompiled code",
                        },
                        "use_ai_enhancement": {
                            "type": "boolean",
                            "description": "Requested AI enhancement — unsupported in this MCP path (ghidra-only)",
                        },
                        "reconstruct_types": {
                            "type": "boolean",
                            "description": "Requested type reconstruction — unsupported in this MCP path",
                        },
                    },
                    "required": ["binary_path"],
                },
                handler=self.decompile_binary,
            )
        )

        self.register_tool(
            MCPTool(
                name="recompile_binary",
                description="Recompile a binary using decompiled or provided source code with Ollama-assisted repair",
                input_schema={
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Path to the original binary to reconstruct",
                        },
                        "source_code": {
                            "type": "string",
                            "description": "Optional C source override to compile instead of re-decompiling",
                        },
                        "output_path": {
                            "type": "string",
                            "description": "Optional output path for the rebuilt binary",
                        },
                    },
                    "required": ["binary_path"],
                },
                handler=self.recompile_binary,
            )
        )

        self.register_tool(
            MCPTool(
                name="diff_binaries",
                description="Compare two binaries and return structured diff results for forensic triage",
                input_schema={
                    "type": "object",
                    "properties": {
                        "binary1": {"type": "string", "description": "Path to first binary"},
                        "binary2": {"type": "string", "description": "Path to second binary"},
                        "semantic_diff": {
                            "type": "boolean",
                            "description": "Use semantic diffing (slower, more accurate)",
                        },
                    },
                    "required": ["binary1", "binary2"],
                },
                handler=self.diff_binaries,
            )
        )

    # ==================================================================================
    # FORENSICS TOOLS
    # ==================================================================================

    def _register_forensics_tools(self):
        """Register forensic analysis tools."""

        self.register_tool(
            MCPTool(
                name="scan_yara",
                description="Scan a file with YARA rules and return structured match details",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the file to scan with YARA",
                        },
                        "rules_path": {
                            "type": "string",
                            "description": "Path to a .yar file or directory containing YARA rules",
                        },
                        "include_string_data": {
                            "type": "boolean",
                            "description": "Include matched string payload previews in the response",
                        },
                    },
                    "required": ["path", "rules_path"],
                },
                handler=self.scan_yara,
            )
        )

        self.register_tool(
            MCPTool(
                name="analyze_memory_dump",
                description="Run memory forensics analysis on a dump or target binary and return structured findings",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the dump or binary to analyze",
                        },
                        "output_dir": {
                            "type": "string",
                            "description": "Optional directory for persisted memory analysis artifacts",
                        },
                        "memory_scan_batch_size": {
                            "type": "integer",
                            "description": "Optional GPU/CPU memory scan batch size override",
                        },
                        "memory_scan_max_wait_seconds": {
                            "type": "number",
                            "description": "Optional maximum queue wait before dispatching a batch",
                        },
                    },
                    "required": ["path"],
                },
                handler=self.analyze_memory_dump,
            )
        )

    # ==================================================================================
    # SECURITY ANALYSIS TOOLS
    # ==================================================================================

    def _register_security_tools(self):
        """Register vulnerability detection and exploit generation tools"""

        self.register_tool(
            MCPTool(
                name="find_vulnerabilities",
                description=(
                    "Find vulnerabilities via symbolic execution when enabled "
                    "(experimental depth; AI-typed filters unsupported in this path)"
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to binary or source code"},
                        "vulnerability_types": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": [
                                    "buffer_overflow",
                                    "heap_overflow",
                                    "use_after_free",
                                    "double_free",
                                    "null_deref",
                                    "integer_overflow",
                                    "format_string",
                                    "command_injection",
                                    "path_traversal",
                                    "sql_injection",
                                ],
                            },
                            "description": "Specific vulnerability types to search for",
                        },
                        "use_symbolic_execution": {
                            "type": "boolean",
                            "description": "Use symbolic execution (angr + Z3)",
                        },
                        "use_ai_analysis": {
                            "type": "boolean",
                            "description": "Use AI-powered vulnerability detection",
                        },
                    },
                    "required": ["path"],
                },
                handler=self.find_vulnerabilities,
            )
        )

        self.register_tool(
            MCPTool(
                name="generate_exploit",
                description="Generate exploit PoC scaffolding for vulnerabilities discovered via angr CFGFast and symbolic execution",
                input_schema={
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Path to vulnerable binary",
                        },
                        "vulnerability_type": {
                            "type": "string",
                            "enum": [
                                "buffer_overflow",
                                "heap_overflow",
                                "use_after_free",
                                "format_string",
                            ],
                            "description": "Type of vulnerability",
                        },
                        "target_address": {
                            "type": "string",
                            "description": "Target address/function (optional)",
                        },
                        "generate_rop_chain": {
                            "type": "boolean",
                            "description": "Generate ROP chain for exploit",
                        },
                        "analysis_depth": {
                            "type": "string",
                            "enum": ["shallow", "medium", "deep"],
                            "description": "Symbolic execution depth to use for exploit analysis",
                        },
                    },
                    "required": ["binary_path"],
                },
                handler=self.generate_exploit,
            )
        )

        self.register_tool(
            MCPTool(
                name="classify_malware",
                description="Classify malware family and APT attribution using ML and threat intelligence",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to potential malware"},
                        "use_ollama_family_naming": {
                            "type": "boolean",
                            "description": "Use Ollama to refine the malware family label when available",
                        },
                        "include_threat_intel": {
                            "type": "boolean",
                            "description": "Include threat intelligence correlation",
                        },
                        "mitre_attack_mapping": {
                            "type": "boolean",
                            "description": "Map to MITRE ATT&CK framework",
                        },
                    },
                    "required": ["path"],
                },
                handler=self.classify_malware,
            )
        )

    # ==================================================================================
    # JAVASCRIPT TOOLS
    # ==================================================================================

    def _register_javascript_tools(self):
        """Register JavaScript deobfuscation and analysis tools"""

        self.register_tool(
            MCPTool(
                name="deobfuscate_javascript",
                description="Advanced JavaScript deobfuscation with ML renaming and malware detection",
                input_schema={
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Obfuscated JavaScript code"},
                        "file_path": {"type": "string", "description": "Or path to .js file"},
                        "use_ml_renaming": {
                            "type": "boolean",
                            "description": "Use ML for intelligent variable renaming when available",
                        },
                        "use_llm_analysis": {
                            "type": "boolean",
                            "description": "Use LLM for semantic analysis",
                        },
                        "detect_malware": {
                            "type": "boolean",
                            "description": "Run malware detection (10 categories, 50+ signatures)",
                        },
                        "unbundle_webpack": {
                            "type": "boolean",
                            "description": "Unbundle webpack/browserify bundles",
                        },
                    },
                    "required": [],
                },
                handler=self.deobfuscate_javascript,
            )
        )

        self.register_tool(
            MCPTool(
                name="detect_js_malware",
                description="Detect malware in JavaScript code with signature and behavioral analysis",
                input_schema={
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "JavaScript code to analyze"},
                        "file_path": {"type": "string", "description": "Or path to .js file"},
                    },
                    "required": [],
                },
                handler=self.detect_js_malware,
            )
        )

    # ==================================================================================
    # AI-POWERED TOOLS
    # ==================================================================================

    def _register_ai_tools(self):
        """Register AI-powered query and analysis tools"""

        self.register_tool(
            MCPTool(
                name="ask_ai_about_binary",
                description="Ask natural language questions about a binary using local Ollama-powered reverse-engineering context",
                input_schema={
                    "type": "object",
                    "properties": {
                        "binary_path": {"type": "string", "description": "Path to binary file"},
                        "question": {
                            "type": "string",
                            "description": "Question (e.g., 'What does this binary do?', 'Find all network connections')",
                        },
                        "context": {
                            "type": "string",
                            "description": "Additional context for the question",
                        },
                    },
                    "required": ["binary_path", "question"],
                },
                handler=self.ask_ai_about_binary,
            )
        )

        self.register_tool(
            MCPTool(
                name="ai_code_reconstruction",
                description="Reconstruct clean idiomatic C from a binary using CFG-aware Ollama prompts",
                input_schema={
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Path to the binary file to reconstruct",
                        },
                        "decompiled_code": {
                            "type": "string",
                            "description": "Optional pre-decompiled code to enhance alongside the binary context",
                        },
                        "add_documentation": {
                            "type": "boolean",
                            "description": "Generate code documentation",
                        },
                        "reconstruct_types": {
                            "type": "boolean",
                            "description": "Infer and reconstruct types",
                        },
                        "rename_variables": {
                            "type": "boolean",
                            "description": "Rename variables to meaningful names",
                        },
                    },
                    "required": ["binary_path"],
                },
                handler=self.ai_code_reconstruction,
            )
        )

    # ==================================================================================
    # UTILITY TOOLS
    # ==================================================================================

    def _register_utility_tools(self):
        """Register utility and helper tools"""

        self.register_tool(
            MCPTool(
                name="get_analysis_report",
                description="Get comprehensive analysis report for a previously analyzed binary",
                input_schema={
                    "type": "object",
                    "properties": {
                        "analysis_id": {
                            "type": "string",
                            "description": "Analysis ID from previous run",
                        },
                        "format": {
                            "type": "string",
                            "enum": ["text", "json", "html", "pdf"],
                            "description": "Report format",
                        },
                    },
                    "required": ["analysis_id"],
                },
                handler=self.get_analysis_report,
            )
        )

        self.register_tool(
            MCPTool(
                name="list_recent_analyses",
                description="List recent binary analyses",
                input_schema={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "description": "Maximum number of results"}
                    },
                    "required": [],
                },
                handler=self.list_recent_analyses,
            )
        )

        self.register_tool(
            MCPTool(
                name="reverse_engineer_app",
                description="Run the shared multi-language app reverse-engineering workflow and return a normalized contract",
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
                            "description": "Optional output directory for artifacts and SPECS",
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

    # ==================================================================================
    # TOOL IMPLEMENTATIONS
    # ==================================================================================

    async def _execute_with_audit(
        self,
        tool_name: str,
        args: Dict[str, Any],
        handler_func: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """Execute tool with rate limiting and audit logging"""
        policy_denied = self._validate_tool_policy(tool_name, args)
        if policy_denied is not None:
            if self.audit_logger:
                self.audit_logger.log_event(
                    event_type="tool_execution",
                    tool_name=tool_name,
                    args=args,
                    result="error",
                    duration_ms=0.0,
                    error="policy_acknowledgement_required",
                )
            return policy_denied

        # Rate limiting
        if self.rate_limiter:
            if not await self.rate_limiter.acquire():
                result = build_mcp_tool_response(
                    tool_name=tool_name,
                    text="Rate limit exceeded. Please try again later.",
                    payload={},
                    status="error",
                    error="rate_limit_exceeded",
                )
                if self.audit_logger:
                    self.audit_logger.log_event(
                        event_type="tool_execution",
                        tool_name=tool_name,
                        args=args,
                        result="error",
                        duration_ms=0.0,
                        error="rate_limit_exceeded",
                    )
                return result

        # Execute with timing
        start_time = time.time()
        error = None

        try:
            result = await handler_func(args)
            result_status = "success" if "error" not in result else "error"
        except Exception as e:
            logger.exception(f"Error executing {tool_name}")
            result = build_mcp_tool_response(
                tool_name=tool_name,
                text=f"Internal error: {str(e)}",
                payload={},
                status="error",
                error=str(e),
            )
            result_status = "error"
            error = str(e)

        duration_ms = (time.time() - start_time) * 1000

        # Audit logging
        if self.audit_logger:
            self.audit_logger.log_event(
                event_type="tool_execution",
                tool_name=tool_name,
                args=args,
                result=result_status,
                duration_ms=duration_ms,
                error=error,
            )

        return result

    async def analyze_binary(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive binary analysis"""
        try:
            from reveng.analysis.analyzer import EnhancedAnalysisFeatures, REVENGAnalyzer

            path = args["path"]
            quick_mode = bool(args.get("quick_mode", False))
            enable_ai = bool(args.get("enable_ai", True))
            find_vulns = bool(args.get("find_vulnerabilities", False))

            features = EnhancedAnalysisFeatures()
            features.enable_vulnerability_discovery = False
            if not enable_ai:
                features.enable_enhanced_analysis = False
                features.enable_corporate_exposure = False
                features.enable_threat_intelligence = False
                features.enable_enhanced_reconstruction = False
                features.enable_demonstration_generation = False

            effective_check_ollama = enable_ai and not quick_mode
            analyzer = REVENGAnalyzer(
                binary_path=path,
                check_ollama=effective_check_ollama,
                enable_ai=enable_ai,
                enhanced_features=features,
            )
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, analyzer.analyze_binary)

            # Cache results
            analysis_id = hashlib.md5(f"{path}{time.time()}".encode()).hexdigest()[:16]
            self.results_cache[analysis_id] = result

            # Format response
            text = self._format_analysis_results(result, path, analysis_id)
            knobs_applied = {
                "quick_mode": quick_mode,
                "enable_ai": enable_ai,
                "check_ollama": effective_check_ollama,
            }
            payload = {
                "analysis_id": analysis_id,
                "file_type": (result if isinstance(result, dict) else {})
                .get("binary", {})
                .get("type", "unknown"),
                "architecture": (result if isinstance(result, dict) else {})
                .get("binary", {})
                .get("architecture", "unknown"),
                "analysis_result": result if isinstance(result, dict) else {},
                "knobs_applied": knobs_applied,
            }
            if find_vulns:
                payload["find_vulnerabilities"] = "not_run_use_find_vulnerabilities_tool"
                text = (
                    f"{text}\n\nWarning: find_vulnerabilities requested but "
                    "not_run_use_find_vulnerabilities_tool"
                )

            return build_mcp_tool_response(
                tool_name="analyze_binary",
                text=text,
                payload=payload,
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "binary_input",
                            path=path,
                            trace_id=f"enterprise:mcp:analysis:{analysis_id}:input",
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
                    "references": [
                        make_trace_reference(
                            "cached_as",
                            analysis_id,
                            trace_id=f"enterprise:mcp:analysis:{analysis_id}",
                            confidence=1.0,
                        )
                    ],
                    "tools": ["analyze_binary", "reveng_analyzer"],
                },
            )

        except Exception as e:
            logger.exception("Error in analyze_binary")
            return build_mcp_tool_response(
                tool_name="analyze_binary",
                text=f"Error analyzing binary: {str(e)}",
                payload={},
                status="error",
                error=str(e),
            )

    async def decompile_binary(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Decompile binary to source code"""
        try:
            path = self._resolve_binary_argument(args, field_name="binary_path")
            output_path = args.get("output_path")
            ghidra_timeout = self._coerce_optional_int(args.get("_ghidra_timeout"))
            use_ai = bool(args.get("use_ai_enhancement", False))
            reconstruct_types = bool(args.get("reconstruct_types", False))
            ghidra_engine = self._get_ghidra_engine(timeout_override=ghidra_timeout)

            # Decompile with Ghidra
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, ghidra_engine.decompile, path)

            structured_result = self._build_decompile_response(path, result)

            # Save decompiled code
            if output_path:
                output_file = Path(output_path)
                output_file.parent.mkdir(parents=True, exist_ok=True)
                output_file.write_text(structured_result["decompiled_source"], encoding="utf-8")
                structured_result["output_path"] = str(output_file)

            text = structured_result["content"][0]["text"]
            payload = {key: value for key, value in structured_result.items() if key != "content"}
            knobs_applied = {}
            if use_ai:
                knobs_applied["use_ai_enhancement"] = "unsupported"
                text = (
                    f"{text}\n\nWarning: use_ai_enhancement requested but unsupported; "
                    "ghidra-only decompile"
                )
            if reconstruct_types:
                knobs_applied["reconstruct_types"] = "unsupported"
                payload["reconstruct_types"] = "unsupported"
                text = (
                    f"{text}\n\nWarning: reconstruct_types requested but unsupported "
                    "in this MCP decompile path"
                )
            if knobs_applied:
                payload["knobs_applied"] = knobs_applied

            return build_mcp_tool_response(
                tool_name="decompile_binary",
                text=text,
                payload=payload,
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "binary_input",
                            path=path,
                            trace_id=f"enterprise:mcp:decompile:{Path(path).name}",
                            evidence_kind="input_binary",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "artifacts": (
                        [
                            make_evidence_item(
                                "decompiled_source",
                                path=structured_result.get("output_path"),
                                trace_id=f"enterprise:mcp:decompile:{Path(path).name}:source",
                                evidence_kind="generated_source",
                                confidence=0.8,
                                source_result_type="mcp_tool_result",
                            )
                        ]
                        if structured_result.get("output_path")
                        else []
                    ),
                    "stages": [
                        "mcp_tool_execution",
                        "binary_decompilation",
                        "result_contract_serialization",
                    ],
                    "references": [
                        make_trace_reference(
                            "derived_from",
                            path,
                            trace_id=f"enterprise:mcp:decompile:{Path(path).name}:input",
                            confidence=1.0,
                        )
                    ],
                    "tools": ["decompile_binary", "ghidra_engine"],
                },
            )

        except Exception as e:
            logger.exception("Error in decompile_binary")
            return build_mcp_tool_response(
                tool_name="decompile_binary",
                text=f"Error decompiling binary: {str(e)}",
                payload={"status_code": 500},
                status="error",
                error=f"Error decompiling binary: {str(e)}",
            )

    async def recompile_binary(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Recompile source to binary"""
        try:
            from reveng.ai.recompilation_engine import BinaryRecompilationEngine

            binary_path = self._resolve_binary_argument(args, field_name="binary_path")
            provided_source = args.get("source_code")
            requested_output_path = args.get("output_path")
            ghidra_timeout = max(180, self._coerce_optional_int(args.get("_ghidra_timeout")) or 0)

            output_dir = self.cache_dir / f"recompile_{Path(binary_path).stem}_{int(time.time())}"
            output_dir.mkdir(parents=True, exist_ok=True)

            if not str(provided_source or "").strip():
                loop = asyncio.get_running_loop()
                bun_result = await loop.run_in_executor(
                    None,
                    lambda: run_bun_sea_workflow(
                        binary_path=binary_path,
                        output_dir=str(output_dir),
                        output_path=requested_output_path,
                        skip_install=False,
                    ),
                )
                if bun_result.info.is_bun_executable:
                    if (
                        bun_result.status == "success"
                        and bun_result.build_result
                        and bun_result.build_result.output_path
                    ):
                        compiled_binary = bun_result.build_result.output_path
                        artifact_details = self._inspect_binary_artifact(compiled_binary)
                        normalization = bun_result.normalization
                        report_path = bun_result.report_path
                        text = (
                            "Bun executable recompilation complete\n"
                            + "=" * 70
                            + "\n\n"
                            + f"Input: {binary_path}\n"
                            + f"Output: {compiled_binary}\n"
                            + f"Size: {artifact_details['size_bytes']} bytes\n"
                            + f"Magic: {artifact_details['magic']}\n"
                            + "Strategy: bun_node_sea\n"
                            + f"Canonical input: {bun_result.canonical_input}\n"
                            + f"Build report: {report_path}\n"
                        )

                        return build_mcp_tool_response(
                            tool_name="recompile_binary",
                            text=text,
                            payload={
                                "status_code": 200,
                                "binary_path": binary_path,
                                "output_path": compiled_binary,
                                "success": True,
                                "recompilation_strategy": "bun_node_sea",
                                "function_overlap": None,
                                "binary_size": artifact_details["size_bytes"],
                                "magic_bytes": artifact_details["magic"],
                                "source_path": (
                                    normalization.entrypoint_path
                                    if normalization
                                    else bun_result.canonical_input
                                ),
                                "canonical_recompilation_input": bun_result.canonical_input,
                                "canonical_recompilation_reason": bun_result.canonical_reason,
                                "bun_report_path": report_path,
                                "bun_build_report": bun_result.report_data,
                                "bun_report_severity": (
                                    bun_result.report_data.get("report_severity")
                                    if bun_result.report_data
                                    else None
                                ),
                                "bun_differential_validation": (
                                    bun_result.report_data.get("differential_validation")
                                    if bun_result.report_data
                                    else None
                                ),
                                "bun_runtime_escalation": (
                                    bun_result.report_data.get("runtime_escalation")
                                    if bun_result.report_data
                                    else None
                                ),
                                "bun_equivalence_validation": (
                                    bun_result.report_data.get("equivalence_validation")
                                    if bun_result.report_data
                                    else None
                                ),
                                "bun_build_verification": (
                                    bun_result.build_result.verification
                                    if bun_result.build_result
                                    else None
                                ),
                                "normalized_project_dir": (
                                    normalization.output_dir if normalization else None
                                ),
                                "sea_blob_path": (
                                    bun_result.build_result.sea_blob_path
                                    if bun_result.build_result
                                    else None
                                ),
                                "installed_dependencies": (
                                    bun_result.build_result.installed_dependencies
                                    if bun_result.build_result
                                    else []
                                ),
                                "compilation_attempts": [],
                                "commands_run": (
                                    bun_result.build_result.commands_run
                                    if bun_result.build_result
                                    else []
                                ),
                                "model": None,
                            },
                            provenance={
                                "inputs": [
                                    make_evidence_item(
                                        "binary_input",
                                        path=binary_path,
                                        trace_id=f"enterprise:mcp:recompile:{Path(binary_path).name}",
                                        evidence_kind="input_binary",
                                        confidence=1.0,
                                        source_result_type="mcp_tool_result",
                                    )
                                ],
                                "artifacts": [
                                    make_evidence_item(
                                        "rebuilt_binary",
                                        path=compiled_binary,
                                        trace_id=(
                                            f"enterprise:mcp:recompile:{Path(binary_path).name}:rebuilt"
                                        ),
                                        evidence_kind="generated_binary",
                                        confidence=0.95,
                                        source_result_type="mcp_tool_result",
                                    ),
                                    make_evidence_item(
                                        "bun_rebuild_report",
                                        path=report_path,
                                        trace_id=(
                                            f"enterprise:mcp:recompile:{Path(binary_path).name}:bun-report"
                                        ),
                                        evidence_kind="analysis_report",
                                        confidence=0.9,
                                        source_result_type="mcp_tool_result",
                                    ),
                                ],
                                "stages": [
                                    "mcp_tool_execution",
                                    "bun_detection",
                                    "bun_bundle_extraction",
                                    "bun_virtual_filesystem_recovery",
                                    "bun_project_normalization",
                                    "node_sea_packaging",
                                    "result_contract_serialization",
                                ],
                                "references": [
                                    make_trace_reference(
                                        "rebuilt_from",
                                        binary_path,
                                        trace_id=(
                                            f"enterprise:mcp:recompile:{Path(binary_path).name}:source"
                                        ),
                                        confidence=0.95,
                                    )
                                ],
                                "tools": [
                                    "recompile_binary",
                                    "bun_extractor",
                                    "node",
                                    "npm",
                                    "postject",
                                ],
                            },
                        )

                    return build_mcp_tool_response(
                        tool_name="recompile_binary",
                        text=(
                            "Bun executable recompilation failed\n"
                            + "=" * 70
                            + "\n\n"
                            + f"Input: {binary_path}\n"
                            + f"Failure reason: {bun_result.reason or 'bun_rebuild_failed'}\n"
                            + (
                                f"Build report: {bun_result.report_path}\n"
                                if bun_result.report_path
                                else ""
                            )
                        ),
                        payload={
                            "status_code": 200,
                            "binary_path": binary_path,
                            "success": False,
                            "recompilation_strategy": "bun_node_sea",
                            "compilation_errors": [bun_result.reason or "bun_rebuild_failed"],
                            "partial_source": None,
                            "source_path": (
                                bun_result.normalization.entrypoint_path
                                if bun_result.normalization
                                else bun_result.canonical_input
                            ),
                            "compilation_attempts": [],
                            "failure_reason": bun_result.reason or bun_result.message,
                            "bun_report_path": bun_result.report_path,
                            "bun_build_report": bun_result.report_data,
                            "bun_report_severity": (
                                bun_result.report_data.get("report_severity")
                                if bun_result.report_data
                                else None
                            ),
                            "bun_differential_validation": (
                                bun_result.report_data.get("differential_validation")
                                if bun_result.report_data
                                else None
                            ),
                            "bun_runtime_escalation": (
                                bun_result.report_data.get("runtime_escalation")
                                if bun_result.report_data
                                else None
                            ),
                            "bun_equivalence_validation": (
                                bun_result.report_data.get("equivalence_validation")
                                if bun_result.report_data
                                else None
                            ),
                            "bun_build_verification": (
                                bun_result.build_result.verification
                                if bun_result.build_result
                                else None
                            ),
                            "model": None,
                        },
                        provenance={
                            "inputs": [
                                make_evidence_item(
                                    "binary_input",
                                    path=binary_path,
                                    trace_id=f"enterprise:mcp:recompile:{Path(binary_path).name}",
                                    evidence_kind="input_binary",
                                    confidence=1.0,
                                    source_result_type="mcp_tool_result",
                                )
                            ],
                            "artifacts": [],
                            "stages": [
                                "mcp_tool_execution",
                                "bun_detection",
                                "bun_bundle_extraction",
                                "bun_virtual_filesystem_recovery",
                                "bun_project_normalization",
                                "node_sea_packaging",
                                "result_contract_serialization",
                            ],
                            "references": [],
                            "tools": [
                                "recompile_binary",
                                "bun_extractor",
                                "node",
                                "npm",
                                "postject",
                            ],
                        },
                    )

            recompilation_ghidra = self._get_ghidra_engine(timeout_override=ghidra_timeout)

            decompile_result: Optional[Dict[str, Any]] = None
            source_text = str(provided_source or "")
            if not source_text.strip():
                decompile_result = await self.decompile_binary(
                    {
                        "binary_path": binary_path,
                        "_ghidra_timeout": ghidra_timeout,
                    }
                )
                if decompile_result.get("error"):
                    raise RuntimeError(str(decompile_result["error"]))

                source_text = self._build_recompilation_translation_unit(decompile_result)
                if not source_text.strip():
                    raise RuntimeError("No decompiled source was available for recompilation")

            llm_backend = OllamaRepairEngine()
            if not llm_backend.is_available():
                raise RuntimeError("ollama Python package is not available")

            engine = BinaryRecompilationEngine(
                ghidra_engine=recompilation_ghidra,
                gemini_engine=llm_backend,
                work_dir=output_dir,
                max_compilation_retries=3,
            )

            ghidra_data = await engine._phase1_decompilation(binary_path, output_dir)

            if decompile_result is not None:
                ghidra_data["functions"] = decompile_result.get("decompiled_functions", [])
                ghidra_data["decompiled_code"] = self._build_decompiled_code_map(
                    ghidra_data.get("functions", [])
                )

            source_file = output_dir / "reconstructed.c"
            source_file.write_text(source_text, encoding="utf-8")

            compile_report = await engine._compile_with_feedback_loop(
                "gcc",
                source_file,
                output_dir,
                ghidra_data,
            )

            if compile_report.get("status") == "success" and compile_report.get("binary_path"):
                compiled_binary = self._finalize_recompiled_binary(
                    compile_report["binary_path"], requested_output_path
                )
                artifact_details = self._inspect_binary_artifact(compiled_binary)
                function_overlap = await self._calculate_function_overlap(
                    binary_path,
                    compiled_binary,
                    ghidra_engine=recompilation_ghidra,
                )

                text = (
                    "Binary recompilation complete\n"
                    + "=" * 70
                    + "\n\n"
                    + f"Input: {binary_path}\n"
                    + f"Output: {compiled_binary}\n"
                    + f"Size: {artifact_details['size_bytes']} bytes\n"
                    + f"Magic: {artifact_details['magic']}\n"
                    + f"Function overlap: {function_overlap:.2f}%\n"
                    + f"Compilation attempts: {compile_report.get('total_attempts', 0)}\n"
                )

                return build_mcp_tool_response(
                    tool_name="recompile_binary",
                    text=text,
                    payload={
                        "status_code": 200,
                        "binary_path": binary_path,
                        "output_path": compiled_binary,
                        "success": True,
                        "function_overlap": function_overlap,
                        "binary_size": artifact_details["size_bytes"],
                        "magic_bytes": artifact_details["magic"],
                        "source_path": compile_report.get("final_source_file", str(source_file)),
                        "compilation_attempts": compile_report.get("attempts", []),
                        "model": llm_backend.model,
                    },
                    provenance={
                        "inputs": [
                            make_evidence_item(
                                "binary_input",
                                path=binary_path,
                                trace_id=f"enterprise:mcp:recompile:{Path(binary_path).name}",
                                evidence_kind="input_binary",
                                confidence=1.0,
                                source_result_type="mcp_tool_result",
                            )
                        ],
                        "artifacts": [
                            make_evidence_item(
                                "rebuilt_binary",
                                path=compiled_binary,
                                trace_id=(
                                    f"enterprise:mcp:recompile:{Path(binary_path).name}:rebuilt"
                                ),
                                evidence_kind="generated_binary",
                                confidence=max(function_overlap / 100.0, 0.0),
                                source_result_type="mcp_tool_result",
                                model=llm_backend.model,
                            )
                        ],
                        "stages": [
                            "mcp_tool_execution",
                            "binary_decompilation",
                            "binary_recompilation",
                            "result_contract_serialization",
                        ],
                        "references": [
                            make_trace_reference(
                                "rebuilt_from",
                                binary_path,
                                trace_id=f"enterprise:mcp:recompile:{Path(binary_path).name}:source",
                                confidence=max(function_overlap / 100.0, 0.0),
                            )
                        ],
                        "tools": ["recompile_binary", "ghidra_engine", "ollama"],
                    },
                )

            final_source_path = Path(str(compile_report.get("final_source_file", source_file)))
            partial_source = (
                final_source_path.read_text(encoding="utf-8", errors="replace")
                if final_source_path.exists()
                else source_text
            )
            compilation_errors = [
                attempt.get("stderr", "")
                for attempt in compile_report.get("attempts", [])
                if str(attempt.get("stderr", "")).strip()
            ]
            if not compilation_errors and compile_report.get("failure_reason"):
                compilation_errors = [str(compile_report["failure_reason"])]

            text = (
                "Binary recompilation failed\n"
                + "=" * 70
                + "\n\n"
                + f"Input: {binary_path}\n"
                + f"Compilation attempts: {compile_report.get('total_attempts', 0)}\n"
                + f"Failure reason: {compile_report.get('failure_reason', 'compilation_failed')}\n"
            )

            return build_mcp_tool_response(
                tool_name="recompile_binary",
                text=text,
                payload={
                    "status_code": 200,
                    "binary_path": binary_path,
                    "success": False,
                    "compilation_errors": compilation_errors,
                    "partial_source": partial_source,
                    "source_path": str(final_source_path),
                    "compilation_attempts": compile_report.get("attempts", []),
                    "failure_reason": compile_report.get("failure_reason"),
                    "model": llm_backend.model,
                },
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "binary_input",
                            path=binary_path,
                            trace_id=f"enterprise:mcp:recompile:{Path(binary_path).name}",
                            evidence_kind="input_binary",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "artifacts": [
                        make_evidence_item(
                            "partial_source",
                            path=str(final_source_path),
                            trace_id=(
                                f"enterprise:mcp:recompile:{Path(binary_path).name}:partial-source"
                            ),
                            evidence_kind="generated_source",
                            confidence=0.3,
                            source_result_type="mcp_tool_result",
                            model=llm_backend.model,
                        )
                    ],
                    "stages": [
                        "mcp_tool_execution",
                        "binary_decompilation",
                        "binary_recompilation",
                        "result_contract_serialization",
                    ],
                    "references": [],
                    "tools": ["recompile_binary", "ghidra_engine", "ollama"],
                },
            )

        except Exception as e:
            logger.exception("Error in recompile_binary")
            return build_mcp_tool_response(
                tool_name="recompile_binary",
                text=f"Error recompiling binary: {str(e)}",
                payload={
                    "status_code": 500,
                    "success": False,
                    "compilation_errors": [str(e)],
                },
                status="error",
                error=str(e),
            )

    async def scan_yara(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a file using YARA rules."""
        try:
            from reveng.tools.threat_intel.yara_scanner import YARAScanner

            path = self._require_existing_file(args, "path")
            rules_path = self._validate_yara_rules_path(
                self._require_existing_path(args, "rules_path")
            )
            include_string_data = args.get("include_string_data", True)

            loop = asyncio.get_running_loop()
            matches = await loop.run_in_executor(
                None, lambda: YARAScanner(rules_path).scan_file(path)
            )

            structured_matches = [
                self._serialize_yara_match(match, include_string_data) for match in matches
            ]
            text = self._format_yara_scan_results(path, rules_path, structured_matches)

            return build_mcp_tool_response(
                tool_name="scan_yara",
                text=text,
                payload={
                    "status_code": 200,
                    "path": path,
                    "rules_path": rules_path,
                    "match_count": len(structured_matches),
                    "matches": structured_matches,
                },
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "binary_input",
                            path=path,
                            trace_id=f"enterprise:mcp:yara:{Path(path).name}",
                            evidence_kind="input_binary",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        ),
                        make_evidence_item(
                            "rule_input",
                            path=rules_path,
                            trace_id=f"enterprise:mcp:yara:{Path(path).name}:rules",
                            evidence_kind="rule_bundle",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        ),
                    ],
                    "artifacts": [],
                    "stages": [
                        "mcp_tool_execution",
                        "yara_scan",
                        "result_contract_serialization",
                    ],
                    "references": [
                        make_trace_reference(
                            "scanned_with_rules",
                            rules_path,
                            trace_id=f"enterprise:mcp:yara:{Path(path).name}:scan",
                        )
                    ],
                    "tools": ["scan_yara", "yara_scanner"],
                },
            )

        except Exception as e:
            logger.exception("Error in scan_yara")
            return build_mcp_tool_response(
                tool_name="scan_yara",
                text=f"Error scanning with YARA: {str(e)}",
                payload={"match_count": 0, "matches": []},
                status="error",
                error=str(e),
            )

    async def analyze_memory_dump(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a memory dump or binary using the memory forensics engine."""
        try:
            from reveng.malware.memory_forensics import MemoryForensics

            path = self._require_existing_file(args, "path")
            output_dir = args.get("output_dir") or str(
                self.cache_dir / f"memory_{Path(path).stem}_{int(time.time())}"
            )
            memory_scan_batch_size = args.get("memory_scan_batch_size")
            memory_scan_max_wait_seconds = args.get("memory_scan_max_wait_seconds")

            loop = asyncio.get_running_loop()
            analysis = await loop.run_in_executor(
                None,
                lambda: MemoryForensics(
                    memory_scan_batch_size=memory_scan_batch_size,
                    memory_scan_max_wait_seconds=memory_scan_max_wait_seconds,
                ).analyze_memory(path, output_dir),
            )

            structured_analysis = self._serialize_memory_analysis(analysis)
            text = self._format_memory_analysis_results(structured_analysis)

            return build_mcp_tool_response(
                tool_name="analyze_memory_dump",
                text=text,
                payload={
                    "status_code": 200,
                    "analysis": structured_analysis,
                    "output_dir": output_dir,
                },
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "binary_input",
                            path=path,
                            trace_id=f"enterprise:mcp:memory-analysis:{Path(path).name}",
                            evidence_kind="input_binary",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "artifacts": [
                        make_evidence_item(
                            "memory_analysis_report",
                            path=output_dir,
                            trace_id=(f"enterprise:mcp:memory-analysis:{Path(path).name}:report"),
                            evidence_kind="analysis_report",
                            confidence=0.9,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "stages": [
                        "mcp_tool_execution",
                        "memory_forensics_analysis",
                        "result_contract_serialization",
                    ],
                    "references": [
                        make_trace_reference(
                            "analyzed_from",
                            path,
                            trace_id=f"enterprise:mcp:memory-analysis:{Path(path).name}",
                        )
                    ],
                    "tools": ["analyze_memory_dump", "memory_forensics"],
                },
            )

        except Exception as e:
            logger.exception("Error in analyze_memory_dump")
            return build_mcp_tool_response(
                tool_name="analyze_memory_dump",
                text=f"Error analyzing memory dump: {str(e)}",
                payload={"analysis": {}, "output_dir": args.get("output_dir")},
                status="error",
                error=str(e),
            )

    async def diff_binaries(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Semantic binary diffing"""
        try:
            from reveng.tools.diffing.binary_differ import BinaryDiffer

            binary1 = self._require_existing_file(args, "binary1")
            binary2 = self._require_existing_file(args, "binary2")
            semantic_diff = args.get("semantic_diff", False)

            loop = asyncio.get_running_loop()
            diff_result = await loop.run_in_executor(
                None,
                lambda: BinaryDiffer().diff(binary1, binary2, deep_analysis=bool(semantic_diff)),
            )

            structured_diff = self._serialize_diff_result(diff_result)
            text = self._format_binary_diff_results(structured_diff)

            diff_trace_id = f"enterprise:mcp:binary-diff:{Path(binary1).name}:{Path(binary2).name}"
            return build_mcp_tool_response(
                tool_name="diff_binaries",
                text=text,
                payload={
                    "status_code": 200,
                    "binary1": binary1,
                    "binary2": binary2,
                    "semantic_diff": bool(semantic_diff),
                    "diff": structured_diff,
                },
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "binary_input",
                            path=binary1,
                            trace_id=f"{diff_trace_id}:left",
                            evidence_kind="input_binary",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        ),
                        make_evidence_item(
                            "binary_input",
                            path=binary2,
                            trace_id=f"{diff_trace_id}:right",
                            evidence_kind="input_binary",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        ),
                    ],
                    "artifacts": [],
                    "stages": [
                        "mcp_tool_execution",
                        "binary_diff_analysis",
                        "result_contract_serialization",
                    ],
                    "references": [
                        make_trace_reference(
                            "compared_with",
                            binary2,
                            trace_id=f"{diff_trace_id}:comparison",
                            metadata={"source": binary1},
                        )
                    ],
                    "tools": ["diff_binaries", "binary_differ"],
                },
            )

        except Exception as e:
            logger.exception("Error in diff_binaries")
            return build_mcp_tool_response(
                tool_name="diff_binaries",
                text=f"Error diffing binaries: {str(e)}",
                payload={"diff": {}},
                status="error",
                error=str(e),
            )

    async def find_vulnerabilities(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Find vulnerabilities in binary"""
        try:
            path = self._require_existing_file(args, "path")
            use_symbolic = args.get("use_symbolic_execution", True)
            vulnerability_types = args.get("vulnerability_types")
            use_ai_analysis = args.get("use_ai_analysis")

            unsupported_knobs: List[str] = []
            if vulnerability_types:
                unsupported_knobs.append("vulnerability_types")
            if use_ai_analysis is True:
                unsupported_knobs.append("use_ai_analysis")

            if unsupported_knobs:
                knobs = ", ".join(unsupported_knobs)
                return build_mcp_tool_response(
                    tool_name="find_vulnerabilities",
                    text=(
                        f"Requested knobs unsupported in this MCP path: {knobs}. "
                        "Omit them or use symbolic-only mode without AI/type filters."
                    ),
                    payload={
                        "vulnerabilities": [],
                        "supported": False,
                        "unsupported_knobs": unsupported_knobs,
                        "reason": "find_vulnerabilities_knobs_unsupported",
                    },
                    status="unsupported",
                    error="find_vulnerabilities_knobs_unsupported",
                )

            if not use_symbolic:
                return build_mcp_tool_response(
                    tool_name="find_vulnerabilities",
                    text=(
                        "Vulnerability scan not measured: use_symbolic_execution=false "
                        "and no alternate analyzer ran."
                    ),
                    payload={
                        "vulnerabilities": [],
                        "measurement": "could_not_measure",
                        "reason": "symbolic_execution_disabled",
                    },
                    status="could_not_measure",
                    error="symbolic_execution_disabled",
                )

            from reveng.security.symbolic_execution_engine import SymbolicExecutionEngine

            engine = SymbolicExecutionEngine(path)
            loop = asyncio.get_running_loop()
            vulnerabilities = await loop.run_in_executor(None, engine.find_vulnerabilities)

            text = f"Vulnerability Analysis: {path}\n"
            text += "=" * 70 + "\n\n"
            text += f"Found {len(vulnerabilities)} vulnerabilities\n\n"

            for vuln in vulnerabilities[:10]:
                text += f"• {vuln.type}: {vuln.description}\n"
                text += f"  Location: {vuln.address}\n"
                text += f"  Severity: {vuln.severity}\n\n"

            serialized = [
                self._serialize_vulnerability(vulnerability) for vulnerability in vulnerabilities
            ]
            return build_mcp_tool_response(
                tool_name="find_vulnerabilities",
                text=text,
                payload={
                    "vulnerabilities": serialized,
                    "measurement": "measured",
                },
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "binary_input",
                            path=path,
                            trace_id=f"enterprise:mcp:vulns:{Path(path).name}",
                            evidence_kind="input_binary",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "artifacts": [],
                    "stages": [
                        "mcp_tool_execution",
                        "symbolic_vulnerability_analysis",
                        "result_contract_serialization",
                    ],
                    "references": [],
                    "tools": ["find_vulnerabilities", "symbolic_execution_engine"],
                },
            )

        except Exception as e:
            logger.exception("Error in find_vulnerabilities")
            return build_mcp_tool_response(
                tool_name="find_vulnerabilities",
                text=f"Error finding vulnerabilities: {str(e)}",
                payload={"vulnerabilities": []},
                status="error",
                error=str(e),
            )

    async def generate_exploit(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Generate exploit for vulnerability"""
        try:
            from reveng.security.symbolic_execution_engine import SymbolicExecutionEngine

            binary_path = self._resolve_binary_argument(args, field_name="binary_path")
            vulnerability_type = self._normalize_vulnerability_filter(
                args.get("vulnerability_type")
            )
            target_address = self._parse_optional_address(args.get("target_address"))
            generate_rop_chain = bool(args.get("generate_rop_chain", False))
            analysis_depth = str(args.get("analysis_depth") or "shallow")
            timeout_seconds = 60

            engine = SymbolicExecutionEngine(binary_path, analysis_depth=analysis_depth)
            loop = asyncio.get_running_loop()
            analysis_start = time.time()
            cfg = await loop.run_in_executor(None, engine.run_cfg_fast)
            cfg_summary = self._summarize_cfg(cfg)

            try:
                discovered_vulnerabilities = await asyncio.wait_for(
                    loop.run_in_executor(None, engine.find_vulnerabilities),
                    timeout=timeout_seconds,
                )
            except TimeoutError:
                note = "No vulnerabilities found within timeout"
                text = self._format_generate_exploit_results(
                    binary_path=binary_path,
                    vulnerabilities=[],
                    analysis_time=float(timeout_seconds),
                    note=note,
                    cfg_summary=cfg_summary,
                )
                return build_mcp_tool_response(
                    tool_name="generate_exploit",
                    text=text,
                    payload={
                        "status_code": 200,
                        "binary_path": binary_path,
                        "analysis_time": timeout_seconds,
                        "cfg_summary": cfg_summary,
                        "vulnerabilities": [],
                        "note": note,
                    },
                    provenance={
                        "inputs": [
                            make_evidence_item(
                                "binary_input",
                                path=binary_path,
                                trace_id=f"enterprise:mcp:exploit:{Path(binary_path).name}",
                                evidence_kind="input_binary",
                                confidence=1.0,
                                source_result_type="mcp_tool_result",
                            )
                        ],
                        "artifacts": [],
                        "stages": [
                            "mcp_tool_execution",
                            "cfg_generation",
                            "symbolic_vulnerability_analysis",
                            "result_contract_serialization",
                        ],
                        "references": [],
                        "tools": ["generate_exploit", "symbolic_execution_engine"],
                    },
                )

            matching_vulnerabilities = [
                vulnerability
                for vulnerability in discovered_vulnerabilities
                if self._vulnerability_matches_filters(
                    vulnerability,
                    vulnerability_type=vulnerability_type,
                    target_address=target_address,
                )
            ]

            serialized_vulnerabilities: List[Dict[str, Any]] = []
            for vulnerability in matching_vulnerabilities:
                exploit_template = await loop.run_in_executor(
                    None, engine.generate_exploit, vulnerability
                )
                serialized_vulnerabilities.append(
                    self._serialize_exploit_candidate(
                        binary_path,
                        vulnerability,
                        exploit_template,
                        generate_rop_chain=generate_rop_chain,
                    )
                )

            analysis_time = round(time.time() - analysis_start, 2)
            note_message: Optional[str] = None
            if not serialized_vulnerabilities:
                note_message = (
                    "No vulnerabilities matched the requested filters"
                    if matching_vulnerabilities != discovered_vulnerabilities
                    else "No vulnerabilities found"
                )

            text = self._format_generate_exploit_results(
                binary_path=binary_path,
                vulnerabilities=serialized_vulnerabilities,
                analysis_time=analysis_time,
                note=note_message,
                cfg_summary=cfg_summary,
            )

            response: Dict[str, Any] = {
                "status_code": 200,
                "binary_path": binary_path,
                "analysis_time": analysis_time,
                "cfg_summary": cfg_summary,
                "vulnerabilities": serialized_vulnerabilities,
            }
            if note_message:
                response["note"] = note_message
            return build_mcp_tool_response(
                tool_name="generate_exploit",
                text=text,
                payload=response,
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "binary_input",
                            path=binary_path,
                            trace_id=f"enterprise:mcp:exploit:{Path(binary_path).name}",
                            evidence_kind="input_binary",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "artifacts": [
                        make_evidence_item(
                            "exploit_candidate",
                            trace_id=f"enterprise:mcp:exploit:{Path(binary_path).name}:{index}",
                            evidence_kind="generated_exploit",
                            confidence=candidate.get("confidence"),
                            source_result_type="mcp_tool_result",
                        )
                        for index, candidate in enumerate(serialized_vulnerabilities, start=1)
                    ],
                    "stages": [
                        "mcp_tool_execution",
                        "cfg_generation",
                        "symbolic_vulnerability_analysis",
                        "exploit_synthesis",
                        "result_contract_serialization",
                    ],
                    "references": [],
                    "tools": ["generate_exploit", "symbolic_execution_engine"],
                },
            )

        except Exception as e:
            logger.exception("Error in generate_exploit")
            return build_mcp_tool_response(
                tool_name="generate_exploit",
                text=f"Error generating exploit: {str(e)}",
                payload={
                    "status_code": 500,
                    "binary_path": str(args.get("binary_path") or args.get("path") or ""),
                    "analysis_time": 0,
                    "vulnerabilities": [],
                },
                status="error",
                error=str(e),
            )

    async def classify_malware(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Classify malware family"""
        try:
            from reveng.security.yara_scanner import YARAScanner

            path = self._require_existing_file(args, "path")
            use_ollama_family_naming = args.get("use_ollama_family_naming", True)

            loop = asyncio.get_running_loop()
            classification = await loop.run_in_executor(
                None,
                lambda: YARAScanner().classify_file(
                    path,
                    use_ollama_family_naming=False,
                ),
            )

            if use_ollama_family_naming:
                refined_family = await self._refine_malware_family_name(path, classification)
                if refined_family:
                    classification["family"] = refined_family

            text = self._format_malware_classification_results(path, classification)

            return build_mcp_tool_response(
                tool_name="classify_malware",
                text=text,
                payload={
                    "path": path,
                    "family": classification["family"],
                    "confidence": classification["confidence"],
                    "matched_rules": classification["matched_rules"],
                    "indicators": classification["indicators"],
                    "yara_matches": classification["yara_matches"],
                    "ml_assessment": classification["ml_assessment"],
                    "feature_summary": classification["feature_summary"],
                },
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "binary_input",
                            path=path,
                            trace_id=f"enterprise:mcp:malware:{Path(path).name}",
                            evidence_kind="input_binary",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "artifacts": [],
                    "stages": [
                        "mcp_tool_execution",
                        "malware_classification",
                        "result_contract_serialization",
                    ],
                    "references": [
                        make_trace_reference(
                            "classified_as",
                            classification["family"],
                            trace_id=f"enterprise:mcp:malware:{Path(path).name}:family",
                            confidence=classification["confidence"],
                        )
                    ],
                    "tools": ["classify_malware", "yara_scanner"],
                },
            )

        except Exception as e:
            logger.exception("Error in classify_malware")
            return build_mcp_tool_response(
                tool_name="classify_malware",
                text=f"Error classifying malware: {str(e)}",
                payload={},
                status="error",
                error=str(e),
            )

    async def deobfuscate_javascript(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Deobfuscate JavaScript code"""
        try:
            from reveng.javascript.deobfuscator import JavaScriptDeobfuscator

            code = args.get("code")
            file_path = args.get("file_path")
            use_ml = args.get("use_ml_renaming", True)
            use_llm = args.get("use_llm_analysis", False)
            detect_malware = args.get("detect_malware", True)
            unbundle_webpack = bool(args.get("unbundle_webpack", False))

            # Read from file if provided
            if file_path and not code:
                file_path = self._require_existing_file({"file_path": file_path}, "file_path")
                code = self._read_utf8_text_file(file_path, purpose="JavaScript file")

            if not code:
                return build_mcp_tool_response(
                    tool_name="deobfuscate_javascript",
                    text="Error: No code or file_path provided",
                    payload={},
                    status="error",
                    error="missing_input",
                )

            # Deobfuscate
            deob = JavaScriptDeobfuscator(use_ml=use_ml, use_llm=use_llm)
            result = await deob.deobfuscate(code)

            text = "JavaScript Deobfuscation Complete\n"
            text += "=" * 70 + "\n\n"
            text += f"Confidence: {result.confidence}%\n"
            text += "Obfuscation Types: "
            text += ", ".join(
                (
                    obfuscation_type.value
                    if hasattr(obfuscation_type, "value")
                    else str(obfuscation_type)
                )
                for obfuscation_type in result.obfuscation_types
            )
            text += "\n\n"
            text += "Deobfuscated Code:\n"
            text += "-" * 70 + "\n"
            text += result.deobfuscated_code[:2000]

            response: Dict[str, Any] = {
                "deobfuscated_code": result.deobfuscated_code,
                "confidence": result.confidence,
                "unbundle_webpack_applied": False,
            }
            warnings: List[str] = []
            if unbundle_webpack:
                warnings.append("unbundle_webpack_unsupported")
                response["unsupported_knobs"] = ["unbundle_webpack"]
                text += (
                    "\n\nNote: unbundle_webpack requested but unsupported in this MCP path "
                    "(not applied).\n"
                )

            # Malware detection
            if detect_malware:
                from reveng.javascript.malware_detector import MalwareDetector

                detector = MalwareDetector()
                malware_result = detector.analyze(result.deobfuscated_code)

                response["malware_score"] = malware_result.threat_score
                response["is_malicious"] = malware_result.is_malicious

                if malware_result.is_malicious:
                    text += f"\n\n⚠️  MALWARE DETECTED (score: {malware_result.threat_score}/100)\n"

            if warnings:
                response["warnings"] = warnings

            return build_mcp_tool_response(
                tool_name="deobfuscate_javascript",
                text=text,
                payload=response,
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "javascript_input",
                            path=file_path,
                            trace_id="enterprise:mcp:deobfuscate:input",
                            evidence_kind="input_script",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "artifacts": [
                        make_evidence_item(
                            "deobfuscated_javascript",
                            trace_id="enterprise:mcp:deobfuscate:output",
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
                    "tools": ["deobfuscate_javascript", "javascript_deobfuscator"],
                },
            )

        except Exception as e:
            logger.exception("Error in deobfuscate_javascript")
            return build_mcp_tool_response(
                tool_name="deobfuscate_javascript",
                text=f"Error deobfuscating JavaScript: {str(e)}",
                payload={},
                status="error",
                error=str(e),
            )

    async def detect_js_malware(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Detect JavaScript malware"""
        try:
            from reveng.javascript.malware_detector import MalwareDetector

            code = args.get("code")
            file_path = args.get("file_path")

            if file_path and not code:
                file_path = self._require_existing_file({"file_path": file_path}, "file_path")
                code = self._read_utf8_text_file(file_path, purpose="JavaScript file")

            if not isinstance(code, str) or not code:
                return build_mcp_tool_response(
                    tool_name="detect_js_malware",
                    text="Error: No code or file_path provided",
                    payload={"threat_score": 0, "is_malicious": False, "indicators": []},
                    status="error",
                    error="missing_input",
                )

            detector = MalwareDetector()
            result = detector.analyze(code)

            text = "JavaScript Malware Analysis\n"
            text += "=" * 70 + "\n\n"
            text += f"Threat Score: {result.threat_score}/100\n"
            text += f"Is Malicious: {'YES ⚠️' if result.is_malicious else 'NO ✓'}\n\n"

            if result.indicators:
                text += "Indicators:\n"
                for indicator in result.indicators:
                    text += f"  • {indicator}\n"

            source_label = str(file_path) if file_path else "<inline>"
            return build_mcp_tool_response(
                tool_name="detect_js_malware",
                text=text,
                payload={
                    "status_code": 200,
                    "file_path": file_path,
                    "threat_score": result.threat_score,
                    "is_malicious": result.is_malicious,
                    "indicators": list(result.indicators),
                },
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "javascript_input",
                            path=str(file_path) if file_path else None,
                            trace_id=f"enterprise:mcp:js-malware:{Path(source_label).name}",
                            evidence_kind="input_source",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                            metadata={"source": "file" if file_path else "inline"},
                        )
                    ],
                    "artifacts": [],
                    "stages": [
                        "mcp_tool_execution",
                        "javascript_malware_detection",
                        "result_contract_serialization",
                    ],
                    "references": [
                        make_trace_reference(
                            "classified_as",
                            "malicious_javascript" if result.is_malicious else "benign_javascript",
                            trace_id=f"enterprise:mcp:js-malware:{Path(source_label).name}:classification",
                            confidence=float(result.threat_score) / 100.0,
                        )
                    ],
                    "tools": ["detect_js_malware", "malware_detector"],
                },
            )

        except Exception as e:
            logger.exception("Error in detect_js_malware")
            return build_mcp_tool_response(
                tool_name="detect_js_malware",
                text=f"Error detecting malware: {str(e)}",
                payload={"threat_score": 0, "is_malicious": False, "indicators": []},
                status="error",
                error=str(e),
            )

    async def ask_ai_about_binary(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """AI-powered Q&A about binaries"""
        binary_path = str(args.get("binary_path") or args.get("path") or "")
        question = str(args.get("question") or "").strip()
        decompile_result: Dict[str, Any] = {}
        prompt_context = ""

        try:
            binary_path = self._resolve_binary_argument(args, field_name="binary_path")
            if not question:
                raise ValueError("Missing required argument: question")

            ghidra_timeout = max(180, self._coerce_optional_int(args.get("_ghidra_timeout")) or 0)
            decompile_result = await self.decompile_binary(
                {"binary_path": binary_path, "_ghidra_timeout": ghidra_timeout}
            )
            if decompile_result.get("error"):
                raise RuntimeError(str(decompile_result["error"]))

            prompt_context = self._build_binary_question_context(
                binary_path=binary_path,
                question=question,
                decompile_result=decompile_result,
                additional_context=args.get("context"),
            )
            answer = await self._query_ollama_chat(
                system_prompt=(
                    "You are a senior reverse engineer answering questions about binaries. "
                    "Use only the supplied decompiled code and program metadata. "
                    "Be precise, explain uncertainty briefly, and avoid inventing facts."
                ),
                user_prompt=prompt_context,
                num_predict=350,
            )

            text = (
                "AI Binary Q&A\n"
                + "=" * 70
                + f"\n\nBinary: {binary_path}\n"
                + f"Question: {question}\n"
                + f"Model: {self.ollama_chat_model}\n\n"
                + answer
            )

            question_trace_id = f"enterprise:mcp:binary-qa:{Path(binary_path).name}"
            return build_mcp_tool_response(
                tool_name="ask_ai_about_binary",
                text=text,
                payload={
                    "status_code": 200,
                    "binary_path": binary_path,
                    "question": question,
                    "answer": answer,
                    "model": self.ollama_chat_model,
                    "context_used": bool(prompt_context.strip()),
                },
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "binary_input",
                            path=binary_path,
                            trace_id=question_trace_id,
                            evidence_kind="input_binary",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "artifacts": [
                        make_evidence_item(
                            "question_answer",
                            trace_id=f"{question_trace_id}:answer",
                            evidence_kind="generated_answer",
                            confidence=0.82,
                            source_result_type="mcp_tool_result",
                            model=self.ollama_chat_model,
                            metadata=self._build_ollama_provenance_metadata(
                                prompt_text=prompt_context,
                                context_text=prompt_context,
                            ),
                        )
                    ],
                    "stages": [
                        "mcp_tool_execution",
                        "binary_decompilation",
                        "llm_question_answering",
                        "result_contract_serialization",
                    ],
                    "references": [
                        make_trace_reference(
                            "answers_question",
                            question,
                            trace_id=f"{question_trace_id}:question",
                        )
                    ],
                    "tools": ["ask_ai_about_binary", "ghidra_engine", "ollama"],
                },
            )
        except TimeoutError as exc:
            message = str(exc) or (
                f"Ollama request timed out after {self.ollama_chat_timeout_seconds} seconds"
            )
            if self._has_decompile_context(decompile_result):
                fallback_answer = self._build_timeout_question_fallback(
                    question=question,
                    decompile_result=decompile_result,
                )
            else:
                fallback_answer = (
                    f"Ollama timed out before it could produce an answer for '{question}'. "
                    "No stable decompiled context was available, so REVENG could not infer a "
                    "reliable behavior summary."
                )
            return build_mcp_tool_response(
                tool_name="ask_ai_about_binary",
                text=(
                    f"Error querying Ollama: {message}\n\n"
                    "Fallback context-only answer:\n"
                    f"{fallback_answer}"
                ),
                payload={
                    "status_code": 504,
                    "binary_path": binary_path,
                    "question": question,
                    "model": self.ollama_chat_model,
                    "context_used": bool(prompt_context.strip()),
                    "fallback_used": True,
                    "answer": fallback_answer,
                },
                status="error",
                error=message,
            )
        except Exception as exc:
            logger.exception("Error in ask_ai_about_binary")
            return build_mcp_tool_response(
                tool_name="ask_ai_about_binary",
                text=f"Error querying binary with AI: {exc}",
                payload={
                    "status_code": 500,
                    "binary_path": binary_path,
                    "question": question,
                    "model": self.ollama_chat_model,
                    "context_used": False,
                },
                status="error",
                error=str(exc),
            )

    async def ai_code_reconstruction(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """AI code reconstruction"""
        binary_path = str(args.get("binary_path") or args.get("path") or "")
        decompile_result: Dict[str, Any] = {}
        cfg_context: Dict[str, Any] = {}

        try:
            binary_path = self._resolve_binary_argument(args, field_name="binary_path")
            ghidra_timeout = max(180, self._coerce_optional_int(args.get("_ghidra_timeout")) or 0)
            decompile_result = await self.decompile_binary(
                {"binary_path": binary_path, "_ghidra_timeout": ghidra_timeout}
            )
            if decompile_result.get("error"):
                raise RuntimeError(str(decompile_result["error"]))

            decompiled_code = str(
                args.get("decompiled_code") or decompile_result.get("decompiled_source") or ""
            ).strip()
            if not decompiled_code:
                raise RuntimeError("No decompiled source was available for AI reconstruction")

            prompt_source = self._build_llm_source_excerpt(
                decompile_result.get("decompiled_functions", []),
                decompiled_code,
                max_functions=6,
                max_source_chars=6000,
            )

            cfg_context = await self._extract_cfg_context(binary_path)
            reconstruction_prompt = self._build_code_reconstruction_prompt(
                binary_path=binary_path,
                decompiled_code=prompt_source,
                cfg_context_text=cfg_context["context_text"],
                reconstruct_types=bool(args.get("reconstruct_types", True)),
                rename_variables=bool(args.get("rename_variables", True)),
                add_documentation=bool(args.get("add_documentation", True)),
            )

            raw_response = await self._query_ollama_chat(
                system_prompt=(
                    "You are an expert reverse engineer reconstructing readable, idiomatic C. "
                    "Return strict JSON with keys reconstructed_code and improvement_notes. "
                    "reconstructed_code must contain plain C source with meaningful variable names. "
                    "improvement_notes must summarize the main cleanup decisions in concise prose."
                ),
                user_prompt=reconstruction_prompt,
                num_predict=900,
            )
            reconstructed_code, improvement_notes = self._parse_reconstruction_response(
                raw_response,
                fallback_source=decompiled_code,
            )

            text = (
                "AI Code Reconstruction\n"
                + "=" * 70
                + f"\n\nBinary: {binary_path}\n"
                + f"Model: {self.ollama_chat_model}\n"
                + (
                    f"CFG summary: {cfg_context['function_count']} functions, "
                    f"{cfg_context['node_count']} nodes, {cfg_context['edge_count']} edges\n\n"
                )
                + "Improvement notes:\n"
                + improvement_notes
                + "\n\nReconstructed code preview:\n"
                + "-" * 70
                + "\n"
                + reconstructed_code[:4000]
            )

            return build_mcp_tool_response(
                tool_name="ai_code_reconstruction",
                text=text,
                payload={
                    "status_code": 200,
                    "binary_path": binary_path,
                    "reconstructed_code": reconstructed_code,
                    "improvement_notes": improvement_notes,
                    "model": self.ollama_chat_model,
                    "context_used": True,
                    "cfg_context_used": True,
                    "cfg_summary": {
                        "function_count": cfg_context["function_count"],
                        "node_count": cfg_context["node_count"],
                        "edge_count": cfg_context["edge_count"],
                    },
                },
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "binary_input",
                            path=binary_path,
                            trace_id=f"enterprise:mcp:ai-reconstruct:{Path(binary_path).name}",
                            evidence_kind="input_binary",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "artifacts": [
                        make_evidence_item(
                            "reconstructed_source",
                            trace_id=f"enterprise:mcp:ai-reconstruct:{Path(binary_path).name}:output",
                            evidence_kind="generated_source",
                            confidence=0.85,
                            source_result_type="mcp_tool_result",
                            model=self.ollama_chat_model,
                            metadata={
                                **self._build_ollama_provenance_metadata(
                                    prompt_text=reconstruction_prompt,
                                    context_text=prompt_source,
                                ),
                                "cfg_context_sha256": self._hash_text(cfg_context["context_text"]),
                            },
                        )
                    ],
                    "stages": [
                        "mcp_tool_execution",
                        "binary_decompilation",
                        "cfg_extraction",
                        "llm_reconstruction",
                        "result_contract_serialization",
                    ],
                    "references": [],
                    "tools": ["ai_code_reconstruction", "ghidra_engine", "ollama"],
                },
            )
        except TimeoutError as exc:
            message = str(exc) or (
                f"Ollama request timed out after {self.ollama_chat_timeout_seconds} seconds"
            )
            fallback_code = self._build_timeout_reconstruction_fallback(decompile_result)
            fallback_notes = self._build_timeout_reconstruction_notes(cfg_context)
            return build_mcp_tool_response(
                tool_name="ai_code_reconstruction",
                text=(
                    f"Error reconstructing code with AI: {message}\n\n"
                    "Fallback reconstruction generated from decompiled context."
                ),
                payload={
                    "status_code": 504,
                    "binary_path": binary_path,
                    "model": self.ollama_chat_model,
                    "context_used": False,
                    "cfg_context_used": False,
                    "fallback_used": True,
                    "reconstructed_code": fallback_code,
                    "improvement_notes": fallback_notes,
                },
                status="error",
                error=message,
            )
        except Exception as exc:
            logger.exception("Error in ai_code_reconstruction")
            return build_mcp_tool_response(
                tool_name="ai_code_reconstruction",
                text=f"Error reconstructing code with AI: {exc}",
                payload={
                    "status_code": 500,
                    "binary_path": binary_path,
                    "model": self.ollama_chat_model,
                    "context_used": False,
                    "cfg_context_used": False,
                },
                status="error",
                error=str(exc),
            )

    async def get_analysis_report(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get analysis report"""
        analysis_id = args["analysis_id"]
        report_format = str(args.get("format") or "text")

        if analysis_id in self.results_cache:
            result = self.results_cache[analysis_id]
            text = self._format_analysis_results(result, "cached", analysis_id)
            return build_mcp_tool_response(
                tool_name="get_analysis_report",
                text=text,
                payload={
                    "status_code": 200,
                    "analysis_id": analysis_id,
                    "format": report_format,
                },
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "analysis_request",
                            trace_id=f"enterprise:mcp:analysis-report:{analysis_id}",
                            evidence_kind="analysis_request",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                            metadata={"format": report_format},
                        )
                    ],
                    "artifacts": [
                        make_evidence_item(
                            "analysis_report",
                            trace_id=f"enterprise:mcp:analysis-report:{analysis_id}:report",
                            evidence_kind="analysis_report",
                            confidence=0.95,
                            source_result_type="mcp_tool_result",
                            metadata={"format": report_format, "cache": "results_cache"},
                        )
                    ],
                    "stages": [
                        "mcp_tool_execution",
                        "analysis_report_lookup",
                        "result_contract_serialization",
                    ],
                    "references": [
                        make_trace_reference(
                            "loaded_from_cache",
                            analysis_id,
                            trace_id=f"enterprise:mcp:analysis-report:{analysis_id}:cache",
                        )
                    ],
                    "tools": ["get_analysis_report", "results_cache"],
                },
            )

        return build_mcp_tool_response(
            tool_name="get_analysis_report",
            text=f"Analysis {analysis_id} not found in cache",
            payload={"status_code": 404, "analysis_id": analysis_id, "format": report_format},
            status="error",
            error="not_found",
        )

    async def list_recent_analyses(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List recent analyses"""
        limit = args.get("limit", 10)
        analyses = list(self.results_cache.keys())[:limit]

        text = "Recent Analyses\n"
        text += "=" * 70 + "\n\n"
        for analysis_id in analyses:
            text += f"• {analysis_id}\n"

        return build_mcp_tool_response(
            tool_name="list_recent_analyses",
            text=text,
            payload={
                "status_code": 200,
                "limit": limit,
                "analyses": analyses,
            },
            provenance={
                "inputs": [
                    make_evidence_item(
                        "analysis_list_request",
                        trace_id="enterprise:mcp:recent-analyses:request",
                        evidence_kind="analysis_request",
                        confidence=1.0,
                        source_result_type="mcp_tool_result",
                        metadata={"limit": limit},
                    )
                ],
                "artifacts": [],
                "stages": [
                    "mcp_tool_execution",
                    "analysis_cache_enumeration",
                    "result_contract_serialization",
                ],
                "references": [
                    make_trace_reference(
                        "enumerates_cache_entries",
                        "results_cache",
                        trace_id="enterprise:mcp:recent-analyses:cache",
                        metadata={"count": len(analyses)},
                    )
                ],
                "tools": ["list_recent_analyses", "results_cache"],
            },
        )

    async def reverse_engineer_app(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Run the shared app reverse-engineering workflow and cache the result."""
        try:
            path = Path(args["path"]).expanduser().resolve()
            if not path.exists():
                raise FileNotFoundError(f"Path not found: {path}")

            language = str(args.get("language") or "auto")
            output_dir = str(
                Path(args.get("output_dir") or (Path.cwd() / f"analysis_{path.stem}"))
                .expanduser()
                .resolve()
            )

            framework = create_default_framework()
            app_result = await framework.reverse_engineer(
                str(path),
                output_dir,
                language=language,
            )

            analysis_id = hashlib.md5(f"{path}{time.time()}".encode()).hexdigest()[:16]
            self.results_cache[analysis_id] = app_result.metadata

            text = (
                f"App reverse engineering completed for {path.name}\n"
                + "=" * 70
                + "\n\n"
                + f"Language: {app_result.language}\n"
                + f"Adapter: {app_result.adapter_name}\n"
                + f"Validation: {app_result.validation_grade}\n"
                + f"Recovered sources: {app_result.source_count}\n"
                + f"Analysis summary: {app_result.analysis_file}\n"
                + f"Analysis ID: {analysis_id}\n"
            )

            trace_id = f"enterprise:mcp:app-re:{path.name}"
            return build_mcp_tool_response(
                tool_name="reverse_engineer_app",
                text=text,
                payload={
                    "analysis_id": analysis_id,
                    "language": app_result.language,
                    "analysis_file": str(app_result.analysis_file),
                    "validation_grade": app_result.validation_grade,
                    "capability_report": (app_result.metadata or {}).get("capability_report"),
                    "app_result": app_result.metadata,
                },
                provenance={
                    "inputs": [
                        make_evidence_item(
                            "app_input",
                            path=str(path),
                            trace_id=trace_id,
                            evidence_kind="input_app",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                        )
                    ],
                    "artifacts": [
                        make_evidence_item(
                            "analysis_summary",
                            path=str(app_result.analysis_file),
                            trace_id=f"{trace_id}:summary",
                            evidence_kind="analysis_summary",
                            confidence=1.0,
                            source_result_type="mcp_tool_result",
                            metadata={"validation_grade": app_result.validation_grade},
                        )
                    ],
                    "stages": [
                        "mcp_tool_execution",
                        "app_reverse_engineering",
                        "result_contract_serialization",
                    ],
                    "references": [
                        make_trace_reference(
                            "cached_as",
                            analysis_id,
                            trace_id=f"{trace_id}:cache",
                            metadata={"cache": "results_cache"},
                        )
                    ],
                    "tools": ["reverse_engineer_app", app_result.adapter_name],
                },
            )
        except Exception as e:
            logger.exception("Error in reverse_engineer_app")
            return build_mcp_tool_response(
                tool_name="reverse_engineer_app",
                text=f"Error reverse engineering app: {str(e)}",
                payload={},
                status="error",
                error=str(e),
            )

    async def run_app_corpus(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Run the manifest-driven app reverse-engineering corpus and cache the rollup."""
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
            analysis_id = hashlib.md5(f"app-corpus{time.time()}".encode()).hexdigest()[:16]
            self.results_cache[analysis_id] = report
            text = (
                "App corpus execution completed\n"
                + "=" * 70
                + "\n\n"
                + f"Matrix status: {report['summary']['matrix_status']}\n"
                + f"Completed entries: {report['summary']['completed_entries']}\n"
                + f"Failed entries: {report['summary']['failed_entries']}\n"
                + f"Analysis ID: {analysis_id}\n"
            )
            return build_mcp_tool_response(
                tool_name="run_app_corpus",
                text=text,
                payload={"analysis_id": analysis_id, "corpus_report": report},
                provenance={
                    "inputs": [],
                    "artifacts": [],
                    "stages": [
                        "mcp_tool_execution",
                        "app_corpus_execution",
                        "result_contract_serialization",
                    ],
                    "references": [
                        make_trace_reference(
                            "cached_as",
                            analysis_id,
                            trace_id=f"enterprise:mcp:app-corpus:{analysis_id}",
                            metadata={"cache": "results_cache"},
                        )
                    ],
                    "tools": ["run_app_corpus"],
                },
            )
        except Exception as e:
            logger.exception("Error in run_app_corpus")
            return build_mcp_tool_response(
                tool_name="run_app_corpus",
                text=f"Error running app corpus: {str(e)}",
                payload={},
                status="error",
                error=str(e),
            )

    # ==================================================================================
    # RESOURCES
    # ==================================================================================

    def _register_resources(self):
        """Register MCP resources for analysis results"""

        self.register_resource(
            MCPResource(
                uri="reveng://analyses/recent",
                name="Recent Analyses",
                description="List of recent binary analyses",
                mime_type="application/json",
            )
        )

        self.register_resource(
            MCPResource(
                uri="reveng://documentation/api",
                name="API Documentation",
                description="REVENG API documentation",
                mime_type="text/markdown",
            )
        )

    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """Read a resource by URI"""
        if uri == "reveng://analyses/recent":
            analyses = list(self.results_cache.keys())
            return {
                "uri": uri,
                "mimeType": "application/json",
                "text": json.dumps(
                    build_mcp_resource_result(
                        resource_name="recent_analyses",
                        payload={"analyses": analyses},
                    ),
                    indent=2,
                ),
            }

        return {
            "uri": uri,
            "mimeType": "text/plain",
            "text": json.dumps(
                build_mcp_resource_result(
                    resource_name="missing_resource",
                    payload={"uri": uri},
                    status="error",
                    error=f"Resource not found: {uri}",
                )
            ),
        }

    # ==================================================================================
    # PROMPTS
    # ==================================================================================

    def _register_prompts(self):
        """Register MCP prompt templates for common workflows"""

        self.register_prompt(
            MCPPrompt(
                name="analyze_malware",
                description="Complete malware analysis workflow",
                arguments=[
                    {
                        "name": "binary_path",
                        "description": "Path to potential malware",
                        "required": True,
                    }
                ],
            )
        )

        self.register_prompt(
            MCPPrompt(
                name="find_and_exploit",
                description="Find vulnerabilities and generate exploits",
                arguments=[
                    {"name": "binary_path", "description": "Path to binary", "required": True}
                ],
            )
        )

        self.register_prompt(
            MCPPrompt(
                name="deobfuscate_analyze",
                description="Deobfuscate and analyze JavaScript",
                arguments=[
                    {"name": "js_file", "description": "Path to JavaScript file", "required": True}
                ],
            )
        )

    async def get_prompt(self, name: str, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get prompt template with filled arguments"""
        if name == "analyze_malware":
            binary_path = arguments.get("binary_path", "<binary_path>")
            return [
                self._build_prompt_message(
                    prompt_name=name,
                    prompt_text=(
                        f"Perform comprehensive malware analysis on {binary_path}. "
                        f"Include binary analysis, vulnerability detection, malware classification, "
                        f"and threat intelligence correlation. Provide a detailed report."
                    ),
                    arguments=arguments,
                )
            ]

        elif name == "find_and_exploit":
            binary_path = arguments.get("binary_path", "<binary_path>")
            return [
                self._build_prompt_message(
                    prompt_name=name,
                    prompt_text=(
                        f"Analyze {binary_path} to find vulnerabilities, then generate "
                        f"working exploit code. Use symbolic execution for vulnerability discovery "
                        f"and create ROP chains if needed."
                    ),
                    arguments=arguments,
                )
            ]

        elif name == "deobfuscate_analyze":
            js_file = arguments.get("js_file", "<js_file>")
            return [
                self._build_prompt_message(
                    prompt_name=name,
                    prompt_text=(
                        f"Deobfuscate {js_file} using ML renaming and LLM analysis. "
                        f"Detect any malware and provide a security assessment."
                    ),
                    arguments=arguments,
                )
            ]

        return []

    # ==================================================================================
    # HELPERS
    # ==================================================================================

    def _build_prompt_message(
        self, *, prompt_name: str, prompt_text: str, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build a versioned prompt message while preserving MCP prompt message shape."""
        return {
            "role": "user",
            "content": {
                "type": "text",
                "text": prompt_text,
                "schema_version": RESULT_SCHEMA_VERSION,
                "result_type": "mcp_prompt_message",
                "prompt_name": prompt_name,
                "prompt_arguments": dict(arguments),
                "provenance": {
                    "stages": ["prompt_template_resolution"],
                    "tools": ["prompt_template"],
                },
            },
        }

    def _format_analysis_results(self, result: Any, path: str, analysis_id: str) -> str:
        """Format analysis results as text"""
        text = "Binary Analysis Results\n"
        text += "=" * 70 + "\n\n"
        text += f"File: {path}\n"
        text += f"Analysis ID: {analysis_id}\n\n"

        if hasattr(result, "file_type"):
            text += f"File Type: {result.file_type}\n"
        if hasattr(result, "architecture"):
            text += f"Architecture: {result.architecture}\n"
        if hasattr(result, "entry_point"):
            text += f"Entry Point: {result.entry_point}\n"

        if hasattr(result, "vulnerabilities") and result.vulnerabilities:
            text += f"\n🔍 Vulnerabilities Found: {len(result.vulnerabilities)}\n"
            for vuln in result.vulnerabilities[:5]:
                text += f"  • {vuln}\n"

        if hasattr(result, "strings"):
            text += f"\nStrings: {len(result.strings)} found\n"

        return text

    def _require_existing_file(self, args: Dict[str, Any], field_name: str) -> str:
        """Require a file argument that exists."""
        value = args.get(field_name)
        if not value:
            raise ValueError(f"Missing required argument: {field_name}")

        path = Path(value)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {value}")
        if path.is_dir():
            raise IsADirectoryError(f"Expected file but received directory: {value}")
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {value}")

        return str(path)

    def _resolve_binary_argument(
        self, args: Dict[str, Any], field_name: str = "binary_path"
    ) -> str:
        """Resolve a binary path while accepting the legacy `path` argument as a fallback."""
        value = args.get(field_name) or args.get("path")
        if not value:
            raise ValueError(f"Missing required argument: {field_name}")

        return self._require_existing_file({field_name: value}, field_name)

    def _build_decompile_response(self, binary_path: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a Ghidra decompile response into MCP-friendly structured JSON."""
        raw_functions = result.get("functions", [])
        decompiled_functions: List[Dict[str, Any]] = []
        source_parts: List[str] = []

        for function in raw_functions if isinstance(raw_functions, list) else []:
            if not isinstance(function, dict):
                continue

            normalized_function = dict(function)
            source = str(
                normalized_function.get("source") or normalized_function.get("decompiled") or ""
            )
            normalized_function["source"] = source
            if source and not normalized_function.get("decompiled"):
                normalized_function["decompiled"] = source
            if source:
                source_parts.append(source.strip())
            decompiled_functions.append(normalized_function)

        if not source_parts and isinstance(result.get("decompiled_code"), dict):
            source_parts = [
                str(code).strip()
                for code in result["decompiled_code"].values()
                if isinstance(code, str) and code.strip()
            ]

        decompiled_source = "\n\n".join(source_parts)
        preview = (
            decompiled_source[:4000] if decompiled_source else "No decompiled source returned."
        )
        text = (
            f"Decompilation Complete: {binary_path}\n"
            f"{'=' * 70}\n\n"
            f"Decompiled {len(decompiled_functions)} functions\n\n"
            f"Preview:\n{'-' * 70}\n{preview}"
        )

        return {
            "content": [{"type": "text", "text": text}],
            "status_code": 200,
            "binary_path": binary_path,
            "decompiled_functions": decompiled_functions,
            "functions": decompiled_functions,
            "function_count": len(decompiled_functions),
            "strings": (
                list(result.get("strings", [])) if isinstance(result.get("strings"), list) else []
            ),
            "imports": (
                list(result.get("imports", [])) if isinstance(result.get("imports"), list) else []
            ),
            "decompiled_source": decompiled_source,
        }

    def _has_decompile_context(self, decompile_result: Dict[str, Any]) -> bool:
        """Return True when decompilation produced enough context for deterministic fallbacks."""
        if not isinstance(decompile_result, dict):
            return False

        if str(decompile_result.get("decompiled_source") or "").strip():
            return True

        list_keys = ("decompiled_functions", "functions", "imports", "strings")
        return any(bool(decompile_result.get(key)) for key in list_keys)

    def _build_binary_question_context(
        self,
        *,
        binary_path: str,
        question: str,
        decompile_result: Dict[str, Any],
        additional_context: Any = None,
        max_functions: int = 10,
        max_source_chars: int = 4000,
    ) -> str:
        """Build a focused prompt context for binary Q&A."""
        functions = decompile_result.get("decompiled_functions", [])
        if not isinstance(functions, list):
            functions = []

        imports = decompile_result.get("imports", [])
        if not isinstance(imports, list):
            imports = []

        strings = decompile_result.get("strings", [])
        if not isinstance(strings, list):
            strings = []

        function_summaries = []
        for function in functions[:max_functions]:
            if not isinstance(function, dict):
                continue
            function_summaries.append(
                f"- {function.get('name', 'unknown')} @ {function.get('entry_point') or function.get('address') or 'unknown'}"
            )

        decompiled_source = self._build_llm_source_excerpt(
            functions,
            str(decompile_result.get("decompiled_source") or "").strip(),
            max_functions=4,
            max_source_chars=max_source_chars,
        )

        import_names = [
            str(item.get("name") if isinstance(item, dict) else item)
            for item in imports[:25]
            if str(item).strip()
        ]
        string_values = [
            str(item.get("value") if isinstance(item, dict) else item)
            for item in strings[:25]
            if str(item).strip()
        ]

        context_sections = [
            f"Binary path: {binary_path}",
            f"Question: {question}",
            f"Decompiled functions available: {len(functions)}",
        ]

        if function_summaries:
            context_sections.extend(["Function list:", *function_summaries])
        if import_names:
            context_sections.append("Imports: " + ", ".join(import_names))
        if string_values:
            context_sections.append("Interesting strings: " + ", ".join(string_values))
        if additional_context:
            context_sections.append(f"Additional user context: {additional_context}")
        if decompiled_source:
            context_sections.extend(
                [
                    "Decompiled code:",
                    "```c",
                    decompiled_source,
                    "```",
                ]
            )

        context_sections.append(
            "Answer the question directly using the supplied binary context. "
            "Call out uncertainty briefly if the evidence is incomplete. Keep the answer under 220 words."
        )
        return "\n".join(context_sections)

    def _build_llm_source_excerpt(
        self,
        functions: Any,
        fallback_source: str,
        *,
        max_functions: int,
        max_source_chars: int,
    ) -> str:
        """Select the most relevant decompiled functions for an LLM prompt."""
        excerpt_parts: List[str] = []
        total_chars = 0

        prioritized = self._prioritize_functions_for_llm(functions)
        for function in prioritized[:max_functions]:
            source = str(function.get("source") or function.get("decompiled") or "").strip()
            if not source:
                continue

            header = (
                f"/* {function.get('name', 'unknown')} @ "
                f"{function.get('entry_point') or function.get('address') or 'unknown'} */\n"
            )
            block = header + source
            if excerpt_parts and total_chars + len(block) > max_source_chars:
                break

            excerpt_parts.append(block)
            total_chars += len(block)

        excerpt = "\n\n".join(excerpt_parts).strip()
        if not excerpt:
            excerpt = fallback_source[:max_source_chars].strip()

        if len(excerpt) > max_source_chars:
            excerpt = (
                excerpt[:max_source_chars].rstrip()
                + "\n/* Decompiled source truncated for prompt size. */"
            )

        return excerpt

    def _build_timeout_question_fallback(
        self,
        *,
        question: str,
        decompile_result: Dict[str, Any],
    ) -> str:
        """Build a deterministic answer when Ollama times out after context was prepared."""
        functions = self._prioritize_functions_for_llm(
            decompile_result.get("decompiled_functions", [])
        )
        function_names = [
            str(function.get("name") or "unknown")
            for function in functions[:4]
            if str(function.get("name") or "").strip()
        ]

        imports = decompile_result.get("imports", [])
        import_names = [
            str(item.get("name") if isinstance(item, dict) else item)
            for item in imports[:6]
            if str(item).strip()
        ]

        strings = decompile_result.get("strings", [])
        string_values = [
            str(item.get("value") if isinstance(item, dict) else item)
            for item in strings[:4]
            if str(item).strip()
        ]

        source_excerpt = self._build_llm_source_excerpt(
            functions,
            str(decompile_result.get("decompiled_source") or ""),
            max_functions=2,
            max_source_chars=1200,
        )
        behavior_hint = self._infer_behavior_from_context(
            import_names, string_values, source_excerpt
        )

        return (
            f"Ollama timed out before it could answer the question '{question}'. "
            f"From the recovered decompiled context, the binary most likely {behavior_hint}. "
            f"The most relevant recovered functions are {', '.join(function_names) if function_names else 'unknown'}, "
            f"with imports such as {', '.join(import_names) if import_names else 'none observed'}"
            f" and notable strings like {', '.join(string_values) if string_values else 'none observed'}."
        )

    def _build_timeout_reconstruction_fallback(self, decompile_result: Dict[str, Any]) -> str:
        """Return a readable reconstruction fallback when Ollama times out."""
        excerpt = self._build_llm_source_excerpt(
            decompile_result.get("decompiled_functions", []),
            str(decompile_result.get("decompiled_source") or ""),
            max_functions=4,
            max_source_chars=5000,
        )
        normalized_excerpt = self._normalize_decompiled_variable_names(excerpt)
        return (
            "/* Fallback reconstruction generated after Ollama timed out. */\n"
            "/* Source is derived from the highest-priority decompiled functions. */\n\n"
            + normalized_excerpt
        ).strip()

    def _build_timeout_reconstruction_notes(self, cfg_context: Dict[str, Any]) -> str:
        """Describe the deterministic fallback path used after an Ollama timeout."""
        function_count = int(cfg_context.get("function_count", 0) or 0)
        node_count = int(cfg_context.get("node_count", 0) or 0)
        edge_count = int(cfg_context.get("edge_count", 0) or 0)
        if function_count and node_count:
            return (
                "Ollama timed out after the CFG-aware prompt was prepared, so REVENG returned a "
                f"cleaned fallback reconstruction derived from decompiled code plus CFG metrics "
                f"({function_count} functions, {node_count} nodes, {edge_count} edges)."
            )
        return (
            "Ollama timed out before reconstruction completed, so REVENG returned a cleaned "
            "fallback reconstruction derived directly from the recovered decompiled functions."
        )

    def _infer_behavior_from_context(
        self,
        import_names: List[str],
        string_values: List[str],
        source_excerpt: str,
    ) -> str:
        """Infer a coarse behavior summary from decompiled context for timeout fallbacks."""
        combined = " ".join(import_names + string_values + [source_excerpt]).lower()

        behavior_map = [
            (
                ["socket", "connect", "send", "recv", "internet", "ws2_32"],
                "performs network communication or telemetry",
            ),
            (
                ["createfile", "readfile", "writefile", "fopen", "fprintf", "puts"],
                "performs file or console I/O",
            ),
            (["regopenkey", "regsetvalue", "registry"], "interacts with the Windows registry"),
            (
                ["crypt", "bcrypt", "sha", "aes", "md5"],
                "performs cryptographic or hashing operations",
            ),
            (
                ["loadlibrary", "getprocaddress", "virtualprotect"],
                "uses dynamic runtime loading or memory-management routines",
            ),
        ]

        for keywords, description in behavior_map:
            if any(keyword in combined for keyword in keywords):
                return description

        return "implements the recovered control flow exposed by its highest-priority functions"

    def _normalize_decompiled_variable_names(self, source_text: str) -> str:
        """Make common decompiler temporary names more readable in fallback reconstructions."""
        replacements = [
            (r"\biVar(\d+)\b", r"int_value_\1"),
            (r"\buVar(\d+)\b", r"unsigned_value_\1"),
            (r"\bcVar(\d+)\b", r"char_value_\1"),
            (r"\bbVar(\d+)\b", r"bool_value_\1"),
            (r"\blVar(\d+)\b", r"long_value_\1"),
            (r"\bv(\d+)\b", r"value_\1"),
            (r"\blocal_([0-9a-fA-F]+)\b", r"local_value_\1"),
            (r"\bparam_([0-9a-fA-F]+)\b", r"param_value_\1"),
        ]

        normalized = source_text
        for pattern, replacement in replacements:
            normalized = re.sub(pattern, replacement, normalized)
        return normalized

    def _prioritize_functions_for_llm(self, functions: Any) -> List[Dict[str, Any]]:
        """Order decompiled functions so user-authored logic is favored over boilerplate."""
        if not isinstance(functions, list):
            return []

        normalized_functions = [function for function in functions if isinstance(function, dict)]

        def sort_key(function: Dict[str, Any]) -> tuple[int, int, int, int, str]:
            raw_name = str(function.get("name") or "")
            normalized_name = self._normalize_function_name(raw_name)
            source = str(function.get("source") or function.get("decompiled") or "")
            is_primary = normalized_name in {"main", "winmain", "wmain", "start"}
            is_runtime = (
                raw_name.startswith("__") or "crt" in normalized_name or "mingw" in normalized_name
            )
            is_generic = raw_name.startswith(("FUN_", "sub_", "LAB_", "thunk_", "_"))
            return (
                0 if is_primary else 1,
                0 if not is_runtime else 1,
                0 if not is_generic else 1,
                -len(source),
                normalized_name,
            )

        return sorted(normalized_functions, key=sort_key)

    async def _extract_cfg_context(self, binary_path: str) -> Dict[str, Any]:
        """Extract CFG context for AI reconstruction prompts."""
        preprocessor = AngrCFGPreprocessor()
        loop = asyncio.get_running_loop()

        try:
            payload = await loop.run_in_executor(
                None, preprocessor.extract_cfg_payload, binary_path
            )
            context_text = await loop.run_in_executor(
                None,
                lambda: preprocessor.build_llm_context(payload),
            )
        except CFGExtractionError as exc:
            raise RuntimeError(f"CFG extraction failed: {exc}") from exc

        metrics = payload.get("graph_metrics", {})
        return {
            "payload": payload,
            "context_text": context_text,
            "function_count": int(payload.get("function_count", 0) or 0),
            "node_count": int(metrics.get("node_count", 0) or 0),
            "edge_count": int(metrics.get("edge_count", 0) or 0),
        }

    def _build_code_reconstruction_prompt(
        self,
        *,
        binary_path: str,
        decompiled_code: str,
        cfg_context_text: str,
        reconstruct_types: bool,
        rename_variables: bool,
        add_documentation: bool,
        max_source_chars: int = 6000,
        max_cfg_chars: int = 2500,
    ) -> str:
        """Build a CFG-aware code reconstruction prompt for Ollama."""
        trimmed_source = decompiled_code[:max_source_chars]
        if len(decompiled_code) > max_source_chars:
            trimmed_source += "\n/* Decompiled source truncated for prompt size. */"

        trimmed_cfg = cfg_context_text[:max_cfg_chars]
        if len(cfg_context_text) > max_cfg_chars:
            trimmed_cfg += "\n... CFG summary truncated ..."

        return "\n".join(
            [
                f"Binary path: {binary_path}",
                "Task: reconstruct clean, idiomatic C code from the supplied decompiler output.",
                f"Rename variables: {rename_variables}",
                f"Reconstruct types: {reconstruct_types}",
                f"Add documentation: {add_documentation}",
                "Return strict JSON with keys reconstructed_code and improvement_notes.",
                "reconstructed_code must be plain C source with function definitions and meaningful names.",
                "Focus on the most important user-authored routines and omit CRT/runtime boilerplate unless it is semantically essential.",
                "improvement_notes must explain the most important structural improvements and assumptions.",
                "CFG summary:",
                trimmed_cfg,
                "Decompiler output:",
                "```c",
                trimmed_source,
                "```",
            ]
        )

    async def _query_ollama_chat(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        timeout: Optional[int] = None,
        num_predict: Optional[int] = None,
    ) -> str:
        """Query the local Ollama chat endpoint and return message content."""
        resolved_timeout = timeout or self.ollama_chat_timeout_seconds
        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    self._post_ollama_chat,
                    system_prompt,
                    user_prompt,
                    resolved_timeout,
                    num_predict,
                ),
                timeout=resolved_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise TimeoutError(
                f"Ollama request timed out after {resolved_timeout} seconds"
            ) from exc

        content = self._extract_ollama_message_content(response)
        if not content:
            raise RuntimeError("Ollama returned an empty response")
        return content

    def _post_ollama_chat(
        self,
        system_prompt: str,
        user_prompt: str,
        timeout: int,
        num_predict: Optional[int],
    ) -> Dict[str, Any]:
        """POST a chat request to the local Ollama HTTP API."""
        options: Dict[str, Any] = {"temperature": 0.1}
        if num_predict is not None:
            options["num_predict"] = int(num_predict)

        payload = {
            "model": self.ollama_chat_model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "options": options,
        }

        try:
            response = requests.post(
                self.ollama_chat_endpoint,
                json=payload,
                timeout=timeout,
            )
            response.raise_for_status()
            return cast(Dict[str, Any], response.json())
        except requests.Timeout as exc:
            raise TimeoutError(f"Ollama request timed out after {timeout} seconds") from exc

    def _extract_ollama_message_content(self, response: Any) -> str:
        """Extract assistant content from an Ollama chat response."""
        if isinstance(response, dict):
            message = response.get("message", {})
            if isinstance(message, dict):
                return str(message.get("content", "")).strip()
            return str(response.get("response", "")).strip()

        return str(response).strip()

    def _parse_reconstruction_response(
        self,
        response_text: str,
        *,
        fallback_source: str,
    ) -> tuple[str, str]:
        """Parse reconstructed code and notes from an LLM response."""
        parsed_json = self._extract_json_dict(response_text)
        reconstructed_code = ""
        improvement_notes = ""

        if parsed_json is not None:
            reconstructed_code = str(
                parsed_json.get("reconstructed_code")
                or parsed_json.get("code")
                or parsed_json.get("source")
                or ""
            ).strip()
            improvement_notes = str(
                parsed_json.get("improvement_notes")
                or parsed_json.get("notes")
                or parsed_json.get("summary")
                or ""
            ).strip()

        if not reconstructed_code:
            code_match = re.search(
                r"```(?:c|cpp)?\s*(.*?)```", response_text, re.DOTALL | re.IGNORECASE
            )
            if code_match:
                reconstructed_code = code_match.group(1).strip()
                improvement_notes = (
                    improvement_notes or response_text.replace(code_match.group(0), "").strip()
                )

        if not reconstructed_code and self._contains_c_function_definition(response_text):
            reconstructed_code = response_text.strip()

        if not reconstructed_code:
            reconstructed_code = fallback_source.strip()
            if not improvement_notes:
                improvement_notes = (
                    "Model output could not be parsed cleanly, so the original decompiled source "
                    "was returned as a fallback for further review."
                )

        if not improvement_notes:
            improvement_notes = (
                "Reconstructed the binary into cleaner C, preserving control flow while improving "
                "naming and readability where possible."
            )

        return reconstructed_code, improvement_notes

    def _extract_json_dict(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract the first JSON object from an LLM response."""
        stripped = text.strip()
        if not stripped:
            return None

        fenced_match = re.search(
            r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.DOTALL | re.IGNORECASE
        )
        candidates = [fenced_match.group(1)] if fenced_match else []
        candidates.append(stripped)

        for candidate in candidates:
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return cast(Dict[str, Any], parsed)

        decoder = json.JSONDecoder()
        for index, char in enumerate(stripped):
            if char != "{":
                continue
            try:
                parsed, _ = decoder.raw_decode(stripped[index:])
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return cast(Dict[str, Any], parsed)

        return None

    def _contains_c_function_definition(self, text: str) -> bool:
        """Return True when the text appears to contain a C-style function definition."""
        return bool(
            re.search(
                r"\b(?:void|int|char|bool|float|double|long|short|unsigned|signed)\s+\**\w+\s*\(",
                text,
            )
        )

    def _build_decompiled_code_map(self, functions: List[Dict[str, Any]]) -> Dict[str, str]:
        """Create an address/name keyed decompiled-code mapping from normalized functions."""
        decompiled_code: Dict[str, str] = {}
        for index, function in enumerate(functions):
            if not isinstance(function, dict):
                continue

            source = str(function.get("source") or function.get("decompiled") or "").strip()
            if not source:
                continue

            key = str(
                function.get("entry_point")
                or function.get("address")
                or function.get("name")
                or f"func_{index}"
            )
            decompiled_code[key] = source

        return decompiled_code

    def _build_recompilation_translation_unit(self, decompile_result: Dict[str, Any]) -> str:
        """Combine decompiled functions into a compilable C translation unit."""
        functions = decompile_result.get("decompiled_functions", [])
        if not isinstance(functions, list):
            functions = []
        imports = decompile_result.get("imports", [])
        if not isinstance(imports, list):
            imports = []

        imported_names = {
            self._normalize_function_name(
                import_name.get("name") if isinstance(import_name, dict) else import_name
            )
            for import_name in imports
            if str(import_name).strip()
        }

        translation_unit = [
            "/* Reconstructed by REVENG MCP recompilation tool */",
            "/*",
            " * The original Ghidra pseudocode is preserved in comments above each stub.",
            " * Stubs keep function names stable so the rebuilt artifact retains overlap",
            " * with the original symbol layout while remaining easy for GCC to compile.",
            " */",
            "",
        ]

        bodies: List[str] = []
        seen_names = set()
        has_entry_point = False

        for index, function in enumerate(functions):
            if not isinstance(function, dict):
                continue

            source = str(function.get("source") or function.get("decompiled") or "").strip()
            function_name = self._sanitize_c_identifier(
                function.get("name") or self._extract_function_name(source),
                fallback=f"func_{index}",
            )
            if self._normalize_function_name(function_name) in imported_names:
                continue
            if function_name in seen_names:
                continue

            seen_names.add(function_name)
            has_entry_point = has_entry_point or function_name.lower() in {
                "main",
                "wmain",
                "winmain",
                "dllmain",
            }
            bodies.append(
                self._generate_stub_function_definition(
                    function_name=function_name,
                    source=source,
                    entry_point=function.get("entry_point") or function.get("address"),
                )
            )

        if not has_entry_point:
            bodies.append("int main(void)\n{\n    return 0;\n}\n")

        if not bodies:
            fallback = str(decompile_result.get("decompiled_source") or "").strip()
            bodies.append(
                self._generate_stub_function_definition(
                    function_name="main",
                    source=fallback,
                    entry_point=None,
                )
            )

        translation_unit.extend(bodies)

        return "\n".join(translation_unit).strip() + "\n"

    def _extract_function_signature(self, source: str) -> Optional[str]:
        """Extract the signature line from a C-like function body."""
        header, separator, _body = source.partition("{")
        candidate = header.strip()
        if not separator or "(" not in candidate or ")" not in candidate:
            return None
        if (
            candidate.startswith("if ")
            or candidate.startswith("while ")
            or candidate.startswith("switch ")
        ):
            return None
        return candidate

    def _extract_function_name(self, source: str) -> Optional[str]:
        """Extract a function name from a C-like source snippet."""
        signature = self._extract_function_signature(source)
        if not signature:
            return None

        before_paren = signature.split("(", 1)[0].strip()
        if not before_paren:
            return None

        return before_paren.split()[-1]

    def _sanitize_c_identifier(self, name: Any, fallback: str) -> str:
        """Convert arbitrary names into valid C identifiers."""
        candidate = str(name or "").strip()
        if not candidate:
            candidate = fallback

        candidate = re.sub(r"[^0-9A-Za-z_]", "_", candidate)
        if not candidate:
            candidate = fallback
        if candidate[0].isdigit():
            candidate = f"func_{candidate}"

        if candidate in {
            "auto",
            "break",
            "case",
            "char",
            "const",
            "continue",
            "default",
            "do",
            "double",
            "else",
            "enum",
            "extern",
            "float",
            "for",
            "goto",
            "if",
            "inline",
            "int",
            "long",
            "register",
            "restrict",
            "return",
            "short",
            "signed",
            "sizeof",
            "static",
            "struct",
            "switch",
            "typedef",
            "union",
            "unsigned",
            "void",
            "volatile",
            "while",
        }:
            candidate = f"func_{candidate}"

        return candidate

    def _generate_stub_function_definition(
        self,
        *,
        function_name: str,
        source: str,
        entry_point: Optional[Any],
    ) -> str:
        """Generate a compilable stub function that preserves the original name."""
        return_type = self._infer_stub_return_type(function_name, source)
        definition = [
            f"/* Original entry: {entry_point or 'unknown'}",
            self._truncate_comment_text(source) if source else "No decompiled source available.",
            "*/",
            f"{return_type} {function_name}(void)",
            "{",
        ]

        if return_type == "void":
            definition.append("    return;")
        elif return_type in {"float", "double"}:
            definition.append("    return 0.0;")
        elif return_type.endswith("*"):
            definition.append("    return (void *)0;")
        else:
            definition.append("    return 0;")

        definition.append("}")
        return "\n".join(definition) + "\n"

    def _infer_stub_return_type(self, function_name: str, source: str) -> str:
        """Infer a safe return type for a generated stub."""
        lowered_name = function_name.lower()
        if lowered_name in {"main", "wmain", "winmain", "dllmain"}:
            return "int"

        signature = self._extract_function_signature(source)
        if not signature:
            return "int"

        before_paren = signature.split("(", 1)[0].strip()
        tokens = before_paren.split()
        if len(tokens) < 2:
            return "int"

        return self._sanitize_stub_return_type(" ".join(tokens[:-1]))

    def _sanitize_stub_return_type(self, return_type: str) -> str:
        """Map Ghidra-style return types to simple GCC-friendly equivalents."""
        cleaned = re.sub(
            r"\b(__cdecl|__stdcall|__fastcall|__thiscall|__noreturn|static|extern|inline|register|volatile|const)\b",
            "",
            return_type,
        )
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        if not cleaned:
            return "int"
        if "*" in cleaned or cleaned == "pointer":
            return "void *"
        if cleaned == "void":
            return "void"
        if cleaned in {"float", "double"}:
            return cleaned
        return "int"

    def _truncate_comment_text(self, source: str, limit: int = 400) -> str:
        """Collapse and truncate decompiled source so it fits safely in a comment."""
        sanitized = source.replace("*/", "* /")
        compact = re.sub(r"\s+", " ", sanitized).strip()
        if len(compact) <= limit:
            return compact
        return compact[: limit - 3] + "..."

    def _finalize_recompiled_binary(
        self, compiled_binary_path: str, requested_output_path: Optional[str]
    ) -> str:
        """Copy the rebuilt binary to a requested output path when provided."""
        compiled_binary = Path(compiled_binary_path)
        if not requested_output_path:
            return str(compiled_binary)

        output_path = Path(requested_output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(compiled_binary, output_path)
        return str(output_path)

    def _inspect_binary_artifact(self, binary_path: str) -> Dict[str, Any]:
        """Return size and magic bytes for a rebuilt binary artifact."""
        path = Path(binary_path)
        header = path.read_bytes()[:4] if path.exists() else b""
        if header.startswith(b"MZ"):
            magic = "MZ"
        elif header.startswith(b"\x7fELF"):
            magic = "7f454c46"
        else:
            magic = header.hex()

        return {
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "magic": magic,
        }

    async def _calculate_function_overlap(
        self,
        original_binary: str,
        rebuilt_binary: str,
        ghidra_engine: Optional[GhidraEngine] = None,
    ) -> float:
        """Calculate function-name overlap between the original and rebuilt binaries."""
        ghidra_engine = ghidra_engine or self.ghidra_engine
        loop = asyncio.get_running_loop()
        original_result = await loop.run_in_executor(None, ghidra_engine.decompile, original_binary)
        rebuilt_result = await loop.run_in_executor(None, ghidra_engine.decompile, rebuilt_binary)

        original_names = self._extract_function_names(original_result)
        rebuilt_names = self._extract_function_names(rebuilt_result)

        if not original_names or not rebuilt_names:
            return 0.0

        overlap = len(original_names & rebuilt_names)
        return round((overlap / len(original_names)) * 100, 2)

    def _get_ghidra_engine(self, timeout_override: Optional[int] = None) -> GhidraEngine:
        """Return the shared Ghidra client or a cloned one with a custom timeout."""
        if timeout_override is None or timeout_override == self.ghidra_engine.timeout:
            return self.ghidra_engine

        return GhidraEngine(
            server_url=self.ghidra_engine.server_url,
            timeout=timeout_override,
            fail_fast=self.ghidra_engine.fail_fast,
        )

    def _coerce_optional_int(self, value: Any) -> Optional[int]:
        """Convert an optional input value to int when possible."""
        if value is None or value == "":
            return None

        try:
            return int(value)
        except (TypeError, ValueError):
            logger.warning("Invalid integer value for optional MCP argument: %r", value)
            return None

    def _extract_function_names(self, result: Dict[str, Any]) -> set[str]:
        """Collect normalized function names from a decompile/analyze response."""
        names = set()
        for function in result.get("functions", []):
            if not isinstance(function, dict):
                continue

            normalized = self._normalize_function_name(function.get("name"))
            if normalized:
                names.add(normalized)

        return names

    def _normalize_function_name(self, name: Any) -> str:
        """Normalize function names before overlap comparison."""
        if name is None:
            return ""

        normalized = str(name).strip().lower()
        normalized = re.sub(r"^_+", "", normalized)
        normalized = re.sub(r"@\d+$", "", normalized)
        return normalized

    def _require_existing_path(self, args: Dict[str, Any], field_name: str) -> str:
        """Require a path argument that exists."""
        value = args.get(field_name)
        if not value:
            raise ValueError(f"Missing required argument: {field_name}")

        path = Path(value)
        if not path.exists():
            raise FileNotFoundError(f"Path not found: {value}")

        return str(path)

    def _read_utf8_text_file(self, file_path: str, *, purpose: str) -> str:
        """Read a UTF-8 text file while surfacing decode failures clearly."""
        try:
            return Path(file_path).read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Could not decode {purpose} as UTF-8: {file_path}") from exc

    def _validate_yara_rules_path(self, rules_path: str) -> str:
        """Validate that a YARA rules path is a rule file or a directory containing rules."""
        path = Path(rules_path)
        valid_suffixes = {".yar", ".yara"}

        if path.is_file():
            if path.suffix.lower() not in valid_suffixes:
                raise ValueError(
                    "YARA rules path must be a .yar/.yara file or directory containing rule files"
                )
            return str(path)

        if path.is_dir():
            rule_files = [
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file() and candidate.suffix.lower() in valid_suffixes
            ]
            if not rule_files:
                raise ValueError(
                    "YARA rules path must be a .yar/.yara file or directory containing rule files"
                )
            return str(path)

        raise ValueError(
            "YARA rules path must be a .yar/.yara file or directory containing rule files"
        )

    def _serialize_yara_match(self, match: Any, include_string_data: bool = True) -> Dict[str, Any]:
        """Convert a YARA match into JSON-safe data."""
        serialized_strings = []
        for offset, identifier, data in getattr(match, "strings", []):
            string_result = {"offset": offset, "identifier": identifier}
            if include_string_data:
                decoded = (
                    data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
                )
                string_result["data_text"] = decoded
                string_result["data_hex"] = data.hex() if isinstance(data, bytes) else str(data)
            serialized_strings.append(string_result)

        return {
            "rule": getattr(match, "rule_name", "unknown"),
            "namespace": getattr(match, "namespace", "default"),
            "tags": list(getattr(match, "tags", [])),
            "meta": dict(getattr(match, "meta", {})),
            "strings": serialized_strings,
        }

    def _serialize_memory_analysis(self, analysis: Any) -> Dict[str, Any]:
        """Convert a memory analysis result into JSON-safe data."""
        return {
            "binary_path": analysis.binary_path,
            "analysis_timestamp": analysis.analysis_timestamp,
            "total_processes": analysis.total_processes,
            "total_memory_regions": analysis.total_memory_regions,
            "total_artifacts": analysis.total_artifacts,
            "risk_score": analysis.risk_score,
            "threat_level": analysis.threat_level,
            "anomaly_score": analysis.anomaly_score,
            "anomaly_threshold": analysis.anomaly_threshold,
            "anomaly_flags": list(analysis.anomaly_flags),
            "processes": [
                {
                    "process_id": process.process_id,
                    "process_name": process.process_name,
                    "parent_id": process.parent_id,
                    "command_line": process.command_line,
                    "working_directory": process.working_directory,
                    "anomaly_score": process.anomaly_score,
                    "anomaly_threshold": process.anomaly_threshold,
                    "is_anomalous": process.is_anomalous,
                    "anomaly_reasons": list(process.anomaly_reasons),
                }
                for process in analysis.processes
            ],
            "artifacts": [
                {
                    "artifact_type": artifact.artifact_type,
                    "address": hex(artifact.address),
                    "size": artifact.size,
                    "hash_md5": artifact.hash_md5,
                    "hash_sha1": artifact.hash_sha1,
                    "hash_sha256": artifact.hash_sha256,
                    "description": artifact.description,
                    "confidence": artifact.confidence,
                    "threat_level": artifact.threat_level,
                    "anomaly_score": artifact.anomaly_score,
                    "anomaly_threshold": artifact.anomaly_threshold,
                    "is_anomalous": artifact.is_anomalous,
                    "anomaly_reasons": list(artifact.anomaly_reasons),
                }
                for artifact in analysis.artifacts
            ],
            "suspicious_processes": [
                {
                    "process_id": process.process_id,
                    "process_name": process.process_name,
                    "parent_id": process.parent_id,
                    "command_line": process.command_line,
                    "anomaly_score": process.anomaly_score,
                    "anomaly_threshold": process.anomaly_threshold,
                    "is_anomalous": process.is_anomalous,
                    "anomaly_reasons": list(process.anomaly_reasons),
                }
                for process in analysis.suspicious_processes
            ],
            "injected_code": [
                {
                    "artifact_type": artifact.artifact_type,
                    "address": hex(artifact.address),
                    "size": artifact.size,
                    "hash_sha256": artifact.hash_sha256,
                    "description": artifact.description,
                    "threat_level": artifact.threat_level,
                    "anomaly_score": artifact.anomaly_score,
                    "anomaly_threshold": artifact.anomaly_threshold,
                    "is_anomalous": artifact.is_anomalous,
                    "anomaly_reasons": list(artifact.anomaly_reasons),
                }
                for artifact in analysis.injected_code
            ],
            "network_connections": list(analysis.network_connections),
            "file_handles": list(analysis.file_handles),
            "registry_handles": list(analysis.registry_handles),
        }

    def _serialize_vulnerability(self, vulnerability: Any) -> Dict[str, Any]:
        """Convert a symbolic-execution vulnerability into JSON-safe data."""
        serialized = asdict(vulnerability)
        serialized["type"] = getattr(vulnerability.type, "value", str(vulnerability.type))
        serialized["severity"] = getattr(
            vulnerability.severity, "value", str(vulnerability.severity)
        )

        exploit_payload = serialized.get("exploit_payload")
        if isinstance(exploit_payload, bytes):
            serialized["exploit_payload"] = exploit_payload.hex()

        return serialized

    def _normalize_vulnerability_filter(self, vulnerability_type: Any) -> Optional[str]:
        """Normalize an optional vulnerability-type filter."""
        if vulnerability_type is None:
            return None

        normalized = str(vulnerability_type).strip().lower()
        return normalized or None

    def _parse_optional_address(self, value: Any) -> Optional[int]:
        """Parse an optional target address accepting hex or decimal strings."""
        if value in (None, ""):
            return None

        try:
            return int(str(value), 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid target_address: {value}") from exc

    def _vulnerability_matches_filters(
        self,
        vulnerability: Any,
        *,
        vulnerability_type: Optional[str],
        target_address: Optional[int],
    ) -> bool:
        """Check whether a discovered vulnerability matches requested filters."""
        if vulnerability_type:
            current_type = str(getattr(vulnerability.type, "value", vulnerability.type)).lower()
            if current_type != vulnerability_type:
                return False

        if target_address is not None:
            try:
                current_address = int(getattr(vulnerability, "address", 0))
            except (TypeError, ValueError):
                return False
            if current_address != target_address:
                return False

        return True

    def _summarize_cfg(self, cfg: Any) -> Dict[str, int]:
        """Return a compact CFGFast summary for MCP responses."""
        graph = getattr(cfg, "graph", None)
        function_count = len(getattr(getattr(cfg, "kb", None), "functions", {}) or {})

        if graph is None:
            return {
                "function_count": function_count,
                "node_count": 0,
                "edge_count": 0,
            }

        node_count_callable = getattr(graph, "number_of_nodes", None)
        edge_count_callable = getattr(graph, "number_of_edges", None)
        nodes_attr = getattr(graph, "nodes", [])
        edges_attr = getattr(graph, "edges", [])

        node_count = (
            int(node_count_callable())
            if callable(node_count_callable)
            else len(nodes_attr) if hasattr(nodes_attr, "__len__") else len(list(nodes_attr))
        )
        edge_count = (
            int(edge_count_callable())
            if callable(edge_count_callable)
            else len(edges_attr) if hasattr(edges_attr, "__len__") else len(list(edges_attr))
        )

        return {
            "function_count": function_count,
            "node_count": node_count,
            "edge_count": edge_count,
        }

    def _default_exploit_payload(self, vulnerability: Any) -> bytes:
        """Create a deterministic payload when symbolic execution did not synthesize one."""
        vulnerability_type = str(getattr(vulnerability.type, "value", vulnerability.type)).lower()
        default_payloads = {
            "buffer_overflow": b"A" * 256 + b"B" * 16,
            "stack_overflow": b"A" * 256 + b"B" * 16,
            "heap_overflow": b"H" * 256 + b"I" * 16,
            "format_string": b"%p.%p.%p.%p.%n",
            "use_after_free": b"FREE_ME_AGAIN",
            "double_free": b"FREE_ME_TWICE",
            "command_injection": b";id",
            "null_pointer_dereference": b"\x00" * 8,
        }
        return default_payloads.get(vulnerability_type, b"TRIGGER")

    def _serialize_exploit_candidate(
        self,
        binary_path: str,
        vulnerability: Any,
        exploit_template: Any,
        *,
        generate_rop_chain: bool,
    ) -> Dict[str, Any]:
        """Serialize a vulnerability together with a pwntools-style PoC script."""
        serialized = self._serialize_vulnerability(vulnerability)
        payload = getattr(exploit_template, "payload", None) or getattr(
            vulnerability, "exploit_payload", None
        )
        if not isinstance(payload, bytes) or not payload:
            payload = self._default_exploit_payload(vulnerability)

        address = getattr(vulnerability, "address", 0)
        try:
            serialized["address"] = hex(int(address))
        except (TypeError, ValueError):
            serialized["address"] = str(address)

        serialized["payload_hex"] = payload.hex()
        serialized["poc_script"] = self._build_poc_script(
            binary_path,
            vulnerability,
            payload,
            generate_rop_chain=generate_rop_chain,
        )
        return serialized

    def _build_poc_script(
        self,
        binary_path: str,
        vulnerability: Any,
        payload: bytes,
        *,
        generate_rop_chain: bool,
    ) -> str:
        """Build a minimal pwntools-style PoC that runs without pwntools installed."""
        vulnerability_type = str(getattr(vulnerability.type, "value", vulnerability.type))
        function_name = str(getattr(vulnerability, "function_name", "unknown"))
        try:
            address = hex(int(getattr(vulnerability, "address", 0)))
        except (TypeError, ValueError):
            address = str(getattr(vulnerability, "address", "unknown"))
        rop_note = (
            "# ROP chain generation was requested, but this PoC intentionally stays minimal\n"
            if generate_rop_chain
            else ""
        )

        return (
            "#!/usr/bin/env python3\n"
            f'"""Minimal pwntools-style PoC for {vulnerability_type} in {function_name}."""\n\n'
            f"binary_path = {binary_path!r}\n"
            f"target_address = {address!r}\n"
            f"payload = {payload!r}\n\n"
            "# Equivalent pwntools flow (kept as comments so the script works without pwntools):\n"
            "# from pwn import *\n"
            "# io = process(binary_path)\n"
            "# io.sendline(payload)\n"
            "# io.interactive()\n"
            f"{rop_note}"
            "import subprocess\n\n"
            "proc = subprocess.Popen(\n"
            "    [binary_path],\n"
            "    stdin=subprocess.PIPE,\n"
            "    stdout=subprocess.PIPE,\n"
            "    stderr=subprocess.PIPE,\n"
            ")\n"
            "stdout, stderr = proc.communicate(payload + b'\\n')\n"
            "print(stdout.decode('latin1', errors='replace'))\n"
            "print(stderr.decode('latin1', errors='replace'))\n"
        )

    def _format_generate_exploit_results(
        self,
        *,
        binary_path: str,
        vulnerabilities: List[Dict[str, Any]],
        analysis_time: float,
        note: Optional[str],
        cfg_summary: Dict[str, int],
    ) -> str:
        """Create a concise MCP text summary for exploit generation."""
        text = "Exploit Generation\n"
        text += "=" * 70 + "\n\n"
        text += f"Binary: {binary_path}\n"
        text += (
            "CFGFast summary: "
            f"{cfg_summary.get('function_count', 0)} functions, "
            f"{cfg_summary.get('node_count', 0)} nodes, "
            f"{cfg_summary.get('edge_count', 0)} edges\n"
        )
        text += f"Analysis time: {analysis_time:.2f}s\n"
        text += f"Vulnerabilities: {len(vulnerabilities)}\n\n"

        if vulnerabilities:
            text += "Generated PoC candidates:\n"
            for vulnerability in vulnerabilities[:10]:
                text += (
                    f"• {vulnerability.get('type', 'unknown')} at "
                    f"{vulnerability.get('address', 'unknown')} "
                    f"({vulnerability.get('function_name', 'unknown')})\n"
                )
        elif note:
            text += note + "\n"
        else:
            text += "No vulnerabilities found.\n"

        return text

    def _serialize_diff_result(self, diff_result: Any) -> Dict[str, Any]:
        """Convert a binary diff result into JSON-safe data."""
        return {
            "binary_v1": diff_result.binary_v1,
            "binary_v2": diff_result.binary_v2,
            "similarity_score": diff_result.similarity_score,
            "unchanged_functions": list(diff_result.unchanged_functions),
            "modified_functions": [asdict(match) for match in diff_result.modified_functions],
            "new_functions": list(diff_result.new_functions),
            "deleted_functions": list(diff_result.deleted_functions),
            "total_functions_v1": diff_result.total_functions_v1,
            "total_functions_v2": diff_result.total_functions_v2,
            "match_count": diff_result.match_count,
            "instruction_changes": diff_result.instruction_changes or {},
            "string_changes": diff_result.string_changes or {},
        }

    async def _refine_malware_family_name(
        self, path: str, classification: Dict[str, Any]
    ) -> Optional[str]:
        """Use Ollama to refine the malware family label when enough context exists."""
        matched_rules = classification.get("matched_rules", [])
        indicators = classification.get("indicators", [])
        if not matched_rules and not indicators:
            return None

        try:
            response = await self._query_ollama_chat(
                system_prompt=(
                    "You are a malware analyst. Return exactly one short human-readable "
                    "family label such as 'Generic Ransomware' or 'Downloader Trojan'. "
                    "Do not add explanations, punctuation, or markdown."
                ),
                user_prompt=(
                    f"Binary path: {path}\n"
                    f"Current family: {classification.get('family', 'Unknown')}\n"
                    f"Confidence: {classification.get('confidence', 0.0)}\n"
                    f"Matched rules: {matched_rules}\n"
                    f"Indicators: {indicators}\n"
                    f"ML assessment: {classification.get('ml_assessment', {})}\n"
                    "Return the best concise family label."
                ),
                timeout=20,
            )
        except Exception as exc:
            logger.warning("Ollama family refinement unavailable: %s", exc)
            return None

        refined = response.strip().splitlines()[0].strip()
        if not refined:
            return None
        refined = refined.strip("` ")
        if len(refined) > 80:
            refined = refined[:80].rsplit(" ", 1)[0].strip()
        return refined or None

    def _format_malware_classification_results(
        self, path: str, classification: Dict[str, Any]
    ) -> str:
        """Create a text summary for malware classification results."""
        text = "Malware Classification\n"
        text += "=" * 70 + "\n\n"
        text += f"Target: {path}\n"
        text += f"Family: {classification.get('family', 'Unknown')}\n"
        text += f"Confidence: {classification.get('confidence', 0.0):.3f}\n"
        text += f"Matched Rules: {len(classification.get('matched_rules', []))}\n"

        ml_assessment = classification.get("ml_assessment", {})
        if ml_assessment:
            text += (
                f"ML Anomaly Score: {ml_assessment.get('score', 0.0):.3f} "
                f"(threshold {ml_assessment.get('threshold', 0.0):.3f})\n"
            )

        indicators = classification.get("indicators", [])
        if indicators:
            text += "\nIndicators:\n"
            for indicator in indicators[:10]:
                text += f"  • {indicator}\n"

        matched_rules = classification.get("matched_rules", [])
        if matched_rules:
            text += "\nMatched Rule Names:\n"
            for rule_name in matched_rules[:10]:
                text += f"  • {rule_name}\n"
        else:
            text += "\nNo YARA rule matches were produced by the active ruleset.\n"

        return text

    def _format_yara_scan_results(
        self, path: str, rules_path: str, matches: List[Dict[str, Any]]
    ) -> str:
        """Create a text summary for YARA scan results."""
        text = "YARA Scan Results\n"
        text += "=" * 70 + "\n\n"
        text += f"Target: {path}\n"
        text += f"Rules: {rules_path}\n"
        text += f"Matches: {len(matches)}\n\n"

        for match in matches[:10]:
            text += f"• {match['rule']} ({match['namespace']})\n"
            if match["tags"]:
                text += f"  Tags: {', '.join(match['tags'])}\n"
            if match["meta"]:
                meta_preview = ", ".join(f"{key}={value}" for key, value in match["meta"].items())
                text += f"  Meta: {meta_preview}\n"

        if not matches:
            text += "No YARA matches found.\n"

        return text

    def _format_memory_analysis_results(self, analysis: Dict[str, Any]) -> str:
        """Create a text summary for memory forensics results."""
        text = "Memory Forensics Analysis\n"
        text += "=" * 70 + "\n\n"
        text += f"Target: {analysis['binary_path']}\n"
        text += f"Threat Level: {analysis['threat_level']}\n"
        text += f"Risk Score: {analysis['risk_score']}\n"
        text += f"Processes: {analysis['total_processes']}\n"
        text += f"Memory Regions: {analysis['total_memory_regions']}\n"
        text += f"Artifacts: {analysis['total_artifacts']}\n"

        if analysis["anomaly_flags"]:
            text += "\nAnomaly Flags:\n"
            for flag in analysis["anomaly_flags"][:10]:
                text += f"  • {flag}\n"

        return text

    def _format_binary_diff_results(self, diff_result: Dict[str, Any]) -> str:
        """Create a text summary for binary diff results."""
        text = "Binary Diff Results\n"
        text += "=" * 70 + "\n\n"
        text += f"Binary 1: {diff_result['binary_v1']}\n"
        text += f"Binary 2: {diff_result['binary_v2']}\n"
        text += f"Similarity Score: {diff_result['similarity_score']:.2%}\n"
        text += f"Matched Functions: {diff_result['match_count']}\n"
        text += f"Modified Functions: {len(diff_result['modified_functions'])}\n"
        text += f"New Functions: {len(diff_result['new_functions'])}\n"
        text += f"Deleted Functions: {len(diff_result['deleted_functions'])}\n"

        if diff_result["modified_functions"]:
            text += "\nModified Functions:\n"
            for match in diff_result["modified_functions"][:10]:
                text += (
                    f"  • {match['func_v1_name']} -> {match['func_v2_name']} "
                    f"({match['similarity']:.2%}, {match['match_type']})\n"
                )

        return text

    # Override handle_message to add enterprise features
    async def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP message with enterprise features"""
        msg_type = message.get("method")
        msg_id = cast(int, message.get("id"))

        # Tool calls go through audit logging
        if msg_type == "tools/call":
            tool_name = message.get("params", {}).get("name")
            arguments = message.get("params", {}).get("arguments", {})

            if tool_name in self.tools:
                tool = self.tools[tool_name]
                if tool.handler is None:
                    return cast(
                        Dict[str, Any],
                        self._create_error(msg_id, -32603, f"No handler for tool: {tool_name}"),
                    )

                handler = cast(Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]], tool.handler)
                result = await self._execute_with_audit(tool_name, arguments, handler)
                return cast(Dict[str, Any], self._create_response(msg_id, result))

        # Delegate to base class for other message types
        return cast(Dict[str, Any], await super().handle_message(message))


# ==================================================================================
# ENTRY POINT
# ==================================================================================


async def main():
    """Run REVENG Enterprise MCP Server"""
    from ..transports import StdioTransport

    logger.info("Starting REVENG Enterprise MCP Server v4.0.0")

    server = REVENGEnterpriseServer(enable_rate_limiting=True, enable_audit_log=True)

    transport = StdioTransport()
    await server.start(transport)

    logger.info("REVENG Enterprise MCP Server stopped")


if __name__ == "__main__":
    asyncio.run(main())
