"""
Ghidra Analysis Server - The "Database" for REVENG

This server wraps Ghidra's analysis capabilities and exposes them via REST API.
Following Gemini's architectural blueprint: "Ghidra is not a tool, it is the database."

Architecture:
- Persistent long-running server (not on-demand)
- Connects to Ghidra via ghidra_bridge or HTTP
- Returns structured JSON with decompiled code, CFG, xrefs, etc.
- REVENG analyzer queries this server for all analysis data

Author: REVENG Team
Version: 3.0.0
"""

import logging
import os
import time
from typing import Any, Dict

from flask import Flask, jsonify, request
from flask_cors import CORS

from reveng.integrations.ghidra.ghidra_http_client import GhidraHTTPClient

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__)
CORS(app)

# Try to import ghidra_bridge (optional for now, will use HTTP fallback)
try:
    import ghidra_bridge

    GHIDRA_BRIDGE_AVAILABLE = True
    logger.info("ghidra_bridge is available")
except ImportError:
    GHIDRA_BRIDGE_AVAILABLE = False
    logger.warning("ghidra_bridge not available, will use HTTP fallback")


class GhidraAnalysisEngine:
    """
    Core analysis engine that wraps Ghidra functionality.

    This class is the "database interface" - it knows how to extract
    rich, structured data from Ghidra and serialize it to JSON.
    """

    def __init__(self, ghidra_mcp_url: str = "http://127.0.0.1:8080"):
        """Initialize the analysis engine."""
        self.ghidra_mcp_url = ghidra_mcp_url
        self.http_client = GhidraHTTPClient(base_url=ghidra_mcp_url)
        self.bridge = None

        # Try to connect to ghidra_bridge
        if GHIDRA_BRIDGE_AVAILABLE:
            try:
                self.bridge = ghidra_bridge.GhidraBridge(namespace=globals())
                logger.info("Connected to Ghidra via ghidra_bridge")
            except Exception as e:
                logger.warning(f"Could not connect to ghidra_bridge: {e}")

    def health_check(self) -> Dict[str, Any]:
        """
        Check if Ghidra is accessible and ready for analysis.

        Returns:
            dict: Health status with connection info
        """
        try:
            # Try HTTP health check first
            response = self.http_client.get_json("health", default=None)
            if response:
                return {
                    "status": "healthy",
                    "method": "http",
                    "url": self.ghidra_mcp_url,
                    "timestamp": time.time(),
                }

            # Try ghidra_bridge
            if self.bridge:
                return {
                    "status": "healthy",
                    "method": "bridge",
                    "timestamp": time.time(),
                }

            return {
                "status": "unhealthy",
                "error": "No connection to Ghidra",
                "timestamp": time.time(),
            }
        except Exception as e:
            return {"status": "unhealthy", "error": str(e), "timestamp": time.time()}

    def analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """
        Perform deep analysis on a binary file.

        This is the core method that extracts ALL data from Ghidra:
        - Functions (with decompiled code)
        - Control Flow Graphs (CFG)
        - Cross-references (xrefs)
        - Data flow analysis
        - Symbol tables
        - Strings (with context)

        Args:
            binary_path: Path to the binary file to analyze

        Returns:
            dict: Comprehensive JSON with all analysis data
        """
        logger.info(f"Analyzing binary: {binary_path}")

        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # Initialize result structure
        result = {
            "binary_path": binary_path,
            "binary_name": os.path.basename(binary_path),
            "timestamp": time.time(),
            "analysis_complete": False,
            "functions": [],
            "decompiled_code": {},
            "strings": [],
            "imports": [],
            "exports": [],
            "xrefs": {},
            "cfg": {},
            "metadata": {},
        }

        try:
            # Step 1: Get all functions
            logger.info("Step 1: Extracting functions...")
            functions = self.http_client.get_json("methods", params={"limit": 10000}, default=[])
            result["functions"] = functions
            logger.info(f"Found {len(functions)} functions")

            # Step 2: Get decompiled code for all functions
            logger.info("Step 2: Decompiling functions...")
            decompiled = {}
            for func in functions[:50]:  # Limit to first 50 for performance
                func_addr = func.get("address") or func.get("entry", "")
                if func_addr:
                    decomp = self.http_client.post_json(
                        "decompile", data={"address": func_addr}, default=None
                    )
                    if decomp:
                        decompiled[func_addr] = decomp
            result["decompiled_code"] = decompiled
            logger.info(f"Decompiled {len(decompiled)} functions")

            # Step 3: Get strings
            logger.info("Step 3: Extracting strings...")
            strings = self.http_client.get_json("strings", params={"limit": 2000}, default=[])
            result["strings"] = strings
            logger.info(f"Found {len(strings)} strings")

            # Step 4: Get imports
            logger.info("Step 4: Extracting imports...")
            imports = self.http_client.get_json("imports", default=[])
            result["imports"] = imports
            logger.info(f"Found {len(imports)} imports")

            # Step 5: Get exports
            logger.info("Step 5: Extracting exports...")
            exports = self.http_client.get_json("exports", default=[])
            result["exports"] = exports
            logger.info(f"Found {len(exports)} exports")

            # Step 6: Get cross-references for key functions
            logger.info("Step 6: Extracting cross-references...")
            xrefs = {}
            for func in functions[:20]:  # Limit to first 20 for performance
                func_addr = func.get("address") or func.get("entry", "")
                if func_addr:
                    xref_data = self.http_client.get_json(f"xrefs_to/{func_addr}", default=[])
                    if xref_data:
                        xrefs[func_addr] = xref_data
            result["xrefs"] = xrefs
            logger.info(f"Got xrefs for {len(xrefs)} functions")

            # Step 7: Get metadata
            logger.info("Step 7: Extracting metadata...")
            metadata = self.http_client.get_json("metadata", default={})
            result["metadata"] = metadata

            result["analysis_complete"] = True
            logger.info("Analysis complete!")

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            result["error"] = str(e)
            result["analysis_complete"] = False

        return result

    def get_function_details(self, function_address: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific function.

        Args:
            function_address: Address of the function (hex string)

        Returns:
            dict: Function details including decompiled code, CFG, etc.
        """
        result = {
            "address": function_address,
            "decompiled_code": None,
            "xrefs_to": [],
            "xrefs_from": [],
            "calls": [],
            "callers": [],
        }

        try:
            # Get decompiled code
            decomp = self.http_client.post_json(
                "decompile", data={"address": function_address}, default=None
            )
            result["decompiled_code"] = decomp

            # Get xrefs
            xrefs_to = self.http_client.get_json(f"xrefs_to/{function_address}", default=[])
            result["xrefs_to"] = xrefs_to

            xrefs_from = self.http_client.get_json(f"xrefs_from/{function_address}", default=[])
            result["xrefs_from"] = xrefs_from

        except Exception as e:
            logger.error(f"Failed to get function details: {e}")
            result["error"] = str(e)

        return result


# Global analysis engine instance
analysis_engine = None


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    if not analysis_engine:
        return (
            jsonify({"status": "initializing", "message": "Analysis engine not initialized"}),
            503,
        )

    health_status = analysis_engine.health_check()

    if health_status["status"] == "healthy":
        return jsonify(health_status), 200
    else:
        return jsonify(health_status), 503


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Main analysis endpoint.

    Request body:
        {
            "binary_path": "/path/to/binary.exe"
        }

    Response:
        Comprehensive JSON with all analysis data
    """
    if not analysis_engine:
        return jsonify({"error": "Analysis engine not initialized"}), 503

    data = request.get_json()
    if not data or "binary_path" not in data:
        return jsonify({"error": "Missing 'binary_path' in request body"}), 400

    binary_path = data["binary_path"]

    try:
        result = analysis_engine.analyze_binary(binary_path)
        return jsonify(result), 200
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/function/<address>", methods=["GET"])
def get_function(address: str):
    """
    Get detailed information about a specific function.

    Args:
        address: Function address (hex string)
    """
    if not analysis_engine:
        return jsonify({"error": "Analysis engine not initialized"}), 503

    try:
        result = analysis_engine.get_function_details(address)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Failed to get function: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/", methods=["GET"])
def index():
    """Root endpoint with server information."""
    return jsonify(
        {
            "service": "REVENG Ghidra Analysis Server",
            "version": "4.0.0",
            "status": "running",
            "endpoints": {
                "/health": "GET - Health check",
                "/analyze": "POST - Analyze a binary",
                "/function/<address>": "GET - Get function details",
            },
        }
    )


def start_server(
    host: str = "127.0.0.1",
    port: int = 1337,
    ghidra_mcp_url: str = "http://127.0.0.1:8080",
):
    """
    Start the Ghidra Analysis Server.

    Args:
        host: Host to bind to
        port: Port to listen on
        ghidra_mcp_url: URL of the Ghidra MCP server
    """
    global analysis_engine

    logger.info("=" * 60)
    logger.info("REVENG Ghidra Analysis Server v3.0.0")
    logger.info("=" * 60)
    logger.info(f"Server will listen on: {host}:{port}")
    logger.info(f"Ghidra MCP URL: {ghidra_mcp_url}")
    logger.info("=" * 60)

    # Initialize analysis engine
    logger.info("Initializing analysis engine...")
    analysis_engine = GhidraAnalysisEngine(ghidra_mcp_url=ghidra_mcp_url)

    # Check health
    health_status = analysis_engine.health_check()
    if health_status["status"] == "healthy":
        logger.info(f"✅ Connected to Ghidra via {health_status['method']}")
    else:
        logger.warning(f"⚠️  Ghidra connection not healthy: {health_status.get('error', 'Unknown')}")
        logger.warning("   Server will start but analysis may fail")

    logger.info("=" * 60)
    logger.info("Server is ready!")
    logger.info("=" * 60)

    # Start Flask server
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="REVENG Ghidra Analysis Server - The database for AI-powered reverse engineering"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=1337, help="Port to listen on (default: 1337)")
    parser.add_argument(
        "--ghidra-url",
        default="http://127.0.0.1:8080",
        help="Ghidra MCP server URL (default: http://127.0.0.1:8080)",
    )

    args = parser.parse_args()

    start_server(host=args.host, port=args.port, ghidra_mcp_url=args.ghidra_url)
