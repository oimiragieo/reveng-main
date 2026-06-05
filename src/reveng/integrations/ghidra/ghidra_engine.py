"""
Ghidra Engine - Client for Ghidra Analysis Server

This is the client-side interface to the Ghidra Analysis Server.
It replaces the old GhidraMCPConnector with a server-based architecture.

Following Gemini's blueprint:
- Ghidra is REQUIRED, not optional
- Analysis fails fast if Ghidra unavailable
- All data comes from structured JSON responses
- AI analyzes real decompiled code, not strings

Author: REVENG Team
Version: 3.0.0
"""

import logging
from typing import Any, Dict, List, Optional, cast

import requests

logger = logging.getLogger(__name__)


class GhidraConnectionError(Exception):
    """Raised when Ghidra Analysis Server is not available."""

    pass


class GhidraEngine:
    """
    Client for the Ghidra Analysis Server.

    This class provides a clean interface to query the Ghidra "database"
    for all reverse engineering data.
    """

    def __init__(
        self,
        server_url: str = "http://127.0.0.1:13370",  # Changed from 1337 to avoid Razer SDK conflict
        timeout: int = 180,
        fail_fast: bool = True,
    ):
        """
        Initialize the Ghidra Engine.

        Args:
            server_url: URL of the Ghidra Analysis Server
            timeout: Request timeout in seconds
            fail_fast: If True, raise exception immediately if server unavailable
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.fail_fast = fail_fast
        self.session = requests.Session()

        logger.info(f"Initializing Ghidra Engine (server: {self.server_url})")

        # Perform health check
        if self.fail_fast:
            self._require_healthy_connection()

    def _require_healthy_connection(self):
        """
        Ensure Ghidra Analysis Server is healthy.

        Raises:
            GhidraConnectionError: If server is not healthy
        """
        logger.info(f"Connecting to Ghidra Analysis Server at {self.server_url}...")

        try:
            response = self.session.get(f"{self.server_url}/health", timeout=2)

            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "healthy":
                    method = data.get("method", "unknown")
                    logger.info(f"✅ Connection successful. Ghidra ready (via {method}).")
                    return
                else:
                    error_msg = data.get("error", "Unknown error")
                    raise GhidraConnectionError(f"Ghidra Analysis Server is unhealthy: {error_msg}")
            else:
                raise GhidraConnectionError(
                    f"Ghidra Analysis Server returned status {response.status_code}"
                )

        except requests.exceptions.ConnectionError:
            raise GhidraConnectionError(
                f"❌ Error: Could not connect to Ghidra Analysis Server at {self.server_url}\n"
                f"\n"
                f"   The server is not running. Please start it with:\n"
                f"\n"
                f"   Option 1 - Start the REVENG Ghidra server:\n"
                f"     python -m reveng.server.ghidra_analysis_server --port 13370\n"
                f"\n"
                f"   Option 2 - Use the external Ghidra HTTP server:\n"
                f"     cd external/ghidra-server && python ghidra_http_server.py\n"
                f"\n"
                f"   Option 3 - Use Docker (recommended):\n"
                f"     docker-compose up ghidra-server\n"
                f"\n"
                f"   For native binary analysis (PE/ELF/Mach-O), Ghidra is REQUIRED.\n"
                f"   For Java/Python/C# files, Ghidra is NOT needed.\n"
            )
        except requests.exceptions.Timeout:
            raise GhidraConnectionError(f"Ghidra Analysis Server at {self.server_url} timed out")

    def analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a binary.

        This is the main entry point for getting all Ghidra data.

        Args:
            binary_path: Path to the binary file

        Returns:
            dict: Comprehensive JSON with:
                - functions: List of all functions
                - decompiled_code: Dict of address -> decompiled code
                - strings: List of all strings
                - imports: List of imported functions
                - exports: List of exported functions
                - xrefs: Dict of address -> cross-references
                - cfg: Dict of address -> control flow graph
                - metadata: Binary metadata

        Raises:
            GhidraConnectionError: If server is not available
            FileNotFoundError: If binary file doesn't exist
        """
        logger.info(f"Requesting analysis of {binary_path}...")

        data = self._request_binary_endpoint(
            endpoint="/analyze",
            binary_path=binary_path,
            action="analysis",
        )

        logger.info(f"✅ Analysis complete for {binary_path}")
        logger.info(f"   Functions: {len(data.get('functions', []))}")
        logger.info(f"   Decompiled: {len(data.get('decompiled_code', {}))}")
        logger.info(f"   Strings: {len(data.get('strings', []))}")
        logger.info(f"   Imports: {len(data.get('imports', []))}")
        return data

    def decompile(self, binary_path: str) -> Dict[str, Any]:
        """
        Decompile a binary via the Ghidra HTTP server.

        Args:
            binary_path: Path to the binary file

        Returns:
            dict: Structured decompilation output from the /decompile endpoint

        Raises:
            GhidraConnectionError: If server is not available
            FileNotFoundError: If binary file doesn't exist
        """
        logger.info(f"Requesting decompilation of {binary_path}...")

        data = self._request_binary_endpoint(
            endpoint="/decompile",
            binary_path=binary_path,
            action="decompilation",
        )

        logger.info(f"✅ Decompilation complete for {binary_path}")
        logger.info(f"   Functions: {len(data.get('functions', []))}")
        return data

    def _request_binary_endpoint(
        self,
        *,
        endpoint: str,
        binary_path: str,
        action: str,
    ) -> Dict[str, Any]:
        """Call a binary-analysis HTTP endpoint and normalize the response."""

        try:
            response = self.session.post(
                f"{self.server_url}{endpoint}",
                json={"binary_path": binary_path, "timeout": self.timeout},
                timeout=self.timeout,
            )

            if response.status_code == 200:
                return self._normalize_analysis_response(response.json())

            elif response.status_code == 404:
                raise FileNotFoundError(f"Binary not found: {binary_path}")

            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get("error", "Unknown error")
                except ValueError:
                    error_msg = response.text.strip() or "Unknown error"
                raise GhidraConnectionError(f"{action.capitalize()} failed: {error_msg}")

        except requests.exceptions.ConnectionError:
            raise GhidraConnectionError(
                f"Lost connection to Ghidra Analysis Server at {self.server_url}"
            )
        except requests.exceptions.Timeout:
            raise GhidraConnectionError(
                f"{action.capitalize()} timed out after {self.timeout} seconds"
            )

    def _normalize_analysis_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract decompiled code into a consistent address-keyed mapping."""
        decompiled_code: Dict[str, str] = {}

        for func in data.get("functions", []):
            if not isinstance(func, dict):
                continue

            source = func.get("decompiled") or func.get("source")
            entry_point = func.get("entry_point") or func.get("address") or func.get("name")

            if source and entry_point:
                decompiled_code[str(entry_point)] = source

        data["decompiled_code"] = decompiled_code
        return data

    def get_function_details(self, function_address: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific function.

        Args:
            function_address: Address of the function (hex string)

        Returns:
            dict: Function details including:
                - decompiled_code: Decompiled C code
                - xrefs_to: References to this function
                - xrefs_from: References from this function
                - calls: Functions called by this function
                - callers: Functions that call this function
        """
        logger.info(f"Getting details for function at {function_address}...")

        try:
            response = self.session.get(
                f"{self.server_url}/function/{function_address}", timeout=self.timeout
            )

            if response.status_code == 200:
                data = cast(Dict[str, Any], response.json())
                logger.info(f"✅ Got details for function at {function_address}")
                return data
            else:
                error_data = cast(Dict[str, Any], response.json())
                error_msg = error_data.get("error", "Unknown error")
                raise GhidraConnectionError(f"Failed to get function details: {error_msg}")

        except requests.exceptions.ConnectionError:
            raise GhidraConnectionError(
                f"Lost connection to Ghidra Analysis Server at {self.server_url}"
            )
        except requests.exceptions.Timeout:
            raise GhidraConnectionError(f"Request timed out after {self.timeout} seconds")

    def is_available(self) -> bool:
        """
        Check if the Ghidra Analysis Server is available.

        Returns:
            bool: True if server is healthy, False otherwise
        """
        try:
            response = self.session.get(f"{self.server_url}/health", timeout=2)
            if response.status_code == 200:
                data = cast(Dict[str, Any], response.json())
                return data.get("status") == "healthy"
            return False
        except (requests.exceptions.RequestException, ValueError):
            return False


class GhidraDataExtractor:
    """
    Helper class to extract specific data from Ghidra analysis results.

    This provides convenience methods for security modules to access
    the structured data they need.
    """

    def __init__(self, analysis_data: Dict[str, Any]):
        """
        Initialize extractor with analysis data.

        Args:
            analysis_data: Result from GhidraEngine.analyze_binary()
        """
        self.data = analysis_data

    def get_all_decompiled_code(self) -> Dict[str, str]:
        """Get all decompiled code indexed by address."""
        decompiled_code = self.data.get("decompiled_code", {})
        return cast(Dict[str, str], decompiled_code)

    def get_decompiled_function(self, address: str) -> Optional[str]:
        """Get decompiled code for a specific function."""
        return self.get_all_decompiled_code().get(address)

    def get_functions_with_string(self, search_string: str) -> List[Dict[str, Any]]:
        """
        Find all functions that contain a specific string in their decompiled code.

        Args:
            search_string: String to search for

        Returns:
            list: Functions containing the string
        """
        results = []
        for addr, code in self.get_all_decompiled_code().items():
            if search_string.lower() in code.lower():
                results.append({"address": addr, "code": code})
        return results

    def get_functions_calling_api(self, api_name: str) -> List[Dict[str, Any]]:
        """
        Find all functions that call a specific API.

        Args:
            api_name: Name of the API function

        Returns:
            list: Functions calling the API
        """
        results = []
        for addr, code in self.get_all_decompiled_code().items():
            if api_name in code:
                results.append({"address": addr, "code": code, "api": api_name})
        return results

    def get_dangerous_functions(self) -> List[Dict[str, Any]]:
        """
        Find functions using dangerous APIs (strcpy, gets, memcpy, etc.)

        Returns:
            list: Functions using dangerous APIs
        """
        dangerous_apis = [
            "strcpy",
            "gets",
            "scanf",
            "sprintf",
            "memcpy",
            "memmove",
            "strcat",
            "vsprintf",
        ]

        results = []
        for api in dangerous_apis:
            funcs = self.get_functions_calling_api(api)
            for func in funcs:
                func["dangerous_api"] = api
                results.append(func)

        return results

    def get_crypto_candidates(self) -> List[Dict[str, Any]]:
        """
        Find functions that might contain cryptographic operations.

        Looks for:
        - Bitwise operations (XOR, shifts)
        - Loop structures
        - Large constants
        - Substitution patterns

        Returns:
            list: Functions that might be doing crypto
        """
        crypto_indicators = [
            "XOR",
            "xor",
            "^",  # XOR operations
            "<<",
            ">>",  # Bit shifts
            "0x[0-9a-fA-F]{8}",  # Large constants
            "for",
            "while",  # Loops
        ]

        results = []
        for addr, code in self.get_all_decompiled_code().items():
            score = 0
            for indicator in crypto_indicators:
                if indicator in code:
                    score += 1

            # If function has multiple indicators, it's probably crypto
            if score >= 3:
                results.append({"address": addr, "code": code, "crypto_score": score})

        return results

    def get_suspicious_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all suspicious patterns in one call.

        Returns:
            dict: Categorized suspicious patterns
        """
        return {
            "dangerous_functions": self.get_dangerous_functions(),
            "crypto_candidates": self.get_crypto_candidates(),
        }
