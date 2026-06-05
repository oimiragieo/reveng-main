"""
Ghidra HTTP Client - Base communication layer for Ghidra MCP Server

This module provides a robust HTTP client for communicating with the Ghidra MCP server.
It handles connection pooling, retries, error handling, and request/response serialization.
"""

import logging
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class GhidraHTTPClient:
    """
    HTTP client for Ghidra MCP server with connection pooling and error handling.

    This class provides a clean interface for making requests to the Ghidra HTTP server,
    with automatic retry logic, connection pooling, and comprehensive error handling.

    Attributes:
        base_url: Base URL of the Ghidra MCP server
        timeout: Request timeout in seconds
        session: Persistent requests Session for connection pooling
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:13370",  # Changed from 1337 to avoid Razer SDK conflict
        timeout: int = 30,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
    ):
        """
        Initialize the Ghidra HTTP client.

        Args:
            base_url: Base URL of the Ghidra MCP server (default: http://127.0.0.1:1337)
            timeout: Request timeout in seconds (default: 30)
            max_retries: Maximum number of retry attempts (default: 3)
            backoff_factor: Backoff factor for retries (default: 1.0)
        """
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

        # Create a session for connection pooling
        self.session = requests.Session()

        # Configure retry strategy (optimized for faster fallback)
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD"],
            connect=2,  # Only 2 connection retries for faster fallback
        )

        # Mount adapter with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.logger.info(f"GhidraHTTPClient initialized with base_url: {self.base_url}")

    def get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> requests.Response:
        """
        Execute a GET request to the Ghidra server.

        Args:
            endpoint: API endpoint (e.g., 'list_functions', 'decompile')
            params: Query parameters as dictionary
            timeout: Request timeout (uses instance timeout if not specified)

        Returns:
            requests.Response object

        Raises:
            requests.exceptions.RequestException: If the request fails
        """
        url = urljoin(self.base_url, endpoint)
        timeout = timeout or self.timeout

        try:
            self.logger.debug(f"GET {url} with params: {params}")
            response = self.session.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout connecting to {url}")
            raise
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"Connection error to {url}: {e}")
            raise
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP error {response.status_code} from {url}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during GET {url}: {e}")
            raise

    def post(
        self,
        endpoint: str,
        data: Optional[Any] = None,
        json: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> requests.Response:
        """
        Execute a POST request to the Ghidra server.

        Args:
            endpoint: API endpoint (e.g., 'decompile', 'analyze')
            data: Request body as string or bytes
            json: Request body as JSON dictionary
            timeout: Request timeout (uses instance timeout if not specified)

        Returns:
            requests.Response object

        Raises:
            requests.exceptions.RequestException: If the request fails
        """
        url = urljoin(self.base_url, endpoint)
        timeout = timeout or self.timeout

        try:
            self.logger.debug(f"POST {url} with data: {data is not None}, json: {json is not None}")
            response = self.session.post(url, data=data, json=json, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout connecting to {url}")
            raise
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"Connection error to {url}: {e}")
            raise
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP error {response.status_code} from {url}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during POST {url}: {e}")
            raise

    def health_check(self) -> bool:
        """
        Check if the Ghidra MCP server is accessible and responding.

        Returns:
            True if server is healthy, False otherwise
        """
        try:
            # Try to hit the base URL or a known health endpoint
            response = self.session.get(self.base_url, timeout=5)
            self.logger.info(f"Health check successful: {response.status_code}")
            return response.status_code in [200, 404]  # 404 is OK, means server is up
        except Exception as e:
            self.logger.warning(f"Health check failed: {e}")
            return False

    def get_json(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        default: Any = None,
    ) -> Any:
        """
        Execute a GET request and return JSON response.

        Args:
            endpoint: API endpoint
            params: Query parameters
            timeout: Request timeout
            default: Default value to return on error

        Returns:
            Parsed JSON response or default value on error
        """
        try:
            response = self.get(endpoint, params=params, timeout=timeout)
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to get JSON from {endpoint}: {e}")
            return default

    def post_json(
        self,
        endpoint: str,
        data: Optional[Any] = None,
        json: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        default: Any = None,
    ) -> Any:
        """
        Execute a POST request and return JSON response.

        Args:
            endpoint: API endpoint
            data: Request body as string or bytes
            json: Request body as JSON dictionary
            timeout: Request timeout
            default: Default value to return on error

        Returns:
            Parsed JSON response or default value on error
        """
        try:
            response = self.post(endpoint, data=data, json=json, timeout=timeout)
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to post JSON to {endpoint}: {e}")
            return default

    def close(self):
        """Close the session and cleanup resources."""
        if self.session:
            self.session.close()
            self.logger.info("GhidraHTTPClient session closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
