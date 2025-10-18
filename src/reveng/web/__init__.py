"""
REVENG Web Interface

Web interface backend for the REVENG platform.
Provides REST API, WebSocket services, and web server functionality.
"""

__version__ = "2.1.0"
__author__ = "REVENG Development Team"

# API routes
from .api import *

# Middleware
from .middleware import *

# Web server
from .server import *

# Services
from .services import *

__all__ = [
    "start_server",
    "create_app",
    "setup_routes",
    "setup_middleware",
]
