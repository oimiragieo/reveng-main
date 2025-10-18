"""
Web API Routes

REST API endpoints for the REVENG web interface.
"""

from .admin import *
from .analysis import *
from .auth import *
from .projects import *
from .users import *

__all__ = [
    "analysis_routes",
    "auth_routes",
    "project_routes",
    "user_routes",
    "admin_routes",
]
