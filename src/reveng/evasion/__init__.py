"""
EDR Evasion Module

Advanced techniques for bypassing Endpoint Detection and Response (EDR)
systems and evading security monitoring.
"""

from .api_unhooking import APIUnhooker
from .edr_evasion_engine import EDREvasionEngine, EvasionTechnique
from .environmental_keying import EnvironmentalKeying
from .process_mockingjay import ProcessMockingjayEngine

__all__ = [
    "EDREvasionEngine",
    "EvasionTechnique",
    "ProcessMockingjayEngine",
    "APIUnhooker",
    "EnvironmentalKeying",
]
