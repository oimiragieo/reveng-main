"""
EDR Evasion Module

Advanced techniques for bypassing Endpoint Detection and Response (EDR)
systems and evading security monitoring.
"""

from .edr_evasion_engine import EDREvasionEngine, EvasionTechnique
from .process_mockingjay import ProcessMockingjayEngine
from .api_unhooking import APIUnhooker
from .environmental_keying import EnvironmentalKeying

__all__ = [
    'EDREvasionEngine',
    'EvasionTechnique',
    'ProcessMockingjayEngine',
    'APIUnhooker',
    'EnvironmentalKeying',
]
