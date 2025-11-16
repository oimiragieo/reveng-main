"""
Protocol Reverse Engineering Module

AI-driven binary protocol reverse engineering using deep learning and LLMs.

Based on "The Modern Hacker's Playbook" - Part 4.2: Binary & Obscure Protocol
Reverse Engineering (PREIUD, DL-ProS2)
"""

from .protocol_analyzer import ProtocolAnalyzer
from .ai_protocol_reverser import AIProtocolReverser

__all__ = [
    'ProtocolAnalyzer',
    'AIProtocolReverser',
]
