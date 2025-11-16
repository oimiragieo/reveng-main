"""
Protocol Analyzer

Traditional protocol analysis techniques complementing AI-based reversing.
"""

import logging
from typing import Dict, List, Optional


class ProtocolAnalyzer:
    """
    Traditional protocol analysis engine.

    Provides manual and semi-automated protocol reverse engineering.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze_messages(self, messages: List[bytes]) -> Dict:
        """Analyze protocol messages"""
        self.logger.info(f"Analyzing {len(messages)} messages...")

        analysis = {
            'message_count': len(messages),
            'unique_lengths': len(set(len(m) for m in messages)),
            'min_length': min(len(m) for m in messages) if messages else 0,
            'max_length': max(len(m) for m in messages) if messages else 0,
        }

        return analysis
