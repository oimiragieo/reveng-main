"""Lightweight heuristic triage engine used by the AI API."""

from __future__ import annotations

import time
from enum import Enum
from pathlib import Path
from typing import Dict, List


class ThreatLevel(Enum):
    """Coarse threat scoring buckets used by the AI API."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InstantTriageEngine:
    """Perform a fast, heuristic-based triage of a binary file."""

    _SUSPICIOUS_MARKERS = {
        b"http": "network",
        b"https": "network",
        b"winexec": "process",
        b"cmd.exe": "process",
        b"powershell": "process",
        b"CreateService": "persistence",
        b"VirtualAlloc": "memory",
        b"MZ": "pe_header",
    }

    _DANGEROUS_EXTENSIONS = {
        ".exe": 25,
        ".dll": 25,
        ".scr": 30,
        ".bat": 20,
        ".ps1": 20,
        ".apk": 15,
    }

    def triage(self, binary_path: str) -> Dict[str, object]:
        start = time.time()
        path = Path(binary_path) if binary_path else None

        indicators: List[str] = []
        capabilities: List[str] = []
        threat_score = 0

        if not path or not path.exists():
            return self._result(
                ThreatLevel.UNKNOWN,
                threat_score,
                capabilities,
                indicators,
                "File not found",
                start,
                metadata={"exists": False},
            )

        ext = path.suffix.lower()
        threat_score += self._DANGEROUS_EXTENSIONS.get(ext, 5 if ext else 0)

        try:
            size_bytes = path.stat().st_size
        except OSError:
            size_bytes = 0

        if size_bytes > 50 * 1024 * 1024:
            indicators.append("Large binary size (>50MB)")
            threat_score += 10

        try:
            with path.open("rb") as handle:
                sample = handle.read(1024 * 1024)
        except OSError:
            sample = b""

        for marker, capability in self._SUSPICIOUS_MARKERS.items():
            if marker in sample:
                capabilities.append(capability)
                indicators.append(f"Marker '{marker.decode(errors='ignore')}' detected")
                threat_score += 10

        capabilities = sorted(set(capabilities))
        indicators = sorted(set(indicators))

        threat_level = self._score_to_level(threat_score)
        reasoning = self._reasoning(threat_level, capabilities, indicators)

        metadata = {
            "extension": ext or "",
            "size_bytes": size_bytes,
            "exists": True,
        }

        return self._result(
            threat_level,
            threat_score,
            capabilities,
            indicators,
            reasoning,
            start,
            metadata=metadata,
        )

    def _score_to_level(self, score: int) -> ThreatLevel:
        if score >= 70:
            return ThreatLevel.CRITICAL
        if score >= 50:
            return ThreatLevel.HIGH
        if score >= 30:
            return ThreatLevel.MEDIUM
        if score > 10:
            return ThreatLevel.LOW
        return ThreatLevel.UNKNOWN

    def _reasoning(
        self,
        level: ThreatLevel,
        capabilities: List[str],
        indicators: List[str],
    ) -> str:
        if level is ThreatLevel.UNKNOWN:
            return "Insufficient indicators detected."

        capability_text = ", ".join(capabilities) if capabilities else "no specific"
        indicator_text = "; ".join(indicators) if indicators else "no explicit"
        return f"Heuristics suggest {level.value} risk with {capability_text} capabilities; indicators: {indicator_text}."

    def _result(
        self,
        level: ThreatLevel,
        score: int,
        capabilities: List[str],
        indicators: List[str],
        reasoning: str,
        start_time: float,
        metadata: Dict[str, object],
    ) -> Dict[str, object]:
        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "threat_level": level.value,
            "threat_score": max(0, min(score, 100)),
            "capabilities": capabilities,
            "indicators": indicators,
            "reasoning": reasoning,
            "file_type": metadata.get("extension", ""),
            "architecture": "unknown",
            "analysis_time_ms": duration_ms,
            "metadata": metadata,
        }
