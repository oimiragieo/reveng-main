"""Backwards-compatible threat-intel wrapper for the built-in YARA scanner."""

from ...security.yara_scanner import YARAMatch, YARAScanner

__all__ = ["YARAMatch", "YARAScanner"]
