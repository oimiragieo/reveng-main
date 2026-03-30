"""Shared models for app-level reverse engineering workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from reveng.result_contracts import RESULT_SCHEMA_VERSION


@dataclass
class AppReverseEngineeringResult:
    """Normalized result returned by language-specific app adapters."""

    language: str
    adapter_name: str
    input_path: Path
    input_root: Path
    output_dir: Path
    specs_dir: Path
    domains_dir: Path
    artifacts_dir: Path
    analysis_file: Path
    topic_files: Dict[str, Path]
    domain_files: Dict[str, Path]
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    primary_artifacts: Dict[str, Path] = field(default_factory=dict)
    source_count: int = 0
    source_language: Optional[str] = None
    schema_version: str = RESULT_SCHEMA_VERSION
    result_type: str = "app_reverse_engineering_result"
    validation_grade: str = "packaging_only"
    validation_summary: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
