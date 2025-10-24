"""Utility modules with lazy loading to avoid heavy imports at module import time."""

import importlib
import sys
from typing import Any

__all__ = [
    "comprehensive_reporting_system",
    "demonstration_generator",
    "educational_content_generator",
    "enhanced_code_generator",
    "export_formats",
    "functional_code_generator",
    "interactive_mode",
    "live_demonstration_engine",
    "ml_pipeline_orchestrator",
    "progress_reporter",
    "purge_stubs",
    "reconstruction_comparator",
    "training_material_generator",
    "vulnerability_dataset_loader",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        module = importlib.import_module(f"{__name__}.{name}")
        setattr(sys.modules[__name__], name, module)
        return module
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
