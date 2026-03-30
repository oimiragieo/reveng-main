"""Shared app reverse-engineering framework with language adapters."""

from .adapters import DotNetAppAdapter, JavaScriptAppAdapter, JVMAppAdapter, PythonAppAdapter
from .corpus import AppCorpusEntry, run_app_corpus, run_app_corpus_sync, select_app_corpus_entries
from .framework import AppReverseEngineeringFramework
from .models import AppReverseEngineeringResult


def create_default_framework() -> AppReverseEngineeringFramework:
    """Create the default framework with built-in adapters."""
    framework = AppReverseEngineeringFramework()
    framework.register(JavaScriptAppAdapter())
    framework.register(JVMAppAdapter())
    framework.register(PythonAppAdapter())
    framework.register(DotNetAppAdapter())
    return framework


__all__ = [
    "AppReverseEngineeringFramework",
    "AppReverseEngineeringResult",
    "AppCorpusEntry",
    "DotNetAppAdapter",
    "JavaScriptAppAdapter",
    "JVMAppAdapter",
    "PythonAppAdapter",
    "create_default_framework",
    "run_app_corpus",
    "run_app_corpus_sync",
    "select_app_corpus_entries",
]
