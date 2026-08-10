"""Language-agnostic app reverse-engineering framework."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Protocol, Sequence, cast

from .contracts import enrich_app_analysis_payload, rewrite_analysis_file
from .models import AppReverseEngineeringResult


class AppAdapter(Protocol):
    """Protocol implemented by language-specific app adapters."""

    language: str
    supported_extensions: Sequence[str]
    adapter_name: str

    def supports_path(self, path: Path) -> bool:
        """Return whether this adapter can handle the given input path."""

    async def reverse_engineer(
        self,
        input_path: str,
        output_dir: str,
        *,
        input_root: Optional[str] = None,
        skip_patterns: Optional[Sequence[str]] = None,
        max_snippets: int = 12,
        snippet_context: int = 2,
        run_deobfuscator: bool = False,
    ) -> AppReverseEngineeringResult:
        """Run the adapter workflow."""


class AppReverseEngineeringFramework:
    """Registry and dispatch layer for app reverse-engineering adapters."""

    def __init__(self) -> None:
        self._adapters: Dict[str, AppAdapter] = {}

    def register(self, adapter: AppAdapter) -> None:
        """Register one adapter by language key."""
        self._adapters[adapter.language] = adapter

    @property
    def adapters(self) -> Dict[str, AppAdapter]:
        """Expose the current adapter registry."""
        return dict(self._adapters)

    def infer_language(self, input_path: str) -> str:
        """Infer an adapter language from the input path."""
        path = Path(input_path).expanduser().resolve()
        for language, adapter in self._adapters.items():
            if adapter.supports_path(path):
                return language
        raise ValueError(f"No registered adapter can handle: {path}")

    async def reverse_engineer(
        self,
        input_path: str,
        output_dir: str,
        *,
        language: str = "auto",
        input_root: Optional[str] = None,
        skip_patterns: Optional[Sequence[str]] = None,
        max_snippets: int = 12,
        snippet_context: int = 2,
        run_deobfuscator: bool = False,
        oracle_dir: Optional[str] = None,
        run_js_syntax_check: bool = True,
        run_js_behavior_probe: bool = True,
        run_js_npm_lifecycle_probe: bool = False,
        run_webcrack: bool = False,
        run_restringer: bool = False,
        run_wakaru: bool = False,
        run_js_deobfuscator: bool = False,
        bun_vfs_dir: Optional[str] = None,
    ) -> AppReverseEngineeringResult:
        """Run the selected adapter and return a normalized result."""
        selected_language = self.infer_language(input_path) if language == "auto" else language
        try:
            adapter = self._adapters[selected_language]
        except KeyError as exc:
            available = ", ".join(sorted(self._adapters))
            raise ValueError(
                f"Unknown language adapter '{selected_language}'. Available: {available}"
            ) from exc

        base_kwargs = {
            "input_root": input_root,
            "skip_patterns": skip_patterns,
            "max_snippets": max_snippets,
            "snippet_context": snippet_context,
            "run_deobfuscator": run_deobfuscator,
        }
        if selected_language == "javascript":
            js_adapter = cast(Any, adapter)
            result = await js_adapter.reverse_engineer(
                input_path,
                output_dir,
                oracle_dir=oracle_dir,
                run_webcrack=run_webcrack,
                run_restringer=run_restringer,
                run_wakaru=run_wakaru,
                run_js_deobfuscator=run_js_deobfuscator,
                bun_vfs_dir=bun_vfs_dir,
                **base_kwargs,
            )
        else:
            result = await adapter.reverse_engineer(input_path, output_dir, **base_kwargs)

        enriched_metadata = enrich_app_analysis_payload(
            result.metadata,
            language=result.language,
            adapter_name=result.adapter_name,
            input_path=result.input_path,
            input_root=result.input_root,
            output_dir=result.output_dir,
            analysis_file=result.analysis_file,
            topic_files=result.topic_files,
            domain_files=result.domain_files,
            primary_artifacts=result.primary_artifacts,
            source_count=result.source_count,
            warnings=result.warnings,
            run_js_syntax_check=run_js_syntax_check,
            run_js_behavior_probe=run_js_behavior_probe,
            run_js_npm_lifecycle_probe=run_js_npm_lifecycle_probe,
        )
        rewrite_analysis_file(result.analysis_file, enriched_metadata)
        validation = enriched_metadata["validation"]
        result.metadata = enriched_metadata
        result.schema_version = str(enriched_metadata["schema_version"])
        result.result_type = str(enriched_metadata["result_type"])
        result.validation_grade = str(validation["grade"])
        result.validation_summary = str(validation["summary"])
        result.evidence = list(enriched_metadata["evidence"])
        result.provenance = dict(enriched_metadata["provenance"])
        return result
