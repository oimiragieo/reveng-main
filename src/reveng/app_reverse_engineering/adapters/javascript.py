"""JavaScript adapter for the shared app reverse-engineering framework."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence

from reveng.javascript.bundle_reverse_engineer import JavaScriptBundleReverseEngineer

from ..models import AppReverseEngineeringResult


class JavaScriptAppAdapter:
    """Adapter that wraps the existing JavaScript bundle workflow."""

    language = "javascript"
    adapter_name = "javascript_bundle_workflow"
    supported_extensions = (".js", ".cjs", ".mjs")

    def supports_path(self, path: Path) -> bool:
        return path.suffix.lower() in self.supported_extensions

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
        engine = JavaScriptBundleReverseEngineer(
            skip_patterns=skip_patterns or [],
            max_snippets_per_topic=max_snippets,
            snippet_context=snippet_context,
            run_deobfuscator=run_deobfuscator,
        )
        result = await engine.reverse_engineer_bundle(
            input_path,
            output_dir,
            input_root=input_root,
        )

        primary_artifacts = {"normalized_bundle": result.normalized_bundle}
        if result.deep_deobfuscation_output:
            primary_artifacts["deobfuscated_bundle"] = result.deep_deobfuscation_output

        return AppReverseEngineeringResult(
            language=self.language,
            adapter_name=self.adapter_name,
            input_path=result.input_path,
            input_root=result.input_root,
            output_dir=result.output_dir,
            specs_dir=result.specs_dir,
            domains_dir=result.domains_dir,
            artifacts_dir=result.artifacts_dir,
            analysis_file=result.analysis_file,
            topic_files=result.topic_files,
            domain_files=result.domain_files,
            warnings=result.warnings,
            metadata={
                "obfuscation_types": result.obfuscation_types,
                "bundler_signals": result.bundler_signals,
                "dependency_candidates": result.dependency_candidates,
                "cli_flags": result.cli_flags,
                "slash_commands": result.slash_commands,
                "topic_match_counts": result.topic_match_counts,
            },
            primary_artifacts=primary_artifacts,
            source_count=1,
            source_language="javascript",
        )
