"""JavaScript adapter for the shared app reverse-engineering framework."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from reveng.javascript.bundle_reverse_engineer import JavaScriptBundleReverseEngineer

from ..js_oracle_scorecard import compute_js_project_file_scorecard
from ..models import AppReverseEngineeringResult

_JS_SUFFIXES = {".js", ".cjs", ".mjs"}


def _project_recovered_root(output_dir: Path) -> Optional[Path]:
    project = Path(output_dir) / "project"
    if not project.is_dir():
        return None
    for path in project.rglob("*"):
        if path.is_file() and path.suffix.lower() in _JS_SUFFIXES:
            return project
    return None


def _collect_project_files(project_root: Path) -> List[Path]:
    return sorted(
        path
        for path in project_root.rglob("*")
        if path.is_file() and path.suffix.lower() in _JS_SUFFIXES
    )


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
        oracle_dir: Optional[str] = None,
        run_webcrack: bool = False,
        run_restringer: bool = False,
        run_wakaru: bool = False,
        run_js_deobfuscator: bool = False,
    ) -> AppReverseEngineeringResult:
        """Run bundle RE; attach filename-set scorecard when oracle_dir is usable.

        recovered_root is ``output_dir/project`` only (never specs/topic trees).
        """
        effective_deobfuscator = bool(run_deobfuscator or run_js_deobfuscator)
        engine = JavaScriptBundleReverseEngineer(
            skip_patterns=skip_patterns or [],
            max_snippets_per_topic=max_snippets,
            snippet_context=snippet_context,
            run_deobfuscator=effective_deobfuscator,
        )
        result = await engine.reverse_engineer_bundle(
            input_path,
            output_dir,
            input_root=input_root,
        )

        warnings = list(result.warnings)
        ralph_knobs: Dict[str, str] = {
            "run_deobfuscator": "requested" if effective_deobfuscator else "not_requested",
            "run_js_deobfuscator": "requested" if run_js_deobfuscator else "not_requested",
        }
        knob_flags = {
            "run_webcrack": run_webcrack,
            "run_restringer": run_restringer,
            "run_wakaru": run_wakaru,
        }
        for name, enabled in knob_flags.items():
            if enabled:
                ralph_knobs[name] = "unsupported"
                warnings.append(f"unsupported_ralph_knob:{name}")
            else:
                ralph_knobs[name] = "not_requested"

        primary_artifacts: Dict[str, Path] = {"normalized_bundle": result.normalized_bundle}
        if result.deep_deobfuscation_output:
            primary_artifacts["deobfuscated_bundle"] = result.deep_deobfuscation_output

        recovered_root = _project_recovered_root(Path(output_dir))
        recovered_paths: List[Path] = []
        if recovered_root is not None:
            primary_artifacts["reconstructed_project"] = recovered_root
            recovered_paths = _collect_project_files(recovered_root)

        metadata: Dict[str, Any] = {
            "obfuscation_types": result.obfuscation_types,
            "bundler_signals": result.bundler_signals,
            "dependency_candidates": result.dependency_candidates,
            "cli_flags": result.cli_flags,
            "slash_commands": result.slash_commands,
            "topic_match_counts": result.topic_match_counts,
            "ralph_knobs": ralph_knobs,
        }

        if oracle_dir is not None:
            oracle_path = Path(oracle_dir)
            if not oracle_path.exists():
                warnings.append("oracle_dir_missing")
            elif not oracle_path.is_dir():
                warnings.append("oracle_dir_invalid")
            else:
                scorecard = compute_js_project_file_scorecard(
                    oracle_path,
                    recovered_paths,
                    recovered_root=recovered_root,
                )
                if recovered_root is None:
                    notes = scorecard.get("notes") or []
                    if isinstance(notes, list):
                        if "no_recovered_project_files" not in notes:
                            notes.append("no_recovered_project_files")
                        scorecard["notes"] = notes
                    else:
                        scorecard["notes"] = f"{notes};no_recovered_project_files"
                metadata["benchmark_scorecard"] = scorecard

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
            warnings=warnings,
            metadata=metadata,
            primary_artifacts=primary_artifacts,
            source_count=1,
            source_language="javascript",
        )
