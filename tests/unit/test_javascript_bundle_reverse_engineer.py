"""Tests for the JavaScript bundle reverse-engineering workflow."""

from __future__ import annotations

import asyncio
from pathlib import Path

from reveng.javascript.bundle_reverse_engineer import (
    TOPIC_DEFINITIONS,
    JavaScriptBundleReverseEngineer,
)
from reveng.javascript.cli import CLI


def test_cli_parser_accepts_reverse_engineer_bundle_command():
    parser = CLI().parser

    args = parser.parse_args(
        [
            "reverse-engineer-bundle",
            "sample.js",
            "-o",
            "analysis_out",
            "--skip-pattern",
            "sentry",
            "--max-snippets",
            "5",
        ]
    )

    assert args.command == "reverse-engineer-bundle"
    assert args.input == "sample.js"
    assert args.output_dir == "analysis_out"
    assert args.skip_pattern == ["sentry"]
    assert args.max_snippets == 5


def test_reverse_engineer_bundle_generates_specs_and_filters_skipped_patterns(tmp_path: Path):
    install_root = tmp_path / "claude-code"
    (install_root / "bin").mkdir(parents=True)
    (install_root / "vendor").mkdir(parents=True)
    (install_root / "bin" / "rg.exe").write_text("binary placeholder", encoding="utf-8")
    (install_root / "vendor" / "manifest.json").write_text("{}", encoding="utf-8")

    bundle_path = install_root / "cli.js"
    bundle_path.write_text(
        """
        const configPath = ".claude/settings.json";
        const statePath = ".claude/state.db";
        const promptLibrary = { systemPrompt: "You are a coding agent", review: "/review", init: "/init" };
        const endpoint = "https://api.example.com/mcp";
        const pkg = "@anthropic-ai/sdk";
        const telemetryLabel = "telemetry";
        const flagA = "--verbose";
        const flagB = "--dangerously-skip-permissions";
        function runTool(name, args) { return spawn("bash", args); }
        function runCommand() { return process.argv.includes("--verbose"); }
        function initTelemetry() { logger.debug("telemetry enabled"); }
        function ignoredTelemetry() { Sentry.init({ dsn: "https://sentry.example" }); }
        module.exports = { runTool, runCommand, promptLibrary, endpoint, configPath, statePath, pkg, flagA, flagB };
        """,
        encoding="utf-8",
    )

    output_dir = tmp_path / "analysis_output"
    engine = JavaScriptBundleReverseEngineer(
        skip_patterns=["sentry"],
        max_snippets_per_topic=4,
        snippet_context=1,
        run_deobfuscator=False,
    )
    result = asyncio.run(
        engine.reverse_engineer_bundle(
            str(bundle_path),
            str(output_dir),
            input_root=str(install_root),
        )
    )

    assert result.normalized_bundle.exists()
    assert result.analysis_file.exists()
    assert len(result.topic_files) == len(TOPIC_DEFINITIONS)
    assert len(result.domain_files) == len(TOPIC_DEFINITIONS)
    assert "--verbose" in result.cli_flags
    assert "/init" in result.slash_commands

    specs_index = (result.specs_dir / "README.md").read_text(encoding="utf-8")
    structure_doc = (result.specs_dir / "00-directory-structure.md").read_text(encoding="utf-8")
    cli_spec = result.topic_files["cli_surface"].read_text(encoding="utf-8")
    observability_spec = result.topic_files["observability_and_telemetry"].read_text(
        encoding="utf-8"
    )

    assert "Specification Library" in specs_index
    assert "`bin/`" in structure_doc
    assert "--dangerously-skip-permissions" in cli_spec
    assert "telemetry enabled" in observability_spec
    assert "Sentry.init" not in cli_spec
    assert "Sentry.init" not in observability_spec
