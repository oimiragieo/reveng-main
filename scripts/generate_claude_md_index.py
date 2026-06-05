#!/usr/bin/env python3
"""
Maintenance helper: regenerate per-folder `claude.md` breadcrumbs.

- `src/reveng/**/claude.md` — Python package map (AST top-level symbols).
- `tests/**/claude.md` — Pytest modules and `test_*` / `Test*` methods.
- `docs/**/claude.md` — Markdown and companion files.
- `examples/**/claude.md` — Examples and sample assets.
- Repository root `claude.md` — master index (this script rewrites it).

Run from repo root: python scripts/generate_claude_md_index.py
"""

from __future__ import annotations

import ast
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_REVENG = REPO_ROOT / "src" / "reveng"
TESTS_ROOT = REPO_ROOT / "tests"
DOCS_ROOT = REPO_ROOT / "docs"
EXAMPLES_ROOT = REPO_ROOT / "examples"
SCRIPTS_ROOT = REPO_ROOT / "scripts"
GITHUB_ROOT = REPO_ROOT / ".github"
TEST_SAMPLES_ROOT = REPO_ROOT / "test_samples"


def first_doc_line(node: ast.AST) -> str | None:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return None
    if (
        node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    ):
        text = node.body[0].value.value.strip().split("\n")[0].strip()
        return text[:240] if text else None
    return None


def module_summary(tree: ast.Module) -> str | None:
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        text = tree.body[0].value.value.strip().split("\n")[0].strip()
        return text[:400] if text else None
    return None


def top_level_symbols(
    tree: ast.Module,
) -> tuple[list[tuple[str, str, str | None]], list[tuple[str, str, str | None]]]:
    classes: list[tuple[str, str, str | None]] = []
    funcs: list[tuple[str, str, str | None]] = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            classes.append(("class", node.name, first_doc_line(node)))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
            funcs.append((prefix, node.name, first_doc_line(node)))
    return classes, funcs


def parse_py_file(path: Path) -> dict:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {"error": str(e), "summary": None, "classes": [], "funcs": []}
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return {"error": f"SyntaxError: {e}", "summary": None, "classes": [], "funcs": []}
    if not isinstance(tree, ast.Module):
        return {"error": "not a module", "summary": None, "classes": [], "funcs": []}
    classes, funcs = top_level_symbols(tree)
    return {
        "error": None,
        "summary": module_summary(tree),
        "classes": classes,
        "funcs": funcs,
    }


def parse_test_py(path: Path) -> dict:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {"error": str(e), "summary": None, "tests": []}
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return {"error": f"SyntaxError: {e}", "summary": None, "tests": []}
    if not isinstance(tree, ast.Module):
        return {"error": "not a module", "summary": None, "tests": []}
    summary = module_summary(tree)
    tests: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
            "test"
        ):
            tests.append(node.name + (" (async)" if isinstance(node, ast.AsyncFunctionDef) else ""))
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            for child in node.body:
                if isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef)
                ) and child.name.startswith("test"):
                    suffix = " (async)" if isinstance(child, ast.AsyncFunctionDef) else ""
                    tests.append(f"{node.name}.{child.name}{suffix}")
    tests.sort()
    return {"error": None, "summary": summary, "tests": tests}


def collect_reveng_dirs() -> list[Path]:
    py_files = sorted(SRC_REVENG.rglob("*.py"))
    dirs: set[Path] = set()
    for p in py_files:
        if "__pycache__" in p.parts:
            continue
        d = p.parent
        for _ in range(200):
            dirs.add(d)
            if d == SRC_REVENG:
                break
            parent = d.parent
            if parent == d:
                break
            d = parent
    dirs.add(SRC_REVENG)
    return sorted(dirs, key=lambda x: str(x).lower())


def list_direct_files(d: Path) -> Iterable[Path]:
    try:
        for p in sorted(d.iterdir(), key=lambda x: x.name.lower()):
            if p.name.startswith(".") or p.name == "claude.md":
                continue
            if p.is_file():
                yield p
    except OSError:
        return


def child_package_dirs(d: Path) -> list[str]:
    names: list[str] = []
    try:
        for p in sorted(d.iterdir(), key=lambda x: x.name.lower()):
            if p.is_dir() and not p.name.startswith(".") and p.name != "__pycache__":
                if any(p.glob("*.py")):
                    names.append(p.name)
    except OSError:
        pass
    return names


def rel_to_reveng(d: Path) -> str:
    return str(d.relative_to(SRC_REVENG)).replace("\\", "/")


def rel_to_repo(d: Path) -> str:
    return str(d.relative_to(REPO_ROOT)).replace("\\", "/")


def format_folder_doc(d: Path) -> str:
    rel = rel_to_repo(d)
    try:
        title = rel_to_reveng(d)
        if title == ".":
            title = "reveng (package root)"
    except ValueError:
        title = rel

    lines: list[str] = [
        f"# `claude.md` — `{title}`",
        "",
        f"**Repository path:** `{rel}/`",
        "",
        "Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.",
        "",
    ]

    subs = child_package_dirs(d)
    if subs and d != SRC_REVENG:
        lines.extend(["## Subpackages / subfolders (see each `claude.md`)", ""])
        for name in subs:
            lines.append(f"- `{name}/` — [`claude.md`]({name}/claude.md)")
        lines.append("")

    py_in_dir = sorted(
        [p for p in list_direct_files(d) if p.suffix == ".py"],
        key=lambda x: x.name.lower(),
    )
    other_files = sorted(
        [p for p in list_direct_files(d) if p.suffix != ".py"],
        key=lambda x: x.name.lower(),
    )

    if py_in_dir:
        lines.extend(["## Python modules", ""])
        for py in py_in_dir:
            info = parse_py_file(py)
            lines.append(f"### `{py.name}`")
            if info["error"]:
                lines.append(f"- **Parse note:** {info['error']}")
            if info["summary"]:
                lines.append(f"- **Summary:** {info['summary']}")
            if info["classes"]:
                lines.append("- **Classes:**")
                for _, name, doc in info["classes"]:
                    extra = f" — {doc}" if doc else ""
                    lines.append(f"  - `{name}`{extra}")
            if info["funcs"]:
                lines.append("- **Functions / coroutines:**")
                for kind, name, doc in info["funcs"]:
                    extra = f" — {doc}" if doc else ""
                    lines.append(f"  - `{kind} {name}()`{extra}")
            lines.append("")

    if other_files:
        lines.extend(["## Other files in this folder", ""])
        for f in other_files:
            lines.append(f"- `{f.name}`")
        lines.append("")

    if not py_in_dir and not other_files and not subs:
        lines.extend(["*(No direct files; see parent folder.)*", ""])

    lines.extend(
        [
            "---",
            "*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*",
            "",
        ]
    )
    return "\n".join(lines)


def collect_tests_dirs() -> list[Path]:
    if not TESTS_ROOT.is_dir():
        return []
    explicit = [
        TESTS_ROOT,
        TESTS_ROOT / "unit",
        TESTS_ROOT / "integration",
        TESTS_ROOT / "e2e",
        TESTS_ROOT / "performance",
        TESTS_ROOT / "poc",
        TESTS_ROOT / "security",
        TESTS_ROOT / "manual",
        TESTS_ROOT / "integration" / "test_web",
        TESTS_ROOT / "integration" / "test_tools",
    ]
    return [d for d in explicit if d.is_dir()]


def format_tests_folder_doc(d: Path) -> str:
    rel = rel_to_repo(d)
    title = str(d.relative_to(TESTS_ROOT)).replace("\\", "/") if d != TESTS_ROOT else "tests (root)"

    lines: list[str] = [
        f"# `claude.md` — `{title}`",
        "",
        f"**Repository path:** `{rel}/`",
        "",
        "Pytest layout: markers and heavy tools are gated in `pytest.ini`. **Parent index:** [`../claude.md`](../claude.md).",
        "",
    ]

    subdirs = []
    if d == TESTS_ROOT:
        for name in ("unit", "integration", "e2e", "performance", "poc", "security", "manual"):
            if (d / name).is_dir():
                subdirs.append(name)
        if subdirs:
            lines.extend(["## Test suites (subfolders)", ""])
            for name in subdirs:
                lines.append(f"- [`{name}/`]({name}/claude.md)")
            lines.append("")

    py_files = sorted(
        [p for p in list_direct_files(d) if p.suffix == ".py" and p.name != "claude.md"],
        key=lambda x: x.name.lower(),
    )
    other = sorted(
        [p for p in list_direct_files(d) if p.suffix != ".py"],
        key=lambda x: x.name.lower(),
    )

    if py_files:
        lines.extend(["## Python files", ""])
        for py in py_files:
            if py.name == "run_all_tests.py":
                lines.append(f"### `{py.name}`")
                lines.append("- **Role:** Legacy or helper test runner entrypoint.")
                lines.append("")
                continue
            info = parse_test_py(py)
            lines.append(f"### `{py.name}`")
            if info["error"]:
                lines.append(f"- **Parse note:** {info['error']}")
            if info["summary"]:
                lines.append(f"- **Summary:** {info['summary']}")
            if info["tests"]:
                lines.append(f"- **Tests ({len(info['tests'])}):**")
                for t in info["tests"][:80]:
                    lines.append(f"  - `{t}`")
                if len(info["tests"]) > 80:
                    lines.append(f"  - … *{len(info['tests']) - 80} more*")
            lines.append("")

    if other:
        lines.extend(["## Other files", ""])
        for f in other:
            lines.append(f"- `{f.name}`")
        lines.append("")

    lines.extend(
        [
            "---",
            "*Generated for AI navigation. Regenerate: `python scripts/generate_claude_md_index.py`.*",
            "",
        ]
    )
    return "\n".join(lines)


def first_nonblank_line(path: Path, max_bytes: int = 4000) -> str | None:
    try:
        raw = path.read_bytes()[:max_bytes].decode("utf-8", errors="replace")
    except OSError:
        return None
    for line in raw.splitlines():
        s = line.strip()
        if s:
            return s[:300]
    return None


def collect_docs_dirs() -> list[Path]:
    if not DOCS_ROOT.is_dir():
        return []
    dirs: set[Path] = set()
    for p in DOCS_ROOT.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".md", ".json", ".py"}:
            if "__pycache__" in p.parts:
                continue
            d = p.parent
            for _ in range(50):
                dirs.add(d)
                if d == DOCS_ROOT:
                    break
                parent = d.parent
                if parent == d:
                    break
                d = parent
    dirs.add(DOCS_ROOT)
    return sorted(dirs, key=lambda x: str(x).lower())


def format_docs_folder_doc(d: Path) -> str:
    rel = rel_to_repo(d)
    title = str(d.relative_to(DOCS_ROOT)).replace("\\", "/") if d != DOCS_ROOT else "docs (root)"

    lines: list[str] = [
        f"# `claude.md` — `{title}`",
        "",
        f"**Repository path:** `{rel}/`",
        "",
        "Documentation breadcrumb: files in this folder only (non-recursive).",
        "",
    ]

    child_dirs: list[str] = []
    try:
        for p in sorted(d.iterdir(), key=lambda x: x.name.lower()):
            if p.is_dir() and not p.name.startswith("."):
                child_dirs.append(p.name)
    except OSError:
        pass
    if child_dirs:
        lines.extend(["## Subfolders", ""])
        for name in child_dirs:
            lines.append(f"- [`{name}/`]({name}/claude.md)")
        lines.append("")

    files = sorted(list_direct_files(d), key=lambda x: (x.suffix.lower(), x.name.lower()))
    if files:
        lines.extend(["## Files", ""])
        for f in files:
            hint = ""
            if f.suffix.lower() in {".md", ".json"}:
                fl = first_nonblank_line(f)
                if fl:
                    hint = f" — {fl}"
            lines.append(f"- `{f.name}`{hint}")
        lines.append("")

    lines.extend(
        [
            "---",
            "*Generated for AI navigation. Regenerate: `python scripts/generate_claude_md_index.py`.*",
            "",
        ]
    )
    return "\n".join(lines)


def collect_examples_dirs() -> list[Path]:
    if not EXAMPLES_ROOT.is_dir():
        return []
    dirs: set[Path] = set()
    for p in EXAMPLES_ROOT.rglob("*"):
        if p.is_file():
            if "__pycache__" in p.parts:
                continue
            d = p.parent
            for _ in range(50):
                dirs.add(d)
                if d == EXAMPLES_ROOT:
                    break
                parent = d.parent
                if parent == d:
                    break
                d = parent
    dirs.add(EXAMPLES_ROOT)
    return sorted(dirs, key=lambda x: str(x).lower())


def format_examples_folder_doc(d: Path) -> str:
    rel = rel_to_repo(d)
    title = (
        str(d.relative_to(EXAMPLES_ROOT)).replace("\\", "/")
        if d != EXAMPLES_ROOT
        else "examples (root)"
    )

    lines: list[str] = [
        f"# `claude.md` — `{title}`",
        "",
        f"**Repository path:** `{rel}/`",
        "",
        "Runnable demos and narrative use cases. Prefer small fixtures in `test_samples/` for CI.",
        "",
    ]

    child_dirs: list[str] = []
    try:
        for p in sorted(d.iterdir(), key=lambda x: x.name.lower()):
            if p.is_dir() and not p.name.startswith("."):
                child_dirs.append(p.name)
    except OSError:
        pass
    if child_dirs:
        lines.extend(["## Subfolders", ""])
        for name in child_dirs:
            lines.append(f"- [`{name}/`]({name}/claude.md)")
        lines.append("")

    files = sorted(list_direct_files(d), key=lambda x: x.name.lower())
    if files:
        lines.extend(["## Files", ""])
        for f in files:
            hint = ""
            if f.suffix == ".py":
                info = parse_py_file(f)
                if info.get("summary"):
                    hint = f" — {info['summary']}"
            elif f.suffix == ".md":
                fl = first_nonblank_line(f)
                if fl:
                    hint = f" — {fl}"
            lines.append(f"- `{f.name}`{hint}")
        lines.append("")

    lines.extend(
        [
            "---",
            "*Generated for AI navigation. Regenerate: `python scripts/generate_claude_md_index.py`.*",
            "",
        ]
    )
    return "\n".join(lines)


def write_src_claude() -> Path:
    text = "\n".join(
        [
            "# `claude.md` — `src/`",
            "",
            "**Repository path:** `src/`",
            "",
            "Installable Python sources. The only production package is **`reveng`** under this directory.",
            "",
            "## Contents",
            "",
            "- **[`reveng/`](reveng/claude.md)** — full platform implementation (CLI, analyzers, pipelines, tools, MCP servers).",
            "",
            "---",
            "*See master [`claude.md`](../claude.md) at repository root.*",
            "",
        ]
    )
    out = REPO_ROOT / "src" / "claude.md"
    out.write_text(text, encoding="utf-8")
    return out


def write_scripts_claude() -> Path:
    files = sorted(
        [p for p in SCRIPTS_ROOT.iterdir() if p.is_file() and p.name != "claude.md"],
        key=lambda x: x.name.lower(),
    )
    lines = [
        "# `claude.md` — `scripts/`",
        "",
        "**Repository path:** `scripts/`",
        "",
        "Maintenance and CI helper scripts (not part of the `reveng` import graph unless documented).",
        "",
        "## Files",
        "",
    ]
    for f in files:
        if f.suffix == ".py":
            info = parse_py_file(f)
            extra = f" — {info['summary']}" if info.get("summary") else ""
            lines.append(f"- `{f.name}`{extra}")
        else:
            lines.append(f"- `{f.name}`")
    lines.extend(
        [
            "",
            "---",
            "*Regenerate breadcrumbs: `python scripts/generate_claude_md_index.py`.*",
            "",
        ]
    )
    out = SCRIPTS_ROOT / "claude.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def collect_github_dirs() -> list[Path]:
    if not GITHUB_ROOT.is_dir():
        return []
    candidates = [
        GITHUB_ROOT,
        GITHUB_ROOT / "workflows",
        GITHUB_ROOT / "ISSUE_TEMPLATE",
    ]
    return [d for d in candidates if d.is_dir()]


def format_github_folder_doc(d: Path) -> str:
    rel = rel_to_repo(d)
    title = (
        str(d.relative_to(GITHUB_ROOT)).replace("\\", "/") if d != GITHUB_ROOT else ".github (root)"
    )

    lines: list[str] = [
        f"# `claude.md` — `{title}`",
        "",
        f"**Repository path:** `{rel}/`",
        "",
        "GitHub metadata: CI workflows, issue templates, and release notes for maintainers.",
        "",
    ]

    child_dirs: list[str] = []
    try:
        for p in sorted(d.iterdir(), key=lambda x: x.name.lower()):
            if p.is_dir() and not p.name.startswith("."):
                child_dirs.append(p.name)
    except OSError:
        pass
    if child_dirs and d == GITHUB_ROOT:
        lines.extend(["## Subfolders", ""])
        for name in child_dirs:
            if (d / name).is_dir():
                lines.append(f"- [`{name}/`]({name}/claude.md)")
        lines.append("")

    exts = {".md", ".yml", ".yaml"}
    files = sorted(
        [p for p in list_direct_files(d) if p.suffix.lower() in exts or p.name == "dependabot.yml"],
        key=lambda x: x.name.lower(),
    )
    if files:
        lines.extend(["## Files", ""])
        for f in files:
            fl = first_nonblank_line(f) if f.suffix.lower() == ".md" else None
            hint = f" — {fl}" if fl else ""
            lines.append(f"- `{f.name}`{hint}")
        lines.append("")

    lines.extend(
        [
            "---",
            "*Generated for AI navigation. Regenerate: `python scripts/generate_claude_md_index.py`.*",
            "",
        ]
    )
    return "\n".join(lines)


def write_test_samples_claude() -> Path | None:
    if not TEST_SAMPLES_ROOT.is_dir():
        return None
    lines = [
        "# `claude.md` — `test_samples/`",
        "",
        "**Repository path:** `test_samples/`",
        "",
        "Small fixtures used by tests and docs (not production code). See [`README.md`](README.md) for intent.",
        "",
        "## Layout (recursive overview)",
        "",
    ]
    for p in sorted(TEST_SAMPLES_ROOT.rglob("*"), key=lambda x: str(x).lower()):
        if p.is_dir() or p.name == "claude.md":
            continue
        rel = p.relative_to(TEST_SAMPLES_ROOT).as_posix()
        lines.append(f"- `{rel}`")
    lines.extend(
        [
            "",
            "---",
            "*Regenerate related indexes: `python scripts/generate_claude_md_index.py`.*",
            "",
        ]
    )
    out = TEST_SAMPLES_ROOT / "claude.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def write_master_claude() -> Path:
    lines: list[str] = [
        "# CLAUDE.md",
        "",
        "This file provides guidance to Claude Code (claude.ai/code) when working with code in "
        "this repository. The hand-written guidance below is emitted by "
        "`scripts/generate_claude_md_index.py`; the machine-derived navigation index follows it.",
        "",
        "REVENG is a large, beta Python reverse-engineering platform (`reveng`, version `4.0.0`). "
        "Real core: the CLI, MCP servers, Ghidra integration, the app reverse-engineering adapters, "
        "and the Verified Recompilation Loop (VRL). Treat advanced claims (exploit gen, full "
        "binary↔source equivalence, broad JS deobfuscation) as experimental until verified on a "
        "tracked corpus. Keep behavior changes tied to tests.",
        "",
        "## Commands",
        "",
        "`src/` layout (`src/reveng/`), Python 3.9+. Config in `pyproject.toml`; task shortcuts in "
        "the `Makefile`; contributor conventions in `AGENTS.md`.",
        "",
        "```bash",
        "make install-dev                 # runtime + dev + java deps",
        "pip install -e . --no-deps       # editable install (required for import-linter / grimp)",
        "",
        "# Entry points (there is NO repo-root reveng.py; that launcher was removed):",
        "reveng --help                    # main CLI            (reveng.cli:main)",
        "reveng-app --help                # app reverse-eng     (reveng.app_reverse_engineering.cli)",
        "reveng-js --help                 # JS analysis         (reveng.javascript.cli)",
        "python -m reveng --help          # module entry        (reveng.__main__)",
        "python src/reveng/cli/reveng.py --help   # source-tree wrapper (self-bootstraps sys.path)",
        "",
        "# Tests (coverage auto-added via pyproject addopts; use --no-cov to skip)",
        "make test                        # full suite",
        "pytest tests/unit/test_foo.py::TestX::test_y      # a single test",
        'pytest -m "not requires_external_tools and not slow and not requires_network"',
        "# Markers: poc, slow, integration, unit, requires_external_tools, requires_network",
        "",
        "# Lint / format (black & isort at 100 cols)",
        "make format                      # black + isort (writes)",
        "make lint                        # black/isort/pylint/mypy + lint-imports (architecture) + hadolint",
        "lint-imports --no-cache          # import-linter architecture contracts (.importlinter)",
        "```",
        "",
        "## Architecture (the big picture)",
        "",
        "**Three surfaces over one package.** Analysis logic is exposed through (a) the CLI "
        "(`reveng.cli`, plus `reveng-app`/`reveng-js`), (b) a Python API (`reveng.api`), and (c) MCP "
        "servers (`reveng.agent_sdk.mcp.servers`). Outputs carry versioned validation/evidence/"
        "provenance contracts (`reveng.core.result_contracts`).",
        "",
        "**Domain layout (enforced by import-linter; see `.importlinter`):**",
        "",
        "- `reveng.core` — foundation layer: exceptions, error codes, validation, config, the shared "
        "`result_contracts`, the `ir` (VRL IR), and `ai_models` (shared AI data models). Must not "
        "import any higher-level domain (the `core-is-foundation` contract).",
        "- `reveng.analysis` — binary/source analysis: `analyzer` (REVENGAnalyzer), `pe`, `native`, "
        "`lifting`, `devirtualization`, `deobfuscation`, `diffing`, `analyzers`.",
        "- `reveng.cli` — a real package (was a 1900-line `cli.py`); `reveng.cli:main` is the console "
        "entry; `cli/reveng.py` is the source-tree wrapper.",
        "- `reveng.security` must not import `reveng.ai`/`reveng.agents.ai` (the cycle was broken by "
        "moving shared models to `reveng.core.ai_models`; enforced contract).",
        "- AI providers live in `reveng.agents.ai` (`ai_provider_registry` → `get_analyzer`, "
        "`anthropic`/`openai`/`ollama`/`claude_cli` analyzers, `ai_enhanced_orchestrator`).",
        "",
        "**Verified Recompilation Loop (VRL) — the flagship.** `reveng.verification.refinement."
        "refiner.IterativeRefiner` drives decompile → compile → differentially-verify → LLM-refine to "
        "convergence. It is dependency-injected (analyzer / compile_fn / oracle_factory). The "
        "differential oracle passes corpus seed tokens as **argv** (not stdin) and records a real "
        "`ValidationGrade` into `.reveng/benchmarks/corpus.yaml`. Runner: `scripts/run_vrl.py` "
        "(`REVENG_AI_PROVIDER`=ollama|anthropic|openai; ollama is local/free).",
        "",
        "**App reverse-engineering** (`reveng.app_reverse_engineering`) dispatches JS/JVM/Python/.NET "
        "inputs to language adapters; it is the corpus-gated, most mature multi-language path.",
        "",
        "**Generated/vendored, do not edit or lint:** `analysis_*/`, `reports/`, `external/ghidra*/`. "
        "Regenerate these breadcrumbs after refactors: `python scripts/generate_claude_md_index.py`.",
        "",
        "## Navigation index",
        "",
        "Each major folder also contains a `claude.md` listing its files and (for Python) top-level "
        "symbols. Start at the area below that matches your task, then drill into subfolders.",
        "",
        "## Repository map",
        "",
        "| Area | Role | Breadcrumb |",
        "|------|------|--------------|",
        "| `src/reveng/` | Core Python package (analyzers, CLI, tools, MCP) | [`src/reveng/claude.md`](src/reveng/claude.md) |",
        "| `src/` | Source tree wrapper | [`src/claude.md`](src/claude.md) |",
        "| `tests/` | Pytest suites | [`tests/claude.md`](tests/claude.md) |",
        "| `docs/` | MkDocs / architecture / API docs | [`docs/claude.md`](docs/claude.md) |",
        "| `examples/` | Demos and use-case writeups | [`examples/claude.md`](examples/claude.md) |",
        "| `scripts/` | Repo maintenance scripts | [`scripts/claude.md`](scripts/claude.md) |",
        "| `.github/` | CI workflows and templates | [`.github/claude.md`](.github/claude.md) |",
        "| `test_samples/` | Small fixtures for tests | [`test_samples/claude.md`](test_samples/claude.md) |",
        "| `AGENTS.md` | Contributor conventions | [`AGENTS.md`](AGENTS.md) |",
        "",
        "## `src/reveng` — grouped `claude.md` index",
        "",
    ]

    crumbs = sorted(
        SRC_REVENG.rglob("claude.md"), key=lambda p: str(p.relative_to(SRC_REVENG)).lower()
    )
    groups: dict[str, list[str]] = defaultdict(list)
    for p in crumbs:
        rel = p.relative_to(SRC_REVENG).as_posix()
        parts = rel.split("/")
        if len(parts) == 1:
            key = "(package root)"
        else:
            key = parts[0]
        groups[key].append(rel)

    for key in sorted(groups.keys(), key=lambda k: (k == "(package root)", k.lower())):
        lines.append(f"### `{key}`")
        lines.append("")
        for rel in sorted(groups[key]):
            lines.append(f"- [`{rel}`](src/reveng/{rel})")
        lines.append("")

    lines.extend(
        [
            "## `tests` — `claude.md` index",
            "",
        ]
    )
    if TESTS_ROOT.is_dir():
        test_crumbs = sorted(
            TESTS_ROOT.rglob("claude.md"), key=lambda p: str(p.relative_to(TESTS_ROOT)).lower()
        )
        for p in test_crumbs:
            rel = p.relative_to(REPO_ROOT).as_posix()
            lines.append(f"- [`{rel}`]({rel})")
    else:
        lines.append("- *(no `tests/` directory)*")
    lines.append("")

    lines.extend(
        [
            "## `docs` — `claude.md` index",
            "",
        ]
    )
    if DOCS_ROOT.is_dir():
        doc_crumbs = sorted(
            DOCS_ROOT.rglob("claude.md"), key=lambda p: str(p.relative_to(DOCS_ROOT)).lower()
        )
        for p in doc_crumbs:
            rel = p.relative_to(REPO_ROOT).as_posix()
            lines.append(f"- [`{rel}`]({rel})")
    else:
        lines.append("- *(no `docs/` directory)*")
    lines.append("")

    lines.extend(
        [
            "## `examples` — `claude.md` index",
            "",
        ]
    )
    if EXAMPLES_ROOT.is_dir():
        ex_crumbs = sorted(
            EXAMPLES_ROOT.rglob("claude.md"),
            key=lambda p: str(p.relative_to(EXAMPLES_ROOT)).lower(),
        )
        for p in ex_crumbs:
            rel = p.relative_to(REPO_ROOT).as_posix()
            lines.append(f"- [`{rel}`]({rel})")
    else:
        lines.append("- *(no `examples/` directory)*")
    lines.append("")

    lines.extend(
        [
            "## `.github` — `claude.md` index",
            "",
        ]
    )
    if GITHUB_ROOT.is_dir():
        gh_crumbs = sorted(
            GITHUB_ROOT.rglob("claude.md"), key=lambda p: str(p.relative_to(GITHUB_ROOT)).lower()
        )
        for p in gh_crumbs:
            rel = p.relative_to(REPO_ROOT).as_posix()
            lines.append(f"- [`{rel}`]({rel})")
    else:
        lines.append("- *(no `.github/` directory)*")
    lines.append("")

    lines.extend(
        [
            "## `test_samples`",
            "",
            "- [`test_samples/claude.md`](test_samples/claude.md)",
            "",
        ]
    )

    lines.extend(
        [
            "---",
            "Human-oriented contributor guide: **`AGENTS.md`**. Generated breadcrumbs: run `python scripts/generate_claude_md_index.py`.",
            "",
        ]
    )
    out = REPO_ROOT / "claude.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def write_all_reveng_claude() -> list[Path]:
    written: list[Path] = []
    for d in collect_reveng_dirs():
        out = d / "claude.md"
        out.write_text(format_folder_doc(d), encoding="utf-8")
        written.append(out)
    return written


def main() -> int:
    if not SRC_REVENG.is_dir():
        print("Expected src/reveng to exist", file=sys.stderr)
        return 1
    paths = write_all_reveng_claude()
    print(f"Wrote {len(paths)} claude.md files under src/reveng")

    for d in collect_tests_dirs():
        (d / "claude.md").write_text(format_tests_folder_doc(d), encoding="utf-8")
    print(f"Wrote tests breadcrumbs in {len(collect_tests_dirs())} folders")

    for d in collect_docs_dirs():
        (d / "claude.md").write_text(format_docs_folder_doc(d), encoding="utf-8")
    print(f"Wrote {len(collect_docs_dirs())} docs claude.md files")

    for d in collect_examples_dirs():
        (d / "claude.md").write_text(format_examples_folder_doc(d), encoding="utf-8")
    print(f"Wrote {len(collect_examples_dirs())} examples claude.md files")

    src_doc = write_src_claude()
    print(f"Wrote {src_doc.relative_to(REPO_ROOT)}")

    scripts_doc = write_scripts_claude()
    print(f"Wrote {scripts_doc.relative_to(REPO_ROOT)}")

    for d in collect_github_dirs():
        (d / "claude.md").write_text(format_github_folder_doc(d), encoding="utf-8")
    print(f"Wrote {len(collect_github_dirs())} .github claude.md files")

    ts = write_test_samples_claude()
    if ts:
        print(f"Wrote {ts.relative_to(REPO_ROOT)}")

    master = write_master_claude()
    print(f"Wrote {master.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
