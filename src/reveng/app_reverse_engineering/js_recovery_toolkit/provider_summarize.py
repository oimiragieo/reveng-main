"""Real LLM summarize providers for AST-chunked module digests.

Tries OpenAI-compatible local endpoint (omega-local :8000), then Ollama,
then Anthropic — never dumps the full bundle. Falls back to heuristic.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Callable, List, Optional, Tuple

from .llm_digest import SummarizeFn, heuristic_summarize_fn

_DEFAULT_OPENAI_BASE = "http://127.0.0.1:8000/v1"
_DEFAULT_OLLAMA = "http://127.0.0.1:11434"


def _http_json(
    url: str, payload: dict, *, timeout_s: float = 120.0, headers: Optional[dict] = None
) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _prompt(path: str, body: str) -> str:
    return (
        "Summarize this JavaScript/TypeScript module in 1-2 sentences. "
        "List 5-10 lowercase snake_case topic tags (APIs, domain, side-effects). "
        "Do not invent file paths. Variable names may be minified — infer from strings and calls.\n\n"
        f"PATH: {path}\n"
        f"CODE:\n{body}\n"
    )


def openai_compat_summarize(
    path: str,
    body: str,
    *,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
    timeout_s: float = 90.0,
) -> str:
    base = (base_url or os.environ.get("REVENG_LLM_BASE") or _DEFAULT_OPENAI_BASE).rstrip("/")
    model_name = model or os.environ.get("REVENG_LLM_MODEL") or "gpt-oss-20b"
    url = f"{base}/chat/completions"
    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": "You are a concise code reverse-engineering assistant."},
            {"role": "user", "content": _prompt(path, body)},
        ],
        "temperature": 0.1,
        "max_tokens": 250,
    }
    headers = {}
    key = os.environ.get("OPENAI_API_KEY") or os.environ.get("REVENG_LLM_API_KEY")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    result = _http_json(url, payload, timeout_s=timeout_s, headers=headers)
    choices = result.get("choices") or []
    if not choices:
        raise RuntimeError("empty_choices")
    msg = choices[0].get("message") or {}
    content = msg.get("content") or ""
    if not str(content).strip():
        raise RuntimeError("empty_content")
    return str(content).strip()


def ollama_summarize(
    path: str,
    body: str,
    *,
    host: Optional[str] = None,
    model: Optional[str] = None,
    timeout_s: float = 90.0,
) -> str:
    host_u = (host or os.environ.get("REVENG_OLLAMA_HOST") or _DEFAULT_OLLAMA).rstrip("/")
    model_name = model or os.environ.get("REVENG_OLLAMA_MODEL") or "phi"
    payload = {
        "model": model_name,
        "prompt": _prompt(path, body),
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 250},
    }
    result = _http_json(f"{host_u}/api/generate", payload, timeout_s=timeout_s)
    text = result.get("response") or ""
    if not str(text).strip():
        raise RuntimeError("empty_ollama_response")
    return str(text).strip()


def anthropic_summarize(
    path: str,
    body: str,
    *,
    model: Optional[str] = None,
    timeout_s: float = 90.0,
) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY_absent")
    model_name = model or os.environ.get("ANTHROPIC_MODEL") or "claude-sonnet-4-20250514"
    payload = {
        "model": model_name,
        "max_tokens": 250,
        "messages": [{"role": "user", "content": _prompt(path, body)}],
    }
    result = _http_json(
        "https://api.anthropic.com/v1/messages",
        payload,
        timeout_s=timeout_s,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    parts = result.get("content") or []
    texts = [p.get("text", "") for p in parts if isinstance(p, dict)]
    text = "\n".join(t for t in texts if t)
    if not text.strip():
        raise RuntimeError("empty_anthropic_response")
    return text.strip()


def build_summarize_fn(
    *,
    prefer: Optional[str] = None,
    allow_heuristic_fallback: bool = True,
) -> Tuple[SummarizeFn, List[str]]:
    """Return (fn, notes). Prefer: openai_compat | ollama | anthropic | heuristic."""
    order = []
    pref = (prefer or os.environ.get("REVENG_AI_PROVIDER") or "openai_compat").strip().lower()
    if pref in {"openai", "openai_compat", "local", "omega", "gemma"}:
        order = ["openai_compat", "ollama", "anthropic"]
    elif pref == "ollama":
        order = ["ollama", "openai_compat", "anthropic"]
    elif pref in {"anthropic", "claude"}:
        order = ["anthropic", "openai_compat", "ollama"]
    else:
        order = ["openai_compat", "ollama", "anthropic"]

    notes: List[str] = [f"prefer:{pref}", f"order:{','.join(order)}"]
    chosen: List[str] = []

    def _fn(path: str, body: str) -> str:
        errors = []
        for name in order:
            try:
                if name == "openai_compat":
                    text = openai_compat_summarize(path, body)
                elif name == "ollama":
                    text = ollama_summarize(path, body)
                else:
                    text = anthropic_summarize(path, body)
                if name not in chosen:
                    chosen.append(name)
                    notes.append(f"used:{name}")
                return text
            except Exception as exc:
                errors.append(f"{name}:{type(exc).__name__}")
                continue
        if allow_heuristic_fallback:
            notes.append("fallback_heuristic")
            notes.append("errors:" + "|".join(errors[:6]))
            return heuristic_summarize_fn(path, body)
        raise RuntimeError("all_providers_failed:" + "|".join(errors))

    return _fn, notes


def probe_providers() -> dict:
    """Lightweight reachability probe (no model generate)."""
    out = {
        "openai_compat": False,
        "ollama": False,
        "anthropic_key": bool(os.environ.get("ANTHROPIC_API_KEY")),
    }
    try:
        base = (os.environ.get("REVENG_LLM_BASE") or _DEFAULT_OPENAI_BASE).rstrip("/")
        with urllib.request.urlopen(f"{base}/models", timeout=2) as resp:
            out["openai_compat"] = resp.status == 200
    except Exception:
        pass
    try:
        host = (os.environ.get("REVENG_OLLAMA_HOST") or _DEFAULT_OLLAMA).rstrip("/")
        with urllib.request.urlopen(f"{host}/api/tags", timeout=2) as resp:
            out["ollama"] = resp.status == 200
    except Exception:
        pass
    return out
