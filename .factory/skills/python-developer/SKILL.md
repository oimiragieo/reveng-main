---
name: python-developer
description: Core Python developer for the REVENG RE platform mission.
---

# Python Developer

NOTE: Startup and cleanup are handled by `worker-base`. This skill defines the WORK PROCEDURE.

## When to Use This Skill

Use this skill to implement all features in the REVENG production-grade reverse engineering platform, including Ghidra integration, MCP tools, Ollama LLM integration, Docker sandbox, YARA scanning, Volatility3 memory forensics, and test suite repairs.

## Work Procedure

1. Read the feature description and constraints from `mission.md` and `AGENTS.md`. Read the relevant `.factory/library/` files for architecture context.

2. **Windows environment setup** (do NOT run init.sh on Windows): Run `python -m pip install yara-python ollama volatility3 pytest-xdist` if these are not yet installed. Check with `python -c "import yara, ollama, volatility3"`.

3. Run the scoped baseline: `pytest tests/unit/ tests/integration/ tests/performance -n 4 --ignore=tests/poc`. If failures match the documented pre-existing list in `AGENTS.md`, document them and continue. Do NOT stop because the baseline is red from pre-existing failures.

4. **Write tests first (red)**. Add test cases to the appropriate file in `tests/unit/` or `tests/integration/`. Run targeted tests to confirm they fail. **TDD exception**: if implementation already exists, add tests and verify they pass.

5. Implement the feature in `src/reveng/...`. Key rules:
   - NEVER return mock data silently from Ghidra — raise `GhidraUnavailableError`
   - Use `ollama` Python package for Ollama calls (model: `qwen2.5-coder:32b-instruct`)
   - YARA rules go in `src/reveng/security/yara_rules/*.yar`, loaded by `YARAScanner`
   - Docker sandbox must check `os.environ.get('SKIP_SANDBOX')` and return graceful result if set
   - Volatility3 must check `os.environ.get('SKIP_VOLATILITY')` and return graceful result if set

6. Run targeted pytest for your feature. Then run `flake8 src/reveng/<changed_files> --extend-ignore=E501,F811,E203`.

7. For features involving Ghidra: start the server first (`python external/ghidra-server/ghidra_http_server.py`) and confirm `/health` returns `{"ghidra_available": true}`.

8. For features involving Ollama: verify `curl http://localhost:11434/api/tags` lists `qwen2.5-coder:32b-instruct`.

9. Manual verification: exercise the feature end-to-end with `test_samples/sample.exe` and confirm the output matches expected behavior from the feature description.

10. Provide a thorough handoff.

## Example Handoff

```json
{
  "salientSummary": "Implemented GhidraEngine.decompile() method that calls the HTTP server's /decompile endpoint; installed yara-python and ollama packages; added them to requirements.txt. All 4 new tests pass. Verified end-to-end: decompile() returns real C pseudocode with 214 functions from sample.exe.",
  "whatWasImplemented": "Added GhidraEngine.decompile(binary_path) in src/reveng/integrations/ghidra/ghidra_engine.py. Installed yara-python==4.5.2 and ollama==0.5.1. Updated requirements.txt. Created tests/unit/test_critical_bugs.py with 4 test cases.",
  "whatWasLeftUndone": "",
  "verification": {
    "commandsRun": [
      {
        "command": "python -c \"import yara; print(yara.__version__)\"",
        "exitCode": 0,
        "observation": "Printed 4.5.2 — yara-python installed successfully."
      },
      {
        "command": "python -c \"import ollama; print('ok')\"",
        "exitCode": 0,
        "observation": "ollama package importable."
      },
      {
        "command": "pytest tests/unit/test_critical_bugs.py -v",
        "exitCode": 0,
        "observation": "4/4 tests passed."
      },
      {
        "command": "flake8 src/reveng/integrations/ghidra/ghidra_engine.py --extend-ignore=E501,F811,E203",
        "exitCode": 0,
        "observation": "No lint violations."
      }
    ],
    "interactiveChecks": [
      {
        "action": "Started Ghidra HTTP server and called decompile() on test_samples/sample.exe",
        "observed": "Returned dict with 214 functions; functions[0]['source'] had 847 chars of C pseudocode."
      }
    ]
  },
  "tests": {
    "added": [
      {
        "file": "tests/unit/test_critical_bugs.py",
        "cases": [
          {"name": "test_ghidra_engine_has_decompile_method", "verifies": "GhidraEngine.decompile() attribute exists"},
          {"name": "test_yara_importable", "verifies": "yara package importable"},
          {"name": "test_ollama_importable", "verifies": "ollama package importable"},
          {"name": "test_decompile_returns_dict_not_attributeerror", "verifies": "decompile() does not raise AttributeError"}
        ]
      }
    ]
  },
  "discoveredIssues": []
}
```

## When to Return to Orchestrator

- Ghidra download fails (network issue, GitHub rate limit) — orchestrator needs to provide an alternative
- Ollama is not running or the `qwen2.5-coder:32b-instruct` model is not available
- Docker daemon not running when implementing sandbox feature
- Feature requires modifying `external/ghidra/` source code (not allowed — return to orchestrator)
- Existing bugs in unrelated code block your feature from working
- Baseline test command is broken in a new way not in the AGENTS.md pre-existing list
