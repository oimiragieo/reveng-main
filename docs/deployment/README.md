# Deployment Notes

REVENG can be run locally from source, containerized for repeatable analysis, or exposed as an MCP-capable service when needed.

## Local First

For most contributors and researchers, local source execution is the default deployment model:

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
reveng analyze sample.exe
```

## Docker

If you want isolated execution, build from the repository root:

```bash
docker build -t reveng:latest .
docker run --rm -it reveng:latest reveng --version
```

For analysis workloads, mount input and output directories explicitly.

## Ghidra-backed Services

Native decompilation and reconstruction workflows depend on the local Ghidra HTTP service:

```bash
python scripts/install_ghidra.py
python external/ghidra-server/ghidra_http_server.py
```

Default endpoint: `http://127.0.0.1:13370`

## MCP Deployment

The detailed MCP operational guide remains in [docs/mcp/README.md](../mcp/README.md). Use that document for agent integration, transport choice, and production-facing MCP setup.

## Production Checklist

- install dependencies in a clean environment
- provide API keys only for the providers you actually use
- start Ghidra separately if native workflows need it
- persist analysis output directories outside ephemeral containers
- validate the CLI (`reveng --version`) and a representative analysis before rollout

## Related Docs

- [Getting Started](../getting-started/installation.md)
- [Architecture Overview](../architecture/overview.md)
- [MCP Guide](../mcp/README.md)
