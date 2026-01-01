# Docker Deployment Guide

This guide covers deploying REVENG using Docker containers.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose v2.0+ (optional)
- 4GB+ RAM available

## Quick Start

### Build and Run

```bash
# Clone repository
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main

# Build Docker image
docker build -t reveng:latest .

# Run analysis
docker run -it --rm \
  -e GEMINI_API_KEY="${GEMINI_API_KEY}" \
  -v $(pwd)/samples:/app/samples \
  -v $(pwd)/results:/app/results \
  reveng:latest analyze /app/samples/binary.exe
```

## Docker Images

### Main REVENG Image

The main `Dockerfile` provides the complete REVENG toolkit:

```dockerfile
# Build
docker build -t reveng:latest .

# Run CLI
docker run -it reveng:latest reveng --help

# Run analysis
docker run -v /path/to/binary:/app/binary.exe reveng:latest analyze /app/binary.exe
```

### MCP Server Image

The `Dockerfile.mcp` provides the MCP server for AI integration:

```dockerfile
# Build
docker build -f Dockerfile.mcp -t reveng-mcp:latest .

# Run server (stdio transport)
docker run -it reveng-mcp:latest

# Run server (HTTP transport)
docker run -p 8080:8080 reveng-mcp:latest --transport http --port 8080
```

## Docker Compose

Use `docker-compose.yml` for multi-service deployment:

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GEMINI_API_KEY` | Google Gemini API key | Yes |
| `ANTHROPIC_API_KEY` | Anthropic Claude API key | Optional |
| `OPENAI_API_KEY` | OpenAI GPT-4 API key | Optional |
| `OLLAMA_HOST` | Ollama server URL | Optional |
| `VT_API_KEY` | VirusTotal API key | Optional |

## Volume Mounts

Recommended volume mounts for persistence:

```bash
docker run -it \
  -v $(pwd)/samples:/app/samples:ro \      # Input binaries (read-only)
  -v $(pwd)/results:/app/results \         # Analysis results
  -v $(pwd)/cache:/app/cache \             # Cache for performance
  -v $(pwd)/models:/app/models:ro \        # ML models (read-only)
  reveng:latest analyze /app/samples/binary.exe
```

## Health Checks

The MCP server includes health check endpoints:

```bash
# Check health
curl http://localhost:8080/health

# Expected response
{"status": "healthy", "version": "4.0.0"}
```

## Production Recommendations

1. **Use specific tags** instead of `:latest`
2. **Set resource limits** with `--memory` and `--cpus`
3. **Use secrets management** for API keys
4. **Enable logging** with `--log-driver`
5. **Configure networking** with custom networks

## Troubleshooting

### Container won't start
```bash
# Check logs
docker logs <container-id>

# Check resource usage
docker stats
```

### API key issues
```bash
# Verify environment variable
docker run -it reveng:latest env | grep API_KEY
```

---

*Docker deployment guide for REVENG v4.0*
