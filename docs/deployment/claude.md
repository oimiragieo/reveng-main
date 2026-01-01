# Deployment Directory Documentation

## Overview

The `docs/deployment/` directory contains deployment documentation for REVENG in production environments.

**Purpose**: Production deployment guides for Docker, Kubernetes, and cloud providers
**Location**: `/home/user/reveng-main/docs/deployment/`

## Directory Contents

```
docs/deployment/
├── README.md           # Deployment overview and quick start
├── docker.md           # Docker deployment guide
├── kubernetes.md       # Kubernetes deployment guide
├── cloud-providers.md  # AWS, GCP, Azure deployment
└── claude.md           # This file
```

## Deployment Options

### 1. Docker (Recommended for Development)
- Single container deployment
- Docker Compose for multi-service
- MCP server container

### 2. Kubernetes (Production)
- Auto-scaling (3-10 pods)
- Health checks and monitoring
- Secrets management
- Ingress configuration

### 3. Cloud Providers
- AWS ECS/EKS
- Google Cloud GKE/Cloud Run
- Azure AKS/Container Instances

## Key Files

### README.md
- Deployment overview
- Quick start commands
- Pre-deployment checklist
- Resource requirements

### docker.md
- Dockerfile usage
- Docker Compose configuration
- Volume mounts
- Environment variables

### kubernetes.md
- k8s/deployment.yaml reference
- ConfigMaps and Secrets
- HPA configuration
- Ingress setup

### cloud-providers.md
- AWS deployment
- GCP deployment
- Azure deployment
- Security considerations

## Related Files

- `Dockerfile` - Main container image
- `Dockerfile.mcp` - MCP server image
- `docker-compose.yml` - Multi-service orchestration
- `k8s/deployment.yaml` - Kubernetes manifests

## Usage

### For Developers
Start with Docker for local testing:
```bash
docker build -t reveng:latest .
docker run -it reveng:latest analyze binary.exe
```

### For DevOps
Use Kubernetes for production:
```bash
kubectl apply -f k8s/deployment.yaml
```

### For AI Assistants
The MCP server can be deployed as a containerized service for integration with Claude Desktop and other MCP clients.

---

*Deployment documentation for REVENG v4.0*
*Created: January 1, 2026*
