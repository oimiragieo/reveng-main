# REVENG Deployment Guide

This directory contains deployment documentation for REVENG in production environments.

## Deployment Options

### 1. Docker Deployment

REVENG can be deployed using Docker for containerized environments.

**Quick Start**:
```bash
# Build the Docker image
docker build -t reveng:latest .

# Run the container
docker run -it --rm \
  -e GEMINI_API_KEY="your-api-key" \
  -v $(pwd)/analysis:/app/analysis \
  reveng:latest analyze binary.exe

# Run the MCP server
docker build -f Dockerfile.mcp -t reveng-mcp:latest .
docker run -p 8080:8080 reveng-mcp:latest
```

**Configuration Files**:
- `Dockerfile` - Main REVENG container
- `Dockerfile.mcp` - MCP server container
- `docker-compose.yml` - Multi-service orchestration

See [docker.md](docker.md) for detailed Docker deployment instructions.

---

### 2. Kubernetes Deployment

For cloud-scale production deployments, REVENG provides Kubernetes manifests.

**Quick Start**:
```bash
# Apply Kubernetes resources
kubectl apply -f k8s/deployment.yaml

# Check deployment status
kubectl get pods -l app=reveng

# Access the MCP server
kubectl port-forward svc/reveng-mcp 8080:8080
```

**Features**:
- Auto-scaling (3-10 pods based on load)
- Health checks and readiness probes
- ConfigMaps for environment configuration
- Secrets management for API keys
- Persistent volume claims for analysis results

See [kubernetes.md](kubernetes.md) for detailed Kubernetes deployment.

---

### 3. Cloud Providers

REVENG can be deployed on major cloud platforms:

| Cloud Provider | Deployment Method | Documentation |
|---------------|-------------------|---------------|
| AWS | ECS/EKS | [cloud-providers.md](cloud-providers.md#aws) |
| Google Cloud | GKE/Cloud Run | [cloud-providers.md](cloud-providers.md#gcp) |
| Azure | AKS/Container Instances | [cloud-providers.md](cloud-providers.md#azure) |

---

## Pre-Deployment Checklist

Before deploying REVENG to production:

- [ ] **Environment Variables**
  - GEMINI_API_KEY configured
  - ANTHROPIC_API_KEY configured (optional)
  - OPENAI_API_KEY configured (optional)

- [ ] **Infrastructure**
  - Container runtime installed (Docker/containerd)
  - Kubernetes cluster available (for K8s deployment)
  - Persistent storage configured

- [ ] **Security**
  - API keys stored in secrets management
  - Network policies configured
  - TLS/HTTPS enabled

- [ ] **Monitoring**
  - Logging configured
  - Metrics collection enabled
  - Alerting rules defined

See [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md) for the complete checklist.

---

## Resource Requirements

### Minimum Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| Memory | 4 GB | 8+ GB |
| Storage | 10 GB | 50+ GB |
| GPU | Optional | NVIDIA (for acceleration) |

### MCP Server Resources

| Resource | Per Instance |
|----------|-------------|
| CPU | 1 core |
| Memory | 2 GB |
| Storage | 5 GB |
| Rate Limit | 5 req/sec |

---

## Related Documentation

- **[Main README](../../README.md)** - Project overview
- **[Installation Guide](../../INSTALLATION.md)** - Local installation
- **[MCP Documentation](../mcp/README.md)** - MCP server details
- **[Architecture](../architecture/overview.md)** - System architecture

---

*Deployment documentation for REVENG v4.0*
