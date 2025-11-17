# Kubernetes Deployment Directory

## Overview

The `k8s/` directory contains Kubernetes deployment manifests for the REVENG MCP (Model Context Protocol) enterprise server. These configurations enable production-grade deployment of REVENG as a cloud-native, scalable reverse engineering service.

**Purpose**: Kubernetes deployment configurations for REVENG MCP server
**Location**: `/home/user/reveng-main/k8s/`

## Directory Contents

```
k8s/
├── claude.md               # This file
└── deployment.yaml         # Kubernetes deployment manifest (5,643 bytes)
```

## Deployment Resources

### deployment.yaml (5,643 bytes)

Complete Kubernetes deployment including:

**Resources Defined**:
1. **Namespace**: `reveng-mcp` - Isolated environment for REVENG
2. **ConfigMap**: Application configuration and environment variables
3. **Secret**: Sensitive data (API keys, credentials)
4. **PersistentVolumeClaim**: Storage for analysis results and caching
5. **Deployment**: REVENG MCP server pods with auto-scaling
6. **Service**: Load balancer for external access
7. **HorizontalPodAutoscaler**: Auto-scaling (3-10 pods based on CPU/memory)
8. **NetworkPolicy**: Security controls for pod communication
9. **ServiceAccount**: Pod security and permissions
10. **RBAC**: Role-based access control

**Key Features**:
- Auto-scaling: 3-10 pods based on 70% CPU/memory threshold
- Health checks: Liveness and readiness probes
- Resource limits: CPU (1-2 cores), Memory (2-4GB per pod)
- Persistent storage: 100GB for analysis caching
- Security: NetworkPolicy, RBAC, non-root containers
- Production-ready: Rolling updates, self-healing

## Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │          Namespace: reveng-mcp                       │   │
│  │                                                       │   │
│  │  ┌─────────────────────────────────────────────┐    │   │
│  │  │  Service (LoadBalancer)                      │    │   │
│  │  │  External IP: <external-ip>                  │    │   │
│  │  │  Port: 8080 → 8080                          │    │   │
│  │  └──────────────┬──────────────────────────────┘    │   │
│  │                 │                                     │   │
│  │  ┌──────────────┴─────────────────────────────┐     │   │
│  │  │  HorizontalPodAutoscaler                    │     │   │
│  │  │  Min: 3 pods, Max: 10 pods                  │     │   │
│  │  │  Target: 70% CPU, 70% Memory                │     │   │
│  │  └──────────────┬──────────────────────────────┘     │   │
│  │                 │                                     │   │
│  │  ┌──────────────┴─────────────────────────────┐     │   │
│  │  │  Deployment: reveng-mcp-server              │     │   │
│  │  │                                              │     │   │
│  │  │  ┌────────┐  ┌────────┐  ┌────────┐        │     │   │
│  │  │  │ Pod 1  │  │ Pod 2  │  │ Pod 3  │  ...   │     │   │
│  │  │  │ (2GB)  │  │ (2GB)  │  │ (2GB)  │        │     │   │
│  │  │  └───┬────┘  └───┬────┘  └───┬────┘        │     │   │
│  │  │      │           │           │              │     │   │
│  │  │  ┌───┴───────────┴───────────┴────┐         │     │   │
│  │  │  │  PersistentVolume (100GB)      │         │     │   │
│  │  │  │  Analysis cache & results      │         │     │   │
│  │  │  └────────────────────────────────┘         │     │   │
│  │  └─────────────────────────────────────────────┘     │   │
│  │                                                       │   │
│  │  Security:                                           │   │
│  │  ├── NetworkPolicy (restrict egress)                │   │
│  │  ├── ServiceAccount + RBAC                          │   │
│  │  └── Non-root containers                            │   │
│  └───────────────────────────────────────────────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Quick Deployment

### Prerequisites

```bash
# Required
- Kubernetes cluster (1.19+)
- kubectl configured
- 100GB available storage
- Docker registry access

# Optional
- Helm (for easier management)
- Ingress controller (for domain routing)
```

### Deploy to Kubernetes

```bash
# 1. Review and configure secrets
# Edit deployment.yaml and set your API keys:
# - GEMINI_API_KEY
# - ANTHROPIC_API_KEY
# - VT_API_KEY (optional)

# 2. Deploy all resources
kubectl apply -f k8s/deployment.yaml

# 3. Verify deployment
kubectl get all -n reveng-mcp

# 4. Check pod status
kubectl get pods -n reveng-mcp

# 5. View logs
kubectl logs -n reveng-mcp -l app=reveng-mcp-server -f

# 6. Get external IP (may take a few minutes)
kubectl get service reveng-mcp-service -n reveng-mcp
```

### Access the Service

```bash
# Get service details
export MCP_IP=$(kubectl get service reveng-mcp-service -n reveng-mcp -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo "REVENG MCP Server: http://$MCP_IP:8080"

# Test health endpoint
curl http://$MCP_IP:8080/health

# Use with Claude Desktop (update mcp.json)
{
  "mcpServers": {
    "reveng": {
      "url": "http://$MCP_IP:8080",
      "transport": "http"
    }
  }
}
```

## Configuration

### Environment Variables (ConfigMap)

```yaml
REVENG_PORT: "8080"
REVENG_HOST: "0.0.0.0"
REVENG_WORKERS: "4"
REVENG_LOG_LEVEL: "INFO"
REVENG_CACHE_DIR: "/data/cache"
REVENG_RESULTS_DIR: "/data/results"
REVENG_MAX_CONCURRENT: "10"
```

### Secrets (Sensitive Data)

```yaml
# Required
GEMINI_API_KEY: <base64-encoded>
ANTHROPIC_API_KEY: <base64-encoded>

# Optional
VT_API_KEY: <base64-encoded>
OLLAMA_HOST: <base64-encoded>
```

### Resource Limits

**Per Pod**:
- CPU: 1000m (request) → 2000m (limit)
- Memory: 2Gi (request) → 4Gi (limit)
- Storage: Shared 100Gi PVC

**Auto-scaling**:
- Min replicas: 3
- Max replicas: 10
- Scale up: >70% CPU or Memory for 30s
- Scale down: <50% for 5 minutes

## Operations

### Scaling

```bash
# Manual scaling
kubectl scale deployment reveng-mcp-server -n reveng-mcp --replicas=5

# View auto-scaling status
kubectl get hpa -n reveng-mcp

# View scaling events
kubectl describe hpa reveng-mcp-hpa -n reveng-mcp
```

### Monitoring

```bash
# View pod metrics
kubectl top pods -n reveng-mcp

# View resource usage
kubectl describe deployment reveng-mcp-server -n reveng-mcp

# Check logs for errors
kubectl logs -n reveng-mcp -l app=reveng-mcp-server --tail=100 | grep ERROR

# View events
kubectl get events -n reveng-mcp --sort-by='.lastTimestamp'
```

### Troubleshooting

```bash
# Check pod status
kubectl get pods -n reveng-mcp

# Describe problematic pod
kubectl describe pod <pod-name> -n reveng-mcp

# View logs
kubectl logs <pod-name> -n reveng-mcp

# Execute commands in pod
kubectl exec -it <pod-name> -n reveng-mcp -- /bin/bash

# Check persistent volume
kubectl describe pvc reveng-mcp-storage -n reveng-mcp

# Test service connectivity
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -n reveng-mcp -- \
  curl http://reveng-mcp-service:8080/health
```

### Updates

```bash
# Update deployment
kubectl apply -f k8s/deployment.yaml

# View rollout status
kubectl rollout status deployment/reveng-mcp-server -n reveng-mcp

# View rollout history
kubectl rollout history deployment/reveng-mcp-server -n reveng-mcp

# Rollback to previous version
kubectl rollout undo deployment/reveng-mcp-server -n reveng-mcp
```

### Cleanup

```bash
# Delete all resources
kubectl delete -f k8s/deployment.yaml

# Or delete namespace (removes everything)
kubectl delete namespace reveng-mcp
```

## Security

### Network Policies

- Egress restricted to necessary services only
- API server access for health checks
- DNS resolution allowed
- External HTTP/HTTPS allowed for AI APIs

### Pod Security

- Non-root user (UID 1000)
- Read-only root filesystem
- No privilege escalation
- Dropped all capabilities except NET_BIND_SERVICE

### RBAC

- Dedicated ServiceAccount
- Minimal permissions
- No cluster-wide access
- Namespace-scoped only

### Secret Management

**Best Practices**:
- Use external secret managers (AWS Secrets Manager, Azure Key Vault, etc.)
- Rotate API keys regularly
- Encrypt secrets at rest
- Use RBAC to limit secret access

```bash
# Create secrets from environment
kubectl create secret generic reveng-mcp-secrets \
  --from-literal=GEMINI_API_KEY=$GEMINI_API_KEY \
  --from-literal=ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -n reveng-mcp
```

## Performance Tuning

### Optimize for High Throughput

```yaml
# Increase replicas
spec:
  replicas: 10

# Increase resource limits
resources:
  limits:
    cpu: "4"
    memory: "8Gi"
```

### Optimize for Cost

```yaml
# Reduce replicas
spec:
  replicas: 1

# Reduce resource limits
resources:
  limits:
    cpu: "500m"
    memory: "1Gi"
```

### Persistent Storage

```yaml
# Use faster storage class
storageClassName: ssd-storage  # Or premium-ssd

# Increase storage size
storage: 500Gi
```

## Integration

### Claude Desktop

Update `~/.config/claude/mcp.json`:

```json
{
  "mcpServers": {
    "reveng": {
      "command": "curl",
      "args": ["http://<external-ip>:8080"],
      "transport": "http"
    }
  }
}
```

### Custom Applications

```python
import requests

# Connect to Kubernetes-hosted MCP server
MCP_URL = "http://<external-ip>:8080"

# Health check
response = requests.get(f"{MCP_URL}/health")
print(response.json())

# Use MCP tools
response = requests.post(f"{MCP_URL}/tools/analyze_binary", json={
    "binary_path": "/path/to/binary.exe"
})
print(response.json())
```

## Related Documentation

- **MCP Integration**: `docs/mcp/README.md`
- **Docker Deployment**: `Dockerfile.mcp`
- **MCP Server**: `src/reveng/agent_sdk/mcp/servers/reveng_enterprise_server.py`
- **MCP Tools**: `src/reveng/agent_sdk/tools/reveng/`
- **Configuration**: `mcp-config.example.json`

## Notes

### Production Checklist

- [ ] Update API keys in secrets
- [ ] Configure resource limits for workload
- [ ] Set up monitoring and alerting
- [ ] Configure backup for persistent volume
- [ ] Set up ingress with TLS/SSL
- [ ] Review network policies
- [ ] Enable audit logging
- [ ] Test auto-scaling behavior
- [ ] Document disaster recovery plan
- [ ] Set up CI/CD pipeline

### Cloud Provider Notes

**AWS (EKS)**:
- Use AWS LoadBalancer for service
- Use EBS CSI driver for PVC
- Consider AWS Secrets Manager integration

**GCP (GKE)**:
- Use Google Cloud LoadBalancer
- Use GCE PD for PVC
- Consider Secret Manager integration

**Azure (AKS)**:
- Use Azure LoadBalancer
- Use Azure Disk for PVC
- Consider Key Vault integration

---

**Purpose**: Kubernetes deployment for REVENG MCP server
**Production Ready**: Yes (with proper configuration)
**Auto-scaling**: 3-10 pods
**Storage**: 100GB persistent
