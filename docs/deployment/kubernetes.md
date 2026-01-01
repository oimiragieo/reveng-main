# Kubernetes Deployment Guide

This guide covers deploying REVENG on Kubernetes clusters.

## Prerequisites

- Kubernetes cluster 1.24+
- kubectl configured
- Helm 3.0+ (optional)

## Quick Start

### Deploy with kubectl

```bash
# Apply all resources
kubectl apply -f k8s/deployment.yaml

# Verify deployment
kubectl get pods -l app=reveng
kubectl get services -l app=reveng

# Access MCP server
kubectl port-forward svc/reveng-mcp 8080:8080
```

## Kubernetes Resources

The `k8s/deployment.yaml` includes:

| Resource | Purpose |
|----------|---------|
| Deployment | MCP server pods (3-10 replicas) |
| Service | Load balancer for MCP server |
| ConfigMap | Non-sensitive configuration |
| Secret | API keys and credentials |
| HPA | Horizontal Pod Autoscaler |
| PVC | Persistent storage for results |
| NetworkPolicy | Security rules |
| ServiceAccount | RBAC configuration |
| Ingress | External access (optional) |

## Configuration

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: reveng-config
data:
  REVENG_LOG_LEVEL: "INFO"
  REVENG_CACHE_DIR: "/app/cache"
  REVENG_TIMEOUT: "600"
```

### Secrets

```bash
# Create secrets from environment
kubectl create secret generic reveng-secrets \
  --from-literal=GEMINI_API_KEY="${GEMINI_API_KEY}" \
  --from-literal=ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}"
```

## Auto-Scaling

The HPA automatically scales based on CPU usage:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: reveng-mcp-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: reveng-mcp
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Monitoring

### Health Checks

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

### Prometheus Metrics

```bash
# Access metrics endpoint
kubectl port-forward svc/reveng-mcp 8080:8080
curl http://localhost:8080/metrics
```

## Ingress Configuration

For external access with TLS:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: reveng-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - reveng.example.com
    secretName: reveng-tls
  rules:
  - host: reveng.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: reveng-mcp
            port:
              number: 8080
```

## Troubleshooting

### Pod not starting
```bash
kubectl describe pod <pod-name>
kubectl logs <pod-name>
```

### Resource issues
```bash
kubectl top pods -l app=reveng
kubectl describe node
```

### Network issues
```bash
kubectl exec -it <pod-name> -- curl localhost:8080/health
```

---

*Kubernetes deployment guide for REVENG v4.0*
