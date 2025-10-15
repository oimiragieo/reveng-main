# REVENG Cloud Deployment Guide
# =============================

This directory contains Kubernetes manifests and deployment scripts for running the REVENG AI-Enhanced Universal Analysis Engine in a cloud environment with high availability and auto-scaling capabilities.

## Architecture Overview

The cloud deployment consists of the following components:

### Core Services
- **MongoDB**: Primary database for storing analysis results and user data
- **Redis**: Message queue and caching layer for job processing
- **Backend API**: Node.js REST API server
- **Frontend**: React-based web interface
- **Nginx**: Reverse proxy and load balancer

### Enhanced Analysis Components
- **Analysis Workers**: Scalable worker processes for handling analysis jobs
- **AI Service**: Dedicated Python service for AI-enhanced analysis capabilities
- **Model Cache**: Persistent storage for AI models and cached results

### Infrastructure Components
- **Istio Gateway**: API gateway for traffic management and security
- **Horizontal Pod Autoscaler**: Automatic scaling based on CPU/memory usage
- **Persistent Volumes**: Shared storage for uploads, reports, and logs
- **Monitoring**: Prometheus metrics and alerting

## Prerequisites

### Required Tools
- `kubectl` (v1.24+)
- `docker` (v20.10+)
- `helm` (v3.8+) - optional but recommended
- Access to a Kubernetes cluster (v1.24+)

### Required Cluster Features
- **Storage Classes**: 
  - `gp3` for block storage (MongoDB, Redis)
  - `efs` for shared file storage (uploads, reports)
- **Load Balancer**: AWS NLB or equivalent
- **Ingress Controller**: Nginx Ingress or Istio Gateway
- **Metrics Server**: For HPA functionality

### Optional Components
- **Istio Service Mesh**: For advanced traffic management
- **Prometheus Operator**: For monitoring and alerting
- **Cert-Manager**: For automatic TLS certificate management

## Quick Start

### 1. Configure Environment

```bash
# Set your container registry
export REGISTRY="your-registry.com"
export VERSION="latest"
export ENVIRONMENT="production"

# Update image references in deployment files
sed -i "s|reveng/|${REGISTRY}/reveng-|g" kubernetes/*.yaml
```

### 2. Deploy with Script

```bash
# Make deployment script executable
chmod +x scripts/deploy-enhanced.sh

# Deploy everything
./scripts/deploy-enhanced.sh deploy
```

### 3. Access the Application

```bash
# Get external IP
kubectl get service reveng-loadbalancer -n reveng

# Access via browser
# https://your-external-ip
```

## Manual Deployment

### 1. Create Namespace and Configuration

```bash
kubectl apply -f kubernetes/namespace.yaml
kubectl apply -f kubernetes/enhanced-config.yaml
```

### 2. Deploy Storage

```bash
kubectl apply -f kubernetes/persistent-volumes.yaml
```

### 3. Deploy Core Services

```bash
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml
```

### 4. Deploy Enhanced Components

```bash
kubectl apply -f kubernetes/enhanced-deployment.yaml
kubectl apply -f kubernetes/enhanced-services.yaml
```

### 5. Configure API Gateway (Optional)

```bash
# If using Istio
kubectl apply -f kubernetes/istio-gateway.yaml

# If using Nginx Ingress
kubectl apply -f kubernetes/ingress.yaml
```

### 6. Enable Monitoring (Optional)

```bash
kubectl apply -f kubernetes/monitoring.yaml
```

## Helm Deployment

### 1. Install with Helm

```bash
# Add dependencies
helm dependency update helm/

# Install
helm install reveng-enhanced helm/ \
  --namespace reveng \
  --create-namespace \
  --set image.registry=your-registry.com \
  --set ingress.hosts[0].host=reveng.example.com
```

### 2. Upgrade

```bash
helm upgrade reveng-enhanced helm/ \
  --namespace reveng \
  --set image.tag=v1.1.0
```

## Configuration

### Environment Variables

Key configuration options in `enhanced-config.yaml`:

- `WORKER_CONCURRENCY`: Number of concurrent analysis jobs per worker (default: 2)
- `MAX_JOB_TIME`: Maximum time for analysis job in milliseconds (default: 3600000)
- `AI_SERVICE_WORKERS`: Number of AI service worker processes (default: 2)
- `MAX_FILE_SIZE`: Maximum file size for analysis (default: 1GB)

### Scaling Configuration

Horizontal Pod Autoscaler settings:

- **Analysis Workers**: 2-10 replicas based on CPU (70%) and memory (80%)
- **AI Service**: 2-6 replicas based on CPU (75%) and memory (85%)
- **Backend API**: 2-10 replicas based on CPU (70%) and memory (80%)

### Storage Configuration

- **Uploads**: 500GB EFS for file uploads (shared)
- **Reports**: 1TB EFS for analysis reports (shared)
- **Logs**: 100GB EFS for centralized logging (shared)
- **Model Cache**: 200GB EFS for AI models (shared)
- **MongoDB**: 100GB GP3 for database
- **Redis**: 20GB GP3 for cache/queue

## Monitoring and Observability

### Metrics Endpoints

- Backend API: `http://backend:5000/metrics`
- Analysis Workers: `http://analysis-worker:3001/metrics`
- AI Service: `http://ai-service:8000/metrics`

### Key Metrics

- `reveng_analysis_duration_seconds`: Analysis processing time
- `reveng_analysis_queue_size`: Number of queued jobs
- `reveng_analysis_failures_total`: Failed analysis count
- `reveng_active_connections`: Active WebSocket connections

### Alerts

- Backend service down
- High CPU/memory usage (>80%)
- Analysis queue backlog (>100 jobs)
- High failure rate (>5 failures/5min)

## Security Considerations

### Network Security

- All internal communication uses ClusterIP services
- External access only through load balancer/ingress
- Network policies can be enabled for additional isolation

### Data Security

- Secrets stored in Kubernetes secrets (base64 encoded)
- File uploads stored in encrypted EFS volumes
- TLS termination at load balancer/ingress

### Container Security

- Non-root containers with dedicated users
- Resource limits to prevent resource exhaustion
- Health checks for automatic recovery

## Troubleshooting

### Common Issues

1. **Pods stuck in Pending**: Check PVC binding and storage classes
2. **Analysis jobs failing**: Check worker logs and AI service connectivity
3. **High memory usage**: Adjust resource limits or enable more replicas
4. **Slow analysis**: Scale up workers or check AI service performance

### Debugging Commands

```bash
# Check pod status
kubectl get pods -n reveng

# View logs
kubectl logs -f deployment/analysis-worker -n reveng

# Check resource usage
kubectl top pods -n reveng

# Describe problematic pods
kubectl describe pod <pod-name> -n reveng

# Check HPA status
kubectl get hpa -n reveng
```

### Performance Tuning

1. **Increase worker concurrency** for CPU-bound workloads
2. **Add more AI service replicas** for ML-heavy analysis
3. **Tune JVM settings** for Java analysis components
4. **Optimize storage** with faster storage classes

## Cleanup

### Remove Deployment

```bash
# Using script
./scripts/deploy-enhanced.sh cleanup

# Using Helm
helm uninstall reveng-enhanced -n reveng

# Manual cleanup
kubectl delete namespace reveng
```

## Support

For deployment issues or questions:

1. Check the troubleshooting section above
2. Review pod logs for error messages
3. Verify cluster resources and storage
4. Contact the REVENG team with deployment details